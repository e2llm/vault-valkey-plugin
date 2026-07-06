package valkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// credToken returns the ACL password argument for `ACL SETUSER`. By default it is
// a hashed `#<sha256hex>` so the cleartext password never reaches a node's command
// log / SLOWLOG / MONITOR; with password_hashing disabled it is `>cleartext`.
// Either way clients still authenticate with the cleartext password Vault issued.
func (c *Config) credToken(password string) string {
	if c.PasswordHashing {
		sum := sha256.Sum256([]byte(password))
		return "#" + hex.EncodeToString(sum[:])
	}
	return ">" + password
}

// persist makes the just-applied ACL change durable on this node.
func persist(ctx context.Context, client *redis.Client, mode string) error {
	switch mode {
	case PersistenceACLFile:
		if err := client.Do(ctx, "ACL", "SAVE").Err(); err != nil {
			return fmt.Errorf("ACL SAVE (persistence_mode=aclfile): %w", err)
		}
	case PersistenceRewrite:
		if err := client.Do(ctx, "CONFIG", "REWRITE").Err(); err != nil {
			return fmt.Errorf("CONFIG REWRITE (persistence_mode=rewrite): %w", err)
		}
	}
	return nil
}

// renderRules joins Vault creation_statements into one ACL rule string. Prefer ACL
// categories over enumerated commands for version portability, e.g.
// "~app:* +@read +@write +@stream".
func renderRules(commands []string) string {
	parts := make([]string, 0, len(commands))
	for _, c := range commands {
		if c = strings.TrimSpace(c); c != "" {
			parts = append(parts, c)
		}
	}
	return strings.Join(parts, " ")
}

func ruleArgs(rules string) []interface{} {
	fields := strings.Fields(rules)
	out := make([]interface{}, len(fields))
	for i, f := range fields {
		out[i] = f
	}
	return out
}

// dangerousTokens, if present in operator-supplied creation_statements, would undermine
// the managed credential — the plugin already issues `reset on <password>`, so these
// would disable the user, strip the password the plugin controls, or wipe restrictions
// the operator just expressed (ACL SETUSER is applied left-to-right).
var dangerousTokens = map[string]bool{
	"nopass": true, "off": true, "reset": true, "resetpass": true,
	"clearselectors": true, "resetkeys": true, "resetchannels": true,
}

// escalationGrants name commands/categories that would let a *dynamic* credential escape
// its lease: administer ACLs (create a permanent user that outlives revocation), rewrite
// config (requirepass/dir), load native modules, take over via replication/cluster, or
// shut the node down. A dynamic credential must not hold these — use a static credential
// for genuine admin access.
var escalationGrants = map[string]bool{
	"@admin": true, "@dangerous": true,
	"acl": true, "config": true, "module": true, "debug": true, "shutdown": true,
	"replicaof": true, "slaveof": true, "cluster": true, "failover": true,
}

// overBroadTokens are legitimate but warrant a least-privilege warning. `@all`/`allcommands`
// also include the admin commands above, so such a user can persist beyond its lease.
var overBroadTokens = map[string]bool{
	"+@all": true, "allcommands": true, "~*": true, "allkeys": true, "&*": true, "allchannels": true,
}

// validateRules rejects creation_statements tokens that would break the credential model
// or let a dynamic credential escape its lease. Each token is stripped of selector parens
// first, because `strings.Fields` splits a selector like `(>pw ...)` into glued tokens —
// so a naive first-byte check would miss `(>backdoor)`.
func validateRules(rules string) error {
	for _, raw := range strings.Fields(rules) {
		tok := strings.Trim(raw, "()")
		if tok == "" {
			continue
		}
		low := strings.ToLower(tok)
		if dangerousTokens[low] {
			return fmt.Errorf("creation_statements may not contain %q: the plugin manages the user's enabled state, password, and selectors (it issues 'reset on <password>'); that token would undermine it", raw)
		}
		if strings.IndexByte("><#!", tok[0]) >= 0 {
			return fmt.Errorf("creation_statements may not contain password directives (token %q): the plugin owns the credential; supply only key/command/channel rules", raw)
		}
		if tok[0] == '+' {
			cmd := low[1:]
			if i := strings.IndexByte(cmd, '|'); i >= 0 {
				cmd = cmd[:i] // acl|setuser -> acl
			}
			if escalationGrants[cmd] {
				return fmt.Errorf("creation_statements may not grant %q: a dynamic credential must not administer ACLs/config/modules/replication or shut down the node — it could persist past its lease; use a static credential for admin access", raw)
			}
		}
	}
	return nil
}

// overBroad returns least-privilege-violating tokens present (for warning, not rejection).
func overBroad(rules string) []string {
	var hits []string
	for _, raw := range strings.Fields(rules) {
		if overBroadTokens[strings.ToLower(strings.Trim(raw, "()"))] {
			hits = append(hits, raw)
		}
	}
	return hits
}

// defaultSentinelRules is the built-in narrow discovery ACL for the shared-identity
// Sentinel user: connection commands plus the read-only SENTINEL subcommands a client
// needs to resolve the master. It deliberately omits the mutating subcommands
// (failover/monitor/remove/set), so a leaked app credential cannot drive the topology.
// Validated sufficient + contained in test/sentinel/spike.sh.
const defaultSentinelRules = "+@connection +sentinel|get-master-addr-by-name +sentinel|replicas +sentinel|sentinels"

// sentinelRules returns the Sentinel-side discovery ACL: the operator override if set,
// otherwise the built-in narrow default.
func (c *Config) sentinelRules() string {
	if r := strings.TrimSpace(c.SentinelCreationStatements); r != "" {
		return r
	}
	return defaultSentinelRules
}

// sentinelMutatingSubs are SENTINEL subcommands that change topology/monitoring; a
// discovery user (the app's shared identity) must never hold these.
var sentinelMutatingSubs = map[string]bool{
	"failover": true, "monitor": true, "remove": true, "set": true,
	"reset": true, "simulate-failure": true, "debug": true, "flushconfig": true,
}

// validateSentinelRules applies the same credential-model checks as the data side
// (no model-breaking tokens, no password directives, no privilege escalation) and
// additionally forbids granting topology control: the whole `sentinel` command, or any
// mutating `sentinel|<sub>`.
func validateSentinelRules(rules string) error {
	if err := validateRules(rules); err != nil {
		return err
	}
	for _, raw := range strings.Fields(rules) {
		tok := strings.Trim(raw, "()")
		if tok == "" || tok[0] != '+' {
			continue
		}
		low := strings.ToLower(tok[1:])
		if low == "sentinel" {
			return fmt.Errorf("sentinel_creation_statements may not grant the whole 'sentinel' command (%q): it includes failover/monitor/remove — grant only read subcommands, e.g. +sentinel|get-master-addr-by-name", raw)
		}
		if i := strings.IndexByte(low, '|'); i >= 0 && low[:i] == "sentinel" && sentinelMutatingSubs[low[i+1:]] {
			return fmt.Errorf("sentinel_creation_statements may not grant the mutating subcommand %q: a discovery user must not control failover/monitoring", raw)
		}
	}
	return nil
}
