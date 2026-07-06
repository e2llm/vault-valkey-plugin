package valkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Persistence modes control how a created/updated/deleted ACL user is made
// durable on each node. Runtime ACL changes are lost on restart unless saved.
const (
	// PersistenceACLFile runs `ACL SAVE` after each change (requires aclfile).
	PersistenceACLFile = "aclfile"
	// PersistenceRewrite runs `CONFIG REWRITE` after each change (users in the
	// main config file). Note CONFIG REWRITE does NOT imply ACL SAVE.
	PersistenceRewrite = "rewrite"
	// PersistenceNone performs no persistence — only safe where the operator
	// persists ACLs out-of-band or accepts loss on restart.
	PersistenceNone = "none"
)

// Sentinel identity modes control whether the dynamic user is also provisioned onto
// the Sentinels (for legacy apps that authenticate to both the data nodes and the
// Sentinels with ONE credential), or whether Sentinel discovery uses a separate
// identity (the secure default).
const (
	// IdentitySeparate (default) keeps dynamic users on the data nodes only;
	// discovery uses the operator-provisioned sentinel_username/password.
	IdentitySeparate = "separate"
	// IdentityShared also provisions the dynamic user onto the Sentinels with a
	// narrow read-only discovery ACL. Less secure (the app credential reaches the
	// Sentinel control plane) — opt-in for clients that cannot use two identities.
	IdentityShared = "shared"
)

// Config is the parsed connection configuration for a Valkey database backend.
type Config struct {
	// Sentinel discovery (preferred). When Sentinels is non-empty the plugin
	// resolves the current master and live replicas dynamically per operation.
	Sentinels          []string
	SentinelMasterName string
	// Separate, low-privilege identity for talking to the Sentinels. Kept
	// distinct from the node admin credentials by design.
	SentinelUsername string
	SentinelPassword string

	// Standalone fallback (used only when Sentinels is empty).
	Host string
	Port int

	// Node admin credentials used to run ACL SETUSER/DELUSER on the data nodes.
	Username string
	Password string

	// Durability of ACL changes on each node.
	PersistenceMode string

	// TLS to the nodes and Sentinels.
	TLS         bool
	InsecureTLS bool
	CACert      string
	TLSCert     string
	TLSKey      string

	// PasswordHashing sends a SHA-256 hash (#<hex>) to ACL SETUSER instead of the
	// cleartext password, so cleartext never reaches a node's command log. Default true.
	PasswordHashing bool

	// UsernameTemplate overrides the generated dynamic username format.
	UsernameTemplate string

	// SentinelIdentityMode selects "separate" (default) or "shared" (see Identity*
	// constants). In shared mode the dynamic user is also provisioned on the
	// Sentinels, and sentinel_username/password must be a Sentinel admin.
	SentinelIdentityMode string
	// SentinelPersistenceMode is the durability of the Sentinel-side user in shared
	// mode: "aclfile" (ACL SAVE — requires an aclfile configured on the Sentinels) or
	// "none" (ephemeral, default). CONFIG REWRITE is unavailable on Sentinels.
	SentinelPersistenceMode string
	// SentinelCreationStatements overrides the Sentinel-side discovery ACL in shared
	// mode. Empty uses the built-in narrow read-only default (see sentinelRules).
	SentinelCreationStatements string

	// Reconcile enables the opportunistic reconcile pass on each NewUser: managed users
	// missing from a returned data node are re-asserted from the master, and orphans a
	// revoke left on a then-down node are removed. Default true.
	Reconcile bool
	// ManagedUsernamePrefix identifies plugin-managed dynamic users for the reconcile
	// pass (default "v_", the built-in username_template prefix). Set this only if
	// username_template is overridden to produce a different prefix.
	ManagedUsernamePrefix string
}

func parseConfig(raw map[string]interface{}) (Config, error) {
	c := Config{
		Sentinels:          cfgCSV(raw, "sentinels"),
		SentinelMasterName: cfgString(raw, "sentinel_master_name"),
		SentinelUsername:   cfgString(raw, "sentinel_username"),
		SentinelPassword:   cfgString(raw, "sentinel_password"),
		Host:               cfgString(raw, "host"),
		Port:               cfgInt(raw, "port", 6379),
		Username:           cfgString(raw, "username"),
		Password:           cfgString(raw, "password"),
		PersistenceMode:    strings.ToLower(cfgString(raw, "persistence_mode")),
		TLS:                cfgBool(raw, "tls"),
		InsecureTLS:        cfgBool(raw, "insecure_tls"),
		CACert:             cfgString(raw, "ca_cert"),
		TLSCert:            cfgString(raw, "tls_cert"),
		TLSKey:             cfgString(raw, "tls_key"),
		PasswordHashing:    cfgBoolDefault(raw, "password_hashing", true),
		UsernameTemplate:   cfgString(raw, "username_template"),

		SentinelIdentityMode:       strings.ToLower(cfgString(raw, "sentinel_identity_mode")),
		SentinelPersistenceMode:    strings.ToLower(cfgString(raw, "sentinel_persistence_mode")),
		SentinelCreationStatements: cfgString(raw, "sentinel_creation_statements"),

		Reconcile:             cfgBoolDefault(raw, "reconcile", true),
		ManagedUsernamePrefix: cfgString(raw, "managed_username_prefix"),
	}
	if c.PersistenceMode == "" {
		c.PersistenceMode = PersistenceACLFile
	}
	if c.SentinelIdentityMode == "" {
		c.SentinelIdentityMode = IdentitySeparate
	}
	if c.SentinelPersistenceMode == "" {
		c.SentinelPersistenceMode = PersistenceNone
	}
	if c.ManagedUsernamePrefix == "" {
		c.ManagedUsernamePrefix = defaultManagedUsernamePrefix
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) validate() error {
	sentinelMode := len(c.Sentinels) > 0
	if sentinelMode && c.SentinelMasterName == "" {
		return errors.New("sentinel_master_name is required when sentinels is set (e.g. sentinel_master_name=mymaster)")
	}
	if !sentinelMode && c.Host == "" {
		return errors.New("either sentinels + sentinel_master_name (Sentinel mode) or host (standalone) must be set")
	}
	if c.Username == "" || c.Password == "" {
		return errors.New("username and password (Valkey node admin credentials) are required")
	}
	switch c.PersistenceMode {
	case PersistenceACLFile, PersistenceRewrite, PersistenceNone:
	default:
		return fmt.Errorf("invalid persistence_mode %q (want one of: aclfile, rewrite, none)", c.PersistenceMode)
	}
	if c.TLSCert != "" && c.TLSKey == "" || c.TLSCert == "" && c.TLSKey != "" {
		return errors.New("tls_cert and tls_key must be supplied together")
	}
	switch c.SentinelIdentityMode {
	case IdentitySeparate, IdentityShared:
	default:
		return fmt.Errorf("invalid sentinel_identity_mode %q (want one of: separate, shared)", c.SentinelIdentityMode)
	}
	// A Sentinel has no CONFIG REWRITE (proven in test/sentinel/spike.sh), so the
	// Sentinel-side user can only be persisted via an aclfile, or left ephemeral.
	switch c.SentinelPersistenceMode {
	case PersistenceACLFile, PersistenceNone:
	case PersistenceRewrite:
		return errors.New("sentinel_persistence_mode=rewrite is impossible: Sentinels have no CONFIG REWRITE — use aclfile (requires an aclfile configured on the Sentinels) or none (ephemeral)")
	default:
		return fmt.Errorf("invalid sentinel_persistence_mode %q (want one of: aclfile, none)", c.SentinelPersistenceMode)
	}
	if c.SentinelIdentityMode == IdentityShared {
		if !sentinelMode {
			return errors.New("sentinel_identity_mode=shared requires Sentinel mode (set sentinels + sentinel_master_name); it is meaningless for a standalone host")
		}
		if err := validateSentinelRules(c.sentinelRules()); err != nil {
			return err
		}
	}
	return nil
}

// sharedSentinelIdentity reports whether the dynamic user must also be provisioned
// onto the Sentinels (shared-identity mode).
func (c *Config) sharedSentinelIdentity() bool { return c.SentinelIdentityMode == IdentityShared }

// --- defensive config decoding (Vault passes everything as map[string]interface{}) ---

func cfgString(m map[string]interface{}, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func cfgBool(m map[string]interface{}, k string) bool {
	v, ok := m[k]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		parsed, _ := strconv.ParseBool(strings.TrimSpace(b))
		return parsed
	default:
		return false
	}
}

// cfgBoolDefault is cfgBool with a default applied when the key is absent.
func cfgBoolDefault(m map[string]interface{}, k string, def bool) bool {
	if _, ok := m[k]; !ok {
		return def
	}
	return cfgBool(m, k)
}

func cfgInt(m map[string]interface{}, k string, def int) int {
	v, ok := m[k]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return def
}

func cfgCSV(m map[string]interface{}, k string) []string {
	// Accept a comma-separated string ("a:26379,b:26379") or a list.
	if v, ok := m[k]; ok {
		if list, ok := v.([]interface{}); ok {
			out := make([]string, 0, len(list))
			for _, e := range list {
				if s := strings.TrimSpace(fmt.Sprintf("%v", e)); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	s := cfgString(m, k)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
