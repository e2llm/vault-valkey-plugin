package valkey

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/redis/go-redis/v9"
)

// nodeACL applies credential operations to a single Valkey node. The real
// implementation (redisNodeACL) talks to the node over go-redis; tests inject a
// fake to exercise the topology orchestration (rollback, error aggregation)
// without a live server. This is the seam that keeps topology.go pure/testable.
type nodeACL interface {
	createUser(ctx context.Context, node, username, password, rules string) error
	setPassword(ctx context.Context, node, username, password string) error
	deleteUser(ctx context.Context, node, username string) error
}

// redisNodeACL is the production nodeACL: short-lived go-redis client per call,
// ACL command, then per-node persistence. It is parametrized by how it connects
// (data node admin vs Sentinel admin) and how it persists, so one implementation
// serves both planes.
type redisNodeACL struct {
	cfg         *Config // for credToken (password hashing)
	log         hclog.Logger
	connect     func(addr string) (*redis.Client, error) // node admin vs Sentinel admin
	persistMode string                                   // persistence mode for this plane
}

// dataNodeACL applies ACL ops to the Valkey data nodes as the node admin identity.
func (cfg *Config) dataNodeACL(log hclog.Logger) redisNodeACL {
	return redisNodeACL{cfg: cfg, log: log, connect: cfg.nodeClient, persistMode: cfg.PersistenceMode}
}

// sentinelNodeACL applies ACL ops to the Sentinels as the Sentinel admin identity
// (shared-identity mode). Sentinels have no CONFIG REWRITE, so persistence is aclfile
// (ACL SAVE) or none.
func (cfg *Config) sentinelNodeACL(log hclog.Logger) redisNodeACL {
	return redisNodeACL{cfg: cfg, log: log, connect: cfg.sentinelAdminClient, persistMode: cfg.SentinelPersistenceMode}
}

// createUser provisions a deterministic, clean user:
//
//	ACL SETUSER <user> reset on <#hash|>password> <rules...>
//
// The `reset` prefix guarantees a known starting state even on the (astronomically
// unlikely) username collision — ACL SETUSER is otherwise additive.
func (r redisNodeACL) createUser(ctx context.Context, node, username, password, rules string) error {
	return r.do(ctx, node, "create", func(c *redis.Client) error {
		args := []interface{}{"ACL", "SETUSER", username, "reset", "on", r.cfg.credToken(password)}
		args = append(args, ruleArgs(rules)...)
		return c.Do(ctx, args...).Err()
	})
}

// setPassword swaps the user's password while preserving its rules:
//
//	ACL SETUSER <user> resetpass on <#hash|>password>
func (r redisNodeACL) setPassword(ctx context.Context, node, username, password string) error {
	return r.do(ctx, node, "rotate", func(c *redis.Client) error {
		return c.Do(ctx, "ACL", "SETUSER", username, "resetpass", "on", r.cfg.credToken(password)).Err()
	})
}

// deleteUser removes the user. DELUSER of an absent user returns 0 (not an error),
// so this is idempotent as the dbplugin contract requires.
func (r redisNodeACL) deleteUser(ctx context.Context, node, username string) error {
	return r.do(ctx, node, "delete", func(c *redis.Client) error {
		return c.Do(ctx, "ACL", "DELUSER", username).Err()
	})
}

func (r redisNodeACL) do(ctx context.Context, node, op string, fn func(*redis.Client) error) error {
	client, err := r.connect(node)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := fn(client); err != nil {
		return fmt.Errorf("ACL %s on %s: %w", op, node, err)
	}
	if err := persist(ctx, client, r.persistMode); err != nil {
		return fmt.Errorf("persist after %s on %s: %w", op, node, err)
	}
	if r.log != nil {
		r.log.Debug("acl op applied", "op", op, "node", node)
	}
	return nil
}

// listUserDefs returns every ACL user on the node with its full rule string (ACL LIST) —
// the reconcile source of truth, from which a user can be cloned verbatim (hash included).
func (r redisNodeACL) listUserDefs(ctx context.Context, node string) ([]aclUserDef, error) {
	var defs []aclUserDef
	err := r.read(ctx, node, "list", func(c *redis.Client) error {
		lines, e := c.Do(ctx, "ACL", "LIST").StringSlice()
		if e != nil {
			return e
		}
		for _, ln := range lines {
			if name, rules, ok := parseACLListLine(ln); ok {
				defs = append(defs, aclUserDef{Name: name, Rules: rules})
			}
		}
		return nil
	})
	return defs, err
}

// listUsernames returns just the set of usernames on the node (ACL USERS) — the cheap read
// the reconcile pass runs per target node to diff against the master's managed set.
func (r redisNodeACL) listUsernames(ctx context.Context, node string) (map[string]struct{}, error) {
	set := map[string]struct{}{}
	err := r.read(ctx, node, "users", func(c *redis.Client) error {
		names, e := c.Do(ctx, "ACL", "USERS").StringSlice()
		if e != nil {
			return e
		}
		for _, n := range names {
			set[n] = struct{}{}
		}
		return nil
	})
	return set, err
}

// applyUserDef clones a user onto a node from its master rule string:
//
//	ACL SETUSER <user> reset <rules...>
//
// The rules already carry "on #hash …" (from ACL LIST), so no credToken is added — the
// copied hash authenticates the same cleartext password Vault issued. Persisted per plane.
func (r redisNodeACL) applyUserDef(ctx context.Context, node, username, rules string) error {
	return r.do(ctx, node, "reconcile", func(c *redis.Client) error {
		args := []interface{}{"ACL", "SETUSER", username, "reset"}
		args = append(args, ruleArgs(rules)...)
		return c.Do(ctx, args...).Err()
	})
}

// read runs a read-only ACL query (no persistence step) against one node.
func (r redisNodeACL) read(ctx context.Context, node, op string, fn func(*redis.Client) error) error {
	client, err := r.connect(node)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := fn(client); err != nil {
		return fmt.Errorf("ACL %s on %s: %w", op, node, err)
	}
	return nil
}
