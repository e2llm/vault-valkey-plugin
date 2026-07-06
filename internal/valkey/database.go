package valkey

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/logical"
)

// typeName is reported to Vault for metrics/logging only; no behavior switches on it.
const typeName = "valkey"

// Version is set by package main from the build-time ldflags value, and surfaced to
// Vault via the logical.PluginVersioner interface.
var Version = "dev"

// valkeyDB implements the dbplugin v5 Database interface for Valkey behind Sentinel.
//
// It holds no long-lived connections: topology changes on failover, so every
// operation re-resolves the master/replicas via Sentinel and opens short-lived
// per-node clients. Correctness under failover beats connection reuse.
type valkeyDB struct {
	mu     sync.RWMutex
	config Config
	logger hclog.Logger
}

func newValkeyDB() *valkeyDB {
	return &valkeyDB{logger: hclog.New(&hclog.LoggerOptions{Name: "valkey-database-plugin"})}
}

// New is the plugin factory passed to dbplugin.ServeMultiplex. The error-sanitizer
// middleware redacts configured secrets from any error returned to Vault.
func New() (interface{}, error) {
	db := newValkeyDB()
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues), nil
}

func (v *valkeyDB) Type() (string, error) { return typeName, nil }

// PluginVersion implements logical.PluginVersioner. Vault rejects a plugin that reports
// a non-semver version, so a dev/unset build reports "unversioned" (empty) rather than
// the non-semver "dev"; release builds inject a vX.Y.Z tag via ldflags.
func (v *valkeyDB) PluginVersion() logical.PluginVersion {
	if Version == "" || Version == "dev" {
		return logical.PluginVersion{}
	}
	return logical.PluginVersion{Version: Version}
}

// secretValues lists sensitive strings to scrub from errors/logs.
func (v *valkeyDB) secretValues() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := map[string]string{}
	if v.config.Password != "" {
		m[v.config.Password] = "[password]"
	}
	if v.config.SentinelPassword != "" {
		m[v.config.SentinelPassword] = "[sentinel_password]"
	}
	if v.config.TLSKey != "" {
		m[v.config.TLSKey] = "[tls_key]"
	}
	return m
}

func (v *valkeyDB) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	cfg, err := parseConfig(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid configuration: %w", err)
	}

	v.mu.Lock()
	v.config = cfg
	v.mu.Unlock()

	mode := "standalone"
	if len(cfg.Sentinels) > 0 {
		mode = "sentinel"
	}
	v.logger.Info("initializing", "mode", mode, "sentinel_identity_mode", cfg.SentinelIdentityMode,
		"master_name", cfg.SentinelMasterName, "persistence_mode", cfg.PersistenceMode,
		"tls", cfg.TLS, "password_hashing", cfg.PasswordHashing)
	if !cfg.TLS {
		v.logger.Warn("TLS disabled: the node admin password and client AUTH traffic travel in cleartext — enable `tls` for any non-trusted network")
	}
	if cfg.InsecureTLS {
		v.logger.Warn("insecure_tls set: server certificate verification is disabled")
	}
	if cfg.sharedSentinelIdentity() {
		v.logger.Warn("sentinel_identity_mode=shared: the dynamic user is provisioned onto the Sentinels too, so the app credential reaches the Sentinel control plane (read-only discovery). Less secure than separate identities — use only for clients that cannot use a dedicated Sentinel discovery user",
			"sentinel_persistence_mode", cfg.SentinelPersistenceMode)
		if cfg.SentinelPersistenceMode == PersistenceNone {
			v.logger.Info("Sentinel-side users are ephemeral (sentinel_persistence_mode=none): they do not survive a Sentinel restart; correctness relies on multiple Sentinels and the app re-fetching credentials")
		}
	}

	if req.VerifyConnection {
		if err := v.verifyConnection(ctx, cfg); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	resp := dbplugin.InitializeResponse{Config: req.Config}
	resp.SetSupportedCredentialTypes([]dbplugin.CredentialType{dbplugin.CredentialTypePassword})
	return resp, nil
}

// NewUser provisions a dynamic user on every node in the current topology, rolling
// back a partial creation so Vault never holds a half-present lease.
func (v *valkeyDB) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	v.mu.RLock()
	cfg := v.config
	v.mu.RUnlock()

	// req.Password is the per-lease secret Vault minted. This plugin never logs it or
	// formats it into an error (the error-sanitizer scrubs the config secrets; go-redis
	// errors carry the transport/server message, not command args), so it cannot leak.
	if req.Password == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("empty password supplied for new user (check Vault's password policy)")
	}

	rules := renderRules(req.Statements.Commands)
	if err := validateRules(rules); err != nil {
		return dbplugin.NewUserResponse{}, err
	}
	if hits := overBroad(rules); len(hits) > 0 {
		v.logger.Warn("role grants broad privileges; @all/allcommands include admin and can persist past the lease — prefer scoped categories or '-@admin -@dangerous'",
			"tokens", strings.Join(hits, " "), "role", req.UsernameConfig.RoleName)
	}

	username, err := generateUsername(req.UsernameConfig, cfg.UsernameTemplate)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
	}
	if username == "" {
		return dbplugin.NewUserResponse{}, fmt.Errorf("generated username is empty (check username_template)")
	}

	topo, err := cfg.discoverTopology(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("topology discovery failed: %w", err)
	}

	dataOps := cfg.dataNodeACL(v.logger)
	if err := topo.create(ctx, dataOps, username, req.Password, rules); err != nil {
		v.logger.Error("create user failed", "user", username, "error", err)
		return dbplugin.NewUserResponse{}, err
	}

	// Shared-identity mode: also provision the user on the Sentinels so the app can
	// discover the master with the same credential. Quorum of one; total failure rolls
	// back the data plane so Vault never holds a lease whose credential is unusable.
	if len(topo.Sentinels) > 0 {
		sentinelOps := cfg.sentinelNodeACL(v.logger)
		done, failed, serr := topo.createSentinels(ctx, sentinelOps, username, req.Password, cfg.sentinelRules())
		if serr != nil {
			if rb := topo.delete(ctx, dataOps, username); rb != nil {
				v.logger.Error("rolled back data nodes after total Sentinel failure, but rollback had errors", "error", rb)
			}
			v.logger.Error("create user failed: no Sentinel accepted the discovery user", "user", username, "error", serr)
			return dbplugin.NewUserResponse{}, serr
		}
		for _, f := range failed {
			v.logger.Warn("Sentinel provisioning failed (tolerated — another Sentinel succeeded)",
				"detail", f, "role", req.UsernameConfig.RoleName)
		}
		v.logger.Info("provisioned discovery user on Sentinels", "user", username,
			"sentinels_ok", len(done), "sentinels_failed", len(failed))
	}

	// Opportunistic reconcile: now that we're topology-resolved and admin-connected, re-assert
	// any managed users a returned data node is missing (it was down at an earlier create) and
	// clear orphans a revoke left on a then-down node. Best-effort — the issued credential is
	// already provisioned, so a reconcile hiccup never fails issuance.
	if cfg.Reconcile && len(topo.Nodes) > 1 {
		if issues := topo.reconcile(ctx, dataOps, cfg.ManagedUsernamePrefix, cfg.Username); len(issues) > 0 {
			v.logger.Warn("reconcile pass reported node drift (non-fatal; the issued credential is already provisioned)",
				"issues", strings.Join(issues, "; "))
		}
	}

	v.logger.Info("created user", "user", username, "role", req.UsernameConfig.RoleName,
		"nodes", len(topo.Nodes), "master", topo.Master)
	return dbplugin.NewUserResponse{Username: username}, nil
}

// UpdateUser handles password changes. The dominant caller is root rotation
// (vault rotate-root), which arrives as UpdateUser on the configured root user;
// that path is all-or-nothing with rollback. A non-root password change (rare for
// dynamic creds) is applied best-effort across nodes.
func (v *valkeyDB) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password == nil {
		return dbplugin.UpdateUserResponse{}, nil
	}
	if req.Password.NewPassword == "" {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("empty new password supplied for %q", req.Username)
	}

	v.mu.RLock()
	cfg := v.config
	v.mu.RUnlock()

	topo, err := cfg.discoverTopology(ctx)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("topology discovery failed: %w", err)
	}

	if req.Username == cfg.Username {
		if err := v.rotateRoot(ctx, &cfg, topo, req.Password.NewPassword); err != nil {
			v.logger.Error("root rotation failed", "error", err)
			return dbplugin.UpdateUserResponse{}, err
		}
		v.logger.Info("rotated root credential", "user", req.Username, "nodes", len(topo.Nodes))
		return dbplugin.UpdateUserResponse{}, nil
	}

	dataOps := cfg.dataNodeACL(v.logger)
	if err := topo.setPassword(ctx, dataOps, req.Username, req.Password.NewPassword); err != nil {
		return dbplugin.UpdateUserResponse{}, err
	}
	if len(topo.Sentinels) > 0 {
		sentinelOps := cfg.sentinelNodeACL(v.logger)
		if err := setPasswordOn(ctx, sentinelOps, topo.Sentinels, req.Username, req.Password.NewPassword); err != nil {
			// Best-effort: a stale Sentinel-side password only affects discovery, and the
			// app re-fetches credentials on restart. Log, don't fail the rotation.
			v.logger.Warn("Sentinel-side password update failed (best-effort)", "user", req.Username, "error", err)
		}
	}
	v.logger.Info("updated user password", "user", req.Username, "nodes", len(topo.Nodes))
	return dbplugin.UpdateUserResponse{}, nil
}

// rotateRoot rotates the plugin's own admin password on every node with all-or-
// nothing semantics: on any node failure it restores the previous password on the
// already-changed nodes (reconnecting with the new password), so the admin identity
// never ends up split-brained across nodes. Only on full success is the in-memory
// credential updated.
func (v *valkeyDB) rotateRoot(ctx context.Context, cfg *Config, topo *Topology, newPass string) error {
	oldPass := cfg.Password
	user := cfg.Username
	opsOld := cfg.dataNodeACL(v.logger) // connects with the current (old) password

	// restore brings a node back to oldPass whether it currently holds the new password
	// (SETUSER applied but persist failed) or still the old one (change never applied):
	// try the new credential first, then fall back to the old. This covers the case where
	// a per-node failure occurs *after* the live password already changed.
	restore := func(node string) error {
		cfgNew := *cfg
		cfgNew.Password = newPass
		if err := cfgNew.dataNodeACL(v.logger).setPassword(ctx, node, user, oldPass); err == nil {
			return nil
		}
		return opsOld.setPassword(ctx, node, user, oldPass)
	}

	var changed []string
	for _, node := range topo.Nodes {
		if err := opsOld.setPassword(ctx, node, user, newPass); err != nil {
			// The failing node may already hold the new password, so roll back the changed
			// nodes AND the failing node.
			var rb []string
			for _, c := range append(append([]string{}, changed...), node) {
				if e := restore(c); e != nil {
					rb = append(rb, fmt.Sprintf("%s: %v", c, e))
				}
			}
			if len(rb) > 0 {
				return fmt.Errorf("root rotation failed on %s: %w; ROLLBACK FAILED on %s — admin credential is INCONSISTENT across nodes, manual recovery required", node, err, strings.Join(rb, "; "))
			}
			return fmt.Errorf("root rotation failed on %s: %w (rolled back %d node(s) to the previous password)", node, err, len(changed)+1)
		}
		changed = append(changed, node)
	}

	v.mu.Lock()
	v.config.Password = newPass
	v.mu.Unlock()
	return nil
}

// DeleteUser revokes the user on every node (idempotent per the dbplugin contract).
func (v *valkeyDB) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	v.mu.RLock()
	cfg := v.config
	v.mu.RUnlock()

	topo, err := cfg.discoverTopology(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("topology discovery failed: %w", err)
	}

	dataOps := cfg.dataNodeACL(v.logger)
	if err := topo.delete(ctx, dataOps, req.Username); err != nil {
		v.logger.Error("delete user failed", "user", req.Username, "error", err)
		return dbplugin.DeleteUserResponse{}, err
	}
	if len(topo.Sentinels) > 0 {
		sentinelOps := cfg.sentinelNodeACL(v.logger)
		for _, f := range topo.deleteSentinels(ctx, sentinelOps, req.Username) {
			v.logger.Warn("Sentinel revoke failed (harmless: discovery-only access; ephemeral Sentinels self-clean on restart)",
				"detail", f, "user", req.Username)
		}
	}
	v.logger.Info("deleted user", "user", req.Username, "nodes", len(topo.Nodes))
	return dbplugin.DeleteUserResponse{}, nil
}

// Close has nothing to release: clients are per-operation and short-lived.
func (v *valkeyDB) Close() error { return nil }

func (v *valkeyDB) verifyConnection(ctx context.Context, cfg Config) error {
	topo, err := cfg.discoverTopology(ctx)
	if err != nil {
		return err
	}
	client, err := cfg.nodeClient(topo.Master)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping master %s: %w", topo.Master, err)
	}
	return nil
}
