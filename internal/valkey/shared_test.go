package valkey

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// --- config validation for shared identity mode ---

func sharedCfg(extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{
		"sentinels":            "10.0.0.1:26379,10.0.0.2:26379",
		"sentinel_master_name": "mymaster",
		"sentinel_username":    "vault-sentinel-admin",
		"sentinel_password":    "spw",
		"username":             "vaultadmin",
		"password":             "apw",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestParseConfig_SharedModeValid(t *testing.T) {
	cfg, err := parseConfig(sharedCfg(map[string]interface{}{"sentinel_identity_mode": "shared"}))
	if err != nil {
		t.Fatalf("valid shared config rejected: %v", err)
	}
	if !cfg.sharedSentinelIdentity() {
		t.Error("sharedSentinelIdentity() should be true")
	}
	if cfg.SentinelPersistenceMode != PersistenceNone {
		t.Errorf("default sentinel_persistence_mode should be none, got %q", cfg.SentinelPersistenceMode)
	}
	if cfg.sentinelRules() != defaultSentinelRules {
		t.Errorf("default sentinelRules mismatch: %q", cfg.sentinelRules())
	}
}

func TestParseConfig_SeparateIsDefault(t *testing.T) {
	cfg, err := parseConfig(sharedCfg(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SentinelIdentityMode != IdentitySeparate || cfg.sharedSentinelIdentity() {
		t.Errorf("identity mode should default to separate, got %q", cfg.SentinelIdentityMode)
	}
}

func TestParseConfig_SharedModeRejections(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"shared on standalone": {"host": "h", "username": "u", "password": "p", "sentinel_identity_mode": "shared"},
		"sentinel rewrite":     sharedCfg(map[string]interface{}{"sentinel_identity_mode": "shared", "sentinel_persistence_mode": "rewrite"}),
		"bad sentinel persist": sharedCfg(map[string]interface{}{"sentinel_identity_mode": "shared", "sentinel_persistence_mode": "bogus"}),
		"bad identity mode":    sharedCfg(map[string]interface{}{"sentinel_identity_mode": "bogus"}),
		"failover in override": sharedCfg(map[string]interface{}{"sentinel_identity_mode": "shared", "sentinel_creation_statements": "+@connection +sentinel|failover"}),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(in); err == nil {
				t.Errorf("expected validation error for %q", name)
			}
		})
	}
}

func TestParseConfig_SharedAcceptsAclfilePersistence(t *testing.T) {
	cfg, err := parseConfig(sharedCfg(map[string]interface{}{
		"sentinel_identity_mode":    "shared",
		"sentinel_persistence_mode": "aclfile",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SentinelPersistenceMode != PersistenceACLFile {
		t.Errorf("sentinel_persistence_mode=aclfile not respected: %q", cfg.SentinelPersistenceMode)
	}
}

func TestSentinelRules_Override(t *testing.T) {
	c := &Config{SentinelCreationStatements: "+@connection +sentinel|get-master-addr-by-name"}
	if c.sentinelRules() != "+@connection +sentinel|get-master-addr-by-name" {
		t.Errorf("override not used: %q", c.sentinelRules())
	}
	if (&Config{}).sentinelRules() != defaultSentinelRules {
		t.Error("empty SentinelCreationStatements should yield the built-in default")
	}
}

// --- sentinel rule validation ---

func TestValidateSentinelRules_Allows(t *testing.T) {
	for _, r := range []string{
		defaultSentinelRules,
		"+@connection +sentinel|get-master-addr-by-name",
		"+sentinel|master +sentinel|replicas",
		"+@connection +sentinel|sentinels +subscribe &*", // a client that watches +switch-master
	} {
		if err := validateSentinelRules(r); err != nil {
			t.Errorf("validateSentinelRules(%q) should pass, got %v", r, err)
		}
	}
}

func TestValidateSentinelRules_RejectsTopologyControl(t *testing.T) {
	for _, r := range []string{
		"+sentinel",          // the whole command (includes failover/monitor/remove)
		"+sentinel|failover", // mutating subcommands
		"+@connection +sentinel|monitor",
		"+sentinel|remove", "+sentinel|set", "(+sentinel|reset)",
		"+SENTINEL|FAILOVER", // case-insensitive
		"nopass",             // inherited base check
		"+@admin",            // inherited escalation grant
		">backdoor",          // inherited password directive
	} {
		if err := validateSentinelRules(r); err == nil {
			t.Errorf("validateSentinelRules(%q) should reject", r)
		}
	}
}

// --- sentinel-plane orchestration (pure, fake nodeACL) ---

type allFailACL struct{}

func (allFailACL) createUser(context.Context, string, string, string, string) error {
	return errors.New("boom")
}
func (allFailACL) setPassword(context.Context, string, string, string) error {
	return errors.New("boom")
}
func (allFailACL) deleteUser(context.Context, string, string) error { return errors.New("boom") }

func sentinelTopo() *Topology {
	return &Topology{Master: "n1", Nodes: []string{"n1"}, Sentinels: []string{"s1", "s2", "s3"}}
}

func TestCreateSentinels_QuorumToleratesPartialFailure(t *testing.T) {
	f := newFake()
	f.failCreateOn = "s1" // one Sentinel down for maintenance
	done, failed, err := sentinelTopo().createSentinels(context.Background(), f, "u", "pw", defaultSentinelRules)
	if err != nil {
		t.Fatalf("a single Sentinel failure should be tolerated (quorum of one), got %v", err)
	}
	if len(done) != 2 || len(failed) != 1 {
		t.Errorf("want 2 done / 1 failed, got %d/%d", len(done), len(failed))
	}
}

func TestCreateSentinels_AllFailErrors(t *testing.T) {
	done, _, err := sentinelTopo().createSentinels(context.Background(), allFailACL{}, "u", "pw", defaultSentinelRules)
	if err == nil {
		t.Fatal("expected error when no Sentinel accepts the user")
	}
	if len(done) != 0 {
		t.Errorf("done should be empty on total failure, got %v", done)
	}
}

func TestCreateSentinels_NoSentinelsIsNoop(t *testing.T) {
	// separate mode: empty Sentinels => no error, nothing done (even with a failing ops)
	topo := &Topology{Master: "n1", Nodes: []string{"n1"}}
	done, failed, err := topo.createSentinels(context.Background(), allFailACL{}, "u", "pw", "")
	if err != nil || len(done) != 0 || len(failed) != 0 {
		t.Errorf("empty Sentinels should be a no-op, got done=%v failed=%v err=%v", done, failed, err)
	}
}

func TestDeleteSentinels_BestEffort(t *testing.T) {
	f := newFake()
	f.failDeleteOn = "s2"
	failed := sentinelTopo().deleteSentinels(context.Background(), f, "u")
	if len(failed) != 1 || !strings.Contains(failed[0], "s2") {
		t.Errorf("want 1 failure naming s2, got %v", failed)
	}
	if f.deleteCalls != 3 {
		t.Errorf("deleteSentinels should attempt all 3 Sentinels, got %d", f.deleteCalls)
	}
}

func TestTopologyString_WithSentinels(t *testing.T) {
	topo := &Topology{Master: "a:6379", Nodes: []string{"a:6379", "b:6379"}, Sentinels: []string{"s:26379"}}
	want := "master=a:6379 nodes=[a:6379 b:6379] sentinels=[s:26379]"
	if got := topo.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
