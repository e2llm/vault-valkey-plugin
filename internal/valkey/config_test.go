package valkey

import "testing"

func TestParseConfig_SentinelMode(t *testing.T) {
	cfg, err := parseConfig(map[string]interface{}{
		"sentinels":            "10.0.0.1:26379, 10.0.0.2:26379 ,10.0.0.3:26379",
		"sentinel_master_name": "mymaster",
		"sentinel_username":    "sentinel-ro",
		"sentinel_password":    "spw",
		"username":             "vaultadmin",
		"password":             "apw",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Sentinels) != 3 {
		t.Errorf("want 3 sentinels, got %d (%v)", len(cfg.Sentinels), cfg.Sentinels)
	}
	if cfg.Sentinels[1] != "10.0.0.2:26379" {
		t.Errorf("sentinel not trimmed: %q", cfg.Sentinels[1])
	}
	if cfg.PersistenceMode != PersistenceACLFile {
		t.Errorf("default persistence_mode should be aclfile, got %q", cfg.PersistenceMode)
	}
}

func TestParseConfig_StandaloneDefaults(t *testing.T) {
	cfg, err := parseConfig(map[string]interface{}{
		"host":     "vk",
		"username": "u",
		"password": "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 6379 {
		t.Errorf("default port should be 6379, got %d", cfg.Port)
	}
}

func TestParseConfig_Validation(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"sentinel without master":   {"sentinels": "a:26379", "username": "u", "password": "p"},
		"neither sentinel nor host": {"username": "u", "password": "p"},
		"missing credentials":       {"host": "h"},
		"bad persistence_mode":      {"host": "h", "username": "u", "password": "p", "persistence_mode": "bogus"},
		"tls_cert without key":      {"host": "h", "username": "u", "password": "p", "tls_cert": "x"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(in); err == nil {
				t.Errorf("expected validation error for %q, got nil", name)
			}
		})
	}
}

func TestCfgHelpers(t *testing.T) {
	m := map[string]interface{}{
		"b_str":  "true",
		"b_bool": true,
		"i_str":  "42",
		"i_flt":  float64(7),
		"csv":    "a, b ,c",
		"list":   []interface{}{"x:1", " y:2 "},
	}
	if !cfgBool(m, "b_str") || !cfgBool(m, "b_bool") {
		t.Error("cfgBool failed")
	}
	if cfgInt(m, "i_str", 0) != 42 {
		t.Error("cfgInt string failed")
	}
	if cfgInt(m, "i_flt", 0) != 7 {
		t.Error("cfgInt float64 failed")
	}
	if cfgInt(m, "missing", 99) != 99 {
		t.Error("cfgInt default failed")
	}
	if got := cfgCSV(m, "csv"); len(got) != 3 || got[1] != "b" {
		t.Errorf("cfgCSV string split/trim: %v", got)
	}
	if got := cfgCSV(m, "list"); len(got) != 2 || got[1] != "y:2" {
		t.Errorf("cfgCSV list: %v", got)
	}
}
