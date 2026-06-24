package valkey

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestValidateRules_RejectsModelBreaking(t *testing.T) {
	bad := []string{
		"nopass", "off", "reset", "resetpass",
		"NoPass", "OFF", // case-insensitive
		"~app:* nopass", "+@read off",
	}
	for _, r := range bad {
		if err := validateRules(r); err == nil {
			t.Errorf("validateRules(%q) should reject", r)
		}
	}
}

func TestValidateRules_RejectsPasswordDirectives(t *testing.T) {
	bad := []string{">backdoor", "#deadbeef", "<remove", "!removehash", "~app:* >sneaky"}
	for _, r := range bad {
		if err := validateRules(r); err == nil {
			t.Errorf("validateRules(%q) should reject password directive", r)
		}
	}
}

func TestValidateRules_AllowsNormalRules(t *testing.T) {
	ok := []string{"", "~app:* +@read +@write +@stream", "+@all ~*", "&channel:* +subscribe"}
	for _, r := range ok {
		if err := validateRules(r); err != nil {
			t.Errorf("validateRules(%q) should pass, got %v", r, err)
		}
	}
}

func TestOverBroad(t *testing.T) {
	if hits := overBroad("~app:* +@read"); len(hits) != 0 {
		t.Errorf("scoped rule should not be over-broad, got %v", hits)
	}
	hits := overBroad("+@all ~* &*")
	if len(hits) != 3 {
		t.Errorf("expected 3 over-broad tokens, got %v", hits)
	}
}

func TestCredToken(t *testing.T) {
	pw := "s3cr3t-passw0rd"
	sum := sha256.Sum256([]byte(pw))
	wantHash := "#" + hex.EncodeToString(sum[:])

	hashed := (&Config{PasswordHashing: true}).credToken(pw)
	if hashed != wantHash {
		t.Errorf("hashed credToken = %q, want %q", hashed, wantHash)
	}
	if len(hashed) != 65 { // '#' + 64 hex chars
		t.Errorf("hashed token length = %d, want 65", len(hashed))
	}

	clear := (&Config{PasswordHashing: false}).credToken(pw)
	if clear != ">"+pw {
		t.Errorf("cleartext credToken = %q, want %q", clear, ">"+pw)
	}
}

func TestParseConfig_PasswordHashingDefault(t *testing.T) {
	def, err := parseConfig(map[string]interface{}{"host": "h", "username": "u", "password": "p"})
	if err != nil {
		t.Fatal(err)
	}
	if !def.PasswordHashing {
		t.Error("password_hashing should default to true")
	}

	off, err := parseConfig(map[string]interface{}{"host": "h", "username": "u", "password": "p", "password_hashing": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if off.PasswordHashing {
		t.Error("password_hashing=false should be respected")
	}
}
