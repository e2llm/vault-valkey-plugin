package valkey

import (
	"strings"
	"testing"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func TestGenerateUsername_Default(t *testing.T) {
	meta := dbplugin.UsernameMetadata{DisplayName: "myapp", RoleName: "reader"}
	u, err := generateUsername(meta, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "v_myapp_reader_") {
		t.Errorf("username %q missing expected prefix", u)
	}
	if len(u) > 64 {
		t.Errorf("username length %d exceeds 64", len(u))
	}
	if u != strings.ToLower(u) {
		t.Errorf("username %q is not lowercase", u)
	}
}

func TestGenerateUsername_LongDisplayNameTruncated(t *testing.T) {
	meta := dbplugin.UsernameMetadata{DisplayName: "verylongapplicationname", RoleName: "verylongrolename"}
	u, err := generateUsername(meta, "")
	if err != nil {
		t.Fatal(err)
	}
	// display/role each truncated to 8 chars in the default template ("verylong")
	if !strings.HasPrefix(u, "v_verylong_verylong_") {
		t.Errorf("expected 8-char truncation prefix, got %q", u)
	}
	if strings.Contains(u, "verylongapplicationname") {
		t.Errorf("display name was not truncated: %q", u)
	}
}

func TestGenerateUsername_CustomTemplate(t *testing.T) {
	meta := dbplugin.UsernameMetadata{DisplayName: "App", RoleName: "Reader"}
	u, err := generateUsername(meta, `{{ .RoleName | lowercase }}`)
	if err != nil {
		t.Fatal(err)
	}
	if u != "reader" {
		t.Errorf("custom template username = %q, want %q", u, "reader")
	}
}
