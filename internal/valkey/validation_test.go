package valkey

import (
	"context"
	"testing"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

// C1: selector-glued password directives must not slip past the first-byte check.
func TestValidateRules_RejectsSelectorGluedDirectives(t *testing.T) {
	for _, r := range []string{"(>backdoor)", "~* (>backdoor)", "(#deadbeef)", "(<x)", "(!y)", "(>back door)"} {
		if err := validateRules(r); err == nil {
			t.Errorf("validateRules(%q) should reject selector-glued password directive", r)
		}
	}
}

// C2: a dynamic credential must not be granted privilege-escalation/persistence commands.
func TestValidateRules_RejectsEscalationGrants(t *testing.T) {
	for _, r := range []string{
		"+acl", "+acl|setuser", "+@admin", "+@dangerous", "+config", "+config|set",
		"+module", "+debug", "+shutdown", "+replicaof", "+slaveof", "+cluster", "+failover",
		"~app:* +acl|setuser", "+ACL", // case-insensitive
	} {
		if err := validateRules(r); err == nil {
			t.Errorf("validateRules(%q) should reject escalation grant", r)
		}
	}
}

// H2: tokens that strip previously-expressed intent are rejected.
func TestValidateRules_RejectsResetFamily(t *testing.T) {
	for _, r := range []string{"clearselectors", "resetkeys", "resetchannels", "~app:* resetkeys"} {
		if err := validateRules(r); err == nil {
			t.Errorf("validateRules(%q) should reject reset-family token", r)
		}
	}
}

// Legitimate rules — including a broad-but-managed +@all (warned, not rejected) and
// revokes like -@admin — must still pass, so we don't over-reject.
func TestValidateRules_AllowsLegitimate(t *testing.T) {
	for _, r := range []string{
		"~app:* +@read +@write +@stream",
		"+get +set",
		"(+get ~app:*)", // selector with an allowed command
		"+@all",         // operator's explicit broad-access choice (warned elsewhere)
		"~* &*",
		"-@admin",            // revoking admin is fine
		"+@read -@dangerous", // scoped + revoke
	} {
		if err := validateRules(r); err != nil {
			t.Errorf("validateRules(%q) should pass, got %v", r, err)
		}
	}
}

// M2: an empty password must be rejected before anything is provisioned.
func TestNewUser_RejectsEmptyPassword(t *testing.T) {
	raw, err := New()
	if err != nil {
		t.Fatal(err)
	}
	db := raw.(dbplugin.Database)
	if _, err := db.Initialize(context.Background(), dbplugin.InitializeRequest{
		Config: map[string]interface{}{"host": "localhost", "username": "u", "password": "p"},
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	_, err = db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "d", RoleName: "r"},
		Statements:     dbplugin.Statements{Commands: []string{"~app:* +@read"}},
		Password:       "",
	})
	if err == nil {
		t.Error("NewUser with empty password should error before provisioning")
	}
}
