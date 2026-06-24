package valkey

import "testing"

func TestRenderRules(t *testing.T) {
	got := renderRules([]string{"~app:* +@read", "   ", "+@stream +@write"})
	want := "~app:* +@read +@stream +@write"
	if got != want {
		t.Errorf("renderRules = %q, want %q", got, want)
	}
	if renderRules(nil) != "" {
		t.Error("renderRules(nil) should be empty")
	}
}

func TestRuleArgs(t *testing.T) {
	args := ruleArgs("~app:* +@read +@stream")
	if len(args) != 3 {
		t.Fatalf("ruleArgs len = %d, want 3", len(args))
	}
	if args[0] != "~app:*" || args[2] != "+@stream" {
		t.Errorf("ruleArgs = %v", args)
	}
	if len(ruleArgs("")) != 0 {
		t.Error("ruleArgs(empty) should be empty")
	}
}
