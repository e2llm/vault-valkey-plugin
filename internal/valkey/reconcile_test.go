package valkey

import (
	"context"
	"errors"
	"sort"
	"testing"
)

// fakeReconcileACL models per-node ACL user state so the pure reconcile convergence logic
// (re-assert missing, remove orphans, never touch static/admin users) is tested without a
// live Valkey.
type fakeReconcileACL struct {
	users     map[string]map[string]string // node -> username -> rules
	applied   []string                     // "node/user" clones performed
	deleted   []string                     // "node/user" orphan removals
	listErrOn map[string]bool              // nodes whose listUsernames fails
	defsErrOn map[string]bool              // nodes whose listUserDefs fails
}

func newFakeReconcile() *fakeReconcileACL {
	return &fakeReconcileACL{
		users: map[string]map[string]string{}, listErrOn: map[string]bool{}, defsErrOn: map[string]bool{},
	}
}

func (f *fakeReconcileACL) set(node string, users map[string]string) {
	m := map[string]string{}
	for k, v := range users {
		m[k] = v
	}
	f.users[node] = m
}

func (f *fakeReconcileACL) listUserDefs(_ context.Context, node string) ([]aclUserDef, error) {
	if f.defsErrOn[node] {
		return nil, errors.New("list defs boom")
	}
	var defs []aclUserDef
	for name, rules := range f.users[node] {
		defs = append(defs, aclUserDef{Name: name, Rules: rules})
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs, nil
}

func (f *fakeReconcileACL) listUsernames(_ context.Context, node string) (map[string]struct{}, error) {
	if f.listErrOn[node] {
		return nil, errors.New("list users boom")
	}
	set := map[string]struct{}{}
	for name := range f.users[node] {
		set[name] = struct{}{}
	}
	return set, nil
}

func (f *fakeReconcileACL) applyUserDef(_ context.Context, node, username, rules string) error {
	if f.users[node] == nil {
		f.users[node] = map[string]string{}
	}
	f.users[node][username] = rules
	f.applied = append(f.applied, node+"/"+username)
	return nil
}

func (f *fakeReconcileACL) deleteUser(_ context.Context, node, username string) error {
	delete(f.users[node], username)
	f.deleted = append(f.deleted, node+"/"+username)
	return nil
}

func reconcileTopo() *Topology {
	return &Topology{Master: "n1", Nodes: []string{"n1", "n2", "n3"}}
}

// The core behaviour: a node missing a managed user gets it cloned from the master; a
// managed user only on a node (orphan from a revoke that missed it) is removed; the node
// admin and default accounts are never touched; the master is never modified.
func TestReconcile_ConvergesToMaster(t *testing.T) {
	f := newFakeReconcile()
	f.set("n1", map[string]string{ // master = source of truth
		"v_a":        "on #ha ~app:* +@read",
		"v_b":        "on #hb ~app:* +@read",
		"vaultadmin": "on #hx ~* +@all",
		"default":    "on nopass ~* +@all",
	})
	f.set("n2", map[string]string{ // was down at v_b's create -> missing it
		"v_a": "on #ha ~app:* +@read", "vaultadmin": "on #hx ~* +@all", "default": "on nopass ~* +@all",
	})
	f.set("n3", map[string]string{ // was down at a revoke -> v_orphan lingers
		"v_a": "on #ha ~app:* +@read", "v_b": "on #hb ~app:* +@read",
		"v_orphan": "on #ho ~* +@read", "vaultadmin": "on #hx ~* +@all", "default": "on nopass ~* +@all",
	})

	issues := reconcileTopo().reconcile(context.Background(), f, "v_", "vaultadmin")
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
	if len(f.applied) != 1 || f.applied[0] != "n2/v_b" {
		t.Errorf("want v_b re-asserted on n2, got applied=%v", f.applied)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "n3/v_orphan" {
		t.Errorf("want v_orphan removed on n3, got deleted=%v", f.deleted)
	}
	if _, ok := f.users["n2"]["v_b"]; !ok {
		t.Error("v_b should now be present on n2")
	}
	if _, ok := f.users["n3"]["v_orphan"]; ok {
		t.Error("v_orphan should be gone from n3")
	}
	// static accounts untouched everywhere
	for _, n := range []string{"n2", "n3"} {
		if _, ok := f.users[n]["vaultadmin"]; !ok {
			t.Errorf("node admin wrongly removed on %s", n)
		}
		if _, ok := f.users[n]["default"]; !ok {
			t.Errorf("default wrongly removed on %s", n)
		}
	}
}

// A node admin whose name happens to differ across nodes, and any non-prefixed operator
// user, must never be added or deleted.
func TestReconcile_NeverTouchesUnmanaged(t *testing.T) {
	f := newFakeReconcile()
	f.set("n1", map[string]string{"vaultadmin": "on #a ~* +@all", "monitoring": "on #m ~* +@read"})
	f.set("n2", map[string]string{"vaultadmin": "on #a ~* +@all"}) // lacks 'monitoring' (not managed)
	issues := (&Topology{Master: "n1", Nodes: []string{"n1", "n2"}}).reconcile(context.Background(), f, "v_", "vaultadmin")
	if len(issues) != 0 || len(f.applied) != 0 || len(f.deleted) != 0 {
		t.Errorf("unmanaged users must be ignored: applied=%v deleted=%v issues=%v", f.applied, f.deleted, issues)
	}
}

// A per-node list failure is recorded but does not stop the other nodes.
func TestReconcile_ListErrorIsNonFatalPerNode(t *testing.T) {
	f := newFakeReconcile()
	f.set("n1", map[string]string{"v_a": "on #ha ~app:* +@read"})
	f.set("n2", map[string]string{})
	f.set("n3", map[string]string{})
	f.listErrOn["n2"] = true
	issues := reconcileTopo().reconcile(context.Background(), f, "v_", "vaultadmin")
	if len(issues) != 1 {
		t.Fatalf("want exactly one issue (n2), got %v", issues)
	}
	if len(f.applied) != 1 || f.applied[0] != "n3/v_a" { // n3 still reconciled despite n2 failing
		t.Errorf("n3 should still be reconciled, got applied=%v", f.applied)
	}
}

// If the master itself cannot be listed there is no source of truth: bail with one issue,
// touch nothing.
func TestReconcile_MasterListErrorBails(t *testing.T) {
	f := newFakeReconcile()
	f.set("n1", map[string]string{"v_a": "on #ha ~app:* +@read"})
	f.set("n2", map[string]string{})
	f.defsErrOn["n1"] = true
	issues := reconcileTopo().reconcile(context.Background(), f, "v_", "vaultadmin")
	if len(issues) != 1 || len(f.applied) != 0 || len(f.deleted) != 0 {
		t.Errorf("master list failure should bail without writes: applied=%v deleted=%v issues=%v", f.applied, f.deleted, issues)
	}
}

func TestParseACLListLine(t *testing.T) {
	cases := []struct {
		line, name, rules string
		ok                bool
	}{
		{"user v_foo on #abc ~app:* +@read", "v_foo", "on #abc ~app:* +@read", true},
		{"user default on nopass ~* &* +@all", "default", "on nopass ~* &* +@all", true},
		{"   user   v_x   on   #h  ", "v_x", "on #h", true}, // collapsed whitespace
		{"", "", "", false},
		{"garbage here", "", "", false},
		{"user", "", "", false}, // name missing
	}
	for _, c := range cases {
		name, rules, ok := parseACLListLine(c.line)
		if ok != c.ok || name != c.name || rules != c.rules {
			t.Errorf("parseACLListLine(%q) = (%q,%q,%v), want (%q,%q,%v)", c.line, name, rules, ok, c.name, c.rules, c.ok)
		}
	}
}

func TestManaged(t *testing.T) {
	cases := []struct {
		name, prefix, admin string
		want                bool
	}{
		{"v_abc", "v_", "vaultadmin", true},
		{"vaultadmin", "v_", "vaultadmin", false},
		{"default", "v_", "vaultadmin", false},
		{"operator", "v_", "vaultadmin", false}, // no prefix
		{"v_admin", "v_", "v_admin", false},     // admin that happens to carry the prefix
	}
	for _, c := range cases {
		if got := managed(c.name, c.prefix, c.admin); got != c.want {
			t.Errorf("managed(%q,%q,%q) = %v, want %v", c.name, c.prefix, c.admin, got, c.want)
		}
	}
}
