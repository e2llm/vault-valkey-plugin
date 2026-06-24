package valkey

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
)

// fakeNodeACL records calls and can be told to fail on specific nodes, so the pure
// topology orchestration (rollback, aggregation) is testable without a live Valkey.
type fakeNodeACL struct {
	present      map[string]bool // nodes currently holding the user
	failCreateOn string
	failDeleteOn string
	failSetOn    string
	createCalls  int
	deleteCalls  int
}

func newFake() *fakeNodeACL { return &fakeNodeACL{present: map[string]bool{}} }

func (f *fakeNodeACL) createUser(_ context.Context, node, _, _, _ string) error {
	f.createCalls++
	if node == f.failCreateOn {
		return errors.New("create boom")
	}
	f.present[node] = true
	return nil
}
func (f *fakeNodeACL) setPassword(_ context.Context, node, _, _ string) error {
	if node == f.failSetOn {
		return errors.New("set boom")
	}
	return nil
}
func (f *fakeNodeACL) deleteUser(_ context.Context, node, _ string) error {
	f.deleteCalls++
	if node == f.failDeleteOn {
		return errors.New("delete boom")
	}
	delete(f.present, node)
	return nil
}

func (f *fakeNodeACL) presentNodes() []string {
	out := make([]string, 0, len(f.present))
	for n := range f.present {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func topo3() *Topology {
	return &Topology{Master: "n1", Nodes: []string{"n1", "n2", "n3"}}
}

func TestCreate_AllSucceed(t *testing.T) {
	f := newFake()
	if err := topo3().create(context.Background(), f, "u", "pw", "~app:* +@read"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := f.presentNodes(); len(got) != 3 {
		t.Errorf("want user on 3 nodes, got %v", got)
	}
}

func TestCreate_RollsBackOnPartialFailure(t *testing.T) {
	f := newFake()
	f.failCreateOn = "n3"
	err := topo3().create(context.Background(), f, "u", "pw", "")
	if err == nil {
		t.Fatal("expected error when a node fails")
	}
	if !strings.Contains(err.Error(), "rolled back 2") {
		t.Errorf("error should report rollback of 2 nodes: %v", err)
	}
	if got := f.presentNodes(); len(got) != 0 {
		t.Errorf("rollback should have removed the user everywhere, still present on %v", got)
	}
}

func TestCreate_ReportsRollbackFailure(t *testing.T) {
	f := newFake()
	f.failCreateOn = "n3"
	f.failDeleteOn = "n1" // rollback of n1 will also fail
	err := topo3().create(context.Background(), f, "u", "pw", "")
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected compound rollback-failure error, got: %v", err)
	}
}

func TestDelete_AggregatesErrors(t *testing.T) {
	f := newFake()
	f.failDeleteOn = "n2"
	err := topo3().delete(context.Background(), f, "u")
	if err == nil || !strings.Contains(err.Error(), "n2") {
		t.Fatalf("expected aggregated delete error naming n2, got: %v", err)
	}
	if f.deleteCalls != 3 {
		t.Errorf("delete should attempt all 3 nodes even on failure, got %d", f.deleteCalls)
	}
}

func TestSetPassword_AggregatesErrors(t *testing.T) {
	f := newFake()
	f.failSetOn = "n2"
	err := topo3().setPassword(context.Background(), f, "u", "newpw")
	if err == nil || !strings.Contains(err.Error(), "n2") {
		t.Fatalf("expected aggregated set-password error naming n2, got: %v", err)
	}
}
