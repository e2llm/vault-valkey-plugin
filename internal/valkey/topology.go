package valkey

import (
	"context"
	"fmt"
	"strings"
)

// Topology is a point-in-time view: the current master plus live replicas. ACL
// operations apply to every node because Valkey ACLs are node-local (see
// test/sentinel/spike.sh). This type is pure — it orchestrates over a nodeACL and
// has no Valkey/network dependency, so the rollback/aggregation logic is unit-tested
// with a fake.
type Topology struct {
	Master string
	Nodes  []string // master first, then live replicas
}

func (t *Topology) String() string {
	return fmt.Sprintf("master=%s nodes=[%s]", t.Master, strings.Join(t.Nodes, " "))
}

// create provisions the user on every node, persisting per node. On the first
// failure it rolls back the nodes already created, so a lease is never left
// half-present across the cluster.
func (t *Topology) create(ctx context.Context, ops nodeACL, username, password, rules string) error {
	var done []string
	for _, node := range t.Nodes {
		if err := ops.createUser(ctx, node, username, password, rules); err != nil {
			rb := rollbackCreate(ctx, ops, username, done)
			if len(rb) > 0 {
				return fmt.Errorf("create user on %s failed: %w; additionally rollback failed on: %s",
					node, err, strings.Join(rb, "; "))
			}
			return fmt.Errorf("create user on %s failed (rolled back %d node(s)): %w", node, len(done), err)
		}
		done = append(done, node)
	}
	return nil
}

func rollbackCreate(ctx context.Context, ops nodeACL, username string, nodes []string) []string {
	var errs []string
	for _, node := range nodes {
		if err := ops.deleteUser(ctx, node, username); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node, err))
		}
	}
	return errs
}

// delete revokes the user on every node, attempting all and aggregating errors.
func (t *Topology) delete(ctx context.Context, ops nodeACL, username string) error {
	var errs []string
	for _, node := range t.Nodes {
		if err := ops.deleteUser(ctx, node, username); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delete user %q failed on %d node(s): %s", username, len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// setPassword rotates a (non-root) user's password on every node, best-effort with
// aggregated errors. Root rotation is handled separately (it needs reconnect-with-
// new-password rollback) in database.go.
func (t *Topology) setPassword(ctx context.Context, ops nodeACL, username, password string) error {
	var errs []string
	for _, node := range t.Nodes {
		if err := ops.setPassword(ctx, node, username, password); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("password update for %q failed on %d node(s): %s", username, len(errs), strings.Join(errs, "; "))
	}
	return nil
}
