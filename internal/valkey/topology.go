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
	Master    string
	Nodes     []string // data nodes: master first, then live replicas
	Sentinels []string // Sentinels to provision in shared-identity mode; empty otherwise
}

func (t *Topology) String() string {
	s := fmt.Sprintf("master=%s nodes=[%s]", t.Master, strings.Join(t.Nodes, " "))
	if len(t.Sentinels) > 0 {
		s += fmt.Sprintf(" sentinels=[%s]", strings.Join(t.Sentinels, " "))
	}
	return s
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

// setPassword rotates a (non-root) user's password on every data node, best-effort
// with aggregated errors. Root rotation is handled separately (it needs reconnect-
// with-new-password rollback) in database.go.
func (t *Topology) setPassword(ctx context.Context, ops nodeACL, username, password string) error {
	return setPasswordOn(ctx, ops, t.Nodes, username, password)
}

// setPasswordOn rotates a user's password on the given nodes, best-effort with
// aggregated errors. Shared by the data plane (via setPassword) and the Sentinels.
func setPasswordOn(ctx context.Context, ops nodeACL, nodes []string, username, password string) error {
	var errs []string
	for _, node := range nodes {
		if err := ops.setPassword(ctx, node, username, password); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", node, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("password update for %q failed on %d node(s): %s", username, len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// createSentinels provisions the discovery user on the Sentinels (shared-identity
// mode). Best-effort with a quorum of one: at least one Sentinel must accept the user
// (so the issued credential can actually resolve the master), but a Sentinel that is
// down (e.g. maintenance) is tolerated. Returns the Sentinels that succeeded (for the
// caller to roll back) and the per-Sentinel failures; err is non-nil only when there
// are Sentinels to provision and NONE succeeded.
func (t *Topology) createSentinels(ctx context.Context, ops nodeACL, username, password, rules string) (done, failed []string, err error) {
	for _, s := range t.Sentinels {
		if e := ops.createUser(ctx, s, username, password, rules); e != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s, e))
			continue
		}
		done = append(done, s)
	}
	if len(t.Sentinels) > 0 && len(done) == 0 {
		return nil, failed, fmt.Errorf("no Sentinel accepted the discovery user (%d tried): %s", len(t.Sentinels), strings.Join(failed, "; "))
	}
	return done, failed, nil
}

// deleteSentinels best-effort removes the discovery user from the Sentinels and
// returns the per-Sentinel failures (never fatal): a lingering discovery user cannot
// reach data (the data nodes already revoked it), and an ephemeral Sentinel
// self-cleans on restart.
func (t *Topology) deleteSentinels(ctx context.Context, ops nodeACL, username string) (failed []string) {
	for _, s := range t.Sentinels {
		if e := ops.deleteUser(ctx, s, username); e != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s, e))
		}
	}
	return failed
}
