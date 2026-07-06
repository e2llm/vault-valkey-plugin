package valkey

import (
	"context"
	"fmt"
	"strings"
)

// defaultManagedUsernamePrefix is the literal prefix the built-in username_template
// produces ("v_..."); the reconcile pass uses it to tell plugin-managed dynamic users
// apart from static accounts (default, the node admin, operator users).
const defaultManagedUsernamePrefix = "v_"

// aclUserDef is one user's name and its ACL rule string — the tokens after "user <name> "
// in ACL LIST output (enabled flag, password hash(es), keys, channels, commands). The rule
// string is copyable verbatim onto another node to clone the user, hash and all.
type aclUserDef struct {
	Name  string
	Rules string
}

// reconcileACL is the read/write surface the reconcile pass needs on top of nodeACL:
// enumerate a node's users (full defs on the source, names on the targets) and clone a
// user's def onto a node. deleteUser (from nodeACL) removes an orphan.
type reconcileACL interface {
	listUserDefs(ctx context.Context, node string) ([]aclUserDef, error)
	listUsernames(ctx context.Context, node string) (map[string]struct{}, error)
	applyUserDef(ctx context.Context, node, username, rules string) error
	deleteUser(ctx context.Context, node, username string) error
}

// managed reports whether a username is a plugin-managed dynamic user: it carries the
// managed prefix and is neither the node admin nor the built-in default account. The
// reconcile pass only ever adds or removes users for which this is true, so a static or
// operator account is never touched.
func managed(name, prefix, adminUser string) bool {
	return name != adminUser && name != "default" && strings.HasPrefix(name, prefix)
}

// parseACLListLine parses one ACL LIST line ("user <name> <rules...>") into the username
// and its rule string (everything after the name). ok is false for a malformed/blank line.
func parseACLListLine(line string) (name, rules string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || fields[0] != "user" {
		return "", "", false
	}
	return fields[1], strings.Join(fields[2:], " "), true
}

// reconcile converges every data node's managed users to the master's set. The master is
// the source of truth — every create writes it first, every revoke deletes from it, and
// every operation re-resolves to it — so it always holds exactly the live set. Two drifts
// are repaired, both node-local ACL gaps the topology can otherwise leave:
//
//   - a managed user on the master but MISSING on a node (that node was down at create-time
//     and returned) is cloned from the master's def, hash and all, via ACL SETUSER reset;
//   - a managed user on a node but ABSENT from the master (a revoke that missed a then-down
//     node left an orphan) is removed.
//
// It is best-effort and non-fatal: it returns per-node issues for the caller to log, and
// never fails the operation it piggybacks on. Cheap when clean — one ACL LIST on the master
// plus one ACL USERS per node; it writes only what actually drifted.
func (t *Topology) reconcile(ctx context.Context, ops reconcileACL, prefix, adminUser string) []string {
	defs, err := ops.listUserDefs(ctx, t.Master)
	if err != nil {
		return []string{fmt.Sprintf("list users on master %s: %v", t.Master, err)}
	}
	want := map[string]string{} // managed username -> def rules (from the master)
	for _, d := range defs {
		if managed(d.Name, prefix, adminUser) {
			want[d.Name] = d.Rules
		}
	}

	var issues []string
	for _, node := range t.Nodes {
		if node == t.Master {
			continue
		}
		have, err := ops.listUsernames(ctx, node)
		if err != nil {
			issues = append(issues, fmt.Sprintf("list users on %s: %v", node, err))
			continue
		}
		for name, rules := range want { // re-assert missing
			if _, ok := have[name]; !ok {
				if e := ops.applyUserDef(ctx, node, name, rules); e != nil {
					issues = append(issues, fmt.Sprintf("re-assert %s on %s: %v", name, node, e))
				}
			}
		}
		for name := range have { // remove orphans
			if _, ok := want[name]; ok || !managed(name, prefix, adminUser) {
				continue
			}
			if e := ops.deleteUser(ctx, node, name); e != nil {
				issues = append(issues, fmt.Sprintf("remove orphan %s on %s: %v", name, node, e))
			}
		}
	}
	return issues
}
