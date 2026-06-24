//go:build integration

// Integration tests: drive the real plugin against a live Valkey+Sentinel topology
// using the SDK's dbplugin/v5 test harness, asserting the node-local invariant, the
// hashed-password-still-authenticates property, ACL scoping, and failover behaviour.
// Bring the topology up with test/integration/run.sh (which sets the env).
package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/redis/go-redis/v9"

	vk "github.com/e2llm/vault-valkey-plugin/internal/valkey"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func sentinels() string  { return os.Getenv("VALKEY_SENTINELS") }
func masterName() string { return env("VALKEY_MASTER_NAME", "mymaster") }
func adminUser() string  { return env("VALKEY_USER", "default") }
func adminPass() string  { return env("VALKEY_PASS", "rootpass") }
func nodes() []string {
	return strings.Split(env("VALKEY_NODES", "10.111.0.10:6379,10.111.0.11:6379,10.111.0.12:6379"), ",")
}

func newDB(t *testing.T) dbplugin.Database {
	t.Helper()
	raw, err := vk.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return raw.(dbplugin.Database)
}

func initReq() dbplugin.InitializeRequest {
	return dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"sentinels":            sentinels(),
			"sentinel_master_name": masterName(),
			"username":             adminUser(),
			"password":             adminPass(),
			"persistence_mode":     "aclfile",
		},
		VerifyConnection: true,
	}
}

func readerReq(display, pw string) dbplugin.NewUserRequest {
	return dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: display, RoleName: "reader"},
		Statements:     dbplugin.Statements{Commands: []string{"~app:* +@read +@write +@stream"}},
		Password:       pw,
		Expiration:     time.Now().Add(time.Hour),
	}
}

func adminClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{Addr: addr, Username: adminUser(), Password: adminPass(), DialTimeout: 5 * time.Second})
}

func userExists(ctx context.Context, addr, username string) (bool, error) {
	c := adminClient(addr)
	defer c.Close()
	err := c.Do(ctx, "ACL", "GETUSER", username).Err()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func TestSentinelLifecycle(t *testing.T) {
	if sentinels() == "" {
		t.Skip("set VALKEY_SENTINELS to run (see test/integration/run.sh)")
	}
	ctx := context.Background()
	db := newDB(t)
	defer dbtesting.AssertClose(t, db)
	dbtesting.AssertInitialize(t, db, initReq())

	const pw = "Integration-Pass-123!"
	resp := dbtesting.AssertNewUser(t, db, readerReq("itest", pw))
	t.Logf("created dynamic user %s", resp.Username)

	// node-local invariant: present on every node
	for _, n := range nodes() {
		ok, err := userExists(ctx, n, resp.Username)
		if err != nil {
			t.Fatalf("check %s: %v", n, err)
		}
		if !ok {
			t.Errorf("user %s MISSING on node %s after NewUser", resp.Username, n)
		}
	}

	// hashed password still authenticates, and ACL key-scoping is enforced
	verifyAuthAndScope(t, ctx, nodes()[0], resp.Username, pw)

	// password rotation on every node
	dbtesting.AssertUpdateUser(t, db, dbplugin.UpdateUserRequest{
		Username: resp.Username,
		Password: &dbplugin.ChangePassword{NewPassword: "Rotated-Pass-456!"},
	})

	// revoke removes from every node
	dbtesting.AssertDeleteUser(t, db, dbplugin.DeleteUserRequest{Username: resp.Username})
	for _, n := range nodes() {
		ok, err := userExists(ctx, n, resp.Username)
		if err != nil {
			t.Fatalf("check %s: %v", n, err)
		}
		if ok {
			t.Errorf("user %s STILL PRESENT on node %s after DeleteUser", resp.Username, n)
		}
	}
}

// verifyAuthAndScope proves (a) the cleartext password authenticates even though the
// plugin provisioned it as a #sha256 hash, and (b) the ~app:* grant is enforced.
func verifyAuthAndScope(t *testing.T, ctx context.Context, node, username, pw string) {
	t.Helper()
	uc := redis.NewClient(&redis.Options{Addr: node, Username: username, Password: pw, DialTimeout: 5 * time.Second})
	defer uc.Close()

	// within grant: a read on app:* succeeds (redis.Nil = key absent, still authorized)
	if err := uc.Get(ctx, "app:probe").Err(); err != nil && !errors.Is(err, redis.Nil) {
		t.Errorf("dynamic user failed to auth/read within its grant (~app:*): %v", err)
	}
	// outside grant: a read on other:* must be denied (NOPERM), i.e. a non-nil, non-redis.Nil error
	if err := uc.Get(ctx, "other:secret").Err(); err == nil || errors.Is(err, redis.Nil) {
		t.Errorf("dynamic user was NOT denied outside its grant (other:*): err=%v", err)
	}
}

// TestFailoverMidLease creates a user, triggers a Sentinel failover, and verifies the
// user survives on the promoted master and that new provisioning targets the new
// topology. Opt-in (VALKEY_RUN_FAILOVER) because it mutates cluster state and needs the
// failover-timeout cooldown; run.sh enables it after a cooldown.
func TestFailoverMidLease(t *testing.T) {
	if sentinels() == "" || os.Getenv("VALKEY_RUN_FAILOVER") == "" {
		t.Skip("set VALKEY_SENTINELS and VALKEY_RUN_FAILOVER=1 to run the failover scenario")
	}
	ctx := context.Background()
	db := newDB(t)
	defer dbtesting.AssertClose(t, db)
	dbtesting.AssertInitialize(t, db, initReq())

	const pw = "Failover-Pass-789!"
	before := dbtesting.AssertNewUser(t, db, readerReq("fo", pw))
	t.Logf("created %s before failover", before.Username)

	masterBefore := currentMaster(t, ctx)
	triggerFailover(t, ctx)
	masterAfter := waitNewMaster(t, ctx, masterBefore)
	t.Logf("failover %s -> %s", masterBefore, masterAfter)

	// pre-existing user survives on the promoted master (it was written to every node)
	if ok, err := userExists(ctx, masterAfter, before.Username); err != nil || !ok {
		t.Errorf("user %s missing on promoted master %s (err=%v)", before.Username, masterAfter, err)
	}

	// New provisioning must re-resolve and target the NEW master — that is the precise
	// proof discovery followed the failover. We assert on the re-resolved master rather
	// than all env nodes because a just-demoted node is transiently excluded from the
	// topology until it rejoins as a healthy replica (the documented reconciliation gap).
	after := dbtesting.AssertNewUser(t, db, readerReq("fo2", pw))
	if ok, err := userExists(ctx, masterAfter, after.Username); err != nil || !ok {
		t.Errorf("post-failover user %s not provisioned on the re-resolved master %s (err=%v)", after.Username, masterAfter, err)
	}
	t.Logf("note: a just-demoted node may be transiently excluded until it rejoins as a healthy replica")

	dbtesting.AssertDeleteUser(t, db, dbplugin.DeleteUserRequest{Username: before.Username})
	dbtesting.AssertDeleteUser(t, db, dbplugin.DeleteUserRequest{Username: after.Username})
}

func sentinelClient() *redis.Client {
	addr := strings.Split(sentinels(), ",")[0]
	return redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 5 * time.Second})
}

func currentMaster(t *testing.T, ctx context.Context) string {
	t.Helper()
	c := sentinelClient()
	defer c.Close()
	res, err := c.Do(ctx, "SENTINEL", "get-master-addr-by-name", masterName()).Result()
	if err != nil {
		t.Fatalf("get-master-addr-by-name: %v", err)
	}
	pair, ok := res.([]interface{})
	if !ok || len(pair) != 2 {
		t.Fatalf("unexpected master addr response: %v", res)
	}
	return fmt.Sprintf("%v:%v", pair[0], pair[1])
}

func triggerFailover(t *testing.T, ctx context.Context) {
	t.Helper()
	c := sentinelClient()
	defer c.Close()
	var lastErr error
	for i := 0; i < 10; i++ {
		if err := c.Do(ctx, "SENTINEL", "FAILOVER", masterName()).Err(); err == nil {
			return
		} else {
			lastErr = err
			time.Sleep(2 * time.Second) // INPROG / cooldown
		}
	}
	t.Fatalf("could not trigger failover: %v", lastErr)
}

func waitNewMaster(t *testing.T, ctx context.Context, before string) string {
	t.Helper()
	for i := 0; i < 40; i++ {
		if m := currentMaster(t, ctx); m != before {
			return m
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("master did not change from %s within timeout", before)
	return ""
}
