#!/usr/bin/env bash
# Real end-to-end for Vault database STATIC ROLES against the Valkey+Sentinel topology:
# ONE shared user whose password Vault owns and rotates on a schedule (or on demand), used
# by many clients. Proves the rotation reaches every Sentinel node (so any node a client
# hits — including a promoted replica — has the current password), that a returned replica
# re-converges, and that the contrib/lazy-rotate.sh wrapper rotates only when stale.
#
#   test/vault/static-e2e.sh
#   PATH=/path/to/older-vault:$PATH test/vault/static-e2e.sh   # pin a specific Vault version
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"

export GOTOOLCHAIN=local

PLUGIN_DIR="$(mktemp -d)"
export VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="root"
VAULT_PID=""
FAIL=0
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

cleanup() {
	[ -n "$VAULT_PID" ] && kill "$VAULT_PID" 2>/dev/null || true
	for n in primary replica1 replica2 sentinel1 sentinel2 sentinel3; do podman rm -f "vk-$n" >/dev/null 2>&1 || true; done
	podman network rm vkspike >/dev/null 2>&1 || true
	rm -rf "$PLUGIN_DIR"
}
trap cleanup EXIT

nacl() { podman exec "vk-$1" valkey-cli -a rootpass --no-auth-warning "${@:2}" 2>/dev/null; }
# has_pw <node> <user> <pass> : 0 if the user authenticates AND can read within its ~app:* grant
has_pw() { ! podman exec "vk-$1" valkey-cli --user "$2" --pass "$3" --no-auth-warning GET app:probe 2>&1 | grep -qiE 'wrongpass|noauth|noperm'; }
replica2_healthy() { podman exec vk-sentinel1 valkey-cli -p 26379 SENTINEL replicas mymaster 2>/dev/null | tr '\n' ' ' | grep -q '10.111.0.12' && ! podman exec vk-sentinel1 valkey-cli -p 26379 SENTINEL replicas mymaster 2>/dev/null | tr '\n' ' ' | grep -q s_down; }
# spike.sh leaves a POST-FAILOVER topology (its INV-4 phase); wait until it re-stabilizes
# (some node is master with both replicas connected) before driving rotations through Vault.
settled() { for _ in $(seq 1 45); do for n in primary replica1 replica2; do local i; i="$(podman exec "vk-$n" valkey-cli -a rootpass --no-auth-warning INFO replication 2>/dev/null | tr -d '\r')"; echo "$i" | grep -q 'role:master' && [ "$(echo "$i" | sed -n 's/^connected_slaves:\([0-9]*\)/\1/p')" = 2 ] && return 0; done; sleep 1; done; return 1; }

echo "=== 1. bring up Valkey+Sentinel topology (podman) ==="
KEEP=1 bash "$REPO/test/sentinel/spike.sh" >/dev/null 2>&1 || true
podman exec vk-primary valkey-cli -a rootpass --no-auth-warning PING >/dev/null 2>&1 || { echo "topology failed to come up"; exit 1; }
settled && echo "  topology up + settled (a master with 2 connected replicas)" || { echo "topology did not settle after spike.sh"; exit 1; }

echo "=== 2. build plugin + start vault dev server ==="
( cd "$REPO" && go build -ldflags "-X main.version=v1.3.0" -o "$PLUGIN_DIR/valkey-database-plugin" ./cmd/valkey-database-plugin ) || { echo "build failed"; exit 1; }
SHA="$(sha256sum "$PLUGIN_DIR/valkey-database-plugin" | cut -d' ' -f1)"
vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PLUGIN_DIR" -dev-listen-address=127.0.0.1:8200 >/tmp/vault-static.log 2>&1 &
VAULT_PID=$!
for _ in $(seq 1 30); do vault status >/dev/null 2>&1 && break; sleep 1; done
vault status >/dev/null 2>&1 || { echo "vault did not start:"; tail -10 /tmp/vault-static.log; exit 1; }
vault plugin register -sha256="$SHA" -command=valkey-database-plugin database valkey-database-plugin
vault secrets enable database >/dev/null
vault write database/config/valkey plugin_name=valkey-database-plugin \
	sentinels="10.111.0.21:26379,10.111.0.22:26379,10.111.0.23:26379" sentinel_master_name=mymaster \
	username=vaultadmin password=vaultpass persistence_mode=aclfile allowed_roles="*" >/dev/null \
	&& ok "database/config/valkey written" || bad "config write"

echo "=== 3. pre-provision the shared static user WITH its ACL rules on EVERY node ==="
# Static roles rotate an existing user; they don't create it. Named with the v_ managed
# prefix so the reconcile pass covers it too.
for n in primary replica1 replica2; do
	nacl "$n" ACL SETUSER v_shared on '>initpass' '~app:*' '+@read' '+@write' '+@stream' >/dev/null
	nacl "$n" ACL SAVE >/dev/null
done
has_pw primary v_shared initpass && ok "v_shared pre-provisioned (initpass) on all nodes" || bad "v_shared pre-provision failed"

echo "=== 4. create static role — Vault takes ownership of the password on every node ==="
vault write database/static-roles/shared db_name=valkey username=v_shared rotation_period=24h >/dev/null \
	&& ok "database/static-roles/shared created" || bad "static-role create"
sleep 2
P1="$(vault read -field=password database/static-creds/shared 2>/dev/null)"
[ -n "$P1" ] && ok "static-creds returns the shared password" || bad "no static-creds password"
revoked=0; for _ in $(seq 1 10); do has_pw primary v_shared initpass || { revoked=1; break; }; sleep 1; done  # initial rotation is async; give it a moment
[ "$revoked" = 1 ] && ok "initial rotation happened (initpass revoked)" || bad "initpass still works — Vault did not rotate on create"
allok=1; for n in primary replica1 replica2; do has_pw "$n" v_shared "$P1" || { allok=0; bad "current password fails on $n"; }; done
[ "$allok" = 1 ] && ok "current shared password authenticates on master + all replicas"

echo "=== 5. manual rotation: new password everywhere, old revoked, consistent across nodes ==="
vault write -f database/rotate-role/shared >/dev/null && ok "rotate-role succeeded" || bad "rotate-role failed"
P2="$(vault read -field=password database/static-creds/shared)"
[ -n "$P2" ] && [ "$P2" != "$P1" ] && ok "password rotated (P2 != P1)" || bad "password did not change"
has_pw primary v_shared "$P1" && bad "old password still authenticates after rotation" || ok "old password revoked"
allok=1; for n in primary replica1 replica2; do has_pw "$n" v_shared "$P2" || { allok=0; bad "rotated password fails on $n"; }; done
[ "$allok" = 1 ] && ok "rotated password is consistent on master + all replicas"

echo "=== 6. returned-replica convergence (rotate while a replica is down, then it catches up) ==="
podman stop vk-replica2 >/dev/null 2>&1
for _ in $(seq 1 20); do podman exec vk-sentinel1 valkey-cli -p 26379 SENTINEL replicas mymaster 2>/dev/null | tr '\n' ' ' | grep -qE 's_down|disconnected' && break; sleep 1; done  # wait until Sentinel excludes it
vault write -f database/rotate-role/shared >/dev/null      # rotates on the up nodes (replica2 excluded)
P3="$(vault read -field=password database/static-creds/shared)"
podman start vk-replica2 >/dev/null 2>&1
for _ in $(seq 1 45); do replica2_healthy && break; sleep 1; done
has_pw replica2 v_shared "$P3" && bad "replica2 already had the new password (was it really down?)" || ok "returned replica2 is stale (it missed the rotation)"
vault write -f database/rotate-role/shared >/dev/null      # next rotation converges every up node (setPassword + reconcile)
P4="$(vault read -field=password database/static-creds/shared)"; sleep 1
allok=1; for n in primary replica1 replica2; do has_pw "$n" v_shared "$P4" || { allok=0; bad "converged password fails on $n"; }; done
[ "$allok" = 1 ] && ok "after the next rotation every node (incl. returned replica2) holds the current password"

echo "=== 7. lazy-rotate wrapper: no-op when fresh, rotates when stale ==="
export ROLE=shared MOUNT=database
BEFORE="$(vault read -field=password database/static-creds/shared)"
MAX_AGE=15552000 FIELD=password bash "$REPO/contrib/lazy-rotate.sh" >/dev/null && ok "wrapper ran (fresh)" || bad "wrapper errored (fresh)"
[ "$(vault read -field=password database/static-creds/shared)" = "$BEFORE" ] && ok "fresh password: wrapper did NOT rotate (age < MAX_AGE)" || bad "wrapper rotated a fresh password"
sleep 2
OUT="$(MAX_AGE=1 FIELD=password bash "$REPO/contrib/lazy-rotate.sh")"
AFTER="$(vault read -field=password database/static-creds/shared)"
{ [ "$AFTER" != "$BEFORE" ] && [ "$OUT" = "$AFTER" ]; } && ok "stale password: wrapper rotated and returned the new password" || bad "wrapper failed to rotate a stale password"

echo
[ "$FAIL" = 0 ] && printf '\033[32mSTATIC-E2E PASS — static-role rotation across Sentinel + lazy wrapper verified\033[0m\n' || printf '\033[31mSTATIC-E2E FAIL\033[0m\n'
exit $FAIL
