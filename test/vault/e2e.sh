#!/usr/bin/env bash
# Real end-to-end: a live `vault server -dev` with the plugin registered, exercising
# the full Vault database-secrets flow (config → role → issue → revoke) against the
# podman Valkey+Sentinel topology. This validates the actual Vault→plugin→Valkey
# contract: plugin registration, the config/role/creds endpoints, and lease revocation.
#
#   test/vault/e2e.sh
#   PATH=/path/to/older-vault:$PATH test/vault/e2e.sh   # validate a specific Vault version (e.g. the 1.14 floor)
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"

export GOTOOLCHAIN=local

PLUGIN_DIR="$(mktemp -d)"
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"
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

# admin-side ACL check on a node container
node_has_user() { podman exec "vk-$1" valkey-cli -a rootpass --no-auth-warning ACL GETUSER "$2" 2>/dev/null | grep -q flags; }

echo "=== 1. bring up Valkey+Sentinel topology (podman) ==="
KEEP=1 bash "$REPO/test/sentinel/spike.sh" >/dev/null 2>&1 || true
podman exec vk-primary valkey-cli -a rootpass --no-auth-warning PING >/dev/null 2>&1 || { echo "topology failed to come up"; exit 1; }
echo "  topology up"

echo "=== 2. build + start vault dev server with the plugin ==="
( cd "$REPO" && go build -ldflags "-X main.version=v0.0.1" -o "$PLUGIN_DIR/valkey-database-plugin" ./cmd/valkey-database-plugin ) || { echo "build failed"; exit 1; }
SHA="$(sha256sum "$PLUGIN_DIR/valkey-database-plugin" | cut -d' ' -f1)"
vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PLUGIN_DIR" -dev-listen-address=127.0.0.1:8200 >/tmp/vault-e2e.log 2>&1 &
VAULT_PID=$!
for _ in $(seq 1 30); do vault status >/dev/null 2>&1 && break; sleep 1; done
vault status >/dev/null 2>&1 || { echo "vault did not start; see /tmp/vault-e2e.log"; exit 1; }
echo "  vault up (pid $VAULT_PID)"

echo "=== 3. register plugin + enable database secrets ==="
vault plugin register -sha256="$SHA" -command=valkey-database-plugin database valkey-database-plugin
vault secrets enable database >/dev/null
PV="$(vault plugin list -detailed -format=json database 2>/dev/null | jq -r '.. | objects | select(.name?=="valkey-database-plugin") | .version? // empty' | head -1)"
[ -n "$PV" ] && ok "plugin version reported via PluginVersioner: $PV" || echo "  (version not reported)"

echo "=== 4. configure connection + role ==="
vault write database/config/valkey \
  plugin_name=valkey-database-plugin \
  sentinels="10.111.0.21:26379,10.111.0.22:26379,10.111.0.23:26379" \
  sentinel_master_name=mymaster \
  username=vaultadmin password=vaultpass \
  persistence_mode=aclfile \
  allowed_roles="app" >/dev/null && ok "database/config/valkey written" || bad "config write"
vault write database/roles/app \
  db_name=valkey \
  creation_statements="~app:* +@read +@write +@stream" \
  default_ttl=5m max_ttl=1h >/dev/null && ok "database/roles/app written" || bad "role write"

echo "=== 5. negative test: a role with a model-breaking token is rejected ==="
vault write database/roles/bad db_name=valkey creation_statements="~app:* nopass" default_ttl=5m >/dev/null 2>&1
if vault read database/creds/bad >/dev/null 2>&1; then bad "role with 'nopass' should not yield usable creds"; else ok "model-breaking creation_statements rejected at issue time"; fi

echo "=== 6. issue dynamic credentials (single read — username+password from one lease) ==="
CREDS="$(vault read -format=json database/creds/app)"
USERNAME="$(echo "$CREDS" | jq -r .data.username)"
PASSWORD="$(echo "$CREDS" | jq -r .data.password)"
{ [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; } && ok "issued user: $USERNAME" || bad "no creds issued"

echo "=== 7. verify the user exists on every node ==="
for n in primary replica1 replica2; do
  node_has_user "$n" "$USERNAME" && ok "present on $n" || bad "missing on $n"
done

echo "=== 8. verify auth (hashed password still authenticates) + ACL scope ==="
OUT="$(podman exec vk-primary valkey-cli --user "$USERNAME" --pass "$PASSWORD" --no-auth-warning GET app:probe 2>&1)"
echo "$OUT" | grep -qiE 'wrongpass|noauth|noperm' && bad "auth/read within grant failed: $OUT" || ok "authenticated + read within grant (~app:*)"
OUT="$(podman exec vk-primary valkey-cli --user "$USERNAME" --pass "$PASSWORD" --no-auth-warning GET other:secret 2>&1)"
echo "$OUT" | grep -qi 'noperm' && ok "denied outside grant (other:*)" || bad "should be denied on other:*, got: $OUT"

echo "=== 9. revoke lease + verify removal on every node ==="
vault lease revoke -prefix database/creds/app >/dev/null 2>&1
sleep 2
for n in primary replica1 replica2; do
  node_has_user "$n" "$USERNAME" && bad "still present on $n after revoke" || ok "removed on $n"
done

echo "=== 10. root rotation (vault rotate-root), then verify issuance still works ==="
# Rotates the plugin's vaultadmin password on every node (all-or-nothing). Sentinel uses
# the separate 'default' identity, so its monitoring is unaffected. Success of a fresh
# issuance proves the admin password is consistent across all nodes post-rotation.
vault write -f database/rotate-root/valkey >/dev/null 2>&1 && ok "rotate-root succeeded" || bad "rotate-root failed"
if vault read -format=json database/creds/app >/dev/null 2>&1; then ok "issuance works after root rotation (admin consistent on every node)"; else bad "issuance broke after root rotation"; fi

echo
[ "$FAIL" = 0 ] && printf '\033[32mE2E PASS — Vault→plugin→Valkey full lifecycle verified\033[0m\n' || printf '\033[31mE2E FAIL\033[0m\n'
exit $FAIL
