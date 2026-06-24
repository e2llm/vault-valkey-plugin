#!/usr/bin/env bash
# Phase 0 spike — empirically settle the Valkey+Sentinel ACL invariants the Vault
# plugin design rests on. Reproducible podman harness: 1 primary + 2 replicas + 3
# sentinels, ACL enabled with an aclfile. No Go required.
#
#   VALKEY_IMAGE=docker.io/valkey/valkey:9 test/sentinel/spike.sh   # version pass
#   KEEP=1 test/sentinel/spike.sh                                   # leave topology up
#
# Key finding it encodes: ACL users are NODE-LOCAL. Data writes replicate; ACL
# SETUSER/DELUSER do NOT, and a replica resync does not carry them either. So the
# plugin must create/persist/delete the user on EVERY node and re-resolve the
# master (via Sentinel) on every operation. The phases below prove that and then
# validate the node-local design across a real failover.
set -uo pipefail

IMG="${VALKEY_IMAGE:-docker.io/valkey/valkey:8}"
NET="vkspike"; SUBNET="10.111.0.0/24"; PASS="rootpass"
WORK="${SPIKE_WORK:-$(cd "$(dirname "$0")" && pwd)/.run}"
FAILED=0

declare -A IP=(
  [primary]=10.111.0.10 [replica1]=10.111.0.11 [replica2]=10.111.0.12
  [sentinel1]=10.111.0.21 [sentinel2]=10.111.0.22 [sentinel3]=10.111.0.23
)
NODES=(primary replica1 replica2)
SENTINELS=(sentinel1 sentinel2 sentinel3)

log()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILED=1; }
note() { printf '  ....  %s\n' "$*"; }

nacl() { local n=$1; shift; podman exec "vk-$n" valkey-cli -a "$PASS" --no-auth-warning "$@" 2>/dev/null; }
sacl() { local n=$1; shift; podman exec "vk-$n" valkey-cli -p 26379 "$@" 2>/dev/null; }
has_user() { nacl "$1" ACL LIST | grep -q "^user $2 "; }
node_for_ip() { local ip=$1 n; for n in "${NODES[@]}"; do [ "${IP[$n]}" = "$ip" ] && { echo "$n"; return; }; done; echo "unknown($ip)"; }
master_ip() { sacl sentinel1 SENTINEL get-master-addr-by-name mymaster | head -1 | tr -d '\r'; }
master_node() { node_for_ip "$(master_ip)"; }
a_replica() { local m=$1 n; for n in "${NODES[@]}"; do [ "$n" != "$m" ] && { echo "$n"; return; }; done; }

# the plugin's real strategy, modelled: write/persist the dynamic user on EVERY node
create_on_all() { local n; for n in "${NODES[@]}"; do
  nacl "$n" ACL SETUSER "$1" on ">${1}pass" '~app:*' '+@stream' '+@read' '+@write' >/dev/null
  nacl "$n" ACL SAVE >/dev/null; done; }
delete_on_all() { local n; for n in "${NODES[@]}"; do
  nacl "$n" ACL DELUSER "$1" >/dev/null; nacl "$n" ACL SAVE >/dev/null; done; }

cleanup() { local n; for n in "${NODES[@]}" "${SENTINELS[@]}"; do podman rm -f "vk-$n" >/dev/null 2>&1; done; podman network rm "$NET" >/dev/null 2>&1; }

gen_configs() {
  rm -rf "$WORK"; mkdir -p "$WORK"
  for n in "${NODES[@]}" "${SENTINELS[@]}"; do mkdir -p "$WORK/$n"; done
  # default = Sentinel's node-auth identity; vaultadmin = the plugin's dedicated admin
  # (kept distinct so rotate-root of the plugin admin does not break Sentinel monitoring).
  for n in "${NODES[@]}"; do
    { printf 'user default on >%s ~* &* +@all\n' "$PASS"
      printf 'user vaultadmin on >vaultpass ~* &* +@all\n'
    } > "$WORK/$n/users.acl"
  done
  cat > "$WORK/primary/node.conf" <<EOF
bind 0.0.0.0
protected-mode no
port 6379
dir /data
aclfile /data/users.acl
masteruser default
masterauth $PASS
appendonly no
save ""
EOF
  for r in replica1 replica2; do cat > "$WORK/$r/node.conf" <<EOF
bind 0.0.0.0
protected-mode no
port 6379
dir /data
aclfile /data/users.acl
replicaof ${IP[primary]} 6379
masteruser default
masterauth $PASS
replica-announce-ip ${IP[$r]}
appendonly no
save ""
EOF
  done
  for s in "${SENTINELS[@]}"; do cat > "$WORK/$s/node.conf" <<EOF
bind 0.0.0.0
protected-mode no
port 26379
dir /data
sentinel resolve-hostnames yes
sentinel announce-ip ${IP[$s]}
sentinel monitor mymaster ${IP[primary]} 6379 2
sentinel auth-user mymaster default
sentinel auth-pass mymaster $PASS
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 12000
sentinel parallel-syncs mymaster 1
EOF
  done
  chmod -R 0777 "$WORK"
}

start() {
  podman network create --subnet "$SUBNET" "$NET" >/dev/null
  for n in "${NODES[@]}"; do podman run -d --name "vk-$n" --network "$NET" --ip "${IP[$n]}" -v "$WORK/$n:/data:Z" "$IMG" valkey-server /data/node.conf >/dev/null; done
  for s in "${SENTINELS[@]}"; do podman run -d --name "vk-$s" --network "$NET" --ip "${IP[$s]}" -v "$WORK/$s:/data:Z" "$IMG" valkey-server /data/node.conf --sentinel >/dev/null; done
}
wait_repl() { for _ in $(seq 1 30); do [ "$(nacl primary INFO replication | tr -d '\r' | sed -n 's/^connected_slaves:\(.*\)/\1/p')" = "2" ] && return 0; sleep 1; done; return 1; }

#############################################################################
trap '[ "${KEEP:-0}" = 1 ] || cleanup' EXIT
log "Spike image: $IMG"
cleanup; gen_configs; start
log "Wait for replication (primary + 2 replicas)"
if wait_repl; then ok "replication up: connected_slaves=2"; else bad "replication did not converge"; fi
sleep 6
note "sentinel master=$(master_node)  replicas seen=$(sacl sentinel1 SENTINEL replicas mymaster | grep -c '^name')"

#############################################################################
log "INV-1  Node-locality: data replicates, ACLs do NOT (positive + negative control)"
m=$(master_node); rep=$(a_replica "$m"); note "current master=$m  sample replica=$rep"
nacl "$m" SET spike:ctl hello >/dev/null; sleep 1
[ "$(nacl "$rep" GET spike:ctl)" = "hello" ] && ok "data write propagated $m -> $rep (replication is live)" || bad "data did not propagate — harness broken"
nacl "$m" ACL SETUSER probe on '>x' '~*' '+@read' >/dev/null; sleep 2
has_user "$m" probe && ok "probe user created on master $m" || bad "probe user not on master"
if has_user "$rep" probe; then bad "ACL unexpectedly propagated — re-check assumption"; else ok "ACL SETUSER did NOT reach $rep — ACLs are node-local (THE finding)"; fi
nacl "$m" ACL DELUSER probe >/dev/null

#############################################################################
log "INV-2  Correct design: create the user on EVERY node -> present everywhere"
create_on_all app1
allok=1; for n in "${NODES[@]}"; do has_user "$n" app1 || { allok=0; bad "app1 missing on $n"; }; done
[ "$allok" = 1 ] && ok "app1 present on all 3 nodes (per-node provisioning)"

#############################################################################
log "INV-3  Persistence is explicit (ACL SAVE) — restart a replica, no failover"
m=$(master_node); rep=$(a_replica "$m"); note "restarting replica $rep (master $m stays up, no failover)"
podman restart "vk-$rep" >/dev/null; sleep 5
has_user "$rep" app1 && ok "app1 survived $rep restart (was ACL SAVEd to aclfile)" || bad "app1 lost on $rep despite ACL SAVE"
nacl "$rep" ACL SETUSER eph on '>x' '~*' '+@read' >/dev/null   # deliberately NOT saved
podman restart "vk-$rep" >/dev/null; sleep 5
if has_user "$rep" eph; then bad "unsaved user 'eph' survived restart"; else ok "unsaved 'eph' lost on restart — durability requires ACL SAVE per node"; fi

#############################################################################
log "INV-4  Failover correctness: promoted node already has the user"
m_before=$(master_node); note "master before failover: $m_before"
sacl sentinel1 SENTINEL FAILOVER mymaster >/dev/null
for _ in $(seq 1 30); do m_after=$(master_node); [ -n "$m_after" ] && [ "$m_after" != "$m_before" ] && break; sleep 1; done
[ "${m_after:-}" != "$m_before" ] && ok "failover promoted new master: $m_after" || bad "failover did not change master"
sleep 3
has_user "$m_after" app1 && ok "app1 present on promoted master $m_after (because we wrote every node)" || bad "app1 missing on promoted master"

#############################################################################
log "INV-5  Revoke targets every node (DELUSER is node-local too)"
delete_on_all app1
gone=1; for n in "${NODES[@]}"; do has_user "$n" app1 && { gone=0; bad "app1 lingers on $n"; }; done
[ "$gone" = 1 ] && ok "app1 removed from all nodes"

#############################################################################
log "SUMMARY for $IMG"
[ "$FAILED" = 0 ] && printf '  \033[32mALL INVARIANTS HELD (node-local design validated)\033[0m\n' || printf '  \033[31mSOME INVARIANTS FAILED — see above\033[0m\n'
exit $FAILED
