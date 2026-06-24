#!/usr/bin/env bash
# Bring up the podman Valkey+Sentinel topology (reusing the spike harness, which also
# self-validates the invariants), run the build-tagged integration test against it
# through the real plugin code, then tear everything down.
#
#   VALKEY_IMAGE=docker.io/valkey/valkey:9 test/integration/run.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"

# Offline-friendly Go env (deps already cached); proxy is only needed if a fetch happens.
export GOTOOLCHAIN=local

teardown() {
  for n in primary replica1 replica2 sentinel1 sentinel2 sentinel3; do podman rm -f "vk-$n" >/dev/null 2>&1 || true; done
  podman network rm vkspike >/dev/null 2>&1 || true
}
trap teardown EXIT

# KEEP=1 leaves the topology running after the spike's own checks.
KEEP=1 bash "$REPO/test/sentinel/spike.sh"

export VALKEY_SENTINELS="10.111.0.21:26379,10.111.0.22:26379,10.111.0.23:26379"
export VALKEY_NODES="10.111.0.10:6379,10.111.0.11:6379,10.111.0.12:6379"
export VALKEY_USER=default VALKEY_PASS=rootpass VALKEY_MASTER_NAME=mymaster

# Respect the Sentinel failover-timeout (12s) cooldown before the plugin-driven
# failover test, so SENTINEL FAILOVER is not refused after the spike's own failover.
echo
echo "=== failover cooldown (~14s) ==="
sleep 14
export VALKEY_RUN_FAILOVER=1

cd "$REPO"
echo
echo "=== integration test (plugin code path vs live topology) ==="
go test -tags integration -race -v -timeout 5m ./test/integration/
