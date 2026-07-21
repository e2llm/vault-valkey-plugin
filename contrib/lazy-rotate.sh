#!/usr/bin/env bash
# lazy-rotate.sh — restart-coupled ("lazy") rotation for a Vault database STATIC role.
#
# Run this at app/pod startup for a SHARED credential. It prints the current static-role
# password — but first rotates it if the current password is older than a threshold. So a
# pod that starts within the window gets the existing shared password; a pod that starts
# after the threshold triggers a rotation, and everyone who starts in the next window gets
# the new one.
#
#   Env:
#     VAULT_ADDR / VAULT_TOKEN   as usual (set up auth before calling)
#     ROLE      static-role name                       (required)
#     MOUNT     database mount path                    (default: database)
#     MAX_AGE   rotate if the current password is older than this many seconds
#                                                       (default: 15552000 = 180 days)
#     FIELD     what to print: password | username | json   (default: password)
#
#   Example (Kubernetes init/entrypoint):
#     export VAULT_ADDR=... ROLE=shared MAX_AGE=15552000
#     APP_PASSWORD="$(lazy-rotate.sh)"
#
# Compliance note: this is LAZY — the password's real max age is bounded by how often a pod
# starts, NOT strictly by MAX_AGE. If nothing starts, the password can exceed MAX_AGE. For a
# hard "rotate every N" ceiling regardless of restarts, ALSO set rotation_period=N on the
# static role: Vault then rotates eagerly on its own and this wrapper only ever brings a
# rotation forward.
#
# Concurrency: if several pods start at once and all see a stale password, each triggers a
# rotation; Vault serializes them and the last one wins. Harmless (an extra rotation or two),
# and every pod re-reads the final password before returning.
set -euo pipefail

MOUNT="${MOUNT:-database}"
ROLE="${ROLE:?set ROLE to the static-role name}"
MAX_AGE="${MAX_AGE:-15552000}" # 180 days
FIELD="${FIELD:-password}"

command -v vault >/dev/null || { echo "lazy-rotate: 'vault' CLI not found" >&2; exit 3; }
command -v jq >/dev/null    || { echo "lazy-rotate: 'jq' not found" >&2; exit 3; }

read_creds() { vault read -format=json "${MOUNT}/static-creds/${ROLE}"; }

creds="$(read_creds)"
last="$(echo "$creds" | jq -r '.data.last_vault_rotation // empty')"
last_epoch="$(date -d "$last" +%s 2>/dev/null || echo 0)"
age=$(( $(date +%s) - last_epoch ))

if [ "$last_epoch" -gt 0 ] && [ "$age" -gt "$MAX_AGE" ]; then
	vault write -f "${MOUNT}/rotate-role/${ROLE}" >/dev/null
	creds="$(read_creds)" # re-read the freshly rotated password
fi

case "$FIELD" in
password) echo "$creds" | jq -r '.data.password' ;;
username) echo "$creds" | jq -r '.data.username' ;;
json)     echo "$creds" | jq -c '.data | {username, password, last_vault_rotation, ttl}' ;;
*) echo "lazy-rotate: unknown FIELD=$FIELD (want password|username|json)" >&2; exit 2 ;;
esac
