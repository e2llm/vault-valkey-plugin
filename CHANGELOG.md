# Changelog

All notable changes to this project are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut by tagging `vX.Y.Z`
(see `PUBLIC-RELEASE-CHECKLIST.md`). The release section becomes the GitHub release notes.

## v1.3.0

**Static roles** — Vault-managed rotation of a pre-existing *shared* credential (one account
used by many clients), alongside the dynamic per-lease creds. Rotation flows through the
plugin's `UpdateUser` and is applied across **every** Sentinel node, so whichever node a
client reaches — including a promoted replica — carries the current password.

- Configure a Vault static role against an existing Valkey user:
  `vault write database/static-roles/<name> db_name=<conn> username=<user> rotation_period=<dur>`
  (or `rotation_schedule` for calendar-aligned rotation). `vault read database/static-creds/<name>`
  returns the current shared password to every reader, plus the time to the next rotation.
- The static user must be **pre-provisioned with its ACL rules on every node** (Vault rotates,
  it does not create). Name it with `managed_username_prefix` (default `v_`) so the reconcile
  pass keeps it converged across the topology; a non-root rotation now runs reconcile too.
- **`contrib/lazy-rotate.sh`** — optional restart-coupled ("lazy") wrapper: at pod start it
  returns the current shared password, first rotating it only if older than `MAX_AGE`. Pair
  with `rotation_period` for a hard compliance ceiling (see the script header for the trade-off).
- Honest limitation: a node **down during a rotation** stays stale until the next rotation (or
  a reconcile triggered by other issuance) re-converges it — fine when nodes are healthy at
  rotation time; frequent rotation or live dynamic traffic tightens the window.

## v1.2.0

Opportunistic **reconcile pass** that heals node-local ACL drift — the honest limitation
called out since v1.0.0. On each credential issuance (when replicas are present) the plugin
converges every data node to the master, the source of truth:

- a managed user **missing** from a data node that was down at an earlier create is
  re-asserted from the master's definition — hash and all, via `ACL LIST` → `ACL SETUSER
  reset` (never cleartext, no Vault lease enumeration);
- a managed user a revoke left as an **orphan** on a then-down node is removed.
- The master is authoritative by construction (every create writes it first, every op
  re-resolves to it), so reconcile needs no external lease-aware reconciler and survives a
  plugin restart — it closes that gap in-plugin.
- `reconcile` = `true` (default) | `false`. Best-effort and non-fatal — a reconcile hiccup
  never fails issuance. Cheap when clean: one `ACL LIST` on the master + one `ACL USERS`
  per node; it writes only actual drift.
- `managed_username_prefix` (default `v_`, the built-in `username_template` prefix)
  identifies plugin-managed users, so static/admin accounts are never touched. Set it only
  if `username_template` is overridden to a different prefix.

## v1.1.0

Optional **shared Sentinel identity** mode for legacy apps that authenticate to both the
data nodes and the Sentinels with a single credential. Separate identities remain the
default — existing connections are unchanged.

- `sentinel_identity_mode` = `separate` (default) | `shared`. In shared mode the dynamic
  user is also provisioned on the Sentinels with a narrow read-only discovery ACL
  (`+@connection +sentinel|get-master-addr-by-name +sentinel|replicas +sentinel|sentinels`,
  overridable via `sentinel_creation_statements`): it resolves the master but cannot
  trigger failover (`SENTINEL failover`/`monitor`/`remove`/`set` rejected by validation).
- `sentinel_persistence_mode` = `none` (default, ephemeral) | `aclfile` (durable via
  `ACL SAVE`, requires an aclfile configured on the Sentinels). `rewrite` is rejected —
  Sentinels have no `CONFIG REWRITE`.
- Sentinel provisioning is best-effort with a quorum of one (an issued credential is
  always usable for discovery); a Sentinel down for maintenance is tolerated. Revocation
  removes the user from the data nodes and the Sentinels; a Sentinel-side failure is
  non-fatal (discovery-only access, and ephemeral Sentinels self-clean on restart).
- In shared mode `sentinel_username`/`sentinel_password` must be a Sentinel admin (it now
  runs `ACL SETUSER`/`DELUSER` on the Sentinels, in addition to discovery).
- Empirically validated — `test/sentinel/spike.sh` INV-6..8 on valkey 8 (the same Sentinel
  behavior confirmed on redis 7.4, the target engine), plus the real-Vault e2e: a Sentinel
  honors a runtime ACL user, has no `CONFIG REWRITE`, and persists users via an aclfile.

## v1.0.0

First release of the Valkey database secrets plugin (`dbplugin v5`).

- Sentinel topology discovery (resolve current master + live replicas, tolerate a dead
  Sentinel) with a separate low-privilege Sentinel discovery identity.
- Node-local credential lifecycle: create/rotate/delete each dynamic user on every node
  with per-node persistence (`aclfile` / `rewrite` / `none`); partial-create rollback.
- TLS support; configurable username template; ACL-category-friendly roles (Streams).
- Reproducible podman Sentinel harness (`test/sentinel/spike.sh`) proving the node-local
  ACL invariants on Valkey 8 and 9; unit tests; build-tagged integration test.
- Empirical finding documented: Valkey ACLs are node-local (no replication propagation,
  no resync transfer) — the design rests on this.
- Security: passwords provisioned as SHA-256 hashes (`#<hex>`, default on) so cleartext
  never reaches a node's command log; `creation_statements` reject model-breaking tokens
  (`nopass`/`off`/`reset`/`resetpass`) and password directives, warn on over-broad grants;
  TLS-disabled and `insecure_tls` warnings; error-sanitized secrets.
- Root rotation (`vault rotate-root`) across all nodes — all-or-nothing with rollback to
  the previous password on partial failure.
- hclog operational logging (no secrets); `logical.PluginVersioner`; declares the password
  credential type. Single-path topology orchestration with unit-tested rollback.
- Real-Vault end-to-end test (`test/vault/e2e.sh`) and a `dbplugin/v5/testing`-based
  integration suite including a plugin-driven failover-mid-lease scenario.
