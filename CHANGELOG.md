# Changelog

All notable changes to this project are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut by tagging `vX.Y.Z`
(see `PUBLIC-RELEASE-CHECKLIST.md`). The release section becomes the GitHub release notes.

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
