# Changelog

All notable changes to this project are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut by tagging `vX.Y.Z`
(see `PUBLIC-RELEASE-CHECKLIST.md`). The release section becomes the GitHub release notes.

## v0.1.0

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
