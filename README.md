# vault-valkey-plugin

[![CI](https://github.com/e2llm/vault-valkey-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/e2llm/vault-valkey-plugin/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://www.mozilla.org/MPL/2.0/)

A HashiCorp Vault / OpenBao **database secrets engine plugin** (`dbplugin v5`) that
issues **dynamic Valkey credentials** across a **Sentinel-managed** primary/replica
topology — including correct behaviour across failover — and supports a **separate,
low-privilege identity for Sentinel discovery**.

> Status: **released (v1.2.0).** Production-hardened — unit, live-cluster integration,
> and real-Vault end-to-end tests pass on Vault 1.14 and 1.21; see `CHANGELOG.md`.

## Why a dedicated plugin

The upstream Vault Redis plugin and OpenBao's native Valkey plugin are **single-node
only**. Neither follows a Sentinel-managed master across failover. This plugin does,
and it is built around one empirically established fact:

**Valkey ACL users are node-local.** Creating a user on the master does *not*
propagate it to replicas, and a replica resync does *not* carry it. (Reproduce:
`test/sentinel/spike.sh`.) So the plugin **provisions, persists, and revokes each
dynamic user on every node**, and **re-resolves the current master through Sentinel
on every operation**.

## Build

```bash
go build -o valkey-database-plugin ./cmd/valkey-database-plugin
```

## Use

Register the plugin with Vault, then configure a connection and a role:

```bash
# 1. configure the connection (Sentinel mode)
vault write database/config/my-valkey \
    plugin_name="valkey-database-plugin" \
    sentinels="10.0.0.1:26379,10.0.0.2:26379,10.0.0.3:26379" \
    sentinel_master_name="mymaster" \
    sentinel_username="vault-sentinel-ro" \
    sentinel_password="$SENTINEL_PW" \
    username="vault-admin" \
    password="$NODE_ADMIN_PW" \
    persistence_mode="aclfile" \
    allowed_roles="app-reader"

# 2. define a role — prefer ACL *categories* over enumerated commands for
#    version portability; this example grants Streams + read/write on app:* keys
vault write database/roles/app-reader \
    db_name="my-valkey" \
    creation_statements="~app:* +@read +@write +@stream" \
    default_ttl="1h" max_ttl="24h"

# 3. get short-lived credentials
vault read database/creds/app-reader
```

## Configuration reference

| Field | Required | Description |
|-------|----------|-------------|
| `sentinels` | Sentinel mode | Comma-separated `host:port` of the Sentinels |
| `sentinel_master_name` | Sentinel mode | Monitored primary name (e.g. `mymaster`) |
| `sentinel_username` / `sentinel_password` | no | Identity for Sentinel discovery (and, in `shared` mode, a Sentinel admin that runs `ACL SETUSER`/`DELUSER` on the Sentinels) |
| `host` / `port` | standalone | Single-node fallback (no Sentinel) |
| `username` / `password` | yes | Node admin identity used to run `ACL SETUSER`/`DELUSER` |
| `persistence_mode` | no | `aclfile` (default, runs `ACL SAVE`), `rewrite` (`CONFIG REWRITE`), or `none` |
| `tls` / `insecure_tls` | no | Enable TLS / skip server-cert verification |
| `ca_cert` / `tls_cert` / `tls_key` | no | PEM material for TLS |
| `password_hashing` | no | Send a SHA-256 hash to `ACL SETUSER` instead of cleartext (default `true`) |
| `username_template` | no | Override the generated dynamic username format |
| `sentinel_identity_mode` | no | `separate` (default) or `shared` — see [Shared identity](#shared-identity) |
| `sentinel_persistence_mode` | no | Sentinel-side durability in `shared` mode: `none` (default, ephemeral) or `aclfile`. `rewrite` is rejected (Sentinels have no `CONFIG REWRITE`) |
| `sentinel_creation_statements` | no | Override the Sentinel-side discovery ACL (`shared` mode); default is a narrow read-only set |
| `reconcile` | no | Heal node-local ACL drift on each issuance (default `true`) — re-assert managed users a returned node is missing, remove orphans a revoke left behind. See [Reconciliation](#reconciliation) |
| `managed_username_prefix` | no | Prefix identifying plugin-managed users for reconcile (default `v_`); set only if `username_template` uses a different prefix |

## Shared identity

By default the dynamic user lives only on the data nodes and Sentinel discovery uses a
separate identity (the secure model). For a **legacy app that authenticates to both the
Valkey nodes and the Sentinels with one credential**, set `sentinel_identity_mode=shared`:
the same dynamic user is also provisioned on the Sentinels with a narrow read-only
discovery ACL — it can resolve the master but not trigger failover.

```bash
vault write database/config/my-valkey \
    plugin_name="valkey-database-plugin" \
    sentinels="10.0.0.1:26379,10.0.0.2:26379,10.0.0.3:26379" \
    sentinel_master_name="mymaster" \
    sentinel_username="vault-sentinel-admin" \
    sentinel_password="$SENTINEL_ADMIN_PW" \
    sentinel_identity_mode="shared" \
    sentinel_persistence_mode="aclfile" \
    username="vault-admin" password="$NODE_ADMIN_PW" \
    allowed_roles="legacy-app"
```

- `sentinel_username`/`sentinel_password` must be a **Sentinel admin** (it runs
  `ACL SETUSER`/`DELUSER` on the Sentinels), not just a discovery user.
- Sentinel-side users are **ephemeral** unless you configure an `aclfile` on the Sentinels
  *and* set `sentinel_persistence_mode=aclfile`. Ephemeral is fine where Sentinels are
  stable and the app re-fetches credentials on restart.
- Shared identity is **less secure** than separate identities (the app credential reaches
  the Sentinel control plane). Prefer separate identities where the client supports them.

## Reconciliation

Because ACL users are node-local, a replica that is **down when a credential is created**
never receives that user, and a node **down when a lease is revoked** keeps a stale one.
The plugin heals both on each subsequent issuance (`reconcile=true`, the default): it treats
the **master** as the source of truth — every create writes the master first and every
operation re-resolves to it — and converges each data node to it.

- A managed user present on the master but missing from a node is **cloned** from the
  master's `ACL LIST` definition (hash included, so no cleartext and no Vault lookup).
- A managed user on a node but absent from the master is **removed** as an orphan.
- Best-effort and non-fatal — the just-issued credential is already provisioned, so a
  reconcile hiccup only logs. Cheap when clean (one `ACL LIST` + one `ACL USERS` per node).

Managed users are identified by `managed_username_prefix` (default `v_`); static and admin
accounts are never touched. Set `reconcile=false` to disable.

## Compatibility

- **Vault 1.14+** (1.x), and OpenBao — one binary targets both via `dbplugin v5`.
- **Valkey 7.x → latest**, and Redis 7.x (RESP/ACL compatible). On **Valkey 9.0+** the
  Sentinel discovery user needs `+failover` and `+client`; size its ACL accordingly.

## Security notes

- Passwords are provisioned to nodes as a **SHA-256 hash** (`#<hex>`), so cleartext never
  reaches a node's command log; clients still authenticate with the cleartext Vault issues.
- `creation_statements` **rejects** credential-model-breaking tokens (`nopass`, `off`,
  `reset`, `resetpass`) and password directives (`>`/`<`/`#`/`!`) — supply only
  key/command/channel rules.
- Use a **separate, low-privilege** Sentinel discovery user (`sentinel_username`); on
  Valkey 9.0+ give it `+failover` and `+client`.
- Enable **TLS** in production — without it, client `AUTH` traffic is cleartext.
- **Restrict `read` on `database/config/*` to operators** — Vault returns plugin-specific
  secrets (`sentinel_password`, `tls_key`) on a connection read; it masks only the built-in
  `password`.

## Testing

```bash
go test ./...                 # unit tests
test/sentinel/spike.sh        # live podman Sentinel topology — proves the invariants
test/integration/run.sh       # plugin code vs live cluster (incl. failover)
test/vault/e2e.sh             # real `vault server -dev` end-to-end
```

## License

[MPL-2.0](LICENSE).
