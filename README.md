# vault-valkey-plugin

[![CI](https://github.com/e2llm/vault-valkey-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/e2llm/vault-valkey-plugin/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://www.mozilla.org/MPL/2.0/)

A HashiCorp Vault / OpenBao **database secrets engine plugin** (`dbplugin v5`) that
issues **dynamic Valkey credentials** across a **Sentinel-managed** primary/replica
topology — including correct behaviour across failover — and supports a **separate,
low-privilege identity for Sentinel discovery**.

> Status: **pre-release (v0.x).** Production-hardened — unit, live-cluster integration,
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
| `sentinel_username` / `sentinel_password` | no | Separate identity for Sentinel discovery |
| `host` / `port` | standalone | Single-node fallback (no Sentinel) |
| `username` / `password` | yes | Node admin identity used to run `ACL SETUSER`/`DELUSER` |
| `persistence_mode` | no | `aclfile` (default, runs `ACL SAVE`), `rewrite` (`CONFIG REWRITE`), or `none` |
| `tls` / `insecure_tls` | no | Enable TLS / skip server-cert verification |
| `ca_cert` / `tls_cert` / `tls_key` | no | PEM material for TLS |
| `password_hashing` | no | Send a SHA-256 hash to `ACL SETUSER` instead of cleartext (default `true`) |
| `username_template` | no | Override the generated dynamic username format |

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

## Testing

```bash
go test ./...                 # unit tests
test/sentinel/spike.sh        # live podman Sentinel topology — proves the invariants
test/integration/run.sh       # plugin code vs live cluster (incl. failover)
test/vault/e2e.sh             # real `vault server -dev` end-to-end
```

## License

[MPL-2.0](LICENSE).
