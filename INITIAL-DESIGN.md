# Design: Vault Dynamic Credentials for Valkey behind Sentinel

Technical design for the `valkey-database-plugin` (Vault/OpenBao `dbplugin v5`).

## 1. Problem

Vault's database secrets engine issues short-lived per-app credentials, but the
upstream Redis plugin and OpenBao's native Valkey plugin are **single-node only**.
Production Valkey runs under **Sentinel**: a primary with replicas, where the primary
moves on failover. A dynamic credential must be usable no matter which node is primary,
and must be cleaned up afterwards. Discovery of the current primary is a separate
concern from data access, and should use a separate, low-privilege identity.

## 2. Goals / non-goals

**Goals**
1. Dynamic Valkey users (create on lease, revoke on expiry), Vault-leased.
2. Correct across Sentinel failover — the user exists on whichever node is primary now.
3. Durable across node restart.
4. Separate identity for Sentinel discovery vs. the data nodes.
5. Version-portable roles (Valkey 7.x → latest; Redis 7.x); Streams supported.
6. One binary serving both Vault (1.14+) and OpenBao.

**Non-goals (now)**
- Redis **Cluster** mode (sharded). We target Sentinel/replication. The structure
  leaves room for it but it is not implemented.
- Provisioning dynamic users **onto the Sentinels** (fragile persistence; see §7).
- Static roles / root rotation (future).

## 3. The load-bearing finding: ACL users are node-local

Established empirically (`test/sentinel/spike.sh`, passing on Valkey 8 and 9):

- A `SET` on the primary replicates to replicas (positive control). An `ACL SETUSER`
  on the primary **does not** appear on replicas.
- A replica resync does **not** carry ACL users either — ACLs are not in the RDB.
- Runtime ACL users are **lost on restart** unless persisted (`ACL SAVE` with an
  `aclfile`, or `CONFIG REWRITE`). `CONFIG REWRITE` does not imply `ACL SAVE`.

Therefore the only correct design is **per-node provisioning**: create/persist/delete
the user on *every* node, and re-resolve the topology on every operation (the primary
may have changed). This is why the plugin does not cache a connection to "the master".

## 4. Architecture

```
NewUser/UpdateUser/DeleteUser
        │
        ├─ discoverTopology(ctx)      # ask each Sentinel until one answers
        │     → {master, [replicas]}  # filter out down/disconnected replicas
        │
        └─ for each node in topology:
              ACL SETUSER / resetpass / DELUSER   (as the node admin identity)
              persist  (ACL SAVE | CONFIG REWRITE | none)
```

- **`dbplugin v5`**, served via `ServeMultiplex`. The error-sanitizer middleware
  redacts configured secrets from any error returned to Vault.
- **Topology discovery** (`sentinel.go`): `SENTINEL get-master-addr-by-name` +
  `SENTINEL replicas`, trying each Sentinel in turn; a single dead Sentinel is tolerated.
- **Per-node application** (`acl.go`, `topology.go`): short-lived `go-redis` client per
  node, ACL command, then persistence per `persistence_mode`.
- **No long-lived state**: `Close()` is a no-op; correctness under failover beats
  connection reuse.

## 5. Credential lifecycle

- **NewUser** — generate username (templated), validate `creation_statements`, discover
  topology, then on **every** node: `ACL SETUSER <u> reset on #<sha256> <rules>` +
  persist. `reset` makes the user deterministic; `#<sha256>` keeps the cleartext off the
  node's command log/SLOWLOG (clients still auth with the cleartext Vault issued).
  **Partial failure rolls back** the nodes already done.
- **UpdateUser** — password change. The dominant caller is **root rotation**
  (`vault rotate-root`), arriving as `UpdateUser` on the configured root user: the plugin
  rotates the admin password on every node **all-or-nothing** — if any node fails it
  restores the old password on the already-changed nodes (reconnecting with the new
  password) and updates its in-memory credential only on full success. A non-root change
  uses `ACL SETUSER <u> resetpass on #<sha256>` best-effort across nodes.
- **DeleteUser** — `ACL DELUSER <u>` on every node; idempotent (absent user is success),
  errors aggregated but all nodes attempted.
- **Initialize** — parse/validate config; declare supported credential type (password);
  warn if TLS is disabled; if `verify_connection`, ping the current master.

## 6. Roles and Streams

`creation_statements` is the ACL rule fragment the plugin appends after its
`ACL SETUSER <u> reset on <password>` prefix. The plugin **rejects** model-breaking
tokens (`nopass`, `off`, `reset`, `resetpass`) and direct password directives
(`>`/`<`/`#`/`!`), so a role cannot mint a passwordless / disabled / backdoored user, and
**warns** on over-broad grants (`+@all`, `~*`, `&*`). Prefer **categories** over
enumerated commands for version portability. Streams:

```
~app:* +@read +@write +@stream
```

`+@stream` covers `XADD`/`XREAD`/`XREADGROUP`/`XACK`/… across versions; an explicit
command list would break against an older or newer engine that lacks/renames a verb.

## 7. Sentinel discovery identity

The plugin authenticates to Sentinel with `sentinel_username`/`sentinel_password`,
**separate** from the node admin credentials. It does **not** create dynamic users on
the Sentinels: Sentinel ACL persistence is undocumented/fragile and no tooling supports
it. Operators should provision a **static, low-privilege discovery user** on the
Sentinels. On **Valkey 9.0+** that user additionally needs `+failover` and `+client`.

The node admin user (`username`/`password`) should also be a **dedicated** account —
*not* the identity Sentinel uses to authenticate to the nodes (`sentinel auth-pass`).
Otherwise `vault rotate-root` of the plugin admin would change the password Sentinel
relies on and break monitoring. Use e.g. a `vaultadmin` node user for the plugin and keep
Sentinel's node-auth user separate (the test fixture and `test/vault/e2e.sh` do this).

## 8. Failure handling

- **Partial create** → rollback (delete on succeeded nodes), surface both the original
  and any rollback errors.
- **Sentinel unreachable** → try the next; only fail if *all* are unreachable.
- **Down replica** → excluded from the node set (won't receive writes; it will be
  re-provisioned on a later operation once healthy, or simply never serves traffic).
- **Revoke after failover** → topology is re-resolved, so DELUSER targets the current
  primary and the live replicas.

Known edge to harden: a replica that is down at
create time and returns later will lack the user until the next operation touches it.
A reconciliation pass (re-assert active leases across the current node set) is the
planned mitigation.

## 9. Compatibility

- **Vault 1.14+** via `dbplugin v5` multiplexing (also OpenBao) — the floor is validated:
  the real-Vault e2e passes against **Vault 1.14.10** (registration, version reporting,
  full lifecycle, rotate-root), and is also exercised on 1.21.
- **Valkey 7.x → latest / Redis 7.x** — RESP + ACL selectors present throughout.
  Behavioural delta at Valkey 9.0 (auth-before-command-validation; Sentinel user perms).

## 10. Testing

- **Unit** — config parsing/validation, ACL rule rendering, username templating,
  Sentinel replica-flag filtering.
- **Spike** (`test/sentinel/spike.sh`) — live 1+2+3 podman topology proving node-locality,
  persistence, failover correctness, and node-local revoke. Runs on Valkey 8 and 9.
- **Integration** (build-tagged, SDK `dbplugin/v5/testing` harness) — drives the plugin
  against the live topology: node-local presence/absence, hashed-password-still-
  authenticates, ACL key-scoping, and a plugin-driven failover-mid-lease scenario.
- **Real-Vault e2e** (`test/vault/e2e.sh`) — a `vault server -dev` with the plugin
  registered, exercising config → role → `creds` → `lease revoke` end-to-end, plus a
  negative test that a `nopass` role is refused.
- **Matrix** (planned) — failover-during-lease, partial-node failure,
  revoke retry, restart persistence, version deltas, Vault version floor.

## 11. Security model

- **Hashed provisioning** — passwords go to nodes as `#<sha256hex>`, not cleartext, so
  they cannot leak via a node's SLOWLOG/MONITOR. Clients still authenticate with the
  cleartext Vault issues. (`password_hashing=false` reverts to `>cleartext` for debugging.)
- **creation_statements validation** — rejected: model-breaking tokens (`nopass`/`off`/
  `reset`/`resetpass`, plus `clearselectors`/`resetkeys`/`resetchannels`), password
  directives (`>`/`<`/`#`/`!`, including selector-glued forms like `(>x)`), and
  privilege-escalation grants that would let a dynamic credential outlive its lease
  (`+acl`/`+@admin`/`+@dangerous`/`+config`/`+module`/`+debug`/`+shutdown`/`+replicaof`/
  `+cluster`/`+failover`). Warn-logged: over-broad grants (`+@all`/`~*`/`&*`) — `@all`
  includes admin and can persist past the lease, so prefer scoped categories. A role thus
  cannot mint a passwordless, disabled, backdoored, or lease-escaping user.
- **Separate Sentinel identity** — discovery uses `sentinel_username`/`sentinel_password`,
  never the node admin creds; the plugin never provisions onto the Sentinels.
- **Secret redaction** — the error-sanitizer middleware scrubs the node password, sentinel
  password, and TLS key from any error returned to Vault. Operational logs carry
  usernames/roles/node counts — never secrets.
- **Transport** — TLS to nodes and Sentinels; the plugin warns when TLS is disabled
  (client `AUTH` is still cleartext) and when `insecure_tls` disables verification.
- **Reset-first create** — `ACL SETUSER <u> reset on …` yields a deterministic user even
  on a username collision (ACL SETUSER is otherwise additive).
