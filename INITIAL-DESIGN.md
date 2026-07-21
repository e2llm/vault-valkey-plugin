# Design: Vault Dynamic Credentials for Valkey behind Sentinel

Technical design for the `valkey-database-plugin` (Vault/OpenBao `dbplugin v5`).
For the market survey and strategic rationale see `docs/landscape.md` and `docs/plan.md`.

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
- Provisioning dynamic users onto the Sentinels *by default* — separate identities are
  the default. The opt-in shared-identity mode (§7.1) does provision onto the Sentinels.
- Static roles (future). Root rotation is implemented (§5).

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
- **UpdateUser** — password change, two callers. **Root rotation** (`vault rotate-root`) on
  the configured root user: rotate the admin password on every node **all-or-nothing** — if
  any node fails, restore the old password on the already-changed nodes (reconnecting with
  the new password), updating the in-memory credential only on full success. **Static-role
  rotation** (a non-root, Vault-managed *shared* user): apply `ACL SETUSER <u> resetpass on
  #<sha256>` across every node, then run the reconcile pass so a replica that missed a
  rotation re-converges. The static user must pre-exist with its ACL rules on all nodes
  (Vault rotates, it does not create); name it with `managed_username_prefix` so reconcile
  covers it. A node down during a rotation re-converges on the next rotation.
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
**separate** from the node admin credentials. By default
(`sentinel_identity_mode=separate`) it does **not** create dynamic users on the Sentinels;
operators provision a **static, low-privilege discovery user** there. The opt-in
shared-identity mode (§7.1) changes this for legacy single-credential apps. On **Valkey
9.0+** the discovery user additionally needs `+failover` and `+client`.

The node admin user (`username`/`password`) should also be a **dedicated** account —
*not* the identity Sentinel uses to authenticate to the nodes (`sentinel auth-pass`).
Otherwise `vault rotate-root` of the plugin admin would change the password Sentinel
relies on and break monitoring. Use e.g. a `vaultadmin` node user for the plugin and keep
Sentinel's node-auth user separate (the test fixture and `test/vault/e2e.sh` do this).

### 7.1 Shared identity (opt-in)

Some legacy apps authenticate to **both** the data nodes and the Sentinels with a single
credential and cannot be given two. For them, `sentinel_identity_mode=shared` provisions
the dynamic user onto the Sentinels too, with a **narrow discovery ACL**
(`+@connection +sentinel|get-master-addr-by-name +sentinel|replicas +sentinel|sentinels`,
overridable via `sentinel_creation_statements`): it resolves the master but is denied
`SENTINEL failover`/`monitor`/`remove`/`set`. In this mode `sentinel_username`/`password`
must be a **Sentinel admin** (it now runs `ACL SETUSER`/`DELUSER` on the Sentinels).

Empirically (`test/sentinel/spike.sh` INV-6..8): a Sentinel accepts a runtime ACL user but
has **no `CONFIG REWRITE`**, so the user is ephemeral unless the operator configures an
**aclfile** on the Sentinels (then `ACL SAVE` persists it). Hence `sentinel_persistence_mode`
is `none` (default, ephemeral) or `aclfile`; `rewrite` is rejected. Provisioning is
best-effort with a **quorum of one** (so an issued credential is always usable for
discovery); revocation is **best-effort** on the Sentinels (a lingering discovery user
cannot reach data — the data nodes already revoked it — and ephemeral Sentinels self-clean
on restart). On **Valkey 9.0+** the discovery ACL may need `+client`; widen it via
`sentinel_creation_statements` (untested here — the validated engines are redis 7 / valkey 8).
Separate identities remain the default and the more secure model.

## 8. Failure handling

- **Partial create** → rollback (delete on succeeded nodes), surface both the original
  and any rollback errors.
- **Sentinel unreachable** → try the next; only fail if *all* are unreachable.
- **Down replica** → excluded from the node set (won't receive writes); the reconcile pass
  (§8.1) re-provisions it from the master on a later issuance once it is healthy again.
- **Revoke after failover** → topology is re-resolved, so DELUSER targets the current
  primary and the live replicas.

### 8.1 Reconcile pass

Node-locality leaves two drifts the per-operation logic cannot see on its own: a replica
**down at create-time** never got the user, and a node **down at revoke-time** keeps a stale
one. The reconcile pass heals both. On each `NewUser` (when replicas are present, unless
`reconcile=false`) the plugin converges every data node to the **master** — authoritative by
construction, since every create writes it first and every op re-resolves to it:

- a managed user on the master but **missing** from a node is cloned from the master's
  `ACL LIST` line via `ACL SETUSER <u> reset <rules>` — the line already carries `#<hash>`,
  so no cleartext leaves the master and no Vault lease lookup is needed;
- a managed user on a node but **absent** from the master is deleted as an orphan.

Managed users are identified by `managed_username_prefix` (default `v_`, the template
prefix); the node admin and `default` are never touched. It is best-effort and non-fatal
(the issued credential is already provisioned) and cheap when clean — one `ACL LIST` on the
master plus one `ACL USERS` per node, writing only actual drift. Because the master is the
source of truth, this needs **no external lease-aware reconciler** and survives a plugin
restart. Sentinel-side reconcile (shared mode) is not yet included — Sentinels are stable
and their users self-clean when ephemeral.

## 9. Compatibility

- **Vault 1.14+** via `dbplugin v5` multiplexing (also OpenBao) — the floor is validated:
  the real-Vault e2e passes against **Vault 1.14.10** (registration, version reporting,
  full lifecycle, rotate-root), and is also exercised on 1.21.
- **Valkey 7.x → latest / Redis 7.x** — RESP + ACL selectors present throughout.
  Behavioural delta at Valkey 9.0 (auth-before-command-validation; Sentinel user perms).

## 10. Testing

- **Unit** — config parsing/validation, ACL rule rendering, username templating,
  Sentinel replica-flag filtering.
- **Spike** (`test/sentinel/spike.sh`) — live 1+2+3 podman topology. INV-1..5 prove
  node-locality, persistence, failover correctness, and node-local revoke. INV-6..8 prove
  the shared-identity Sentinel facts: a hashed runtime discovery user resolves the master
  but is denied failover; a Sentinel has no `CONFIG REWRITE`; an aclfile-configured
  Sentinel persists the user across restart. Runs on Valkey 8 and 9; the same Sentinel-ACL
  behavior was independently confirmed on redis 7.4 (the target engine).
- **Integration** (build-tagged, SDK `dbplugin/v5/testing` harness) — drives the plugin
  against the live topology: node-local presence/absence, hashed-password-still-
  authenticates, ACL key-scoping, and a plugin-driven failover-mid-lease scenario.
- **Real-Vault e2e** (`test/vault/e2e.sh`) — a `vault server -dev` with the plugin
  registered, exercising config → role → `creds` → `lease revoke` end-to-end, a negative
  test that a `nopass` role is refused, and a **shared-identity** scenario: one issued
  credential present on the data nodes *and* the Sentinels, discovering the master via a
  Sentinel and denied failover, then revoked from both planes.
- **Matrix** (planned, `docs/plan.md`) — failover-during-lease, partial-node failure,
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
- **Separate Sentinel identity (default)** — discovery uses `sentinel_username`/
  `sentinel_password`, never the node admin creds; by default the plugin does not
  provision onto the Sentinels.
- **Shared-identity blast radius (opt-in)** — `sentinel_identity_mode=shared` puts the app
  credential on the Sentinel control plane, but the narrow discovery ACL denies
  failover/monitor/admin, so a leaked credential can only enumerate topology, not drive
  it. Wider than separate mode but bounded; opt-in and warned at init.
- **Secret redaction** — the error-sanitizer middleware scrubs the node password, sentinel
  password, and TLS key from any error returned to Vault. Operational logs carry
  usernames/roles/node counts — never secrets.
- **Connection config is secret-bearing on read** — `vault read database/config/<name>`
  returns plugin-specific secrets (`sentinel_password`, `tls_key`/`tls_cert`) in cleartext;
  Vault masks only the built-in `password`. The plugin cannot mask them (Vault persists and
  returns the connection config), so restrict `read` on `database/config/*` to operators.
- **Transport** — TLS to nodes and Sentinels; the plugin warns when TLS is disabled
  (client `AUTH` is still cleartext) and when `insecure_tls` disables verification.
- **Reset-first create** — `ACL SETUSER <u> reset on …` yields a deterministic user even
  on a username collision (ACL SETUSER is otherwise additive).
