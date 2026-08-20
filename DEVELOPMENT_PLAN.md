# share_service — Development Plan

Status: **M0 not started.** This plan covers **M0 only** — the service skeleton,
the data model, the delegated core client, and link creation/listing/revocation.
It stops deliberately short of the public door: nothing in M0 is reachable
without a bearer token, and no recipient can redeem anything yet.

Companion: [`design_documents/OUTSIDE_SHARE_LINKS.md`](design_documents/OUTSIDE_SHARE_LINKS.md)
(the specification; section references below are to it). Later milestones are
listed in its §14.

## 1. What M0 delivers

An authenticated user with the right permissions can **mint, list, and revoke** a
share link, and every safety rule that governs redemption is implemented and
tested — even though nothing redeems yet. That ordering is the point: the rules
that make this feature safe (§6.3's authority re-check, admin-role stripping,
uid containment, fail-closed audit) are all exercised through the creation
pre-flight, which runs the *exact* check a redemption will run. If they are
wrong, M0 is where it shows, with no public surface open.

**Done means:** `POST /share/v1/nodes/{uid}/links` mints a link whose secret is
returned once; `GET`/`DELETE` list and revoke it; a link that would be born dead
is refused at creation with a reason; and the whole test list in §6 passes
against a live core, LDAP, Postgres and Redis.

**Not in M0:** the public prefix, OTP, sessions, redemption, zip, uploads, any
frontend. Recipients are *recorded* (the allowlist is part of the model) but
nothing mails them and nothing verifies them.

## 2. Position in the ecosystem

| Dependency | Role | Dev endpoint |
|---|---|---|
| FileEngine core (gRPC) | Permission checks + (later) bytes, **called as the link creator** | `:50051` |
| LDAP / OpenLDAP | Creator role resolution + the `share_external` group | `:1389` |
| PostgreSQL | Link records, recipients, redemption ledger (own per-tenant schema) | `:5434` (dev) |
| Redis | Audit stream (`audit_service` drains it) | `:6379` |

**Ports:** API `:8101`, monitoring `:8102` — the next free pair after
`difference_service` (`:8100`). Per platform convention the monitoring listener
binds **loopback-only**; `/healthz` `/readyz` `/poolz` `/metrics` are
unauthenticated and must not be reachable off-host.

Conventions inherited from `folder_actions` / `difference_service` — mirror them
rather than inventing: `pyproject.toml` src-layout, `FILEENGINE_*` shared config
names with `SHARE_*` private ones, `.env` in the working directory, `Config`
dataclass, `pytest` with `@live` gating, a `Containerfile`.

## 3. Reuse map — what is copied, what is imported, what is written

Most of M0 is assembly. Knowing which is which up front avoids the two failure
modes: rewriting something that exists, and copying something that should have
been imported.

| Piece | Source | How |
|---|---|---|
| `metrics.py` | `folder_actions/src/folder_actions/metrics.py` | **Copy verbatim.** It is byte-identical across `folder_actions`, `difference_service` and `discussion` (same md5) — keep it that way. |
| Audit publishing | `audit_service.publisher.AuditPublisher` | **Import**, with the sibling-checkout fallback `ldap_manager/audit.py` uses. Do not write a publisher. |
| gRPC core client | `python_interface` (`fileengine`) | **Import.** `ManagedFiles(server_address, user_name, user_roles, tenant, source_addr)` is the delegation primitive (§4.1). |
| `config.py`, `db.py`, `schema.py` | `folder_actions` equivalents | **Adapt.** `connect_for_tenant(config, tenant, provision=True)` is the tenancy pattern; keep the circuit-breaker/read-only failover behaviour. |
| Bearer verification | `folder_actions/jwt_verify.py` + `bridge_auth.py` | **Adapt.** Same shared `FILEENGINE_JWT_SECRET`, same HS256 tokens the bridge mints. |
| LDAP role resolution | `folder_actions/ldap_auth.py` | **Adapt — with one deliberate change, see §4.2.** |
| Everything else | — | New. |

## 4. The three things M0 must get exactly right

Everything else in this milestone is ordinary service work. These three are where
the design's safety actually lives, and all three lost their backstop when R13
moved the feature out of the core — there is no second enforcement point behind
any of them.

### 4.1 Delegation: calls run as the creator

Every core call on a share path is made as the **link creator**, never as a
service principal and never as a synthetic user:

```python
ManagedFiles(server_address=cfg.grpc_address,
             user_name=link.created_by,
             user_roles=creator_roles,        # live from LDAP, admin-stripped (§4.2)
             tenant=link.tenant,
             source_addr=<the outside caller's IP>)
```

Note this differs from `folder_actions`, which has both an end-user client *and*
an agent service principal. **`share_service` has no service principal at all**
and must not acquire one: an agent account would be an identity that outlives any
particular creator's access, which is precisely the lingering-grant problem §6.3
exists to prevent.

### 4.2 The reused LDAP resolver adds `system_admin` — it must not, here

`folder_actions/ldap_auth.py` resolves roles from `groupOfNames` membership and
then does this (`:121–122`):

```python
if "administrators" in roles and "system_admin" not in roles:
    roles.append("system_admin")
```

That is correct for an ordinary door and **catastrophic on this path**. The core
trusts the roles it is handed and `system_admin` bypasses every ACL check
(`acl_manager.cpp:214–220`), so a link minted by an administrator would redeem
against the bypass rather than against real ACLs — an unauthenticated URL with
admin reach, which is the single worst outcome this design can produce.

So the adapted resolver **strips** `system_admin`, `tenant_admin`, and
`administrators` rather than deriving them. Concretely:

- One function, `resolve_share_roles(username, tenant) -> list[str]`, is the
  *only* way roles reach a delegated call. It resolves over the service bind (no
  user credentials — the creator is absent at redemption) and filters the admin
  set on the way out.
- Nothing else in the service may construct an `Identity` for a delegated call.
  If a second path appears, that is the bug.
- LDAP unreachable ⇒ **deny**, never "proceed with no roles". Empty roles is a
  legitimate answer that silently strips access inside a gated section (§6.3),
  so it must be distinguishable from failure.

### 4.3 The target uid comes only from the link record

The core will now stream anything the creator may read, so nothing behind this
service constrains *which* uid gets asked for (§4.3 of the spec). The rule:

- Resolve `resource_uid` (and, later, `member_uid`) **exclusively from the stored
  link row**. Caller-supplied uids are not validated-then-used — they are never
  read at all.
- Structure it so this is unexpressible rather than merely checked: the request
  model for these routes has no uid field to populate.

## 5. Build order

Each step is independently reviewable and leaves the repo working.

1. **Skeleton.** `pyproject.toml` (src layout, `share-service = "share_service.app:main"`),
   `Config` (`FILEENGINE_*` + `SHARE_*`), FastAPI app, `metrics.py` verbatim,
   `/healthz` `/readyz` `/poolz` on the loopback monitoring listener at `:8102`.
   Readiness probes core gRPC, LDAP, Postgres and the audit stream.
2. **Persistence.** `schema.py` + `db.py`: per-tenant schema, the four tables from
   §5 (`share_links`, `share_link_members`, `share_redemptions`,
   `share_link_recipients`) with their indexes, `connect_for_tenant(..., provision=True)`.
   Tables only — no behaviour yet.
3. **Audit.** `audit.py` wrapping `AuditPublisher`, `source_iface = "share"`, plus
   the fail-closed helper §5.1 describes. Emit `share_link_create` /
   `share_link_revoke` (both fail-closed, §12) from the routes in step 6.
4. **Identity in.** Bearer verification (shared HS256 secret) → the caller's
   identity for owner-side routes.
5. **Identity out.** `resolve_share_roles` (§4.2) and the delegated
   `client_for_creator` (§4.1) — the two functions the rest of the milestone
   depends on, and the two that carry the §6 tests that matter most.
6. **Routes.** `POST /share/v1/nodes/{uid}/links`, `GET /share/v1/nodes/{uid}/links`,
   `GET /share/v1/links`, `GET /share/v1/links/{id}`, `DELETE /share/v1/links/{id}`,
   `GET /share/v1/links/{id}/recipients` (read + add + remove). Creation runs the
   §8.1 gate, then the pre-flight, then mints; the secret is returned **once**.
7. **Containerfile + `.env.example`**, mirroring `difference_service`.

### 5.1 Fail-closed audit needs an explicit decision, not the default

`AuditPublisher.publish()` returns `False` rather than raising when the XADD
fails — that is the fail-closed signal, and it is well-behaved. But the shared
emitter wrapper in `ldap_manager/audit.py` returns **`True` when auditing is
disabled**, so that a guarded operation "never blocks" on a service that is not
configured for auditing.

**`share_service` must not inherit that.** R13 makes the audit chain the only
place recording that an access was external (§4.3), so "auditing is off" and
"share links work" are not compatible states: the result would be external
downloads with no record anywhere that they were external, which is exactly the
hole the fail-closed rule exists to prevent.

So: if the audit publisher is unavailable or disabled, **`share.enabled` is
false** — the service refuses to mint links and (from M4) refuses to redeem them,
and says so on `/readyz`. Treat it as a hard dependency alongside Postgres, not
as an optional feature. This is a deviation from the platform's usual emitter
convenience and should carry a comment saying why, because it reads as an
inconsistency otherwise.

## 6. Tests

`@live` against a dev core + LDAP + Postgres + Redis, per the `pytest` marker
convention. The first four are the milestone; the rest are correctness.

**The invariants with no backstop** (§4 above — these are why M0 exists before
the public door):

1. **Admin roles never reach a delegated call.** Mint as a member of
   `administrators`; assert the roles handed to `ManagedFiles` contain none of
   `system_admin` / `tenant_admin` / `administrators`. Then the behavioural
   half: a file the admin can reach *only* via the bypass is **refused at
   creation** by the pre-flight, not minted and silently dead.
2. **The uid cannot be redirected.** Attempt every shape of caller-supplied uid
   against the link routes; assert the resolved uid always equals the stored
   `resource_uid`.
3. **`share_link_create` is fail-closed.** With the audit stream unreachable,
   creation fails and no row is written. With auditing *disabled*, `/readyz` is
   not ready and creation refuses (§5.1).
4. **LDAP unreachable denies**, and is distinguishable from "resolved, no roles".

**The authority model** (§6.3):

5. Creator loses READ after minting → the pre-flight re-run reports the link dead
   (the state the Share tab renders as *"not working: you no longer have access"*).
6. A link inside a `DENY everyone + ALLOW role` gated section pre-flights
   **successfully** with resolved roles, and **fails** when roles are withheld —
   the R5 regression, and the reason live LDAP resolution exists.
7. Creation requires **both** gates (§8.1): a `share_external` member without READ
   is refused; a reader outside the group is refused.

**The model** (§5):

8. Kind/type mismatch refused (file link on a directory and vice versa).
9. `expires_at` beyond `share.max_ttl_days` refused; `max_uses` beyond
   `share.max_uses_cap` refused.
10. At least one recipient required; more than `share.max_recipients` refused;
    addresses normalized (lowercased, trimmed) and de-duplicated.
11. Revocation is idempotent; a revoked link still lists (it is evidence) with a
    revoked status and `revoked_by`.
12. The secret is returned exactly once — re-reading the link never yields it,
    and only `sha256(secret)` is stored.
13. Several live links may exist on one node, of different kinds (§13-R8) — no
    uniqueness constraint.

**The milestone's own acceptance criterion:**

14. **`git diff` against `file_engine_core` is empty.** Check it mechanically in
    CI, not by intention. If M0 wants a core change, that is the signal to
    re-open §4 deliberately (§14 of the spec).

## 7. Risks and open items

- **N `CheckPermission` calls at session open** is an M1 concern (§7.3), but the
  delegated client written here is what will make or break it — build it so a
  bounded concurrent pool can be dropped in, rather than assuming one call per
  request.
- **`python_interface` coverage.** M0 needs `CheckPermission` and `Stat` through
  `ManagedFiles`; M1/M4 need `StreamFileDownload` / `StreamFileUpload` /
  `SetMetadata`. Confirm all five are exposed with an identity binding before
  committing to the client shape — a gap here is cheapest to find now.
- **Recipient rows are PII in a tenant schema** (§5.4) from the first migration,
  even though nothing mails them until M3. The retention sweep is M9, so M0
  should at minimum not log addresses.
- **The `share_external` group must exist** in the dev LDAP fixture before the
  §6 tests can pass. Add it alongside the existing test users rather than
  creating it by hand on the dev box.
