# share_service

> **M0 complete** (2026-08-20) — an authenticated user can mint, list and revoke
> links, and every rule that will govern redemption is implemented and tested.
> No public door yet: nothing here is reachable without a bearer token. See
> [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) for what M0 covered and
> [`design_documents/OUTSIDE_SHARE_LINKS.md`](design_documents/OUTSIDE_SHARE_LINKS.md)
> for the specification.

FastAPI microservice for **outside share links** — time- and count-limited URLs
that let someone with no FileEngine account download a file, download a folder as
a zip, or drop files into a folder. Every redemption is gated on a one-time code
sent to an address the creator named at creation, so the link alone is inert.

Three share shapes, all minted on a node the user is already looking at:

| Shape | Recipient gets |
|---|---|
| A file | that file, at the version pinned when the link was made |
| A folder's contents | one zip of the folder's own files |
| A folder and its subfolders | one zip mirroring the subtree |

…plus a **drop box** on a folder, for receiving files rather than sending them.

## Why this is a service and not part of the core

`file_engine_core` does not change — no tables, no RPCs, no permission bit, and
no idea that share links exist. This service owns the records and every
share-specific decision, and reaches the core only through RPCs that already
exist.

The mechanism is **delegation**: a redemption calls the core as the *link's
creator* — a real principal, with roles resolved live from LDAP, evaluated
against real ACLs — never as a synthetic `share:*` user. So a link can never
convey more than its creator holds at the moment it is redeemed, and revoking
someone's access retroactively kills every link they minted. The core needs no
special path for any of this, because there is nothing special about the calls it
receives.

The consequence to understand before working here: because the core sees the
creator, **`audit_service` is the only place recording that an access was
external**. That is why redemption events are fail-closed and why every delegated
call carries a correlation id. §4.3 of the specification is the section to read
first.

## Where things live

| Concern | Owner |
|---|---|
| Link records, budgets, recipients, redemption ledger | **here** (own per-tenant Postgres schema) |
| ACL evaluation, bytes | `file_engine_core`, asked as the creator |
| Recipient one-time codes: delivery, verification, rate limits | `ldap_manager` |
| That a redemption was external — authoritatively | `audit_service` |
| Share tab, recipient landing page, dashboard items | `frontend` |
| Creator notifications (attention feed) | `discussion_threaded_communication` |

Structurally a sibling of `folder_actions` / `difference_service`: reused
`fileengine` gRPC client, LDAP→bearer auth, `FILEENGINE_*` shared config with
`SHARE_*` private knobs.

## Running it

```bash
pip install ../python_interface ../audit_service .   # sibling packages
cp .env.example .env                                 # fill in the shared secrets
share-service                                        # API :8101, monitoring :8102
PYTHONPATH=src pytest src/tests                      # add -m live for integration
./tools/check-core-untouched.sh                      # M0's acceptance criterion
```

`FILEENGINE_AUDIT_ENABLED=false` does not quietly disable the recording — it
disables the feature. Without a reachable audit stream nothing external would be
recorded as external, so `/readyz` stays red and the routes refuse.

## Status

The specification is complete and has no open design questions — §13 records
decisions R1–R13, including the ones that reversed earlier positions. §14 lists
the milestones. **M0 is done**; M1 (folder snapshots) is next, and M4 is where
an unauthenticated door first exists and earns its own security review.
