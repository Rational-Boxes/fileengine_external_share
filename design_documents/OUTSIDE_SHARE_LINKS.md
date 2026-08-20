# Outside share links — verified-recipient download & drop links

> **Terminology.** The *door* is unauthenticated — no account, no session, no
> bearer token. The *person* is not anonymous: every redemption is gated on a
> one-time code sent to an address the creator named at creation (§6.9). Where
> this document says "unauthenticated" it means the route; it never means
> "unidentified".

**Status:** Design proposal — for review
**Scope (cross-repo):** **`share_service`** (new — owner of the record, the
public door, and every share-specific decision), `ldap_manager` (recipient OTP:
delivery, verification, rate limits), `frontend` (drawer tab + public landing
view + dashboard items + help), `audit_service` (new action codes; **the
authoritative record that a redemption was external**),
`discussion_threaded_communication` (owner of the Dashboard attention feed the
creator's share notifications land in — §10.6), `docker_unified` (new service +
nginx routing + rate-limit zone). No change to `webdav_bridge`, and — the
governing constraint of this design — **no change to `file_engine_core`**
(§4).

> Expanded from the original one-paragraph sketch (kept verbatim as §1). Every
> decision is grounded in current code; what has been settled is collected in
> **§13**, where **R7–R11 (2026-08-19) closed the last open questions** — the URL
> form, the three share shapes, folder size reporting, creator notifications, and
> the brute-force posture of the OTP gate. **No questions remain open.**

---

## 1. The original sketch

> Support to generate a URL to a file for download, with a limited number of
> downloads, and a specific timeframe. For folders an upload link that allows a
> max number of files to drop, and also a validity period. This allows
> unauthenticated external users to receive the 'magic' link to download/upload
> with no additional visibility or access.
>
> These features will be integrated as new sharing tabs on the file/folder drawer.

Everything below is the mechanism for that, plus the parts the sketch leaves
implicit: where the state lives, what a link is allowed to do when the creator's
own access has changed since, and how an unauthenticated door onto the tenant
origin avoids becoming the weakest thing in the deployment.

---

## 2. Goals & non-goals

**Goals**

1. **Download link** on a *file*: an opaque URL an outside recipient — someone
   with no account here — can fetch the bytes from, bounded by *N* uses **and** a
   validity window.
2. **Folder-download link**: the same, for a *folder*, served as a single
   streamed zip of a **snapshot** of its members taken at creation (§6.5).
3. **Upload link** ("drop box") on a *folder*: an opaque URL an outside sender
   can drop files into, bounded by a file count, a byte budget, and a validity
   window.
4. **No additional visibility.** A redeemed link exposes exactly the resource
   set it was minted for — never a sibling, never a parent, never the tenant's
   user directory, never the fact that other links exist. (A folder-download
   link's *members* are exposed by construction: they are the payload.)
5. **Delegation, not escalation.** A link can never convey more than its creator
   held at redemption time (§6.3) — this is the property that makes the feature
   safe to hand to ordinary users rather than admins only.
6. **Verified recipients.** Using a link requires proving control of an email
   address the creator listed at creation — enter the address, receive a
   one-time code, then proceed (§6.9). The URL alone is inert.
7. **Fully accountable.** Creation, revocation, every redemption, and every
   denied attempt are audited; the roadmap already names *share link* as a
   first-class audit object and "every object a departed employee could still
   reach via lingering share links" as a required reverse query
   (`FILEENGINE_ROADMAP.md` §1.5).

**Non-goals (v1)**

- Not a replacement for real sharing. Sharing *with a FileEngine user* stays the
  ACL path (`frontend/src/help/content/sharing.md`); this is for people who will
  never have an account.
- No "sign in to view" upgrade path, and no account is ever created for a
  recipient. Recipients *are* identified — by a verified email address, not by a
  directory entry (§6.9).
- Not a way to publish. Every link is addressed to a closed set of people named
  at creation; there is no "anyone with the link" mode (§6.9, §13-R4).
- No public *browsing*. A folder-download link yields one archive, not a
  navigable listing; an upload link never reveals what is already in the folder
  (§6.6).
- Not exposed to the MCP door (§11) — an LLM agent minting outside share links
  is not a default anyone should get by accident.

**Threat model.** The link URL is assumed to leak: forwarded email, a chat
scrollback, a proxy log, a screenshot. Every control is designed around *the
token is public knowledge eventually* — hence the use cap, the window, the
pinned version, the single-resource scope, immediate revocation, and above all
the recipient OTP (§6.9), which makes a leaked URL inert in the hands of anyone
the creator did not name. The adversary is also assumed to try enumerating link
ids, guessing codes, and probing the recipient list from many IPs (§8.4).

---

## 3. Decisions (locked unless §13 reopens them)

| Topic | Decision |
|---|---|
| Where the record lives | **`share_service`** — a new feature service with its own per-tenant schema. **The core does not change at all**: no tables, no RPCs, no permission bit (§4, §13-R13). |
| How a redemption reaches the bytes | **Delegated as the creator.** The service calls the core's existing `CheckPermission` / `StreamFileDownload` / `StreamFileUpload` with `AuthenticationContext{user: created_by}`. No synthetic principal exists anywhere (§4.1). |
| Who knows it was external | **`audit_service`, authoritatively** — the core attributes the activity to the creator and cannot be asked otherwise, so the audit log is the sole custodian and `share_link_redeem` is fail-closed (§4.3, §12). |
| Token shape | `{link_uid}.{secret}` — 128-bit uid + 256-bit CSPRNG secret, base64url. The DB stores **only** `sha256(secret)`; the plaintext is shown once at creation. |
| Authority | The link carries the **creator's** authority, re-evaluated on **every** redemption via `CheckPermission`, with their roles resolved **live from LDAP** and admin roles stripped. Creator loses READ/WRITE → the link is dead (§6.3). |
| Creation gate | Membership of the **`share_external` LDAP group** (per-user, never granted by default) **and** `CheckPermission` for READ (download) or WRITE (upload) on the target. No new ACL bit — the core's permission model is untouched (§8.1, §13-R13). |
| Use accounting | A **redemption session** consumes one use, not an HTTP request — so Range requests, resumes, and retries do not burn the budget (§6.4). |
| Version served | A file download link is **pinned** to the version current at creation. `follow_latest` is an explicit opt-in (§6.2). |
| Folder downloads | **In v1.** A folder link serves a **member snapshot** taken at creation, as a **store-only zip64** streamed by `share_service` with a precomputed `Content-Length` (§6.5). Every member's authority is re-checked at redemption. |
| Passphrase | **None.** The OTP is the second factor; a passphrase would be a third secret to distribute for no additional property (§13-R1). |
| Upload versioning | An upload link **never** creates a new version of an existing file. Name collisions get a de-duplicating suffix (§6.7). |
| Upload ownership | Dropped files are **owned by the link creator**; the outside origin — including the verified sender address — is recorded in metadata and audit (§6.8). |
| Recipient verification | **Mandatory.** Email + one-time code before any session opens, for downloads and drops alike. Recipients are an **allowlist fixed at creation**; there is no open-email mode (§6.9). |
| Share shapes | **Three, all minted on a node the user is already looking at**: a file; a folder's contents; a folder and its subfolders (both folder shapes as one zip). No cross-folder file picker in v1 — `include_subdirs` is the only control that separates the last two (§13-R8). A node may carry several live links at once. |
| Delivering the URL | **The creator composes their own email.** v1 sends no invite mail; the system's only outbound mail is the recipient's OTP (§6.9, §13-R9). |
| Token in the URL | **Path form** — `/s/{uid}.{secret}`. The OTP is what makes a leaked URL inert, so the fragment form buys little and costs `curl`/QR (§13-R7). |
| Creator notifications | **The Dashboard attention feed**, not email — share events join the existing "Needs your attention" list (§10.6, §13-R10). |
| Failure disclosure | Unknown / expired / revoked / exhausted / unlisted-address / wrong-code all return the **same** generic response to the outside caller. The real reason goes to audit only (§8.5). |
| Routes | Served by `share_service`, not the bridge: public `/share/v1/public/*` (unauthenticated) and owner-side `/share/v1/*` (bearer), both behind nginx on the tenant origin (§7). |
| Frontend | A **Share** tab in `FileDetailsDrawer.vue`, plus a `requiresAuth: false` route `/s/:token` for the recipient (§10). |

---

## 4. Why this is a service, and why the core does not change

**The core does not learn what a share link is.** No tables, no RPCs, no
permission bit, no vocabulary. A new `share_service` owns the record and every
share-specific decision, and reaches the core only through RPCs that already
exist — `CheckPermission`, `StreamFileDownload`, `StreamFileUpload`,
`SetMetadata` — exactly as `convert_search_ai`, `discussion`, `folder_actions`
and `difference` already do (`CLAUDE.md`: feature services *"re-check every
access as the end-user via the core's `CheckPermission`"*).

### 4.1 The delegation model: the creator's identity, not a synthetic one

A redemption calls the core as **`created_by`** — a real principal, with real
roles resolved live from LDAP, evaluated against real ACLs. There is no
`share:abc` pseudo-user anywhere in the system.

This matters more than it first appears. `AclManager` ships with
`default_read_ = true` (`core/include/fileengine/acl_manager.h:277`): a principal
with no matching rule reads everything whose parent chain is readable. A
*synthetic* share principal would therefore have been a tenant-wide reader, kept
scoped to one file only by whoever remembered to pass the right uid. Delegating
the creator's own identity removes that failure mode at the root — the redemption
can never exceed what the creator holds, because it *is* the creator, and §6.3's
re-check is then an ordinary `CheckPermission` call rather than a special path.

The property the feature is sold on — *delegation, not escalation* (§2) — is
therefore preserved intact, and preserved by construction rather than by the core
policing a credential type it would have had to learn.

### 4.2 What moves out of the core, and where it lands

| Concern | Owner | How |
|---|---|---|
| Link records, budgets, recipients, redemption ledger | `share_service` | its own per-tenant Postgres schema (§5) |
| "May this user mint a link?" | `share_service` | LDAP group + `CheckPermission` (§6.1, §8.1) |
| "Does the creator still have access?" | **the core**, asked by the service | `CheckPermission(created_by, uid, READ)` per redemption (§6.3) |
| Bytes | **the core**, asked as the creator | `StreamFileDownload` / `StreamFileUpload` |
| Recipient OTP | `ldap_manager` | existing 2FA seam (§6.9) |
| *That a redemption was external* | `audit_service` | **the authoritative record** (§4.3) |

The three things §4 previously argued only the core could do turn out not to need
it: a durable atomic use counter is a Postgres statement in *any* service's
schema (§5.3); instant revocation is a row update in the same place; and the
forensic queries — "which links still reach this file", "what did this departed
user leave open" — are table queries wherever the table lives. Only the ACL
evaluation genuinely required the core, and that is available over an RPC built
for precisely this.

### 4.3 Auditability is preserved in full — it just lives in the event chain

The delegation is **"an external party, authorized by a named system user"**, and
that is exactly the shape the audit record already takes (§6.8): one event
carrying `actor = "share:<link_uid>|<verified_email>"` — the door and the
verified human who walked through it — with `created_by` in `detail`, the person
accountable for opening it. Both identities, in one hash-chained record, on the
same event stream that already holds the file's complete activity history. The
reverse queries the roadmap asks for ("everything that touched this file",
"every object a departed employee could still reach") are answered there, over
share traffic and ordinary traffic alike.

So nothing is lost from the audit trail. What changes is **which system you ask**.
Because redemptions are delegated as the creator, the *core's* own events
attribute the activity to the creator: querying the core directly for "who read
this file" shows *Alice, 400 times*, and the core cannot be asked to say
otherwise. The externality lives one layer up, in the security event chain, which
is where a security team looks anyway and which is tamper-evident in a way core
table queries are not.

That is a sound arrangement. It carries three requirements, and none is optional
— because the audit chain is now the *sole* custodian of the distinction, where a
core-owned design would have kept a second copy inside the core:

1. **`share_link_redeem` becomes fail-closed** (§12). Under a core-owned design a
   lost audit event still left a `share_redemptions` row inside the core as a
   second copy. Here there is no second copy anywhere the security model trusts:
   an unrecorded redemption is external access that is **permanently
   unattributable**. If the event cannot be written, the redemption does not
   happen.
2. **Every delegated core call carries a correlation id.** `AuditEntry` already
   has a `request_id` field, plumbed all the way into the audit tables
   (`core/src/audit_entry.cpp:104`, `database.cpp:138,2316`) and **populated by
   nothing today**. The service stamps the `redemption_uid` there — on its own
   event and, via `AuthenticationContext.claims` (`proto/fileservice.proto:76`),
   on the delegated call — so the core's "Alice read X" and the service's
   "bob@contractor.example redeemed link Y" join on one key. This fills an
   existing unused column; it is not a core change.
3. **Scope containment is now the service's job.** Previously the core would have
   known a share credential was confined to one uid. Now the service holds the
   creator's full authority and asks for a uid, so *a bug that asks for the wrong
   uid is not contained by anything*. The service must resolve the target uid
   **only** from the link record, never from caller input (§6.6), and that rule
   carries a test of its own (§14).

In short: the core stays clean, the delegation model is sound, and the full
history of who touched a file — insider and outsider alike — remains answerable
from the security event chain. The one thing to hold onto is that the chain is
now the *only* place the distinction exists, which is what makes point 1
non-negotiable: an event that fails to write is not a gap in a report, it is an
external access that can never be attributed to anyone.

---

## 5. Data model (`share_service`, per-tenant schema)

**In `share_service`'s own schema, not the core's.** Tenancy follows the pattern
the other Python feature services already use — one schema per tenant, created on
first use (`discussion`'s `connect_for_tenant(..., provision=True)` is the
reference) — so a new tenant costs nothing and no core migration is ever
involved. The DDL below is written in the same `CREATE TABLE IF NOT EXISTS` +
additive-migration style the platform uses everywhere.

Nothing here is reachable from the core, and nothing in the core references it.
The only identifiers that cross the boundary are `resource_uid` / `member_uid`
(core file UIDs, opaque here) and `created_by` (an LDAP username).

### 5.1 `share_links`

```sql
CREATE TABLE IF NOT EXISTS "<tenant>".share_links (
    link_uid        UUID PRIMARY KEY,
    kind            SMALLINT     NOT NULL,   -- 0 = file download, 1 = upload,
                                             -- 2 = folder download (zip)
    resource_uid    UUID         NOT NULL,   -- file (0) or directory (1, 2)
    secret_hash     BYTEA        NOT NULL,   -- sha256(secret); never the secret
    created_by      TEXT         NOT NULL,   -- the delegating principal
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ  NOT NULL,   -- hard requirement; no perpetual links
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT,
    -- budgets (0 = unlimited, subject to the deployment cap in §9)
    -- A "use" is a REDEMPTION SESSION for every kind, without exception (§6.4).
    max_uses        INTEGER      NOT NULL DEFAULT 0,
    uses_consumed   INTEGER      NOT NULL DEFAULT 0,
    max_uses_per_recipient INTEGER NOT NULL DEFAULT 0,  -- 0 = only the shared pool
    max_bytes       BIGINT       NOT NULL DEFAULT 0,
    bytes_consumed  BIGINT       NOT NULL DEFAULT 0,
    max_file_bytes  BIGINT       NOT NULL DEFAULT 0,   -- upload: per-file cap
    -- upload: how many FILES may be dropped in total, across all sessions.
    -- Separate from max_uses because a session is not a file: one sender opens
    -- one session and drops six things (§6.7).
    max_files       INTEGER      NOT NULL DEFAULT 0,
    files_consumed  INTEGER      NOT NULL DEFAULT 0,
    -- file-download options
    pinned_version  TEXT,                    -- version name; NULL = follow latest
    -- folder-download options
    follow_folder   BOOLEAN      NOT NULL DEFAULT false,  -- true = live folder, no snapshot
    include_subdirs BOOLEAN      NOT NULL DEFAULT true,   -- false = the folder's own
                                             -- files only. This flag IS the difference
                                             -- between two of R8's three share shapes,
                                             -- not a refinement of one (§13-R8).
    archive_bytes   BIGINT,                  -- precomputed zip size at creation (§6.5)
    -- upload options
    landing_prefix  TEXT,                    -- optional subfolder name, created lazily
    ext_allowlist   TEXT[],                  -- NULL = any
    -- abuse (§8.4): a ROLLING count, not a lifetime total — counts older than
    -- share.lockout_window_minutes are discarded and a verified redemption
    -- clears them, or ordinary typos accumulate into a permanent lockout.
    failed_attempts    INTEGER   NOT NULL DEFAULT 0,
    failed_window_start TIMESTAMPTZ,
    locked_until    TIMESTAMPTZ,
    note            TEXT                     -- creator's own label, shown in the UI
);
CREATE INDEX IF NOT EXISTS share_links_resource ON "<tenant>".share_links (resource_uid);
CREATE INDEX IF NOT EXISTS share_links_creator  ON "<tenant>".share_links (created_by);
CREATE INDEX IF NOT EXISTS share_links_live     ON "<tenant>".share_links (expires_at)
    WHERE revoked_at IS NULL;
```

### 5.2 `share_link_members` (folder-download snapshot)

Written once at creation for `kind = 2` when `follow_folder = false` (the
default). It is the authoritative member set: a redemption serves *this* list,
never a fresh directory walk, so files added to the folder after the link was
minted are never included.

```sql
CREATE TABLE IF NOT EXISTS "<tenant>".share_link_members (
    link_uid     UUID   NOT NULL REFERENCES "<tenant>".share_links(link_uid) ON DELETE CASCADE,
    member_uid   UUID   NOT NULL,
    archive_path TEXT   NOT NULL,   -- path inside the zip, relative to the folder
    version_name TEXT   NOT NULL,   -- pinned, same reasoning as §6.2
    size_bytes   BIGINT NOT NULL,
    PRIMARY KEY (link_uid, member_uid)
);
```

`archive_path` is normalized and validated at creation — no `..`, no absolute
paths, no leading `/` — so a hostile file name cannot produce a zip-slip archive
on the recipient's machine.

**There is deliberately no `crc32` column.** Filling one would mean reading every
member's bytes at creation, and the core stores no digest to copy from; the CRC
is instead computed as the bytes stream and written into a per-entry data
descriptor (§6.5). `archive_path` and `size_bytes` are all the archive-length
arithmetic needs.

### 5.3 `share_redemptions`

One row per consumed use — simultaneously the counter's ledger and the forensic
record the roadmap's reverse queries read.

```sql
CREATE TABLE IF NOT EXISTS "<tenant>".share_redemptions (
    redemption_uid UUID PRIMARY KEY,
    link_uid       UUID        NOT NULL REFERENCES "<tenant>".share_links(link_uid),
    opened_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,   -- session TTL (§6.4), default 1 h
    verified_email TEXT        NOT NULL,   -- the recipient who passed the OTP (§6.9);
                                           -- NOT NULL is the schema-level statement
                                           -- that no session opens unverified
    source_addr    TEXT,
    user_agent     TEXT,
    bytes_moved    BIGINT      NOT NULL DEFAULT 0,
    result_uid     UUID,                   -- upload: the file the drop created
    -- folder download: the member set frozen at session open, and the exact
    -- archive length derived from it (§7.3). Members the creator could no
    -- longer read are already excluded here.
    frozen_members UUID[],
    archive_bytes  BIGINT,
    completed_at   TIMESTAMPTZ
);
```

**The atomic consume** — one statement, one row lock, no serializable retries.

There are **two** counters to move together: the link's shared pool
(`share_links.uses_consumed`) and, when `max_uses_per_recipient` is set, that
recipient's own tally (`share_link_recipients.uses_consumed`, §5.4). An earlier
draft of this section incremented only the first and claimed "one statement, no
races" — which was true of the pool and false of the pair: two separate
statements let concurrent sessions from one recipient each pass a per-recipient
check that neither had yet invalidated, overrunning a personal cap while the
shared pool stayed perfectly correct.

Both move in one statement, gated on the link row being locked first:

```sql
WITH lim AS (
    SELECT max_uses, uses_consumed, max_uses_per_recipient
      FROM "<tenant>".share_links
     WHERE link_uid = $1
       AND revoked_at IS NULL
       AND expires_at > now()
       AND (locked_until IS NULL OR locked_until < now())
       FOR UPDATE                      -- serializes concurrent redemptions of THIS link
), rcpt AS (
    UPDATE "<tenant>".share_link_recipients r
       SET uses_consumed = r.uses_consumed + 1, last_used_at = now()
      FROM lim
     WHERE r.link_uid = $1 AND r.email = $2 AND r.removed_at IS NULL
       AND (lim.max_uses = 0 OR lim.uses_consumed < lim.max_uses)
       AND (lim.max_uses_per_recipient = 0
            OR r.uses_consumed < lim.max_uses_per_recipient)
    RETURNING r.email
), pool AS (
    UPDATE "<tenant>".share_links
       SET uses_consumed = uses_consumed + 1
     WHERE link_uid = $1 AND EXISTS (SELECT 1 FROM rcpt)
    RETURNING kind, resource_uid, created_by, pinned_version, max_bytes, bytes_consumed
)
SELECT * FROM pool;
```

The ordering is the point: the **recipient** update is the gate and the pool
update is conditional on it, so a recipient at their personal cap consumes
nothing from the shared pool. Reversing them — the obvious shape — increments the
pool in the same snapshot and then discovers the recipient was ineligible, having
already burnt a use that no rollback inside a single statement will return.

`FOR UPDATE` narrows concurrency to one in-flight session *per link*, which is
not a hot path: redemptions of a single link are a handful of people over days.
The lock is what a second counter costs, and it is cheaper than the transaction
retry loop the lock-free version would need.

Zero rows returned ⇒ generic 404 (§8.5). The secret and the recipient's OTP are
verified *before* this statement, so nothing an unverified caller does can burn a
use.

**Uploads consume a file slot separately**, by the same shape and for the same
reason (§6.7): `UPDATE … SET files_consumed = files_consumed + 1 WHERE link_uid = $1
AND (max_files = 0 OR files_consumed < max_files) RETURNING files_consumed` runs
per dropped file, before any bytes are stored, and is **released on failure** so
an aborted upload does not spend the sender's budget. One counter here, so no
lock is needed.

### 5.4 `share_link_recipients`

The closed destination set (§6.9). Written at creation and editable afterwards
**only by an authenticated user with rights on the link** (§10.2) — an outside
caller can never add an address, and a redemption never mutates the list.
Removal is a soft delete (`removed_at`) so a partial revoke keeps its history.

```sql
CREATE TABLE IF NOT EXISTS "<tenant>".share_link_recipients (
    link_uid          UUID        NOT NULL REFERENCES "<tenant>".share_links(link_uid) ON DELETE CASCADE,
    email             TEXT        NOT NULL,   -- normalized (lowercased, trimmed)
    invited_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    invited_by        TEXT        NOT NULL,   -- creator, or whoever added them later
    -- the status ladder the Share tab renders (§10.2) — every rung is a column so
    -- the roster is one query, not a reconstruction from the audit log
    invite_sent_at    TIMESTAMPTZ,            -- RESERVED, always NULL in v1: the creator
    invite_error      TEXT,                   -- mails the link themselves (§13-R9), so the
                                              -- system never sends an invite and has nothing
                                              -- to report. Kept in the schema so the v2
                                              -- "email it for me" option is a behaviour
                                              -- change, not a migration.
    last_code_sent_at TIMESTAMPTZ,            -- "Opened" — they reached the landing page
    first_verified_at TIMESTAMPTZ,            -- "Verified"
    last_used_at      TIMESTAMPTZ,            -- "Downloaded" / "Dropped"
    uses_consumed     INTEGER     NOT NULL DEFAULT 0,
    failed_codes      INTEGER     NOT NULL DEFAULT 0,
    removed_at        TIMESTAMPTZ,            -- partial revoke; row kept for history
    removed_by        TEXT,
    PRIMARY KEY (link_uid, email)
);
```

Stored in plaintext because it is a delivery address — hashing it would make the
mail undeliverable. It is therefore **PII in a tenant schema**, and the §5.5
retention window applies to it as much as to the ledger.

`max_uses` remains a pool shared across recipients; the optional
`max_uses_per_recipient` on the link bounds any single recipient
(`uses_consumed` here is what it is checked against), which is how "each of the
three of them may download twice" is expressed.

### 5.5 Retention

Expired and revoked rows are **kept** (they are audit evidence) and purged by the
existing background-worker pattern (`FileCuller`) after
`share.retention_days` (default 365), emitting `share_link_expired` on the way
out. That emission is **fail-closed** (§12): a row whose purge cannot be recorded
is not purged, and the sweeper retries on its next pass. Nothing about
correctness depends on the sweeper — every check is evaluated at redemption
time — so a stalled sweep costs disk and a little PII retention, never
enforcement.

---

## 6. Behaviour

### 6.1 Creating a link

`POST /share/v1/nodes/{uid}/links` requires:

- the caller is in the **`share_external` LDAP group** for this tenant (§8.1) —
  a per-user gate the service reads from the caller's resolved roles, **and**
- `CheckPermission(caller, resource_uid, READ)` for `kind = 0 | 2` (download) or
  `WRITE` for `kind = 1` (upload) — asked of the core, as the caller, **and**
- the target's type matches the kind — file for `0`, directory for `1` and `2`
  (mismatch ⇒ `400`), established from `Stat` as the caller, **and**
- at least one recipient address, capped at `share.max_recipients` (§6.9), **and**
- `expires_at` within the deployment's `share.max_ttl_days` cap (§9), **and**
- for `kind = 2`: the snapshot walk succeeds within
  `share.zip_max_members` / `share.zip_max_bytes` (§9). Creation is where an
  oversized folder is refused — with a clear count/size in the error — so the
  recipient never discovers the limit mid-download.

The response carries the **only** copy of the secret the system will ever emit.
Re-reading a link later returns its uid, budgets, and usage — never the secret.

### 6.2 Version pinning (file download)

By default `pinned_version` is set to the version current at creation. The
reason is a leak the obvious design has: an unpinned link keeps serving *future*
edits of the file, so a document shared for review in March silently exposes
whatever it becomes in September. `follow_latest: true` is available and is a
deliberate choice the UI labels as such ("always send the newest version").

If the pinned version is later culled (`CULL_VERSIONS`) the link is dead —
generic 404, audited as `share_link_denied / version_gone`.

### 6.3 The authority re-check (the defining rule)

On every redemption the core re-evaluates, as `created_by`:

- `check_permission(created_by, resource_uid, READ|WRITE)` — the *current* ACL
  state, including parent traversal, and
- that the resource still exists and is not deleted.

Any failure ⇒ the link is dead. Consequences, all of them intended:

- Revoking a user's access to a folder retroactively kills every link they minted
  under it. No separate cleanup step, no lingering grants.
- A departed employee's links die the moment their access does — this is what
  makes the roadmap's "lingering share links" query actionable rather than
  merely informative.
- A link can never outrank its creator. That is what allows link creation to be
  an ordinary user capability (the `share_external` group, §8.1) instead of an
  admin-only one.

#### Resolving the creator's roles when nobody is authenticated

This is the subtle part, and the naive reading of the code gets it wrong.
`AclManager::resolve_effective_roles` (`core/src/acl_manager.cpp:242`) unions the
*request-supplied* roles with `db_->get_roles_for_user`. A share redemption
carries no session, so it supplies none — and the obvious implementation
therefore evaluates the creator as
**role-less**.

That is not a corner case here. Role membership in this platform lives in
**LDAP**, not in the core: `ldap_manager` administers `groupOfNames` entries
(the SPA's role admin calls `/v1/admin/roles/{role}/members`,
`frontend/src/services/ldapAdminService.ts`), and the bridge attaches the
resolved groups to every request in `fillAuth` / `addRolesAliased`
(`http_bridge/src/http_server.cpp:479–493`). The core's `user_roles` table is
written only by its own `AssignUserToRole` RPC, which is not on that path — so
in a normal deployment `get_roles_for_user` returns **empty** and the DB union
contributes nothing.

Read-by-default (`default_read_ = true`) hides this most of the time: a
role-less principal still holds baseline READ. It stops hiding it the moment a
folder carries `DENY READ → everyone` plus `ALLOW READ → some role` — which is
exactly the **"👥 Gated section (role)"** one-click template the product ships
(`frontend/src/help/content/sharing.md`). Links minted inside a gated section
would be born dead. Claims have the same shape: CLAIM-tier rules match on
JWT-borne claims, and a redemption carries no JWT.

**Therefore, two rules.**

1. **`share_service` re-resolves the creator's roles live, at redemption**, over
   its own LDAP service bind — the same lookup `ldap_manager` performs for an
   arbitrary username, needing no credentials from the absent user. Those roles
   go into the `AuthenticationContext.roles` of every delegated call, which is
   the ordinary `request_roles` path the core's evaluator already unions
   (`acl_manager.cpp:242`). Roles are therefore **current, not snapshotted**:
   removing a departed employee from the LDAP group kills their links on the next
   redemption, with nothing stored anywhere to go stale. LDAP being unreachable
   denies the redemption (fail-closed, consistent with every other door).

   Note this is the *whole* mechanism — because the redemption runs as the
   creator rather than as a synthetic principal, "give the core the creator's
   real roles" is all that role resolution means here. There is no special
   evaluation path for the core to implement, which is precisely why it needs no
   change (§4.1).
2. **Admin roles are stripped before the delegated call** — `system_admin`,
   `tenant_admin`, and the `administrators` alias. The ACL bypass must never
   reach an unauthenticated route: a link minted by an admin has to stand on
   ordinary ACL rules or not stand at all. An admin who can reach a file *only*
   via the bypass therefore cannot mint a working link to it — the safe failure,
   caught at creation by the pre-flight below.

   **This one is now load-bearing in a way it was not before.** Under a
   core-owned design the core could have stripped admin roles itself as a second
   line of defence. Here the core simply believes the `AuthenticationContext` it
   is handed — that is its documented trust model — so **`share_service` is the
   only thing standing between an admin's bypass and a public URL**. If it
   forgets, the core will faithfully grant everything. That makes the stripping a
   tested invariant of the service (§14), not an implementation detail.

**Pre-flight at creation.** Link creation runs the *exact* check a redemption
will run — creator, LDAP-resolved roles, no claims, no admin bypass — and refuses
to mint a link that would be born dead, naming the reason. This turns every
variant of the problem above (claim-only access, bypass-only access, an LDAP
lookup that resolves differently than the caller's live JWT) into a clear error
at creation rather than a mystery 404 for the recipient.

### 6.4 Redemption sessions (why a use ≠ a request)

Naively decrementing per HTTP request breaks on the first real browser: a Range
request, a resumed download, or a retry after a dropped connection would each
burn a use, and a 5-use link would be exhausted by one recipient.

Instead, opening a session writes a **redemption session** row (`share_redemptions`,
TTL `share.session_ttl_seconds`, default 1 h) and *that* consumes the use. Every
byte transfer within the session — including `Range` continuations and retries —
rides `redemption_uid` and consumes nothing further. `bytes_moved` accumulates
on the row; `bytes_consumed` on the link is updated at session close.

The SPA landing page therefore calls **peek** (metadata only: file name, size,
expiry, uses remaining), which consumes nothing.
Peek is rate-limited like everything else on the public prefix (§8.4).

Everything before the session is likewise free: the whole recipient-verification
exchange in §6.9 — entering an address, receiving a code, entering it — consumes
nothing. The use is spent at session open, once a verified recipient has actually
asked for the payload.

**A use is a session for every kind, uploads included — and that is why uploads
need a second budget.** An earlier draft said a use was a session (here) and also
that `max_uses` was "the file count" for drops (§6.7). Both cannot hold: if one
session admits any number of files, `max_uses` bounds nothing about how much
arrives; if each file burns a use, the retry-safety this whole section exists to
provide is gone for exactly the transfers most likely to fail. So the two things
are counted separately and named separately:

| Budget | Bounds | Applies to |
|---|---|---|
| `max_uses` | **Redemption sessions** | all kinds |
| `max_files` | **Files dropped**, across all sessions | `kind = 1` only |
| `max_bytes` | Total bytes moved | all kinds |

A drop box minted as "5 files" therefore sets `max_files = 5`, and the sender may
open as many sessions as `max_uses` allows to deliver them — a phone that drops
its connection after three files resumes in a new session and still has two files
left, which is the behaviour anyone would expect and the one the single-counter
design could not express. §10.1's upload form asks for the file count and sets
`max_files`; `max_uses` gets a sensible default the creator rarely touches.

### 6.5 Folder downloads (zip)

Two of R8's three share shapes land here — *the folder's contents*
(`include_subdirs = false`) and *the folder with everything under it*
(`include_subdirs = true`). They differ only in how far the creation-time walk
descends; everything below applies identically to both.

**Snapshot, not a live walk.** At creation the core walks the folder (respecting
`include_subdirs`) as the creator and writes `share_link_members` (§5.2): each
member's uid, its **pinned version**, its size, and its path inside the archive.
Redemption serves that list. This is the folder-scale form of §6.2's argument —
a live link keeps exposing whatever anyone drops into the folder next month,
which for a shared project directory is a much bigger leak than a single file's
future edits. `follow_folder: true` opts into live semantics and the UI labels it
plainly ("include anything added later").

**Store-only zip64, with a known length.** The archive is assembled with **no
compression** (`method 0`), which makes its byte length exactly computable at
creation from the member sizes plus fixed per-entry overhead — so `archive_bytes`
is stored on the link and served as a real `Content-Length`. The recipient gets a
progress bar instead of an indefinite chunked stream, and the deployment gets an
exact number to budget against. Zip64 unconditionally, so >4 GiB archives and
>65 535 members are not a special case. Most of what this system holds (PDF, IFC,
images, office documents) is already compressed, so the forfeited ratio is small;
`share.zip_deflate = true` is available for text-heavy corpora and trades
`Content-Length` for compression.

**Streaming forces data descriptors, and they must be in the arithmetic.** A
store-only local file header carries the CRC-32 and both sizes *before* the
entry's data — but the CRC is only known once the bytes have been read, and the
core stores no per-file checksum to look it up from (`versions` holds
`size`/`storage_path`, no digest, `database.cpp:2072`). Precomputing CRCs at
creation would mean reading every byte of a 2 GiB folder while the creator waits
in the drawer, which is not acceptable for an interactive action.

So each entry is written with the **general-purpose bit 3** set and its CRC and
sizes deferred to a **zip64 data descriptor** after the data — CRC-32 computed
per member as its bytes pass through, exactly as §7.3 says. The descriptor is a
fixed 24 bytes (signature 4 + CRC 4 + compressed size 8 + uncompressed size 8),
so the length stays exactly computable; it just has a term the earlier draft
omitted:

```
per entry   = 30 + len(archive_path) + 20   (local header + zip64 extra)
            + size_bytes                    (stored, uncompressed)
            + 24                            (zip64 data descriptor)
per central = 46 + len(archive_path) + 28   (central directory + zip64 extra)
total       = Σ per entry + Σ per central + 56 + 20 + 22
                                            (zip64 EOCD + locator + EOCD)
```

Every term is known at creation from `share_link_members` alone — names and sizes
— which is what keeps `archive_bytes` honest. Empty directories are entries with
`size_bytes = 0` and count in both sums.

Two consequences worth stating plainly rather than discovering in support:

- **Bit 3 is the one compatibility cost.** Every mainstream extractor handles
  streamed zips (that is what every "download as zip" on the web produces), but
  some older Windows-native paths and embedded tools are unhappy with data
  descriptors. The alternative was worse, and `share.zip_deflate` already exists
  for anyone who needs to trade the exact length away.
- **A member whose stored size no longer matches its bytes breaks the
  `Content-Length` contract.** The size is pinned at creation and the version is
  pinned with it, so this means the object was culled or corrupted mid-flight. On
  a mismatch the service **aborts the connection** rather than padding or
  truncating: a short body under a declared length is a silently corrupt archive,
  and a broken transfer is the honest failure. Audited on the redemption row.

**Per-member authority re-check.** §6.3 runs on the folder *and* on each member
at redemption. A member the creator can no longer read is **omitted**, not
fatal — the archive is still served, and the redemption's audit `detail` carries
`members_served` / `members_omitted`. Failing the whole download because one file
gained a DENY would make the feature unusable in exactly the deployments that
manage ACLs carefully.

**No resume.** A zip stream is not Range-servable, so `/content` returns
`Accept-Ranges: none` for `kind = 2`. This is precisely why uses are counted per
*session* and not per request (§6.4): a recipient whose connection drops retries
inside the same session and burns nothing.

**Path safety.** `archive_path` is normalized and validated at creation (§5.2).
Empty folders are emitted as zip directory entries so the structure survives.

### 6.6 What a redemption exposes

The resource set the link was minted for, and nothing else. Concretely, the core
resolves every operation against `resource_uid` (and, for `kind = 2`, against
`share_link_members`) and ignores any uid the caller supplies. A share credential
grants **no** `ListDirectory`, no `Stat` of a parent, no ACL read, no role or
principal lookup, no metadata read beyond display name / size / content-type,
and no version listing.

- **File download:** one file, one version.
- **Folder download:** the snapshot's members. Peek returns the member count and
  total size; the full member list is available at `/manifest` — hiding it would
  be theatre, since the archive contains it.
- **Upload:** the sender never sees the folder's existing contents — only what
  *they* dropped in the current session.

Renditions (`file_renditions.md`) are **not** served in v1: a download link
serves the parent file only, and a folder snapshot contains no rendition
children.

### 6.7 Upload semantics

- **Never versions.** A drop whose name collides with an existing entry is stored
  as `name (1).ext`, `name (2).ext`, … It must not be possible for an outside
  sender to inject a new version into an existing document's history — that is
  both a data-integrity problem and a plausible attack (poison the "latest" of a
  file someone else trusts).
- **Budgets** are enforced twice: streaming in the service (fail fast, don't buffer
  a 40 GB body) and authoritatively in the core — `max_file_bytes` per file,
  `max_bytes` remaining across the link, and **`max_files`** as the file count
  (§6.4; *not* `max_uses`, which counts sessions). The file slot is reserved
  before bytes are stored and released if the upload fails (§5.3), so a dropped
  connection costs the sender nothing.
- **Extension allowlist** is optional and matched on the claimed name only —
  it is a convenience for the sender, never a security control. Content type is
  never trusted; nothing is executed.
- **Landing prefix**: an optional subfolder (created lazily on first drop, owned
  by the creator) for deployments that want outside drops quarantined from the
  folder proper. Default is none — drops land in the target folder and flow
  through the normal `file.created` event, so `folder_actions` and CSAI ingest
  them like any other upload.

### 6.8 Drop provenance

Dropped files are **owned by `created_by`** — so inherited ACLs behave exactly as
if the creator had uploaded them, and no orphan principal appears in the ACL
tables. The outside origin is recorded in full, in file metadata:

| Key | Value |
|---|---|
| `share.link_uid` | the link |
| `share.redemption_uid` | the specific drop |
| `share.source_addr` | client IP, resolved from the forwarded headers by the service |
| `share.verified_email` | the recipient address that passed the OTP challenge (§6.9) — **verified**, not claimed |
| `share.claimed_name` | free text the sender optionally typed; **untrusted**, and the UI must render it as such |

Audit events for the drop use `actor = "share:<link_uid>|<verified_email>"`,
`source_iface = "rest"`, with `created_by` carried in `detail` — so the ledger
shows the door, the verified human who walked through it, and the person
accountable for opening it.

`share.verified_email` is the load-bearing one. Ownership is a deliberate lie of
convenience — the file is owned by `created_by` so that ACL inheritance works and
no orphan principal appears in the ACL tables — and this key is the only thing on
the file itself that says a stranger put it there. Three properties have to hold
for it to function as an accounting record rather than a hint.

**1. The on-file copy is a convenience, and the audit log is the record.**
`SetMetadata` gates on `WRITE` and validates nothing about the key
(`core/src/grpc_service.cpp:1119–1137`), and **the core is not being changed to
reserve the `share.*` namespace** (§13-R13). So these keys are, frankly,
forgeable and erasable: any user with WRITE on the file can rewrite
`share.verified_email` — or, in the more damaging direction, stamp it onto a file
they uploaded themselves and attribute their own document to an outside party.

That is acceptable **only** because the metadata is not what anything trusts. The
authoritative record of who dropped what is the `share_redemptions` row in
`share_service` (with `result_uid` pointing at the file it created) and the
hash-chained `share_link_redeem` event in `audit_service` — neither of which any
file-level `WRITE` can touch. The metadata exists so the Origin block (point 3)
can render without a second service call, and so an ordinary user browsing files
sees where something came from.

Two rules follow from that, and the UI must honour both:

- **Never present the on-file value as verified.** The Origin block reads from
  metadata for speed but labels it as descriptive, and the Share tab's ledger
  (§10.2) — served from `share_service` — is what gets shown when someone asks
  *"is that really who sent it?"*.
- **Where they disagree, the ledger wins**, and the disagreement is itself worth
  surfacing: metadata that no longer matches the redemption record means someone
  edited it, which is exactly the signal a reserved namespace would have
  prevented and now has to be detected instead. A periodic reconcile in
  `share_service` (it already sweeps for retention, §5.5) can compare the two and
  raise an attention item on drift.

If the on-file record ever needs to be evidence rather than a hint, the change is
small and self-contained — key validation in `SetMetadata` / `DeleteMetadata`,
about fifteen lines — and can be made later without touching anything designed
here. It is deliberately out of scope now because it is a core change (§4).

**2. The provenance belongs to the version, not just the file.** Drops never
version an existing file (§6.7), but nothing stops an *internal* user adding a
version to a dropped file afterwards — and at that point file-level metadata
saying "uploaded by bob@contractor.example" is describing bytes bob never sent.
The keys are therefore written as **version metadata** on the dropped version
(the core already carries per-version metadata — `GetVersionMetadata`,
`proto/fileservice.proto:397`) *and* mirrored to file metadata for
discoverability. Where they disagree, the version record governs, and the UI
reads the version's. `share_service` writes both, as the creator, on the same
delegated call path as the upload itself.

**3. It has to be visible where the file is.** Today the drawer renders metadata
as a flat, editable key/value table (`FileDetailsDrawer.vue:109`, with set and
delete handlers) beside an `Owner` field — so as things stand this would surface
as an editable row saying `share.verified_email`, next to an Owner field naming
someone who never touched the file. That is precisely the accounting confusion
this key exists to prevent. Instead:

- `share.*` keys are **excluded from the editable metadata table** and rendered
  as a distinct read-only **Origin** block: *"Received from
  bob@contractor.example via a share link · 14 Aug 2026 · from 203.0.113.7"*,
  with the link's note and a deep link to its ledger (§10.2) for anyone holding
  rights on it.
- The block states the ownership split in words rather than leaving the reader to
  infer it — owned by the creator, *sent by* the outside address — because "Owner:
  Alice" on a file Alice never saw is the single most misleading thing this
  feature can put on a screen.
- `share.claimed_name` renders inside that block clearly marked as sender-typed
  and unverified, never adjacent to the verified address in a way that lets the
  two be read as equally trustworthy.
- The file browser marks dropped files with a small origin badge, so "what came
  in from outside" is answerable by looking rather than by querying the audit
  service.

### 6.9 Recipient verification (email + OTP) — required

**Every redemption is gated on a verified recipient.** Before any byte moves, the
visitor enters an email address, receives a one-time code at that address, and
enters it. Only then does a session open (and only then is a use consumed). This
applies to **all three kinds** — a folder drop is gated exactly like a download,
which is what turns an anonymous drop into an attributable one (§6.8).

#### The recipient allowlist — and why there is no open-email mode

Recipient addresses are **fixed at creation** (`share_link_recipients`, §5.4).
The OTP is only ever mailed to an address on that list. A visitor who enters
anything else gets the same response as one who entered a listed address —
*"if that address is authorized, we've sent a code"* — so the endpoint never
discloses who the intended recipients are (§8.5's rule, applied here).

The alternative — accept any address the visitor types, mail a code to it, and
record it for the audit trail — was **rejected outright**. It makes an
unauthenticated internet caller the chooser of a destination address for
tenant-branded mail: an open relay with the deployment's own sending reputation
behind it. No rate limit makes that acceptable; the allowlist removes the
capability entirely, because the destination set is closed at creation by an
authenticated user in the `share_external` group (§8.1).

Two consequences, both intended:

- **The link is genuinely non-forwardable.** Forwarding the URL conveys nothing:
  the forwardee cannot receive a code. This is the property the plain
  use-cap/expiry design could never provide.
- **The creator must know the address up front.** "Post the link in a channel and
  let whoever needs it grab a copy" is no longer a supported shape. That is the
  direct cost of the requirement, and it is the right trade for documents worth
  gating.

#### Flow

1. `GET …/{link_uid}` — **peek**. Consumes nothing, reveals nothing about
   recipients, states that a code will be required.
2. `POST …/{link_uid}/identify` `{email}` — if the address is on the allowlist,
   mint a 6-digit code and mail it. The code **expires after 10 minutes**
   (`share.otp_ttl_seconds`, §9) and the mail states the deadline, since a code
   that has quietly gone stale is otherwise indistinguishable to the recipient
   from one they mistyped. Uniform response either way.
   **Re-posting `/identify` is the resend path** — there is no separate route.
   A recipient whose code expired, never arrived, or arrived after the mail was
   delayed asks for another by submitting the same address again, bounded only
   by the send limit (`3 / 15 min` per `(link, email)`, §9). The landing page
   offers this as an explicit *"Didn't get a code? Send another"* control rather
   than making the recipient guess that re-entering their address is safe
   (§10.4), and shows the remaining wait when throttled instead of silently
   doing nothing.

   Two consequences of `issue_code`'s semantics that the UI has to carry, because
   both are otherwise experienced as "the code doesn't work":
   - **A new code invalidates the previous one.** `TokenStore.issue_code` keeps
     one live code per `(kind, uid)` — a new challenge replaces the old
     (`tokens.py:106–111`). That is the right behaviour (two live codes doubles
     the guessing surface and the confusion), but it produces a sharp edge:
     request a resend, then the *first, delayed* mail lands, type that code, and
     it fails. The copy must say **"use the most recent code"**, and the mail
     itself should carry its send time so two mails can be told apart.
   - **A resend does not buy fresh attempts** — see §8.4. Otherwise "request a
     new code" is an unlimited reset on the 5-attempt guess budget.
3. `POST …/{link_uid}/verify` `{email, code}` — on success, issue a
   **recipient token** (256-bit, hashed at rest, TTL
   `share.recipient_ttl_seconds`, bound to link + email). Consumes nothing.
4. `POST …/{link_uid}/session` — requires the recipient token. **This is where
   the use is consumed** (§6.4) and where `verified_email` is written onto the
   redemption row.
5. Transfer, as §6.4/§6.5 describe.

A failed or abandoned challenge therefore never costs a use, and a recipient who
already holds a live recipient token can start a second session (a re-download
inside the window) without a fresh code — subject to the same use budget.

#### Where each piece lives

The split follows the platform's existing 2FA seam, documented in
`ldap_manager/src/ldap_manager/routers/twofa.py`: *"the identity service owns the
secret + verification; http_bridge orchestrates."*

| Piece | Owner | Reuses |
|---|---|---|
| Recipient allowlist, budgets, `verified_email` on the ledger | **core** | durable authorization state, per §4 |
| Code generation, delivery, storage, single-use verify, send/attempt rate limits | **ldap_manager** | `TokenStore.issue_code` / `consume_code` (hashed, TTL, constant-time, single-use) and `rate_ok` — `tokens.py:106–137` |
| Orchestration, recipient-token minting | **`share_service`** | the same `require_internal` server-to-server seam the bridge already uses for `/internal/2fa/*` — a second client of an established pattern, not a new one |

**New endpoints on ldap_manager:** `POST /internal/share/email-challenge` and
`POST /internal/share/email-verify`, guarded by the same shared internal secret.
They are *siblings* of the 2FA pair, not reuses of it: `/internal/2fa/email-challenge`
refuses when a tenant's 2FA policy excludes the `email` method
(`routers/twofa.py:218`) and renders the 2FA template — neither of which should
govern whether an outside recipient can open a share link. New `kind` for the
token store (`share_otp`), keyed by `link_uid|email`; new mail template
`SHARE_OTP_EMAIL` in `templates.py`.

**`share_service` enforces the allowlist; `ldap_manager` proves the address.**
The verification happens in `ldap_manager` (it owns the code and the mailbox);
`share_service` relays the result and checks it against the link's recipient list
before opening a session. The core is not in this loop at all — it never learns
an email address was involved, and by the time it is asked for bytes the caller
is simply the creator.

That concentrates trust in `share_service`: nothing downstream will catch it if
it opens a session for an address that was never verified. There is no second
enforcement point to fall back on, which is the direct consequence of taking this
out of the core (§4.3) and the reason the allowlist check is a tested invariant
(§14) rather than an assertion in prose.

#### Sending the link — the creator does it, not the system

**v1 sends no invite mail.** Creation returns the URL once; the creator pastes it
into whatever they were going to write anyway. The system's *only* outbound mail
on this feature is the recipient's OTP (§13-R9).

The reasoning is that the invite is a message, not a mechanism. The URL is inert
without a code, so mailing it conveys no access — while an auto-sent invite
inherits every hard part of transactional mail (deliverability, per-tenant
branding, the recipient's "who is this and why", bounce handling) for a body the
creator would write better themselves. It also means one fewer place where a
misconfigured SMTP relay silently produces a recipient who never heard anything.

What creation owes the creator instead is a message worth pasting: the URL, the
expiry, the use budget, and — for a folder link — the **member count and
estimated archive size** (§13-R9), so the recipient can be told *"38 files, about
412 MB, link expires 26 Aug"* before they click. §10.1 specifies that block as
copy-to-clipboard text, not just on-screen labels.

Consequences carried through the rest of this document: no `SHARE_INVITE_EMAIL`
template, no `send_invite` field on the create call, no `share.send_invite_default`
config key, and no **Invited / Invite failed** rungs on the recipient roster
(§10.2) — the system cannot report on mail it did not send. `invite_sent_at` /
`invite_error` stay in the schema (§5.4) as the v2 seam.

#### New failure modes to plan for

- **Redis down ⇒ no redemptions.** `issue_code` no-ops and `consume_code`
  returns `False` when Redis is off (`tokens.py:106,113`), so the gate fails
  closed. Correct, and a hard new dependency: share links now require Redis and
  SMTP to be healthy, alongside the core and LDAP.
- **SMTP misconfigured ⇒ every link is unusable**, and the current 2FA handler
  swallows send failures into `sent = False` (`routers/twofa.py:231`). The share
  variant must keep the *recipient's* response uniform while surfacing the
  failure loudly — audit event, service log, and an **attention item for the link's
  creator** (§10.6). A silent mail failure here looks identical to a wrong
  address, which is the worst possible support experience. Note this is now the
  *only* mail path (§13-R9), so an SMTP outage takes the whole feature down
  rather than degrading it — there is no invite mail left to fail separately.
- **Mail-flooding a listed recipient** by a party who holds the URL: per
  `(link, email)` and per-link send caps via `rate_ok` (§8.4).
- **OTP brute force:** `consume_code` deliberately does *not* delete on a wrong
  code — its docstring puts rate-limiting on the caller. That counter must live
  in **`ldap_manager`'s Redis** (a `rate_ok` bucket keyed `share_otp:{link}:{email}`),
  **not** in `share_service` process memory: the service may be replicated, and a
  per-process counter would give an attacker one fresh allowance per replica —
  the same trap `ReplayGuard`'s own header calls out ("a multi-bridge deployment
  would back this with a shared store"). Five failures lock **that address out
  of this link** for the window (not the link itself, and not the address's
  ability to request a fresh code once the window passes); the failures also
  feed the link's `failed_attempts` (§8.4). The bucket key
  `share_otp:{link}:{email}` is what makes this survive a resend — it is scoped
  to the address, not to the challenge the resend replaces (§8.4).

---

## 7. `share_service` routes

All of it is served by `share_service` — the bridge is not involved and gains no
routes. nginx puts the service on the tenant origin under `/share/`, alongside
`/api/`, `/csai/`, `/diff/` and the rest, so the SPA reaches it same-origin and
the public landing page is served from the same host as the bytes (§8.3).

Two clearly separated families, and the split is **structural here in a way it
could not be in the bridge**. In the bridge, unauthenticated paths are exceptions
allowlisted inline inside an otherwise-authenticated prefix (`handleV1`,
`http_server.cpp:303`, with `/v1/auth/token` and `/v1/auth/sso/redeem` carved out
at `:336`/`:351`) — one forgotten `else` away from exposing something. A
standalone service can instead mount **two routers with different dependencies**:
`/share/v1/*` requires a bearer token by construction, `/share/v1/public/*`
refuses to read one at all. Nothing is allowlisted, so nothing can be
accidentally added to the allowlist.

The public router also **never** falls back to session auth, so a logged-in
browser hitting a public route is still session-less there and a redemption can
never be misattributed to a passing authenticated user.

### 7.1 Owner-side (bearer auth — the SPA's own session)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/share/v1/nodes/{uid}/links` | Create a link. Body: `kind`, **`recipients[]` (required, ≥1)**, `expires_at`\|`ttl`, `max_uses`, `max_uses_per_recipient?`, `max_bytes`, `max_file_bytes`, `max_files?` (upload — the file count, distinct from `max_uses`, §6.4), `follow_latest?`, `follow_folder?`, `include_subdirs?`, `landing_prefix?`, `ext_allowlist?`, `note?`. **201** returns the full URL once, plus `archive_bytes` / member count for `kind = 2` — the numbers §10.1 renders into the copyable summary the creator pastes into their own mail (§13-R9). No `send_invite`: v1 sends no invite. |
| `GET` | `/share/v1/nodes/{uid}/links` | Links on this node (requires `MANAGE_ACL` or being the creator). |
| `GET` | `/share/v1/links` | The caller's own links. `?all=true` (**`tenant_admin` only**) returns the tenant-wide set backing the admin console (§10.3), with `creator`, `recipient`, `subtree`, and `status` filters and `live=true` by default. |
| `DELETE` | `/share/v1/links/{link_uid}` | Revoke. Idempotent. |
| `GET` | `/share/v1/links/{link_uid}` | One link's **live status** (§10.2): computed state, budgets, and the result of the §6.1 pre-flight re-run — this is what surfaces "not working: you no longer have access". |
| `GET` | `/share/v1/links/{link_uid}/recipients` | The roster: per-address status ladder, invite/verify/download timestamps, uses consumed, failure counts. |
| `POST` | `/share/v1/links/{link_uid}/recipients` | Add an address to the allowlist after creation (creator only; optionally mails the invite). |
| `DELETE` | `/share/v1/links/{link_uid}/recipients/{email}` | Partial revoke — that address loses access, the link keeps working for the rest. |
| `POST` | `/share/v1/links/{link_uid}/recipients/{email}/resend` | Re-send the invite (or a fresh code), subject to the §9 send limits; returns the remaining wait when throttled. |
| `GET` | `/share/v1/links/{link_uid}/redemptions` | Usage ledger for one link (who, when, from where, how much; members served/omitted; `result_uid` for drops). |

### 7.2 Public (unauthenticated — new `/share/v1/public/` prefix)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/share/v1/public/{link_uid}` | **Peek.** Consumes nothing. Returns `kind`, display name, `expires_at`, `uses_remaining`, and either size + content-type (`kind = 0`) or member count + `archive_bytes` (`kind = 2`) or the remaining **file** and byte budget — `max_files - files_consumed` and `max_bytes - bytes_consumed` (`kind = 1`). |
| `POST` | `/share/v1/public/{link_uid}/identify` | `{email}` → mails a 6-digit code **iff** the address is on the link's allowlist. Uniform response either way (§6.9). Consumes nothing. |
| `POST` | `/share/v1/public/{link_uid}/verify` | `{email, code}` → the **recipient token** (TTL `share.recipient_ttl_seconds`). Consumes nothing; 5 failures per `(link, email)` per window lock that address out — a resend does **not** reset the count (§8.4). |
| `POST` | `/share/v1/public/{link_uid}/session` | Open a redemption session (**this is the use-consuming call**). Requires the recipient token. Returns `redemption_uid` + TTL, and writes `verified_email` onto the ledger row. |
| `GET` | `/share/v1/public/{link_uid}/content` | Stream the payload. `kind = 0`: the file, Range-capable, reusing the existing `streamFileDownload` path (`src/http_server.cpp:562`). `kind = 2`: the zip, `Content-Length: archive_bytes`, `Accept-Ranges: none`, assembled member-by-member (§7.3). Requires an open session. |
| `POST` | `/share/v1/public/{link_uid}/files` | Drop a file (raw body + `X-File-Name`, streamed through `StreamFileUpload`). Requires an open session. |
| `GET` | `/share/v1/public/{link_uid}/manifest` | `kind = 2`: the snapshot's member list (name, path, size). `kind = 1`: what *this session* dropped — never the folder's contents. |

The secret travels in the `X-Share-Secret` header (SPA) or `?k=` (direct-link
fallback for `curl`/email clients). **R7 settles the URL form as the path**
(`/s/{uid}.{secret}`), so the plain-URL form ships — which makes the query-string
scrubbing below load-bearing rather than belt-and-braces. Notes that apply to the
whole public family:

- **No CORS wildcard.** Same-origin only; the SPA and the public routes are the
  same host under `docker_unified/images/nginx/snippets/tenant.conf`.
- **No bearer token is read, and none is issued.** A logged-in browser hitting a
  public route is still session-less there — the routes never fall back to session
  auth, so the audit record can never misattribute a redemption to a passing
  authenticated user.
- **Response headers, set once for the whole prefix** — not per route:
  `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store`, `X-Robots-Tag: noindex, nofollow`,
  `Content-Security-Policy: sandbox`. This is the anti-XSS boundary; §8.3 says
  why it is a handler-level concern and what has to be tested to keep it true.
- **Logging:** the service logs `link_uid` and never the secret; the nginx
  `access_log` for `location /share/v1/public/` must strip the query string
  (`log_format` without `$query_string`) or the fallback `?k=` form defeats
  itself.

### 7.3 Where the zip is assembled

**In `share_service`.** The core stays a byte source and nothing more: the
service opens the session, reads its own member list, and for each member issues
`StreamFileDownload` **as the creator** (§4.1). It frames the resulting streams
into zip entries and streams them straight out; nothing is buffered to disk or to
memory beyond one chunk, and nginx needs the same `proxy_request_buffering off` /
`proxy_buffering off` posture already set for `/api/` in
`docker_unified/images/nginx/snippets/tenant.conf`.

**Membership is enforced here, and only here.** Under a core-owned design the
core would have validated each `member_uid` against `share_link_members` — a
second check behind the service's first. That check no longer exists: the core
will stream any uid the creator may read. So the service must take member uids
**exclusively from its own snapshot rows**, never from anything the caller
supplied, and a `member_uid` that is not in this link's snapshot must be
impossible to express rather than merely rejected. This is §4.3's containment
point in its most concrete form, and it is why §14 tests it directly.

**The per-member re-check runs at session open, not mid-stream.** Opening a
`kind = 2` session re-evaluates §6.3 across the whole snapshot — one
`CheckPermission` per member, as the creator — freezes the surviving member list
onto the `share_redemptions` row, and computes the exact archive length that
`/content` then serves as `Content-Length`. Doing it any later means discovering
an omitted member after the header is on the wire, and a zip whose declared
length no longer matches its body is a corrupt download. The residual window (an
ACL change between session open and stream end) is bounded by the transfer itself
and is accepted; the link's *next* session sees the new state.

One operational note the core-owned design did not have: this is **N
`CheckPermission` round-trips at session open**, where N is the member count
(capped at `share.zip_max_members`, default 5000). They are independent and
should be issued concurrently with a bounded pool; a 5000-member folder must not
turn session-open into a minute of serial gRPC calls. Worth measuring in M1
against the fixture tree.

The zip writer itself is ~200 lines of local-header / central-directory framing
— store-only removes the compressor entirely — with CRC-32 computed per member
as its bytes pass through.

### 7.4 Where the recipient token lives

The recipient token (§6.9 step 3) is a 256-bit bearer credential, hashed at rest,
bound to `(link_uid, email)`, TTL `share.recipient_ttl_seconds`. Earlier drafts
said "hashed at rest" without ever saying **where**, which left the obvious
implementation — a map in the process that minted it — available by default.

It goes in **`ldap_manager`'s Redis**, alongside the OTP state, as a
`TokenStore`-issued value keyed `share_recipient:{link_uid}:{email}`. Two
reasons:

1. **Process memory does not survive replication.** `share_service` is an
   ordinary stateless service and will be run with more than one replica
   eventually. A recipient who verifies against replica A and then opens a
   session on replica B would be unknown there — and by §8.5 the failure is a
   generic 404, so the symptom is *"the link works sometimes"*, which is close to
   undiagnosable from either side. This is exactly the trap `ReplayGuard`'s own
   header names ("a multi-bridge deployment would back this with a shared
   store"), and it has now caught two designs in this document; the OTP attempt
   counter (§6.9) is the other.
2. **It is a verification artifact, not an authorization record.** The token says
   "this address proved control recently" — the same kind of statement, with the
   same lifecycle, as the code that produced it. `TokenStore` already provides
   hashing, TTL, constant-time compare, and single-use semantics. The thing that
   actually *grants* anything remains the `share_redemptions` row in
   `share_service` (§5.3), which is where authorization state belongs.

Client-side, the token lives in **`sessionStorage`, never `localStorage`** — the
landing page is on the SPA's origin (§8.3), and a 24-hour bearer credential
sitting in `localStorage` on a shared machine outlives the visit that earned it.

### 8.1 The creation gate: an LDAP group, not a permission bit

Minting a link is gated by **two independent checks**, both made by
`share_service`, neither requiring a change to the core's permission model:

```python
# per-user: may this person share outside at all?
if "share_external" not in ldap_roles(caller, tenant):      deny
# per-resource: may they reach this thing, right now?
if not core.CheckPermission(caller, resource_uid, READ):    deny   # WRITE for kind=1
```

**Why a group rather than an ACL bit.** An earlier draft proposed
`SHARE_EXTERNAL = 0x4000` in the core's `Permission` enum. That is a clean design
in the abstract, but it puts a share concept in the core's vocabulary — including
`kAllPermissions`, the proto enum, the REST name map, and `AclEditor.vue` — for a
feature the core is otherwise entirely unaware of (§4). The group achieves the
same *gating* outcome with no core surface at all, and it fits where role
membership actually lives in this platform: LDAP `groupOfNames`, administered
through `ldap_manager`, resolved per request — never the core's `user_roles`
table, which is effectively always empty (§13-R5).

**What the two checks buy separately.** The group answers *"is this person
trusted to send things outside the organization?"* — an HR-shaped question,
answered once per person, administered where every other role already is. The
`CheckPermission` call answers *"can they reach this file?"* — asked fresh, per
resource, per creation. Neither alone is sufficient: read-by-default means nearly
everyone holds `READ` nearly everywhere, so the resource check alone would leave
creation effectively ungated; and the group alone would let a trusted sharer mint
links to things they cannot open.

**What is lost, honestly.** An ACL bit would have been *per-resource* —
"Priya may share out of `/Projects/Acme` but not `/HR`". The group is
per-user: someone in `share_external` may share anything they can read. For
finer control the deployment splits the group by scope (`share_external_projects`)
and the service maps group → permitted subtree prefix, which is a service-side
policy table and still no core change. Not needed for v1, and worth stating so
nobody assumes the granularity is there.

The admin bypass needs no special handling at creation: `CheckPermission` will
happily return true for an admin, and the **pre-flight** (§6.3) is what refuses
to mint a link whose access exists only through the bypass — because the
pre-flight runs the redemption's check, with admin roles already stripped.

### 8.2 Token strength & storage

- Secret: 32 bytes from the CSPRNG, base64url (43 chars) ⇒ 256 bits. The
  practical enumeration bound is the rate limiter, not the entropy, but the
  entropy makes offline reasoning trivial.
- Stored as `sha256(secret)`; compared in constant time. A dump of
  `share_links` yields **no live links**.
- `link_uid` is public (it is in the URL and in logs); the secret is the only
  bearer credential.
- **No passphrase.** The second factor is the OTP to a listed address (§6.9),
  which is stronger than a shared passphrase (it cannot be forwarded with the
  link, it expires, and it identifies who used it) and asks the creator to
  distribute one secret fewer. See §13-R1.

### 8.3 Serving share bytes from the tenant origin

This is the sharpest new risk and it is not about share links at all — it is
about *any* unauthenticated GET that returns user-controlled bytes on the SPA's
origin. A shared `.html` (or `.svg`, or anything sniffable) fetched at
`https://acme.example.com/api/v1/public/...` runs script in the SPA's origin and
can read `localStorage` — where the frontend keeps its bearer token
(`frontend/src/stores/auth.ts`).

**Decision: the header triple, not an origin split.** `Content-Disposition:
attachment` + `X-Content-Type-Options: nosniff` + `Content-Security-Policy:
sandbox` (§7.2) closes this for every current browser, with no new vhost, TLS
name, or cross-origin dance between the landing page and the bytes. The cost is
that the property is *maintained* rather than *structural*: a future public
route that forgets one header reopens it. Two guards follow from that, and they
are not optional:

1. The headers are set **once**, in the public-prefix handler, before dispatch —
   never per route. A new public route inherits them or does not ship.
2. A test asserts all three on every response from `/share/v1/public/*`,
   including error responses.

A separate `dl.<base>` origin remains the structural answer if the deployment
ever serves untrusted HTML/SVG at volume; **URLs are built from
`SHARE_PUBLIC_BASE_URL`** (§9) precisely so that move does not invalidate links
already in the wild.

### 8.4 Abuse controls

| Vector | Control |
|---|---|
| Guessing secrets for a known `link_uid` | `failed_attempts` on the row; after 10 within the window, `locked_until = now() + 15 min`, and the link's creator is notified. Distributed guessing hits the same per-link counter, so IP rotation does not help. |
| Enumerating `link_uid`s | 128-bit uid + a per-IP nginx `limit_req` zone on `location /share/v1/public/` + identical 404s (§8.5). |
| Upload flood / storage exhaustion | Per-link file count (`max_files`), per-file bytes (`max_file_bytes`), total bytes (`max_bytes`), and session count (`max_uses`) — four independent bounds, since one sender's single session could otherwise deliver unlimited files (§6.4); per-IP request rate; a service-level request-body cap (`share.max_body_bytes`) as the outer bound, since the bridge's `max_body_bytes` no longer sits in front of this traffic. |
| Bandwidth drain on a download link | `max_uses` is the primary bound; sessions are also capped in count per link per hour. |
| Zip amplification (a folder link as a bandwidth cannon) | `share.zip_max_bytes` / `share.zip_max_members` refused **at creation** (§6.1); `archive_bytes × max_uses` is the exact worst-case egress of a link and the UI shows it; concurrent zip streams capped per link and per service instance. |
| Zip-slip against the recipient | `archive_path` normalized and validated at creation (§5.2) — no `..`, no absolute paths, no leading separator. |
| Replaying a session or recipient token | Both are random 256-bit values, hashed at rest, bound to `link_uid` (and the recipient token also to the verified address); neither survives its TTL. |
| **Using the OTP endpoint as a mail relay** | Structurally impossible: the destination set is closed at creation (§6.9). There is no mode in which an outside caller chooses an address. |
| **Mail-flooding a listed recipient** | `rate_ok` buckets per `(link, email)` (3 / 15 min) and per link (20 / day) — `tokens.py:128`. |
| **OTP brute force** | 6 digits, **5 attempts per `(link, email)` per rolling window — not per challenge**, failures also feed the link's `failed_attempts`. `consume_code` does not delete on a wrong code, so the counter is an explicit `rate_ok` bucket in `ldap_manager`'s Redis — **shared across bridge replicas**, never per-process (§6.9). |
| **Resetting the guess budget by requesting a new code** | The reason the bucket above is keyed per `(link, email)` and not per challenge. A per-challenge counter is defeated by the resend the recipient is explicitly offered (§6.9): burn 5 guesses, request a fresh code, get 5 more — 3 resends per 15 min turns a 10⁻⁶ guess into a steady 15 attempts per quarter-hour against a 6-digit space, indefinitely. Keying the attempt bucket to the address rather than the challenge closes it while leaving the resend freely available, since resending is what a stuck recipient legitimately needs and guessing is not. |
| **Enumerating the recipient list** | `/identify` returns the identical response for listed and unlisted addresses (§6.9, §8.5). |
| Confused deputy via MCP | Structural: the MCP door speaks to the core, and the core has no share operations to expose (§11). |

#### Exceeding the attempt budget is a brute-force signal, not a user error

A link is a **publicly reachable URL**. One recipient fat-fingering a 6-digit
code twice is ordinary; a link accumulating wrong codes across addresses, or the
same address exhausting its budget repeatedly, is someone working on the door.
The two readings need different responses, so the counters escalate in three
rungs rather than one:

| Rung | Trigger | Response |
|---|---|---|
| **1 — address** | `share.otp_max_attempts` (5) wrong codes for one `(link, email)` in the window | That address cannot verify until the window passes. The link keeps working for everyone else. Nobody is notified — this rung is indistinguishable from a person having a bad day. |
| **2 — link** | `share.link_lockout_threshold` (default **15**) failed verifications across *any* addresses, or **3** distinct addresses each hitting rung 1, within `share.lockout_window_minutes` (60) | `locked_until = now() + share.lockout_minutes` (15) on the link: **every** redemption path 404s for the duration (§8.5). Audit `share_link_denied` with `detail.reason = brute_force_lockout`; an attention item to the creator (§10.6) reading *"someone is trying codes against your link"*; the **Blocked** badge in the Share tab (§10.2). |
| **3 — deployment** | Rung 2 recurring on one link, or firing across many links at once | Escalation beyond the tenant: correlated across links by the rules engine, where "many links at once" distinguishes a targeted recipient from someone working through the whole tenant. |

#### Rung 0 — timing: nobody types that fast

Counting attempts alone lets a script spend its whole budget in 200 ms and come
back the moment the window rolls. **How fast the attempts arrive is itself the
signal**, and it separates the two populations cleanly: a person reads a code out
of a mail client and types or pastes it; a script submits as fast as the network
allows, at metronomic intervals, and often before the mail could plausibly have
been delivered at all.

Two checks, both cheap, both evaluated in `ldap_manager` alongside the attempt
bucket (same Redis, same `(link, email)` key, so they are equally
replica-safe):

| Check | Default | Rationale |
|---|---|---|
| **Time since the code was sent** | `share.otp_min_seconds_after_send` = `5` | The strongest of the two, because it is bounded by physics outside the attacker's control: a code cannot be *read* before the mail is delivered. An attempt 300 ms after `/identify` was not typed by someone who received an email. |
| **Interval between consecutive attempts** | `share.otp_min_submit_interval_ms` = `1500` | A person who mistypes re-reads the code before retrying. Sub-second retries are a loop. |

**A tripped timing check is not rejected differently — it is counted more
heavily.** The response stays byte-identical to an ordinary wrong code (§8.5);
what changes is that the attempt contributes to the link-level counter at a
higher weight (`share.otp_timing_weight`, default `5`), so a script hits rung 2
almost immediately while a fast-but-real recipient does not. Rejecting with a
distinct "too fast" response would be the worst of both worlds: it teaches the
script exactly what to tune, and it tells a legitimate recipient something
useless.

Two honest caveats, since this is heuristic where the other rungs are not:

- **Paste is fast.** A recipient with the mail open in a second tab can paste a
  code within a second or two of the page rendering — but not within a second or
  two of *requesting* it, which is why the send-time check carries more weight
  than the interval check and why neither denies on its own.
- **Interval jitter analysis is deliberately out of scope for v1.** Scripts are
  metronomic and the variance is a strong tell, but building a distribution test
  on top of a 5-attempt budget is machinery for a population too small to learn
  from. The two thresholds above catch the unsubtle case, which is the case that
  actually shows up.

**Rung 2 raises a first-class security alert.** It emits its own audit action —
`share_link_locked`, category `permission`, fail-closed (§12) — rather than
leaving the signal to be inferred from a burst of `share_link_denied`. A burst
threshold is a heuristic that has to be tuned and can be paced under; a lockout
is a **discrete, already-adjudicated event**: the system has concluded that a
publicly reachable door is being worked on. That deserves an alert on its own,
at the moment it happens, with `link_uid`, `resource_uid`, `created_by`, the
source addresses seen, and which rung-1 addresses contributed. The
`share_link_denied` burst rule stays as the broader net for everything that
never reaches a lockout.

Three properties of that ladder are deliberate:

- **Wrong secrets and wrong codes feed the same link-level counter.** They are
  the same adversary from the link's point of view, and keeping two independent
  budgets would let an attacker spend both. `detail.reason` still separates them
  in audit, so the forensic view can tell "guessing the URL" from "holding the
  URL and guessing the code" — a materially different disclosure, since the
  latter means the token already leaked.
- **Lockout is temporary and never auto-revokes.** A link is public: anyone
  holding the URL can deliberately burn attempts. If exhaustion revoked the
  link, any recipient — or anyone they forwarded the mail to — could permanently
  destroy a colleague's share with a few wrong codes, turning an abuse control
  into a third-party denial of service. Rung 2 therefore expires on its own, and
  only a human (creator or `tenant_admin`, §10.3) revokes.
- **`failed_attempts` is a rolling count, not a lifetime total.** It carries
  `failed_window_start`; counts older than `share.lockout_window_minutes` are
  discarded, and a **successful verified redemption clears it**. Without that,
  every long-lived link eventually accumulates its way into a permanent lockout
  from ordinary typos — the failure mode where a security control quietly
  becomes an expiry mechanism nobody documented.

The recipient sees none of this beyond the uniform response and their own
attempt state (§10.4); the distinction between "you are locked out" and "this
link is blocked" is not disclosed to an unverified caller.

### 8.5 Uniform failure

Unknown uid, bad secret, expired, revoked, exhausted, locked, resource deleted,
creator lost access, pinned version culled — **all** return
`404 {"error":"not_found"}` with no timing-distinguishable path. The real reason
goes into the audit `detail` only. Anything else turns the public endpoint into
an oracle: "this link exists but is exhausted" tells an attacker they hold a
valid uid, and a distinct response for an unlisted address would enumerate the
recipient list (§6.9).

---

## 9. Configuration (`share_service` env)

All of it belongs to `share_service` unless marked otherwise. **Nothing here goes
in `core.conf`** — the core has no share configuration because it has no share
feature (§4).

> Note the two `share.*` namespaces: the **configuration** keys below, and the
> per-file **metadata** keys in §6.8 (`share.link_uid`, `share.verified_email`,
> `share.source_addr`, `share.claimed_name`). They never appear in the same
> place, but the shared prefix is worth knowing before grepping.

| Key | Default | Meaning |
|---|---|---|
| `share.enabled` | `false` | Deployment kill switch. Off ⇒ creation refuses and the public prefix 404s wholesale. **Off by default** — an unauthenticated door is opt-in. Not deploying the service at all is the stronger form of the same switch, and is now available. |
| `share.core_grpc` | `core:50051` | The core endpoint delegated calls go to. The service is a trusted gRPC caller like every other feature service, so this address must stay on the internal network (`CLAUDE.md`: gRPC must never be network-exposed). |
| `share.ldap_group` | `share_external` | The group whose members may mint links (§8.1). |
| `share.max_body_bytes` | `100 MiB` | Request-body cap on the public prefix. Replaces the bridge's `max_body_bytes`, which no longer sits in front of this traffic. |
| `share.max_ttl_days` | `30` | Cap on `expires_at`; the UI cannot offer longer. |
| `share.max_uses_cap` | `100` | Cap on `max_uses`; `0` (unlimited) is only accepted if this is `0`. |
| `share.default_ttl_days` | `7` | Pre-filled in the UI. |
| `share.session_ttl_seconds` | `3600` | Redemption-session lifetime (§6.4). |
| `share.max_sessions_per_hour` | `20` | Sessions one link may open per hour, independent of the use cap (§8.4). |
| `share.max_recipients` | `20` | Addresses one link may be minted for. |
| `share.otp_ttl_seconds` | `600` | Code lifetime — **10 minutes** (§6.9). Long enough to survive mail-delivery latency and a recipient who switches devices to read it; short enough that a code sitting in an unattended inbox is not a standing credential. Note it is deliberately *shorter* than the `3 / 15 min` send window below, so a recipient whose code expires can always request another without being rate-limited for it. |
| `share.otp_max_attempts` | `5` | Wrong codes per `(link, email)` per window before that address is locked out (§8.4 rung 1). Counted against the **address**, not the challenge, so requesting a fresh code does not restore attempts. |
| `share.otp_min_seconds_after_send` | `5` | Minimum plausible gap between mailing a code and someone submitting it (§8.4 rung 0). |
| `share.otp_min_submit_interval_ms` | `1500` | Minimum plausible gap between two consecutive code submissions. |
| `share.otp_timing_weight` | `5` | How much an attempt that trips either timing check counts toward the link-level counter. Never a distinct response — only a heavier count (§8.4). |
| `share.link_lockout_threshold` | `15` | Failed verifications across any addresses within the window before the **link** locks (§8.4 rung 2). `3` distinct addresses hitting rung 1 trips it too. With the weight above, one scripted burst reaches this in three attempts. |
| `share.lockout_window_minutes` | `60` | The rolling window `failed_attempts` is counted over. |
| `share.lockout_minutes` | `15` | How long `locked_until` holds. Temporary by design — a lockout never revokes, or anyone holding the URL could destroy the link (§8.4). |
| `share.otp_send_limit` | `3 / 15 min` per `(link, email)`, `20 / day` per link | `rate_ok` buckets. |
| `share.recipient_ttl_seconds` | `86400` | Recipient-token lifetime — how long a verified recipient can open further sessions without a new code. |
| `share.attention_events` | `drop_received, otp_send_failed, link_dead, first_redemption` | Which share events raise a creator attention item (§10.6). `budget_exhausted` / `expiry_soon` are available and off by default — they are the two most likely to become noise. |
| `share.upload_max_files` | `20` | Default file count for a new upload link (`max_files`). Bounds how many files may be dropped in total; `max_uses` separately bounds sessions (§6.4). |
| `share.upload_max_bytes` | `1 GiB` | Default byte budget for a new upload link. |
| `share.upload_max_file_bytes` | `256 MiB` | Default per-file cap. |
| `share.zip_max_bytes` | `2 GiB` | Largest folder snapshot a link may be minted over; refused at creation (§6.1). |
| `share.zip_max_members` | `5000` | Same, by file count. |
| `share.zip_deflate` | `false` | Compress instead of store — forfeits `Content-Length` and resume-free progress (§6.5). |
| `share.zip_max_concurrent` | `4` | Simultaneous zip streams per bridge instance. |
| `share.retention_days` | `365` | How long dead rows — including recipient addresses (PII, §5.4) — are kept for audit (§5.5). |
| `SHARE_PUBLIC_BASE_URL` | derived from `Host` | The origin URLs are built from at creation. Set explicitly to move share traffic to a separate download host later without invalidating links already sent (§8.3). |

---

## 10. Frontend

### 10.1 The drawer tab

`FileDetailsDrawer.vue` gains **`Share`** in `visibleTabs` (`:245–253`), shown
only when the user is in the `share_external` group, holds READ/WRITE on the
item, and `share.enabled` is
advertised by `share_service`. A file gets the download-link form; a **folder gets
both**, as a two-way choice at the top of the tab — *"Let someone download this
folder"* vs *"Let someone send you files"* — since a folder can carry links of
either kind at once. The tab is deliberately **separate from `Access`** — Access
is "which of our people", Share is "someone outside" — and the empty state links
to the Access tab for the common case where the user actually wanted ACLs.

Create form: **recipients** (an email-chip field, at least one, capped at
`share.max_recipients`); expiry (presets + date picker, clamped to
`share.max_ttl_days`); max downloads / max files and an optional per-recipient
cap; optional note; plus per kind. There is **no "email it for me" option** — the
creator sends the link themselves (§13-R9), and the form should say so plainly
next to the recipient field, because an address entered there does *not* mail
anyone: it authorizes them. That is a genuinely surprising distinction and the
one thing in this form a user can get wrong without noticing.

- **File download** — "always send the newest version" toggle (off = pinned,
  with the current version name shown).
- **Folder download** — **"include subfolders"** (on by default), which is the
  entire difference between the two folder shapes in R8: off sends the folder's
  own files, on mirrors the subtree. Both arrive as one zip, so the toggle should
  restate what the recipient will get rather than name the flag. Plus "include
  anything added later" (off = snapshot, §6.5). The form shows the resolved
  **member count and archive size** before the user commits — recomputed when the
  subfolders toggle changes, since that is exactly the moment the number moves —
  and refuses with a clear count/size when the folder exceeds `share.zip_max_*`.
  Worst-case egress (`archive size × max downloads`) is shown beside the use cap;
  it is the number that surprises people.
- **Upload** — **how many files** they may send (`max_files`, the number the
  creator actually thinks in), per-file cap, total byte budget, optional landing
  subfolder, optional extension allowlist. The session cap (`max_uses`) is not on
  this form: it defaults from `share.max_uses_cap` and exists so a drop box
  cannot be reopened indefinitely, not as something a creator should reason about
  (§6.4).

On success: the URL exactly once, in a copy-to-clipboard field, with the existing
`QrCode.vue` beside it (a QR of a one-time drop link is genuinely useful on a
job site) and an unmistakable *"this is the only time this link is shown"*
notice.

Beside it, a second **copy-the-whole-message** control — the block the creator
pastes into their own mail (§13-R9):

> *Drawings – Level 3 · 38 files, about 412 MB*
> `https://acme.example.com/s/9f2c…`
> *Expires 26 Aug 2026 · 5 downloads · you'll be emailed a code when you open it.*

This exists because v1's hand-off is manual, and a bare URL leaves the creator to
explain the OTP step themselves — the step their recipient is most likely to
mistake for phishing. The last clause is the one that must not be dropped: an
unexpected code request on an unfamiliar domain is exactly what security training
tells people to ignore. For a folder link the size line is the R9 payload, so the
recipient is not surprised by 412 MB on a phone.

### 10.2 Status and history — did they actually get it?

The question a sharing user asks five minutes after sending a link is *"did it
arrive, and did they open it?"* — and with no account on the far side, the Share
tab is the only place that can answer. This is not a nice-to-have panel; it is
what makes an unauthenticated hand-off usable by someone who is accountable for
the document.

#### Link-level status

Each link in the list shows one computed state, not a pile of raw fields:

| Badge | Meaning |
|---|---|
| **Active** | Redeemable right now. Shows the expiry countdown and `3 / 5 used`. |
| **Exhausted** | Use budget spent. Distinct from expired — the fix is a new link, not a longer one. |
| **Expired** | Past `expires_at`. |
| **Revoked** | Revoked by *(who, when)*. |
| **Blocked** | `locked_until` is live after repeated bad secrets or codes (§8.4) — someone is probing it. |
| **⚠ Not working — you no longer have access** | The §6.3 re-check now fails for the creator. |

That last state earns its prominence. Because a link carries its creator's
*current* authority, a link can stop working with nothing about the link having
changed — someone edited an ACL three folders up, or the pinned version was
culled. Without this badge the creator's experience is "my recipient says the
link is broken and everything looks fine to me", which is the single most
expensive support conversation this feature could generate. The list therefore
runs the same pre-flight as creation (§6.1) when the tab opens, and names the
reason in a tooltip.

#### Per-recipient status

Because the recipient set is closed (§6.9), the useful view is a **roster**, not
an event stream — "who has picked this up and who hasn't" is the actual
question. One row per address, with a status ladder:

| Status | Reached when |
|---|---|
| **On the list** | Added to the allowlist, by whom, when. The system has not mailed them — the creator sends the link themselves (§13-R9) — so this rung says nothing about whether they *received* anything. |
| **⚠ Code send failed** | The OTP mail bounced or SMTP rejected (§6.9). Also raised as an attention item (§10.6) — the creator should not have to be looking at this roster to find out. |
| **Opened** | A code was requested — proof the person reached the landing page. |
| **Verified** | Code accepted; they proved control of the address. |
| **Downloaded** *(or **Dropped 3 files**)* | A session completed with bytes moved. Shows count, timestamp, and size. |
| **⚠ Code attempts failing** | Repeated wrong codes against this address. |

The roster answers "Priya has it, Marcus never opened the mail" at a glance,
which is what a person chasing a deliverable needs — and it doubles as the
nudge list.

#### History

Expanding a recipient (or the link's **History** view) shows the ledger from
`GET /share/v1/links/{link_uid}/redemptions` (§7.1), newest first: verified address,
timestamp, source IP, user agent, bytes moved, and — for a folder download — how
many members were served and how many were omitted by the §6.5 per-member
re-check. For an upload link each row links to the file the drop created
(`result_uid`), so "what did they send us" is one click, not a hunt through the
folder.

Failed attempts are summarised from the link's counters rather than the audit
log, so an ordinary user needs no `AUDIT_READ` scope to see that their link is
being probed. The full forensic trail stays in `audit_service` for anyone who
does (§12).

#### Actions on the roster

- **Resend invite** / **Resend code** — subject to the §9 send limits, with the
  remaining wait shown rather than a silent no-op.
- **Add recipient** — extends the allowlist after the fact (the common case:
  "loop in their site manager"). An **authenticated creator** may extend the
  list; an outside caller never can (§6.9). Audited as a permission change.
- **Remove recipient** — a partial revoke: kills that address's access while the
  link keeps working for everyone else. Cheaper and less disruptive than revoking
  and re-issuing, which would invalidate the URL for people who already have it.
- **Revoke** — the whole link, immediately.

### 10.3 The admin console — everything currently reachable from outside

A `tenant_admin` sees the Share tab's status model applied to the whole tenant at
`/admin/shares` (`meta: { requiresAuth: true, requiresAdmin: true }`, alongside
the existing admin routes in `src/router/index.ts:55–67`), backed by
`GET /share/v1/links?all=true` (§7.1).

**The question it answers** is not "list some rows" — it is *what is currently
reachable from outside this tenant, by whom, and who opened that door*. So the
default view is **live links only**, sorted by risk rather than by date: links
whose resource sits highest in the tree first, then by recipient count, then by
remaining budget. A hundred expired links are noise; one live link on a project
root shared with eleven outside addresses is the finding.

Columns: resource (deep-linked), kind, **creator**, recipient count, status badge
(§10.2), expiry countdown, uses `n / m`, and last activity. Filters that matter
in practice:

- **By creator** — the departed-employee query. Selecting a person shows every
  door they left open; **Revoke all** ends the review in one action, which is the
  whole point of having the console rather than a report.
- **By recipient address / domain** — "what did we ever send to
  `@contractor.example`", the question that arrives when a relationship ends or a
  counterparty is breached.
- **By resource subtree** — everything shared out of a given folder.
- **Status** — live / expired / revoked / **not working**, that last one being a
  useful queue in its own right: links a creator will complain about tomorrow.

**Admin powers stop at revocation.** The console can revoke a link or a
recipient, and read the ledger. It cannot *mint* a link on someone else's behalf,
cannot re-send a URL (the plaintext secret does not exist server-side, §8.2), and
cannot see file contents it would not otherwise be entitled to — the resource
column deep-links into the normal browser, where the admin's own ACLs apply. An
oversight surface should shrink the blast radius, not become a new way to
enlarge it.

Every action here is audited with the acting admin as `actor`, and the console
itself carries the honest caveat that a revoked link's *already-downloaded* bytes
are gone — revocation stops future redemptions, it does not un-send anything.

### 10.4 The recipient's view

New route `{ path: '/s/:token', name: 'ShareLanding', component: ShareLandingView,
meta: { requiresAuth: false } }` in `src/router/index.ts` — the same shape
`SsoLandingView` already uses (`:41`). The SPA fallback in
`docker_unified/images/nginx/snippets/tenant.conf` (`try_files … /index.html`)
means **no nginx change is required** for the route itself.

The view peeks (§6.4), then runs the **verification step first, before any of the
kind-specific UI**: an email field, then a 6-digit code field, then the payload
screen. The copy has to carry the uniform-response rule without sounding evasive
— *"If that address is on this link, a code is on its way"* — and must not hint
at how many recipients exist or who they are.

**The code-entry screen must assume the code did not arrive.** Mail is delayed,
filtered, and sometimes silently dropped, and the recipient has no account, no
support channel, and no way to tell a slow relay from a link that never worked.
So that screen carries, visibly and without the user having to ask:

- a **countdown** to the code's 10-minute expiry (`share.otp_ttl_seconds`, §9),
  so a stale code is self-evident rather than a mysterious rejection;
- **"Didn't get a code? Send another"**, enabled the moment the send limit
  allows and showing the remaining wait when it does not (never a dead button
  and never a silent no-op) — this re-posts `/identify` (§6.9);
- after a resend, **"use the code from the newest email"**, because the previous
  code is now invalid and a delayed first mail will otherwise be tried first;
- on a wrong code, how many attempts remain, and on lockout **when it lifts** —
  the recipient must be able to distinguish "wait 15 minutes" from "this link is
  broken".

**But all of that is pre-verification, so it must be identical for a listed and
an unlisted address.** Everything on this screen is shown to a caller who has
proved nothing yet — anyone holding the URL can type an address and reach it. If
a listed address produced a countdown and an attempt counter while an unlisted
one produced anything else, the screen would be exactly the recipient-list oracle
§6.9 closed at `/identify`. Two rules follow, and they are cheap:

1. The countdown and the "code sent" state are rendered from the **uniform**
   `/identify` response — the page always shows them, whether or not a code was
   really minted.
2. The attempt bucket is keyed on the **submitted** address
   (`share_otp:{link}:{email}`) whether or not it is on the allowlist, so an
   unlisted address burns and reports the same budget, hits the same lockout,
   and sees the same words. Uniformity here costs one Redis key per probed
   address — bounded by the same per-IP rate limit as everything else on the
   public prefix (§8.4).

The §8.5 uniform-failure rule therefore holds all the way through verification.
It relaxes only *after* a recipient token exists: a caller who has proved control
of a listed address may be told plainly that their session expired or their link
is exhausted, because at that point they are a known recipient and the disclosure
is to the person the link was minted for.

After verification the view shows one of:

- **File download:** file name, size, "expires in 6 days", "2 downloads left", a
  Download button. Nothing else — no nav bar, no tenant branding beyond the logo,
  no login affordance.
- **Folder download:** folder name, "38 files, 412 MB", a collapsible member
  list (from `/manifest`), and one Download button producing the zip. The list
  is read-only text — no per-file fetch, no preview, no navigation.
- **Drop:** a drop zone reusing `UploadTray.vue`, the remaining budget
  ("4 of 5 files, 780 MB left" — `max_files` and `max_bytes`, never the session
  count, which is not the sender's business), an optional free-text name
  (`share.claimed_name` — the address is already verified, so there is no email
  field here), and a list of what *this* session dropped. A file that fails
  mid-upload releases its slot and the counter goes back up (§5.3), so the
  displayed budget is refreshed from the server after each file rather than
  decremented locally. On completion, a plain confirmation.

All three render a session-less shell: `AppNav` is not mounted, and no call on
this page may carry a bearer token even if one is in `localStorage`.

### 10.5 Help

New `frontend/src/help/content/share-links.md` (category *Permissions*,
`related: [sharing, acl-basics]`), and a paragraph in the existing
`sharing.md` pointing at it — "sharing with someone who has no account". Per
project convention end-user docs live in the frontend repo, and this doc is the
internal counterpart, not a substitute.

### 10.6 The Dashboard — attention items and a Sharing panel

The Share tab (§10.2) answers *"how is this link doing"* for a link the user has
already navigated to. That is the wrong shape for the two questions that actually
need answering unprompted: **"something needs me"** and **"what have I got open
right now"**. Both belong on the Dashboard, and the Dashboard already has the
two idioms for them — the *"Needs your attention"* feed and the `ReviewsInbox`
panel (`frontend/src/views/DashboardView.vue`).

#### Share events in the attention feed

Share events join the existing feed rather than growing a parallel one — one
place a user looks, one unread badge, one seen-state. The feed is owned by
**`discussion_threaded_communication`** (`src/discussion/notifications.py`,
surfaced via `discussionService.attention()` on a ~30 s poll), which is why that
repo is now in this document's scope.

Events raised (subject to `share.attention_events`, §9):

| Item | Raised when | Why it earns an interrupt |
|---|---|---|
| **A drop arrived** | An upload session completed with bytes | A drop box nobody watches is useless; this is the feature's only inbound signal. |
| **⚠ Your link stopped working** | The §6.3 re-check now fails for the creator | Otherwise the creator learns from the recipient, and cannot explain it (§10.2). |
| **⚠ We could not send a code** | The OTP mail failed (§6.9) | Indistinguishable from a wrong address if it stays silent — and now the only mail path (§13-R9). |
| **First redemption** | The first session opens on a link | Carries a verified name — *"alice@contractor.example downloaded Drawing-A.pdf"* — which is the confirmation a sender is waiting for having posted the link themselves. |

#### The feed needs divisions by originating system

Today the feed is one undifferentiated list because everything in it comes from
one system — threads and reviews, both `discussion`'s. Share links are the
**third** kind of thing to write into it, and a flat list of "someone mentioned
you", "a review is waiting", "a stranger dropped a file into your folder" reads
as noise: those items want different reactions, on different timescales, from
different parts of the user's day.

So the feed renders **grouped by source system**, each division with its own
heading and unread count, in a fixed order (Comments · Reviews · Sharing), empty
divisions omitted. The Dashboard's single unread badge stays the total, so
nothing about the "one place to look" property changes — only the reading of it.

Mechanically this wants a **`source` field returned by the API**, not a prefix
convention parsed in the SPA: `notifications.py` grows `SOURCES` alongside
`KINDS` and maps kind → source at write time (`mention`/`reply`/`thread_resolved`
→ `comments`; `review_*` → `reviews`; `share_*` → `sharing`). Deriving it in the
frontend by string-matching the kind would put the mapping in the one place that
does not know when a new kind is added — the same failure mode as constraint 1
below, one layer up. A source the SPA does not recognize renders under its own
raw heading rather than disappearing.

This is a change to a **shared surface**: the divisions must land in
`discussion`'s API and `DashboardView.vue` whether or not share links ship, and
they improve the existing two systems on their own. Worth sequencing as its own
small piece of work (§14, M8) rather than smuggling it in as share-link scope —
it touches a feed users already rely on.

Four integration constraints, from the code as it stands — none hard, all silent
if missed:

1. **`KINDS` is a closed allowlist and `add()` drops unknown kinds without
   erroring** (`notifications.py:30,45` — `if … kind not in KINDS: return`). The
   new share kinds must be appended there or every share notification vanishes
   with no log line. Cheapest possible bug to write, hardest to notice.
2. **`add()` suppresses self-notification** (`user_id == actor → return`). Share
   items are *addressed to the creator*, so `actor` must be the share identity
   (`share:<link_uid>|<verified_email>`, per §6.8) and never `created_by` —
   otherwise a creator's own links can never notify them. For the two events with
   no external actor (link went dead, OTP send failed) the actor is the system;
   pick a reserved non-user string rather than the creator's name.
3. **The `notifications` row has nowhere to put a `link_uid`** — the columns are
   `(user_id, kind, file_uid, thread_id, review_id, actor)`. Add a nullable
   `share_link_uid`, and branch `attentionLink()` (`DashboardView.vue:96`) on it:
   share items deep-link to the resource's **Share tab**, not to
   `/preview/{fileUid}?thread=…`. The existing deep-link is doubly wrong for a
   folder-download link, since folders have no preview route at all.
4. **The feed re-checks READ per row on read** (`notifications.py` docstring) —
   and *"your link stopped working"* is most often raised precisely because the
   creator lost access to the resource. The one notification that matters most is
   therefore the one the READ filter would suppress. That row must be exempt from
   the per-row re-check, or carry enough denormalized text (resource name, link
   note) to be rendered without resolving the resource at all. **Prefer the
   second** — it keeps the filter honest and leaks nothing the creator did not
   already know when they minted the link.

**Where the events come from.** The discussion consumer already does
`XREADGROUP` over the core's event stream and maps `file.created/updated/…`
(`src/discussion/consumer.py`), so the seam is: the core emits `share.*` events
onto the same stream, the consumer grows one branch, and no new transport is
introduced. A drop additionally arrives as an ordinary `file.created` (§6.7), so
take care not to raise it twice.

*"Your link stopped working"* is the exception and needs a decision: it is a
**computed state with no triggering event** — nothing happens when an ACL three
folders up is edited. Options, cheapest first: evaluate the pre-flight for the
user's live links when the Dashboard loads (bounded by their link count, no new
machinery); or have the retention sweeper (§5.5) re-run the pre-flight on live
links and emit `share.link_dead` on transition. **Recommend the Dashboard-load
evaluation for v1** — it is the same call §10.2 already makes, and a link that is
dead but unnoticed costs nothing until someone looks.

#### The Sharing panel

Alongside `ReviewsInbox`, a `SharingInbox` section — the same idiom, the same
place, the standing answer to *"what have I got open right now"*. Grouped, not a
flat list:

- **Needs attention** — dead links, failed sends, drops not yet looked at. Empty
  most days, and that emptiness is the point.
- **Drop boxes** — open upload links with what has landed in each ("3 of 5 files
  used, 2 new"), since a drop box is a thing you are *waiting on* and the one
  share shape with an inbox character.
- **Active links** — outbound links still live, newest first, with the §10.2
  status badge, the expiry countdown, and `n / m` used. Expired and revoked links
  are not shown here; the Share tab is where history lives.

Every row deep-links to the resource's Share tab. The panel is per-user and
reuses `GET /share/v1/links` (§7.1) — no new route — and reuses the status computation
from M5 rather than re-deriving it. `tenant_admin`'s tenant-wide view stays a
separate surface (§10.3): this panel is *your* links, not the deployment's.

---

## 11. Other doors

- **WebDAV** — no change. Share links are an HTTP/browser concept (the OTP
  exchange needs a browser); the WebDAV door has no session-less mode and gains
  none.
- **MCP** — deliberately **not** exposed in v1. Minting a link that reaches
  outside the tenant is exactly the action an agent should not be able to take
  from a prompt-injected document (the roadmap's own confused-deputy concern,
  §9.2). If it is ever wanted, it wants the interactive-consent path, not a tool
  call. This is now *structurally* true rather than a policy: the MCP server
  talks to the core, and the core has no share operations to expose.
- **CSAI / discussion / folder_actions** — no change. Outside drops arrive as
  ordinary `file.created` events and are indexed, converted, and processed
  normally.
- **`fileengine_cli`** — **no change, and no share subcommand.** The CLI is a
  core gRPC client, and the core has no share RPCs; a `share create` there would
  mean either a second client for `share_service`'s REST API or exactly the core
  surface §4 removed. Scripted minting, if it is ever wanted, is an ordinary
  authenticated `POST /share/v1/nodes/{uid}/links` — `curl` and a bearer token,
  no new tool.
- **`http_bridge`** — **no change.** An earlier draft put the public routes, the
  zip writer, and the recipient-token minting here. All of it moved to
  `share_service` (§7), and the bridge keeps its single unauthenticated-path
  allowlist rather than growing a second family of exceptions.

---

## 12. Audit events (`audit_service`)

New actions, added to `codes.py` and `audit_entry.h`'s string map in lockstep
(append, never renumber — the header says so at `:25`):

| Action | Category | Fail-closed? | Notes |
|---|---|---|---|
| `share_link_create` | `permission` | **yes** | It is a grant of access; `is_fail_closed(Permission)` is already `true` (`audit_entry.cpp:62`). Creation must fail if it cannot be recorded. |
| `share_link_revoke` | `permission` | **yes** | Same reasoning. |
| `share_link_recipient_add` | `permission` | **yes** | Extending the allowlist widens who can reach the resource — the same class of change as the grant itself. |
| `share_link_recipient_remove` | `permission` | **yes** | The partial revoke (§10.2). |
| `share_link_redeem` | `access` (download) / `mutate` (upload) | **yes — overriding the category default** | `actor = "share:<link_uid>\|<verified_email>"`, `created_by` in `detail` — the door, the verified human, and the person accountable, in one record (§4.3). **This is the only place in the platform where the fact of external access exists.** The category default would make it fail-open like any other access event; here a lost event is external access that can never be attributed, so the redemption must not proceed if it cannot be recorded. `is_fail_closed()` is per-category, so this is an explicit per-action override — call it out in the emitter, because it reads as an inconsistency to anyone who does not know why. |
| `share_link_denied` | `access` | no | Outcome `denied`; `detail.reason` carries the real cause the caller never sees (§8.5). This is the event a rules-engine alert should watch — a burst of `denied` on one uid is a guessing attempt. |
| `share_link_challenge_sent` | `auth` | **yes** | An OTP was mailed (§6.9). `is_fail_closed(Auth)` is already `true` — consistent with the platform rule that auth events block the operation if they cannot be recorded. `detail` carries the address; `outcome = error` when SMTP failed, which is the event support will look for. |
| `share_link_challenge_verified` | `auth` | **yes** | The recipient proved control of the address. This is the event that makes a redemption attributable to a human. |
| `share_link_challenge_failed` | `auth` | **yes** | Wrong code, burned challenge, or an unlisted address — `detail.reason` separates them, the recipient's response does not. |
| `share_provenance_drift` | `permission` | no | Raised by `share_service`'s reconcile sweep when a dropped file's `share.*` metadata no longer matches the redemption ledger (§6.8) — i.e. someone edited it. The core does not reserve the namespace, so drift is **detected rather than prevented**; this event is the detection. `detail` carries the file uid, the ledger value, and the current metadata value. |
| `share_link_locked` | `permission` | **yes** | **The security alert** (§8.4 rung 2): a publicly reachable link crossed the brute-force threshold and is locked. Distinct from `share_link_denied` because it is an adjudicated conclusion, not a data point — the rules engine should alert on *this* directly rather than inferring it from a burst. `detail` carries the contributing addresses, source IPs, and whether the failures were wrong secrets, wrong codes, or both. Fail-closed for the same reason as the grant events: a lockout the log did not record is a lockout nobody can investigate. |
| `share_link_expired` | `admin` | **yes** | Emitted by the retention sweeper when a dead row is purged (§5.5). Fail-closed is not a concession to `is_fail_closed(Admin)` being `true` (`audit_entry.cpp:62`) — it is the right behaviour on its own: this event records the **destruction of audit evidence**, so if it cannot be written the purge must not happen. The sweeper skips the row and retries next pass; rows outliving `share.retention_days` during an audit outage is the harmless failure, and purging them unrecorded is not. |

**Correlation with the core's own events.** Every delegated call carries the
`redemption_uid` as `AuthenticationContext.claims["share.redemption_uid"]`
(`proto/fileservice.proto:76`) and in `AuditEntry.request_id` — a field the
envelope and the audit tables already have and nothing currently populates
(`audit_entry.cpp:104`, `database.cpp:138,2316`). The core's event for the same
operation therefore says *"Alice read X, request_id R"* while the service's says
*"bob@contractor.example redeemed link Y as Alice, redemption R"*, and the two
join on `R`. Without this the security log holds both halves of every external
access and no way to connect them.

`detail` carries `link_uid`, `resource_uid`, `created_by`, `verified_email`,
budgets, and `bytes_moved`; `target_uid` / `target_type` are the shared resource, so the
existing "everything that touched this file" query picks share traffic up with
no new query path.

For a folder download the redemption event additionally carries
`members_served` / `members_omitted` (§6.5) and the member uid list, so
"everything that left the building in that archive" is answerable per file
rather than only per folder — otherwise a zip is a hole in the very reverse
query this feature exists to keep answerable.

---

## 13. Decisions taken, and what is still open

Identifiers are stable: a question keeps its number when it is answered, so
**R1–R6** below are the resolved ones (R1 and R2 were originally posed as Q1 and
Q2).

**Nothing is open as of 2026-08-19.** The last four questions were answered
together and are recorded as **R7–R10**. Note they could *not* keep their
original numbers — R3–R6 were already taken by decisions that were never posed
as questions, so Q3→R7, Q4→R8, Q5→R9, Q6→R10. The mapping is spelled out in each
heading; the "identifiers are stable" convention above survives only because the
collision is documented rather than silently renumbered.

### Resolved (2026-08-19)

**R13 — Share links are a service; the core does not change.** *(Supersedes §4's
original argument, which concluded the opposite.)* The record, the public door,
and every share-specific decision live in a new **`share_service`**; the core
gains no tables, no RPCs, and no permission bit. A redemption is **delegated as
the creator** — a real principal with real LDAP roles and real ACLs, never a
synthetic `share:*` user — so the core is asked only questions it already
answers: `CheckPermission`, `Stat`, `StreamFileDownload`, `StreamFileUpload`,
`SetMetadata`. Three sub-decisions were taken with it:

- **Creation is gated by the `share_external` LDAP group plus a
  `CheckPermission` on the resource** (§8.1), not by a new ACL bit. Per-user
  rather than per-resource granularity is the accepted cost.
- **The `share.*` file metadata stays as a convenience copy**, unprotected and
  therefore not evidence; the redemption ledger and the audit chain are
  authoritative, and drift between them is detected rather than prevented
  (§6.8).
- **`share_link_redeem` becomes fail-closed**, overriding its category default.
  The security event chain is now the only place recording that an access was
  external, so an unwritten event is an access nobody can ever attribute (§4.3).

What this buys: the core stays the thing it is — the ACL enforcer, unaware of
sharing — and the feature can ship, change, and be redeployed without touching
C++ or the permission model. What it costs: **scope containment moves into the
service.** The core would have known a share credential was confined to one uid;
now the service holds the creator's whole authority and asks for a uid, so
nothing behind it catches a bug that asks for the wrong one. That is why the
"target uid comes only from the link record" rule (§4.3) and the admin-role
stripping (§6.3) are tested invariants of M0 rather than remarks in prose.

**R11 — The OTP gate is a brute-force surface, and says so.** The code is short
(6 digits) and the door is a public URL, so the attempt budget is not a
usability detail — it is the control standing between a leaked link and its
contents. Settled together: a **10-minute** code lifetime; a recipient-driven
**resend** so a delayed mail is recoverable; the attempt budget keyed to the
**address, not the challenge**, so the resend does not restore attempts; a
escalation from a **timing check** that catches scripted submission (rung 0)
through address lockout and link lockout to a correlated deployment signal
(§8.4); and a **dedicated `share_link_locked` audit action
that raises a security alert on its own** rather than waiting for a burst rule
to infer one. Lockout is always temporary and never auto-revokes — a link is
public, so anyone holding the URL could otherwise destroy it on purpose.

**R7 (was Q3) — Token in the URL: the path form, `/s/{uid}.{secret}`.**
The fragment form was the alternative, keeping the secret out of proxy and
access logs at the cost of `curl`, QR codes, and anyone who copies "the part
before the #". The decision rests on R4 having already demoted the token: a
leaked URL is inert without a code mailed to an address fixed at creation, so
the token is now the *weaker* of two factors and log hygiene is defence in
depth rather than the control. The compensating measures in §7.2 stand — nginx
must still strip the query string on the public location, and `share_service`
still logs `link_uid` and never the secret.

**R8 (was Q4) — A link is minted on one existing node; there is no file-picker.**
The decision is about **UI complexity**, not about the record: v1 does not build
a cross-folder selection surface, so a link is always minted on something the
user is already looking at. Exactly three download shapes, and they are the three
the schema already expresses:

| Shape | How it is expressed | The recipient gets |
|---|---|---|
| **A file** | `kind = 0` on the file | that file, at its pinned version (§6.2) |
| **A folder's contents** | `kind = 2`, `include_subdirs = false` | one zip of the folder's own files |
| **A folder and everything under it** | `kind = 2`, `include_subdirs = true` (the default) | one zip mirroring the subtree |

Plus `kind = 1`, the drop box, which is minted on a folder and is not a download
shape at all.

So `include_subdirs` (§5.1) is not an incidental flag — it is the whole
difference between the second and third shapes, and §10.1's *"include
subfolders"* checkbox is the only control the creator needs. No new field, no
new kind, no picker.

**This is a scope decision, not a uniqueness constraint.** A resource may carry
several live links at once, and must: a folder commonly holds a download link
*and* a drop box (§10.1), and re-issuing to a second set of recipients later
must not invalidate the URL the first set already has. Nothing here limits a
node to one link.

The v2 path — "share *these six* drawings from across two folders" — stays cheap
and needs no schema change: `share_link_members` (§5.2) has no folder dependency,
so an arbitrary uid set is a selection UI plus a creation call that takes a uid
list. It was deferred because that selection UI is the expensive half, and
because a folder is how people already organize the things they send together.

**R9 (was Q5) — Folder links: no cap change; surface the estimated archive size,
and the creator sends their own mail.** Two halves:

- **The size is the answer, not a smaller cap.** `share.zip_max_*` stays as the
  refusal boundary (§6.1). What was missing was not a lower limit but *telling
  people the number*: the creator sees member count and estimated archive size
  before committing (§10.1), and the recipient sees it on the landing page from
  `peek` (§7.2) before starting a download that might be 400 MB on a phone. The
  "6 000-file project folder" case is handled by the creator seeing the number
  and choosing a subfolder, not by the system guessing on their behalf.
- **v1 sends no invite mail.** The creator composes their own email and pastes
  the link — so creation must hand them a block worth pasting: URL, expiry, use
  budget, and for a folder the member count and archive size (§6.9, §10.1).
  This removes `send_invite`, `SHARE_INVITE_EMAIL`, `share.send_invite_default`,
  and the roster's *Invited / Invite failed* rungs from v1 scope. The OTP mail
  remains, and remains the only outbound mail — which means SMTP health now
  takes the feature down entirely rather than degrading it.

**R10 (was Q6) — Creator notifications: the Dashboard, not email.** Important
share events raise items in the existing *"Needs your attention"* feed, and the
Dashboard gains a **Sharing panel** beside `ReviewsInbox` for the standing
"what have I got open" view (§10.6). Three things follow that are decisions in
their own right:

- **`discussion_threaded_communication` joins the cross-repo scope** — it owns
  the attention feed and its store, so the new notification kinds, the
  `share_link_uid` column, and the source grouping land there.
- **The feed gains divisions by originating system** (Comments · Reviews ·
  Sharing). Share links are the third system to write into a feed built when
  there was only one, and a flat list of mentions, review requests, and outside
  drops reads as noise. The division improves the existing surfaces on its own
  and is sequenced as its own work (§14, M8).
- **No email notifications to the creator in v1.** Consistent with R9: the
  feature's only outbound mail is the recipient's OTP. A creator who wants a
  mail digest already has one — `discussion`'s digest job — and that is where
  the follow-on belongs if it is wanted.

### Resolved (2026-08-17)

**R1 — Passphrase: dropped.** *(Reversed once R4 made recipient verification
mandatory.)* An optional passphrase was proposed as the "email the link, text the
code" second factor. R4 supplies a strictly better one: the OTP goes to an
address fixed at creation, expires, is single-use, and **names the person who
used it** — none of which a shared passphrase does. Keeping both would mean two
secrets to distribute out-of-band for one property, and a passphrase is the half
that gets written in the same email as the link. Removes
`passphrase_salt`/`passphrase_hash` from `share_links`, the PBKDF2 work from the
core, and the `/unlock` route from the public surface.

**R2 — Folder download: in v1.** Store-only zip64 over a creation-time member
snapshot, assembled in `share_service` (**was** the bridge — moved by R13), with
the member set and exact archive length
frozen at session open (§6.5, §7.3). This is the largest single piece of new
work in the proposal — it adds a zip writer, a members table, a
per-member authority pass, and a genuine egress-amplification surface on an
unauthenticated route (§8.4). Two sub-decisions were taken with it and are worth
revisiting if the first real corpus argues otherwise:

- **Snapshot by default, not a live walk.** Symmetric with §6.2's version
  pinning, and the bigger of the two leaks — a live folder link keeps exposing
  whatever lands in the folder next month.
- **Store-only, not deflate.** Buys an exact `Content-Length` (progress bars,
  precise egress budgeting) at a ratio cost that is near zero for PDF/IFC/image
  corpora. `share.zip_deflate` flips it for text-heavy folders.

**R3 — XSS boundary: header triple, no origin split** (§8.3), with
`SHARE_PUBLIC_BASE_URL` in place from day one so the split stays available
later without invalidating live links. The two guards in §8.3 are the price of
choosing the maintained property over the structural one.

**R4 — Recipient email gating: in v1, and mandatory.** *(Reversed 2026-08-17;
the earlier draft deferred this to v2.)* Every redemption — download **and**
drop — requires the recipient to enter an email address, receive a one-time code
there, and enter it before a session opens (§6.9). Two things follow that are
worth stating as decisions in their own right:

- **Recipients are an allowlist fixed at creation, and there is no open-email
  mode.** Accepting any address the visitor types would make an unauthenticated
  caller the chooser of a destination for tenant-branded mail — an open relay
  backed by the deployment's sending reputation. The closed list removes the
  capability rather than rate-limiting it, and as a side effect makes the link
  genuinely non-forwardable. The cost is real and accepted: "post the link and
  let whoever needs it grab it" is no longer supported.
- **`ldap_manager` joins the cross-repo scope**, owning code generation,
  delivery, single-use verification, and the send/attempt rate limits — reusing
  `TokenStore.issue_code` / `consume_code` / `rate_ok` and the
  `require_internal` server-to-server seam the 2FA flow already established.
  Share links now depend on **Redis and SMTP** being healthy; both fail closed.

**R5 — Creator role resolution at redemption: live from LDAP** *(via the bridge
as originally decided; the resolver moved to `share_service` under R13, the
mechanism is unchanged)*
(§6.3, verified against the code). The earlier draft assumed the core could
re-resolve the creator's roles from `user_roles` and proposed refusing links
whose access came from a request-attached role. Both halves were wrong on the
facts: `user_roles` is effectively always **empty** in this platform (roles live
in LDAP `groupOfNames`, administered through `ldap_manager`; the core's
`AssignUserToRole` is off that path), so "refuse when the DB has no role" would
refuse links inside any **"Gated section (role)"** folder — one of the two
one-click templates the product ships. The resolved design instead has the
bridge call the existing `getRolesByTenant(created_by)` at redemption (current,
never snapshotted), **strips `system_admin` / `tenant_admin` / `administrators`**
so the ACL bypass can never reach a session-less route, and runs the identical
check as a **pre-flight at creation** so a link that would be born dead is
refused with a reason instead of 404-ing the recipient.

**R6 — Tenant-wide admin console: yes.** A `tenant_admin` gets one view of
**every live link in the tenant** — the deployment's answer to "what is currently
reachable from outside, by whom, and who opened that door" (§10.3). It is the
concrete form of the roadmap's *"every object a departed employee could still
reach via lingering share links"* reverse query, and it is nearly free: the
tables and the per-link status computation already exist for the Share tab, so
the console is a different query over the same data plus one route.

### Still open

**Nothing.** Q3–Q6 were answered on 2026-08-19 and are recorded above as R7–R10;
Q7 (the tenant-wide admin console) was resolved earlier as R6; R11 settled the
OTP gate's abuse posture at the same time.

Deferred to v2 by the decisions above, collected here so they are not rediscovered
as gaps: the cross-folder file picker and arbitrary multi-file links (R8),
system-sent invite mail and its `invite_sent_at` / `invite_error` reporting (R9),
and email notification of the creator (R10).

**R12 — the four review corrections, applied.** All four were internal
inconsistencies rather than open questions, and all four are now fixed in place:

- **Uploads count files, not sessions.** §6.4 said a use was a session; §6.7 said
  `max_uses` was the file count. New `max_files` / `files_consumed` columns
  (§5.1), a use is a session for every kind without exception, and the file slot
  is reserved before bytes are stored and released on failure.
- **The per-recipient counter moves with the pool.** §5.3's "one statement, no
  races" was true of the shared pool and false of the pair. One statement now,
  with the link row `FOR UPDATE` and the *recipient* update gating the pool
  update — the ordering matters, since the reverse burns a use before
  discovering the recipient was ineligible.
- **The zip length arithmetic has a CRC story.** Store-only headers need the CRC
  up front, the core stores no digest to look it up from, and computing one at
  creation means reading every byte while the creator waits. Entries are written
  with bit 3 and a 24-byte zip64 data descriptor, which is now a term in the
  `archive_bytes` formula (§6.5) rather than a missing one.
- **`share_link_expired` is fail-closed.** It records the destruction of audit
  evidence, so a purge that cannot be recorded does not happen — which is also
  what `is_fail_closed(Admin)` already does.

---

## 14. Implementation stages

1. **M0 — `share_service`: skeleton, model & delegation.** A new Python/FastAPI
   service on the folder_actions / difference pattern — health, readiness, the
   verbatim `metrics.py`, per-tenant schema provisioning, audit publishing to the
   Redis stream, bearer verification against the shared JWT secret. Then the
   model: `share_links` / `share_link_members` / `share_redemptions` /
   `share_link_recipients` (§5); link create / list / revoke; the **delegated
   core client** (`CheckPermission`, `Stat`, `StreamFileDownload`,
   `StreamFileUpload`, `SetMetadata` as `created_by`, §4.1); the `share_external`
   group gate plus `CheckPermission` at creation (§8.1); the §6.3 re-check with
   LDAP-resolved roles and **admin roles stripped**; the creation pre-flight; the
   recipient allowlist enforced at session open; audit emission with
   `request_id` correlation (§12).
   **Tests:** the authority re-check (creator loses READ mid-life); a link inside
   a `DENY everyone + ALLOW role` gated section redeeming correctly with resolved
   roles and failing without them; **admin roles never reaching the delegated
   call** — the invariant that now has no second line of defence behind it
   (§6.3); **the target uid comes only from the link record** and no caller input
   can redirect it (§4.3, the containment the core used to provide); atomic use
   consumption under concurrency **including the per-recipient cap** (concurrent
   sessions from one recipient must not overrun `max_uses_per_recipient`, and a
   recipient refused by their personal cap must not consume from the shared pool
   — §5.3); `max_files` bounding drops independently of `max_uses` with a failed
   upload releasing its slot (§6.4/§6.7); uniform failure; a session refusing to
   open for an address not on the allowlist; a wrong secret consuming an attempt
   but not a use; and **`share_link_redeem` failing closed** — with the audit
   sink unreachable, no bytes move (§4.3).
   **Verify the core is untouched:** this milestone must land with an empty diff
   against `file_engine_core`. That is the milestone's actual acceptance
   criterion, and it is worth checking mechanically rather than by intention.
2. **M1 — `share_service`: folder snapshots.** The creation-time walk and member
   capture (as the creator), `archive_bytes` computation, the per-member re-check
   at session open, the frozen member list on the redemption row. Kept separate
   from M0 because it is the one piece with real algorithmic content (§6.5, §7.3)
   and it should be testable against a fixture tree before any public surface
   exists. **Tests:** snapshot excludes later additions; a member gaining DENY is
   omitted and audited, not fatal; **archive-length arithmetic matches a real zip
   byte-for-byte** — the term that matters is the 24-byte zip64 data descriptor
   per entry (§6.5), so the test must extract with a real tool *and* compare the
   declared `Content-Length` to the produced byte count, including zip64 and
   empty directories; a member whose stored size no longer matches its bytes
   aborts the transfer rather than sending a short body; `archive_path` rejects
   `..` and absolute forms. **Measure** the N-`CheckPermission` fan-out at
   session open against a 5000-member fixture (§7.3).
3. **M2 — `share_service`: owner-side routes.** `/share/v1/nodes/{uid}/links`,
   `/share/v1/links/*`; URL assembly from `SHARE_PUBLIC_BASE_URL`; nginx `/share/`
   routing in `docker_unified`. No public surface yet — the model is exercisable
   end-to-end by an authenticated caller before any public door opens.
4. **M3 — `ldap_manager`: recipient OTP.** `POST /internal/share/email-challenge`
   and `/internal/share/email-verify` behind `require_internal`; `share_otp` token
   kind keyed by `link_uid|email`; the `SHARE_OTP_EMAIL` template (**only** — no
   invite template, R9) carrying the expiry deadline and send time; send/attempt
   rate-limit buckets keyed to the **address** (§8.4 rung 1); the **rung 0 timing
   checks** and their weighted counting; loud failure on SMTP error (unlike the
   2FA handler's swallow). Independent of M4 and parallelizable with it.
   **Tests:** code single-use and constant-time (inherited from `consume_code`),
   send limits, a resend replacing the live code without restoring attempts,
   the two timing thresholds counting heavily while responding identically,
   and SMTP failure surfaced rather than swallowed.
5. **M4 — `share_service`: public routes + zip writer.** `/share/v1/public/*`
   including `identify` / `verify` and the recipient token (in **shared storage**,
   never process memory — §7.4), the allowlist check, the uniform response for
   unlisted addresses, the per-challenge
   attempt counter; the separately-mounted public router (§7); the creator-role
   resolution over the service's LDAP bind on the redeem path (§6.3) with
   LDAP-unreachable failing closed; the store-only zip64 framer; response-header
   hardening (with the §8.3 all-routes test); per-IP rate-limit zone; concurrency
   cap; log scrubbing. **This is the review gate** — it warrants its own
   security-review pass before merge, and it is where an unauthenticated door
   first exists.
6. **M5 — Frontend: owner side.** Share tab — recipient chips (no invite toggle,
   R9), the file/folder-download/upload forms, member-count and archive-size
   preview, egress preview, QR, and the **copyable summary block** the creator
   pastes into their own mail (URL, expiry, budget, folder size — R9) — plus the
   **status and history** surface (§10.2): computed link badges including *"not
   working: you no longer have access"*, the per-recipient roster, the redemption
   ledger, resend code / add / remove-recipient / revoke. The status half is the
   part users will judge the feature by; it is not trimmable scope.
   Also the **Origin block** (§6.8) on any dropped file — `share.*` keys pulled
   out of the editable metadata table into a read-only provenance panel that
   states the owned-by / sent-by split in words, plus the browser's origin badge.
   Small, and the only thing standing between a dropped file and an `Owner` field
   that names someone who never touched it.
7. **M6 — Frontend: recipient side.** `/s/:token` landing, the email → code
   verification step, file download, folder download + manifest, drop flow.
8. **M7 — Frontend + bridge: admin console.** `/admin/shares` (§10.3) over
   `GET /share/v1/links?all=true` with the creator / recipient / subtree / status
   filters, bulk **Revoke all by creator**, and the read-only ledger. Gated on
   `tenant_admin`; reuses the status computation written in M5 rather than
   re-deriving it.
9. **M8 — Dashboard: attention items + Sharing panel** (§10.6, R10). Three
   separable pieces, in this order:
   - **M8a — feed divisions.** `source` on the notification API, `SOURCES`
     alongside `KINDS` in `discussion/notifications.py`, grouped rendering in
     `DashboardView.vue` (Comments · Reviews · Sharing). **Independent of share
     links entirely** — it improves the two existing systems and can ship first,
     which is the argument for doing it first: it is the only piece here that
     touches a surface users already depend on.
   - **M8b — share attention items.** New `share_*` kinds appended to `KINDS`;
     the nullable `share_link_uid` column; the `attentionLink()` branch to the
     Share tab; the `share.*` events emitted by the core and consumed by
     `discussion`'s consumer; the Dashboard-load pre-flight that raises *"your
     link stopped working"*. **Tests:** an unknown kind is rejected loudly rather
     than silently dropped; a creator's own link notifies them (the
     `user_id == actor` trap); a *link dead* item survives the per-row READ
     re-check when the creator has lost access to the resource.
   - **M8c — Sharing panel.** `SharingInbox` beside `ReviewsInbox` over
     `GET /share/v1/links`, reusing M5's status computation.
10. **M9 — Ops & docs.** `audit_service` codes; **a rules-engine alert on
   `share_link_locked` directly** (the adjudicated brute-force signal, §8.4
   rung 2) plus the broader `share_link_denied` burst rule; retention sweeper;
   `share-links.md` help page; `core.conf` / compose defaults
   (`share.enabled = false`). **Tests:** the three-rung escalation — an address
   locking out without affecting others, distinct addresses tripping the link
   lock, `failed_attempts` ageing out of its window and clearing on a verified
   redemption, and a lockout expiring on its own rather than revoking. Rung 0
   gets its own: a submission inside `otp_min_seconds_after_send` and a
   sub-interval retry each return a response **byte-identical** to an ordinary
   wrong code while counting at `otp_timing_weight`.

M0–M4 are the security-bearing work; M5–M9 are surface. M2 is deliberately
shippable on its own so the model can be exercised before a public door exists
anywhere; M1 is separable so the zip arithmetic is proven against fixtures
rather than debugged through an HTTP stream; M3 sits in a different repo, so it
can run in parallel with M2 once the two `/internal/share/*` request shapes are
agreed; and M8a sits in a *third* repo (`discussion_threaded_communication`)
with no dependency on any of it.

**`file_engine_core` is not on this list, and that is the point.** Every
milestone above lands in `share_service`, `ldap_manager`, `frontend`,
`discussion`, `audit_service` or `docker_unified`. If a milestone starts wanting
a core change, that is the signal to re-open §4 deliberately rather than to make
the change quietly — the whole architecture rests on the core staying unaware
that share links exist (§13-R13).

**Ops preconditions before M4 ships** — the unauthenticated door now depends on
more than the core: **Redis** (OTP storage) and **SMTP** (delivery) must be
healthy or no link can be redeemed, and the sending domain needs working
SPF/DKIM/DMARC or codes land in spam and every link looks broken. Verify these in
the target deployment before turning `share.enabled` on, not after the first
recipient complains.
