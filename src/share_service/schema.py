# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Per-tenant schema for share_service (spec §5).

One schema per tenant, created on first use — the pattern the other Python
feature services already use. **None of this lives in the core** (spec §4): the
only identifiers crossing that boundary are `resource_uid` / `member_uid` (core
file UIDs, opaque here) and `created_by` (an LDAP username).

DDL is idempotent (`CREATE TABLE IF NOT EXISTS` + `ADD COLUMN IF NOT EXISTS`) so
`ensure_tenant_schema` is safe to run on every connection to a new tenant.
"""
from __future__ import annotations

import re

_SAFE = re.compile(r"[^a-zA-Z0-9_]")

# Link kinds (spec §5.1). Stored as SMALLINT so they are wire/DB-stable.
KIND_FILE_DOWNLOAD = 0
KIND_UPLOAD = 1
KIND_FOLDER_DOWNLOAD = 2
# MEDIA_SHARE.md §6.1. resource_uid is the SOURCE file; what plays is its newest
# published `media` / `audio` rendition, resolved at session open and never
# stored or accepted from a caller.
KIND_MEDIA = 3
KINDS = (KIND_FILE_DOWNLOAD, KIND_UPLOAD, KIND_FOLDER_DOWNLOAD, KIND_MEDIA)

# MEDIA_SHARE.md §5. 'verified' is the default, so every existing row and every
# non-media link keeps today's behaviour with no migration.
ACCESS_VERIFIED = "verified"
ACCESS_CLAIMED = "claimed"
ACCESS_OPEN = "open"
ACCESS_MODES = (ACCESS_VERIFIED, ACCESS_CLAIMED, ACCESS_OPEN)

# A media link's readiness. NULL for every other kind.
MEDIA_PENDING = "pending_media"
MEDIA_READY = "ready"
MEDIA_FAILED = "failed"
MEDIA_STATES = (MEDIA_PENDING, MEDIA_READY, MEDIA_FAILED)


# The one table that is NOT per-tenant, and the reason it has to exist.
#
# A recipient clicking a link from their email presents a uid and a secret and
# nothing else — no session, no tenant, and no way to know one. The public route
# has to resolve which tenant's schema holds that link BEFORE it can look it up,
# and every other signal is unavailable or unreliable at that moment: there is no
# X-Tenant header on a cold navigation, and the Host is rewritten by any proxy
# that sets changeOrigin (the dev proxy does exactly this).
#
# Without it, a link minted in any tenant other than the default is
# unredeemable — it answers with the uniform "this link isn't available",
# which is indistinguishable from an expired link and therefore very hard to
# diagnose from the outside.
#
# It holds no secret: a uid is unguessable, the secret is not stored here, and
# anyone holding a working link learns the tenant from the content anyway.
GLOBAL_DDL = """
CREATE TABLE IF NOT EXISTS public.share_link_directory (
    link_uid   UUID PRIMARY KEY,
    tenant     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


def ensure_global_directory(conn) -> None:
    """Create the cross-tenant link directory (idempotent).

    Locked on a FIXED key, not a per-tenant one: this table is shared by every
    tenant, so the first connection for *any* tenant runs this DDL against the
    same object. A per-tenant key would let two different tenants' first
    requests collide on it — the one case where keying by tenant would look
    correct and serialise nothing."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                    (_PROVISION_LOCK_CLASS, "public.share_link_directory"))
        cur.execute(GLOBAL_DDL)
    conn.commit()


def schema_name(tenant: str) -> str:
    """`tenant_<sanitized>`, mirroring the core's own schema naming so a human
    reading two databases sees the same tenant spelled the same way."""
    return "tenant_" + _SAFE.sub("_", (tenant or "default").strip().lower())


def _ddl(schema: str) -> list[str]:
    s = f'"{schema}"'
    return [
        f"CREATE SCHEMA IF NOT EXISTS {s};",

        # --- share_links (spec §5.1) ----------------------------------------
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_links (
            link_uid        UUID PRIMARY KEY,
            kind            SMALLINT     NOT NULL,
            resource_uid    UUID         NOT NULL,
            secret_hash     BYTEA        NOT NULL,
            created_by      TEXT         NOT NULL,
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
            expires_at      TIMESTAMPTZ  NOT NULL,
            revoked_at      TIMESTAMPTZ,
            revoked_by      TEXT,
            -- Budgets. 0 = unlimited, subject to the deployment cap (spec §9).
            -- A "use" is a REDEMPTION SESSION for every kind, without exception
            -- (spec §6.4) -- which is why uploads need max_files as well.
            max_uses        INTEGER      NOT NULL DEFAULT 0,
            uses_consumed   INTEGER      NOT NULL DEFAULT 0,
            max_uses_per_recipient INTEGER NOT NULL DEFAULT 0,
            max_bytes       BIGINT       NOT NULL DEFAULT 0,
            bytes_consumed  BIGINT       NOT NULL DEFAULT 0,
            max_file_bytes  BIGINT       NOT NULL DEFAULT 0,
            max_files       INTEGER      NOT NULL DEFAULT 0,
            files_consumed  INTEGER      NOT NULL DEFAULT 0,
            -- File-download options
            pinned_version  TEXT,
            -- Folder-download options. include_subdirs IS the difference
            -- between two of the three share shapes (spec §13-R8), not a
            -- refinement of one.
            follow_folder   BOOLEAN      NOT NULL DEFAULT false,
            include_subdirs BOOLEAN      NOT NULL DEFAULT true,
            archive_bytes   BIGINT,
            -- Upload options
            landing_prefix  TEXT,
            ext_allowlist   TEXT[],
            -- Abuse (spec §8.4). failed_attempts is a ROLLING count, not a
            -- lifetime total: counts older than the lockout window are
            -- discarded and a verified redemption clears them, or ordinary
            -- typos accumulate into a permanent lockout.
            failed_attempts     INTEGER  NOT NULL DEFAULT 0,
            failed_window_start TIMESTAMPTZ,
            locked_until        TIMESTAMPTZ,
            note            TEXT
        );
        """,
        # --- oversight columns (spec §10.3) ---------------------------------
        # Both are recorded at CREATION, from the delegated core connection that
        # is already open, and both are deliberately a snapshot rather than a
        # live lookup:
        #
        #   * the admin console lists a whole tenant, and resolving a path per
        #     row would be one core round-trip per link on every page load;
        #   * /peek is unauthenticated and must never drive core work at all.
        #
        # The cost is that a later move or rename makes them stale, so the
        # console labels the column "at share time" rather than implying it is
        # current. Depth exists to answer the question the console is FOR — a
        # link on a project root is the finding, a link on one leaf file is
        # routine — so it sorts risk without needing the tree at read time.
        # Rung 2 of the abuse escalation (spec §8.4): which ADDRESSES have
        # tripped rung 1 inside the current window. Stored as short salted
        # hashes, never plaintext — distinctness is the only property needed,
        # and most of these addresses belong to people who are not recipients
        # and never consented to be recorded here.
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS failed_addresses TEXT[];",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS resource_depth INTEGER;",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS resource_path TEXT;",
        f"CREATE INDEX IF NOT EXISTS share_links_resource ON {s}.share_links (resource_uid);",
        f"CREATE INDEX IF NOT EXISTS share_links_creator  ON {s}.share_links (created_by);",
        f"CREATE INDEX IF NOT EXISTS share_links_live     ON {s}.share_links (expires_at) "
        f"    WHERE revoked_at IS NULL;",

        # --- media links (MEDIA_SHARE.md §5, §6.2) --------------------------
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS access_mode TEXT NOT NULL DEFAULT 'verified';",
        # 0 = no cap on distinct viewers (the egress budget still binds).
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS max_viewers INTEGER NOT NULL DEFAULT 0;",
        # frame-ancestors for the embed (§9.3); NULL = not embeddable.
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS allowed_embed_origins TEXT[];",
        # What the landing page and the embed title the video (§9.2).
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS display_name TEXT;",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS media_state TEXT;",
        # Stored so /peek and the embed answer without touching the core (§6.2
        # rule 4). Describe the newest published set this service has heard of.
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS media_version TEXT;",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS duration_ms BIGINT;",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS output_bytes BIGINT;",
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS poster_uid UUID;",
        # The rules are CONSTRAINTS, not route-handler validation (§5 rule 2):
        # a new endpoint that forgets to call a validator must still be unable
        # to write an open or claimed link of any other kind. Added only when
        # absent — ADD CONSTRAINT has no IF NOT EXISTS.
        _add_constraint(schema, "share_links_access_mode_valid",
                        "CHECK (access_mode IN ('verified','claimed','open'))"),
        _add_constraint(schema, "share_links_access_mode_media_only",
                        "CHECK (access_mode = 'verified' OR kind = 3)"),
        _add_constraint(schema, "share_links_media_state_valid",
                        "CHECK (media_state IS NULL OR "
                        "media_state IN ('pending_media','ready','failed'))"),
        # §5 rule 1: access_mode is immutable — widening an already-distributed
        # URL from verified to open must be IMPOSSIBLE, not merely audited. kind
        # is frozen with it, since flipping kind is the other way to change what
        # a URL already in someone's inbox does.
        f"""
        CREATE OR REPLACE FUNCTION {s}.share_links_freeze_mode() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        BEGIN
            IF NEW.access_mode IS DISTINCT FROM OLD.access_mode THEN
                RAISE EXCEPTION 'share_links.access_mode is immutable (link %)', OLD.link_uid
                    USING ERRCODE = 'check_violation';
            END IF;
            IF NEW.kind IS DISTINCT FROM OLD.kind THEN
                RAISE EXCEPTION 'share_links.kind is immutable (link %)', OLD.link_uid
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END
        $fn$;
        """,
        f"DROP TRIGGER IF EXISTS share_links_freeze_mode ON {s}.share_links;",
        f"CREATE TRIGGER share_links_freeze_mode BEFORE UPDATE ON {s}.share_links "
        f"FOR EACH ROW EXECUTE FUNCTION {s}.share_links_freeze_mode();",
        f"CREATE INDEX IF NOT EXISTS share_links_media_live ON {s}.share_links (resource_uid) "
        f"    WHERE kind = 3 AND revoked_at IS NULL;",

        # Rung 3 of the media ladder (§6.9): until when a link is parked. NOT a
        # revocation — anyone holding the URL could otherwise destroy the link.
        f"ALTER TABLE {s}.share_links ADD COLUMN IF NOT EXISTS parked_until TIMESTAMPTZ;",

        # --- share_link_audience (MEDIA_SHARE.md §7.1) ----------------------
        # NOT share_link_recipients. That table is an ALLOWLIST written by an
        # authenticated user; this one is an open-ended set written by outsiders,
        # and putting internet-created rows into the table that defines who is
        # authorized is a privilege bug two refactors away.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_link_audience (
            audience_uid     UUID PRIMARY KEY,
            link_uid         UUID        NOT NULL REFERENCES {s}.share_links(link_uid) ON DELETE CASCADE,
            email            TEXT,
            email_norm       TEXT,
            verified         BOOLEAN     NOT NULL DEFAULT false,
            on_allowlist     BOOLEAN     NOT NULL DEFAULT false,
            first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            sessions         INTEGER     NOT NULL DEFAULT 0,
            bytes_served     BIGINT      NOT NULL DEFAULT 0,
            coverage         BIT VARYING,
            coverage_pct     SMALLINT    NOT NULL DEFAULT 0,
            furthest_pct     SMALLINT    NOT NULL DEFAULT 0,
            plays            INTEGER     NOT NULL DEFAULT 0,
            completed_at     TIMESTAMPTZ,
            completion_basis TEXT,
            source_addr      TEXT,
            user_agent       TEXT,
            referer_host     TEXT,
            consent_text_id  TEXT,
            UNIQUE (link_uid, email_norm),
            CHECK (completion_basis IS NULL OR
                   completion_basis IN ('beacon','beacon+bytes','bytes-floor')),
            CHECK (coverage_pct BETWEEN 0 AND 100 AND furthest_pct BETWEEN 0 AND 100)
        );
        """,
        f"CREATE INDEX IF NOT EXISTS share_link_audience_link ON {s}.share_link_audience "
        f"    (link_uid, last_seen_at DESC);",

        # --- share_media_sessions (MEDIA_SHARE.md §6.3-6.4) -----------------
        # NOT share_redemptions. That table's verified_email is NOT NULL — the
        # schema-level statement that no session opens unverified — and a
        # claimed or open viewer is exactly that. Keeping the invariant intact
        # beats weakening it for a new kind.
        #
        # The session token is the viewer's credential for every ranged GET
        # (a <video> element cannot send a header), so only its hash is kept.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_media_sessions (
            session_uid    UUID PRIMARY KEY,
            link_uid       UUID        NOT NULL REFERENCES {s}.share_links(link_uid) ON DELETE CASCADE,
            audience_uid   UUID        REFERENCES {s}.share_link_audience(audience_uid) ON DELETE SET NULL,
            mode           TEXT        NOT NULL CHECK (mode IN ('verified','claimed','open')),
            token_hash     BYTEA       NOT NULL UNIQUE,
            opened_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at     TIMESTAMPTZ NOT NULL,
            last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
            checked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            bytes_served   BIGINT      NOT NULL DEFAULT 0,
            ended_at       TIMESTAMPTZ,
            end_reason     TEXT,
            source_addr    TEXT,
            user_agent     TEXT,
            referer_host   TEXT
        );
        """,
        f"CREATE INDEX IF NOT EXISTS share_media_sessions_link ON {s}.share_media_sessions "
        f"    (link_uid, opened_at DESC);",
        f"CREATE INDEX IF NOT EXISTS share_media_sessions_open ON {s}.share_media_sessions "
        f"    (expires_at) WHERE ended_at IS NULL;",

        # --- share_media_playback (MEDIA_SHARE.md §7.4) ---------------------
        # One row per viewing session: the cumulative state its beacons carried,
        # merged by UNION (coverage |) and maximum, so a lost beacon costs
        # nothing and a duplicated one is a no-op. Keyed on the media session —
        # the spec's sketch named share_redemptions, which media sessions are
        # deliberately not (see share_media_sessions).
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_media_playback (
            session_uid    UUID PRIMARY KEY REFERENCES {s}.share_media_sessions(session_uid) ON DELETE CASCADE,
            link_uid       UUID        NOT NULL,
            audience_uid   UUID,
            started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_beacon_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            buckets        SMALLINT    NOT NULL CHECK (buckets BETWEEN 1 AND 1000),
            coverage       BIT VARYING NOT NULL,
            furthest_ms    BIGINT      NOT NULL DEFAULT 0,
            watch_ms       BIGINT      NOT NULL DEFAULT 0,
            plays          INTEGER     NOT NULL DEFAULT 0,
            rate_max       REAL        NOT NULL DEFAULT 1.0,
            ended          BOOLEAN     NOT NULL DEFAULT false,
            quality        TEXT,
            device_class   TEXT CHECK (device_class IN ('desktop','mobile','tablet'))
        );
        """,
        f"CREATE INDEX IF NOT EXISTS share_media_playback_audience ON {s}.share_media_playback (audience_uid);",

        # --- the audience sidecar's state (MEDIA_SHARE.md §8.2) -------------
        # Which files have audience changes not yet projected, and the hash of
        # what each sidecar last held — so a debounced projection writes only
        # when something changed, and an idle link accrues no identical versions.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_audience_sidecars (
            resource_uid  UUID        NOT NULL,
            name          TEXT        NOT NULL,
            content_sha   BYTEA,
            written_at    TIMESTAMPTZ,
            last_error    TEXT,
            PRIMARY KEY (resource_uid, name)
        );
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_audience_dirty (
            resource_uid  UUID PRIMARY KEY,
            dirty_since   TIMESTAMPTZ NOT NULL DEFAULT now(),
            force         BOOLEAN     NOT NULL DEFAULT false
        );
        """,

        # --- share_link_members (spec §5.2) ---------------------------------
        # The folder-download snapshot. Deliberately NO crc32 column: filling
        # one would mean reading every member's bytes at creation, and the core
        # stores no digest to copy from. The CRC is computed as the bytes stream
        # and written into a per-entry zip64 data descriptor (spec §6.5).
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_link_members (
            link_uid     UUID   NOT NULL REFERENCES {s}.share_links(link_uid) ON DELETE CASCADE,
            member_uid   UUID   NOT NULL,
            archive_path TEXT   NOT NULL,
            version_name TEXT   NOT NULL,
            size_bytes   BIGINT NOT NULL,
            PRIMARY KEY (link_uid, member_uid)
        );
        """,

        # --- share_redemptions (spec §5.3) ----------------------------------
        # One row per consumed use: the counter's ledger and the forensic
        # record. verified_email is NOT NULL -- the schema-level statement that
        # no session opens unverified.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_redemptions (
            redemption_uid UUID PRIMARY KEY,
            link_uid       UUID        NOT NULL REFERENCES {s}.share_links(link_uid),
            opened_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at     TIMESTAMPTZ NOT NULL,
            verified_email TEXT        NOT NULL,
            source_addr    TEXT,
            user_agent     TEXT,
            bytes_moved    BIGINT      NOT NULL DEFAULT 0,
            files_moved    INTEGER     NOT NULL DEFAULT 0,
            result_uid     UUID,
            frozen_members UUID[],
            archive_bytes  BIGINT,
            completed_at   TIMESTAMPTZ
        );
        """,
        f"CREATE INDEX IF NOT EXISTS share_redemptions_link ON {s}.share_redemptions (link_uid, opened_at DESC);",
        # "Was this file dropped from outside, and by whom?", asked once per
        # file-list page. Keyed on the file UID, so the answer survives a move
        # or a rename -- a path-keyed marker would not.
        #
        # This ledger, not the core's share.* metadata, is what the UI reads.
        # Those metadata keys are a convenience copy for anyone inspecting the
        # file directly: the core reserves no namespace, so ANYONE WITH WRITE
        # CAN REWRITE THEM, which disqualifies them as evidence. This table
        # mirrors the audit chain, which is the actual source of truth and
        # outlives these rows when retention prunes them (spec §5.5).
        f"CREATE INDEX IF NOT EXISTS share_redemptions_result ON {s}.share_redemptions (result_uid) "
        f"    WHERE result_uid IS NOT NULL;",

        # --- share_drops ----------------------------------------------------
        # ONE ROW PER DROPPED FILE. share_redemptions has a single result_uid
        # column, which record_drop overwrote on every file — so a session that
        # dropped five files left provenance for exactly one of them, and the
        # other four looked like ordinary internal uploads in the file list.
        #
        # Provenance is a property of a FILE, not of a session: "who sent us
        # this?" is asked of a file, months later, by someone who never saw the
        # session. Modelling it per session was the mistake.
        #
        # Keyed on result_uid so the marker survives a move or rename, and so a
        # re-drop of the same uid cannot double-count.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_drops (
            result_uid     UUID PRIMARY KEY,
            redemption_uid UUID        NOT NULL REFERENCES {s}.share_redemptions(redemption_uid),
            link_uid       UUID        NOT NULL REFERENCES {s}.share_links(link_uid),
            stored_name    TEXT,
            size_bytes     BIGINT      NOT NULL DEFAULT 0,
            dropped_at     TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """,
        f"CREATE INDEX IF NOT EXISTS share_drops_link ON {s}.share_drops (link_uid, dropped_at DESC);",
        f"CREATE INDEX IF NOT EXISTS share_drops_redemption ON {s}.share_drops (redemption_uid);",

        # --- share_link_recipients (spec §5.4) ------------------------------
        # The closed destination set. PII in a tenant schema -- never logged,
        # and subject to the retention window (spec §5.5).
        #
        # invite_sent_at / invite_error are RESERVED and always NULL in v1: the
        # creator mails the link themselves (spec §13-R9), so the system never
        # sends an invite and has nothing to report. Kept so the v2 "email it
        # for me" option is a behaviour change, not a migration.
        f"""
        CREATE TABLE IF NOT EXISTS {s}.share_link_recipients (
            link_uid          UUID        NOT NULL REFERENCES {s}.share_links(link_uid) ON DELETE CASCADE,
            email             TEXT        NOT NULL,
            invited_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
            invited_by        TEXT        NOT NULL,
            invite_sent_at    TIMESTAMPTZ,
            invite_error      TEXT,
            last_code_sent_at TIMESTAMPTZ,
            first_verified_at TIMESTAMPTZ,
            last_used_at      TIMESTAMPTZ,
            uses_consumed     INTEGER     NOT NULL DEFAULT 0,
            failed_codes      INTEGER     NOT NULL DEFAULT 0,
            removed_at        TIMESTAMPTZ,
            removed_by        TEXT,
            PRIMARY KEY (link_uid, email)
        );
        """,
    ]


def _add_constraint(schema: str, name: str, definition: str) -> str:
    """``ALTER TABLE … ADD CONSTRAINT`` once. Postgres has no IF NOT EXISTS for
    constraints, and re-adding one on every provisioning would fail. Runs under
    the provisioning advisory lock like everything else here."""
    return f"""
        DO $do$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint
                            WHERE conname = '{name}'
                              AND conrelid = '"{schema}".share_links'::regclass) THEN
                ALTER TABLE "{schema}".share_links ADD CONSTRAINT {name} {definition};
            END IF;
        END
        $do$;
        """


# Namespace for the provisioning advisory lock — fixed, so these locks cannot
# collide with any other advisory lock taken on this database.
_PROVISION_LOCK_CLASS = 0x0D15C


def ensure_tenant_schema(conn, tenant: str) -> str:
    """Create the tenant's schema + tables if absent. Idempotent. Returns the
    schema name.

    Serialised across PROCESSES by an advisory lock: idempotent DDL is not the
    same as concurrency-safe DDL, and two transactions running these statements
    at once take table locks in interleaved order, which Postgres resolves by
    killing one with DeadlockDetected. ``db.connect_for_tenant`` holds the
    matching in-process lock; this covers separate processes, which cannot see
    each other's memo.

    Transaction-scoped, so the commit below releases it — this must therefore
    NOT be handed an autocommit connection, or the lock would be dropped before
    the DDL it guards."""
    name = schema_name(tenant)
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                    (_PROVISION_LOCK_CLASS, name))
        for stmt in _ddl(name):
            cur.execute(stmt)
    conn.commit()
    return name
