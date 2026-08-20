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
KINDS = (KIND_FILE_DOWNLOAD, KIND_UPLOAD, KIND_FOLDER_DOWNLOAD)


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


def ensure_tenant_schema(conn, tenant: str) -> str:
    """Create the tenant's schema + tables if absent. Idempotent. Returns the
    schema name."""
    name = schema_name(tenant)
    with conn.cursor() as cur:
        for stmt in _ddl(name):
            cur.execute(stmt)
    conn.commit()
    return name
