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

"""Link records: minting, reading, revoking (spec §5, §8.2).

The token is ``{link_uid}.{secret}`` — a 128-bit uid and a 256-bit CSPRNG
secret, base64url. **Only ``sha256(secret)`` is stored**, so a dump of
``share_links`` yields no live links, and the plaintext exists exactly once: in
the response to the creation call.

Everything here reads the target uid from the *stored row*. Nothing in this
module accepts a caller-supplied uid for an existing link — that containment
used to be the core's job and is now this service's (spec §4.3).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, List, Optional

from .config import Config
from .schema import KIND_FILE_DOWNLOAD, KIND_FOLDER_DOWNLOAD, KIND_UPLOAD

log = logging.getLogger("share_service.links")

_SECRET_BYTES = 32  # 256 bits


class LinkNotFound(LookupError):
    """No such link in this tenant, or not visible to this caller."""


# --- token ---------------------------------------------------------------

def mint_secret() -> str:
    """A 256-bit base64url secret (43 chars, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(_SECRET_BYTES)).decode().rstrip("=")


def hash_secret(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def secret_matches(secret: str, stored_hash: bytes) -> bool:
    """Constant-time compare (spec §8.2)."""
    return secrets.compare_digest(hash_secret(secret), bytes(stored_hash))


def split_token(token: str) -> tuple[str, str]:
    """``{link_uid}.{secret}`` -> (link_uid, secret). Raises ValueError."""
    uid, sep, secret = token.partition(".")
    if not sep or not uid or not secret:
        raise ValueError("malformed share token")
    return uid, secret


# --- rows ----------------------------------------------------------------

@dataclass
class Link:
    link_uid: str
    kind: int
    resource_uid: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    max_uses: int = 0
    uses_consumed: int = 0
    max_uses_per_recipient: int = 0
    max_bytes: int = 0
    bytes_consumed: int = 0
    max_file_bytes: int = 0
    max_files: int = 0
    files_consumed: int = 0
    pinned_version: Optional[str] = None
    follow_folder: bool = False
    include_subdirs: bool = True
    archive_bytes: Optional[int] = None
    landing_prefix: Optional[str] = None
    ext_allowlist: Optional[List[str]] = None
    locked_until: Optional[datetime] = None
    note: Optional[str] = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= datetime.now(timezone.utc)

    @property
    def is_exhausted(self) -> bool:
        return self.max_uses > 0 and self.uses_consumed >= self.max_uses

    def status(self) -> str:
        """The computed state the Share tab renders as one badge (spec §10.2).

        Ordering matters: revoked beats expired beats exhausted, because that is
        the order in which a human would want the reason explained. "Not
        working — you no longer have access" is *not* here: it needs a live
        pre-flight, so the API layer overlays it.
        """
        if self.is_revoked:
            return "revoked"
        if self.is_expired:
            return "expired"
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return "blocked"
        if self.is_exhausted:
            return "exhausted"
        return "active"


_COLUMNS = """link_uid, kind, resource_uid, created_by, created_at, expires_at,
              revoked_at, revoked_by, max_uses, uses_consumed,
              max_uses_per_recipient, max_bytes, bytes_consumed, max_file_bytes,
              max_files, files_consumed, pinned_version, follow_folder,
              include_subdirs, archive_bytes, landing_prefix, ext_allowlist,
              locked_until, note"""


def _row_to_link(row: tuple) -> Link:
    return Link(
        link_uid=str(row[0]), kind=row[1], resource_uid=str(row[2]),
        created_by=row[3], created_at=row[4], expires_at=row[5],
        revoked_at=row[6], revoked_by=row[7], max_uses=row[8],
        uses_consumed=row[9], max_uses_per_recipient=row[10], max_bytes=row[11],
        bytes_consumed=row[12], max_file_bytes=row[13], max_files=row[14],
        files_consumed=row[15], pinned_version=row[16], follow_folder=row[17],
        include_subdirs=row[18], archive_bytes=row[19], landing_prefix=row[20],
        ext_allowlist=list(row[21]) if row[21] else None,
        locked_until=row[22], note=row[23])


# --- writes --------------------------------------------------------------

def create(conn, *, kind: int, resource_uid: str, created_by: str,
           expires_at: datetime, recipients: Iterable[str],
           secret: Optional[str] = None, **budgets: Any) -> tuple[Link, str]:
    """Insert a link and its recipient allowlist. Returns (link, plaintext secret).

    The secret is returned, never stored — this is the only moment it exists
    outside the creator's clipboard.
    """
    secret = secret or mint_secret()
    link_uid = str(uuid.uuid4())

    fields = {
        "max_uses": 0, "max_uses_per_recipient": 0, "max_bytes": 0,
        "max_file_bytes": 0, "max_files": 0, "pinned_version": None,
        "follow_folder": False, "include_subdirs": True, "landing_prefix": None,
        "ext_allowlist": None, "note": None, "archive_bytes": None,
    }
    # Reject rather than ignore. Filtering silently to the known keys turns a
    # typo — or a newly added budget the INSERT does not carry yet — into a
    # link created with a default nobody asked for, which surfaces later as a
    # limit that mysteriously is not enforced.
    unknown = set(budgets) - set(fields)
    if unknown:
        raise TypeError(f"create() got unexpected link fields: {sorted(unknown)}")
    fields.update(budgets)

    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO share_links
                 (link_uid, kind, resource_uid, secret_hash, created_by, expires_at,
                  max_uses, max_uses_per_recipient, max_bytes, max_file_bytes,
                  max_files, pinned_version, follow_folder, include_subdirs,
                  landing_prefix, ext_allowlist, note, archive_bytes)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (link_uid, kind, resource_uid, hash_secret(secret), created_by, expires_at,
             fields["max_uses"], fields["max_uses_per_recipient"], fields["max_bytes"],
             fields["max_file_bytes"], fields["max_files"], fields["pinned_version"],
             fields["follow_folder"], fields["include_subdirs"],
             fields["landing_prefix"], fields["ext_allowlist"], fields["note"],
             fields["archive_bytes"]))

        for email in recipients:
            cur.execute(
                """INSERT INTO share_link_recipients (link_uid, email, invited_by)
                   VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
                (link_uid, email, created_by))
    conn.commit()
    return get(conn, link_uid), secret


def revoke(conn, link_uid: str, revoked_by: str) -> bool:
    """Idempotent. Returns True if this call performed the revocation."""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links SET revoked_at = now(), revoked_by = %s
                WHERE link_uid = %s AND revoked_at IS NULL""",
            (revoked_by, link_uid))
        changed = cur.rowcount > 0
    conn.commit()
    return changed


# --- reads ---------------------------------------------------------------

def get(conn, link_uid: str) -> Link:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_COLUMNS} FROM share_links WHERE link_uid = %s", (link_uid,))
        row = cur.fetchone()
    if not row:
        raise LinkNotFound(link_uid)
    return _row_to_link(row)


def list_for_resource(conn, resource_uid: str) -> List[Link]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_COLUMNS} FROM share_links WHERE resource_uid = %s "
                    f"ORDER BY created_at DESC", (resource_uid,))
        return [_row_to_link(r) for r in cur.fetchall()]


def list_for_creator(conn, created_by: str, live_only: bool = True) -> List[Link]:
    sql = f"SELECT {_COLUMNS} FROM share_links WHERE created_by = %s"
    if live_only:
        sql += " AND revoked_at IS NULL AND expires_at > now()"
    sql += " ORDER BY created_at DESC"
    with conn.cursor() as cur:
        cur.execute(sql, (created_by,))
        return [_row_to_link(r) for r in cur.fetchall()]


def recipients(conn, link_uid: str, include_removed: bool = False) -> List[dict]:
    sql = ("""SELECT email, invited_at, invited_by, last_code_sent_at,
                     first_verified_at, last_used_at, uses_consumed, failed_codes,
                     removed_at, removed_by
                FROM share_link_recipients WHERE link_uid = %s""")
    if not include_removed:
        sql += " AND removed_at IS NULL"
    sql += " ORDER BY invited_at"
    with conn.cursor() as cur:
        cur.execute(sql, (link_uid,))
        return [{"email": r[0], "invited_at": r[1], "invited_by": r[2],
                 "last_code_sent_at": r[3], "first_verified_at": r[4],
                 "last_used_at": r[5], "uses_consumed": r[6], "failed_codes": r[7],
                 "removed_at": r[8], "removed_by": r[9],
                 # v1 sends no invite mail (spec §13-R9), so "on the list" says
                 # nothing about whether they received anything.
                 "status": _recipient_status(r)}
                for r in cur.fetchall()]


def _recipient_status(r: tuple) -> str:
    if r[8]:                      # removed_at
        return "removed"
    if r[5]:                      # last_used_at
        return "used"
    if r[4]:                      # first_verified_at
        return "verified"
    if r[3]:                      # last_code_sent_at
        return "opened"
    return "on_the_list"


def add_recipient(conn, link_uid: str, email: str, invited_by: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO share_link_recipients (link_uid, email, invited_by)
               VALUES (%s,%s,%s)
               ON CONFLICT (link_uid, email)
               DO UPDATE SET removed_at = NULL, removed_by = NULL,
                             invited_by = EXCLUDED.invited_by""",
            (link_uid, email, invited_by))
        changed = cur.rowcount > 0
    conn.commit()
    return changed


def remove_recipient(conn, link_uid: str, email: str, removed_by: str) -> bool:
    """Partial revoke: that address loses access, the link keeps working for the
    rest. A soft delete, so the history survives (spec §5.4)."""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_link_recipients
                  SET removed_at = now(), removed_by = %s
                WHERE link_uid = %s AND email = %s AND removed_at IS NULL""",
            (removed_by, link_uid, email))
        changed = cur.rowcount > 0
    conn.commit()
    return changed


def redemptions(conn, link_uid: str, limit: int = 200) -> List[dict]:
    """The usage ledger for one link — who, when, from where, how much.

    This is what answers "did they actually get it?" for a hand-off with no
    account on the far side, and for a drop box it is "what did they send us":
    ``result_uid`` links to the file each drop created, so that is one click
    rather than a hunt through the folder.

    Newest first. `verified_email` is PII and belongs to the creator's own
    link — the route above it is what enforces that.
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT redemption_uid, opened_at, completed_at, verified_email,
                      source_addr, user_agent, bytes_moved, files_moved,
                      result_uid, archive_bytes,
                      coalesce(array_length(frozen_members, 1), 0)
                 FROM share_redemptions
                WHERE link_uid = %s
                ORDER BY opened_at DESC
                LIMIT %s""",
            (link_uid, limit))
        rows = cur.fetchall()
    return [{
        "redemption_uid": str(r[0]), "opened_at": r[1], "completed_at": r[2],
        "verified_email": r[3], "source_addr": r[4], "user_agent": r[5],
        "bytes_moved": r[6], "files_moved": r[7],
        "result_uid": str(r[8]) if r[8] else None,
        "archive_bytes": r[9], "members_served": r[10],
    } for r in rows]


def count_recipients(conn, link_uid: str) -> int:
    with conn.cursor() as cur:
        cur.execute("""SELECT count(*) FROM share_link_recipients
                        WHERE link_uid = %s AND removed_at IS NULL""", (link_uid,))
        return int(cur.fetchone()[0])


# --- validation helpers ---------------------------------------------------

def normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def clamp_expiry(cfg: Config, requested: Optional[datetime],
                 ttl_days: Optional[int]) -> datetime:
    """Resolve and cap the expiry (spec §9). No perpetual links: an absent
    request gets the default TTL, and nothing may exceed the deployment cap."""
    now = datetime.now(timezone.utc)
    cap = now + timedelta(days=cfg.max_ttl_days)
    if requested is not None:
        chosen = requested if requested.tzinfo else requested.replace(tzinfo=timezone.utc)
    elif ttl_days is not None:
        chosen = now + timedelta(days=ttl_days)
    else:
        chosen = now + timedelta(days=cfg.default_ttl_days)
    if chosen <= now:
        raise ValueError("expires_at must be in the future")
    return min(chosen, cap)


def kind_matches_resource(kind: int, is_dir: bool) -> bool:
    """File for kind 0, directory for kinds 1 and 2 (spec §6.1)."""
    if kind == KIND_FILE_DOWNLOAD:
        return not is_dir
    if kind in (KIND_UPLOAD, KIND_FOLDER_DOWNLOAD):
        return is_dir
    return False
