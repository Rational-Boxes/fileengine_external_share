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
import re
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

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


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
    # Snapshots taken at creation, for the admin console's risk ordering.
    # Stale after a move or rename by design (see schema.py).
    resource_depth: Optional[int] = None
    resource_path: Optional[str] = None

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
              locked_until, note, resource_depth, resource_path"""


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
        locked_until=row[22], note=row[23], resource_depth=row[24],
        resource_path=row[25])


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
        "resource_depth": None, "resource_path": None,
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
                  landing_prefix, ext_allowlist, note, archive_bytes,
                  resource_depth, resource_path)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       %s,%s)""",
            (link_uid, kind, resource_uid, hash_secret(secret), created_by, expires_at,
             fields["max_uses"], fields["max_uses_per_recipient"], fields["max_bytes"],
             fields["max_file_bytes"], fields["max_files"], fields["pinned_version"],
             fields["follow_folder"], fields["include_subdirs"],
             fields["landing_prefix"], fields["ext_allowlist"], fields["note"],
             fields["archive_bytes"], fields["resource_depth"],
             fields["resource_path"]))

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


def list_for_tenant(conn, *, live_only: bool = True, creator: str = "",
                    recipient: str = "", subtree: str = "", status: str = "",
                    limit: int = 500) -> List[dict]:
    """The tenant-wide oversight query behind ``/links?all=true`` (spec §10.3).

    Returns dicts, not ``Link`` objects, because the console needs two
    aggregates per row — recipient count and last activity — and fetching them
    per link would be an N+1 across a whole tenant.

    Ordered by RISK, not by date: shallowest resource first (a link on a project
    root is the finding; a link on one leaf file is routine), then by how many
    outside addresses can use it, then by how much budget is left. A hundred
    expired links are noise.
    """
    where = ["1=1"]
    params: List[Any] = []
    if live_only:
        where.append("l.revoked_at IS NULL AND l.expires_at > now()")
    if creator:
        where.append("lower(l.created_by) = lower(%s)")
        params.append(creator)
    if subtree:
        # Either a uid (the folder itself) or a path prefix. The uid branch is
        # guarded because resource_uid is a UUID column: handing it a path
        # string is a cast error, not an empty result.
        #
        # Prefix, anchored, and never a bare substring — "/projects/x" must not
        # match "/archive/projects/x-old". Matching the path captured at
        # creation rather than walking the live tree keeps this one query, at
        # the cost of missing resources MOVED into the subtree after being
        # shared; the UI labels the column "at share time" for that reason.
        if _UUID_RE.match(subtree):
            where.append("l.resource_uid = %s")
            params.append(subtree)
        else:
            base = subtree.rstrip("/")
            where.append("(l.resource_path = %s OR l.resource_path LIKE %s)")
            params.extend([base, base + "/%"])
    if recipient:
        # Substring, so "@contractor.example" answers the whole-domain question
        # ("what did we ever send there") and not just one address.
        where.append("""EXISTS (SELECT 1 FROM share_link_recipients r
                                WHERE r.link_uid = l.link_uid
                                  AND r.removed_at IS NULL
                                  AND r.email LIKE %s)""")
        params.append(f"%{recipient.lower()}%")

    sql = f"""
        SELECT {", ".join("l." + c.strip() for c in _COLUMNS.replace(chr(10), " ").split(","))},
               (SELECT count(*) FROM share_link_recipients r
                 WHERE r.link_uid = l.link_uid AND r.removed_at IS NULL),
               (SELECT max(opened_at) FROM share_redemptions d
                 WHERE d.link_uid = l.link_uid)
          FROM share_links l
         WHERE {" AND ".join(where)}
         ORDER BY COALESCE(l.resource_depth, 9999) ASC,
                  (SELECT count(*) FROM share_link_recipients r2
                    WHERE r2.link_uid = l.link_uid AND r2.removed_at IS NULL) DESC,
                  (CASE WHEN l.max_uses = 0 THEN 2147483647
                        ELSE l.max_uses - l.uses_consumed END) DESC,
                  l.created_at DESC
         LIMIT %s
    """
    params.append(limit)
    with conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

    # The caller is told when the cap bit. A console that says "here is what is
    # reachable from outside" while silently stopping at 500 rows is worse than
    # one that shows fewer and says so — the whole value is completeness.
    truncated = len(rows) >= limit
    out: List[dict] = []
    n = len(_COLUMNS.split(","))
    for r in rows:
        link = _row_to_link(r[:n])
        # `status` is computed in Python, not SQL, so the console and the
        # owner-side Share tab cannot drift apart on what "expired" means.
        if status and link.status() != status:
            continue
        out.append({"link": link, "recipient_count": r[n],
                    "last_activity": r[n + 1], "truncated": truncated})
    return out


def address_marker(link_uid: str, email: str) -> str:
    """A short, link-salted hash of an address, for counting distinct ones.

    Never the plaintext: rung 2 counts addresses that have TRIPPED, most of
    which belong to people who are not recipients and never consented to appear
    in this tenant's data. Salting with the link uid also stops the column being
    correlated across links.
    """
    digest = hashlib.sha256(f"{link_uid}\x00{email.strip().lower()}".encode())
    return digest.hexdigest()[:16]


def record_failed_verification(conn, link_uid: str, email: str, *,
                               address_locked: bool, threshold: int,
                               distinct_threshold: int, window_minutes: int,
                               lock_minutes: int) -> dict:
    """Rung 2 (spec §8.4): a failed verification against the LINK, not one address.

    Rung 1 caps attempts per address, which an attacker sidesteps simply by
    varying the address — the link is the thing being attacked, so it needs its
    own budget. Two ways to trip it: enough failures in total, or enough
    DISTINCT addresses each having hit rung 1 (the spread pattern rung 1 cannot
    see).

    The window is ROLLING and the count is not a lifetime total: counts older
    than the window are discarded, or ordinary typos accumulate over months into
    a permanent lockout of a link nobody is attacking.

    Returns ``{"locked": bool, "attempts": int, "distinct": int}``.
    """
    marker = address_marker(link_uid, email) if address_locked else None
    with conn.cursor() as cur:
        cur.execute(
            f"""UPDATE share_links SET
                  -- Restart the window (and the tallies) if the old one has
                  -- aged out; otherwise accumulate into it.
                  failed_window_start = CASE
                      WHEN failed_window_start IS NULL
                        OR failed_window_start < now() - make_interval(mins => %(win)s)
                      THEN now() ELSE failed_window_start END,
                  failed_attempts = CASE
                      WHEN failed_window_start IS NULL
                        OR failed_window_start < now() - make_interval(mins => %(win)s)
                      THEN 1 ELSE failed_attempts + 1 END,
                  failed_addresses = CASE
                      WHEN failed_window_start IS NULL
                        OR failed_window_start < now() - make_interval(mins => %(win)s)
                      THEN CASE WHEN %(marker)s::text IS NULL THEN ARRAY[]::text[]
                                ELSE ARRAY[%(marker)s::text] END
                      WHEN %(marker)s::text IS NULL THEN COALESCE(failed_addresses, ARRAY[]::text[])
                      ELSE (SELECT ARRAY(SELECT DISTINCT unnest(
                              COALESCE(failed_addresses, ARRAY[]::text[])
                              || ARRAY[%(marker)s::text]))) END
                WHERE link_uid = %(link)s
            RETURNING failed_attempts,
                      coalesce(array_length(failed_addresses, 1), 0)""",
            {"link": link_uid, "win": window_minutes, "marker": marker})
        row = cur.fetchone()
        if not row:
            conn.commit()
            return {"locked": False, "attempts": 0, "distinct": 0}
        attempts, distinct = int(row[0]), int(row[1])

        locked = attempts >= threshold or distinct >= distinct_threshold
        if locked:
            # Lock, do not revoke. A lockout expires on its own; revoking would
            # punish the creator permanently for someone else's behaviour, and
            # the link's URL cannot be re-issued to the people already holding it.
            cur.execute(
                """UPDATE share_links
                      SET locked_until = now() + make_interval(mins => %s)
                    WHERE link_uid = %s""",
                (lock_minutes, link_uid))
    conn.commit()
    return {"locked": locked, "attempts": attempts, "distinct": distinct}


def clear_failed_verifications(conn, link_uid: str) -> None:
    """A verified redemption clears the rolling count (spec §8.4).

    Someone got in legitimately, so whatever the count had accumulated was
    noise. Without this, a busy link with occasional typos walks itself into a
    lockout it never recovers from.
    """
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links
                  SET failed_attempts = 0, failed_window_start = NULL,
                      failed_addresses = NULL
                WHERE link_uid = %s""", (link_uid,))
    conn.commit()


def provenance_for_files(conn, file_uids) -> dict:
    """Which of these files arrived from outside, and from whom.

    One indexed query for a whole file-list page — the alternative is reading
    metadata per row, which is both N core round-trips and, more importantly,
    NOT EVIDENCE: the core reserves no `share.*` namespace, so anyone with WRITE
    can rewrite those keys. This ledger mirrors the audit chain instead.

    Keyed on the file uid, so the marker survives a move or a rename.

    `claimed_name` is sender-typed free text and stays UNTRUSTED all the way to
    the UI; `email` beside it is the verified half and is the one to believe.
    """
    uids = [u for u in dict.fromkeys(file_uids) if u]
    if not uids:
        return {}
    with conn.cursor() as cur:
        cur.execute(
            """SELECT d.result_uid, d.verified_email, d.opened_at, d.link_uid,
                      l.created_by
                 FROM share_redemptions d
                 JOIN share_links l ON l.link_uid = d.link_uid
                WHERE d.result_uid = ANY(%s::uuid[])""",
            (uids,))
        rows = cur.fetchall()
    return {
        # Stringified at the boundary: psycopg returns UUID objects here while
        # the caller's uids are strings, and a mismatch silently matches nothing.
        str(r[0]): {"email": r[1], "at": r[2], "link_uid": str(r[3]),
                    "shared_by": r[4]}
        for r in rows
    }


def revoke_all_for_creator(conn, created_by: str, revoked_by: str) -> List[str]:
    """The departed-employee action: end every live link one person left open.

    Returns the uids actually revoked, so the caller can audit each one
    individually — a single "revoked 14 links" event is not a record anyone can
    later answer questions from.
    """
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_links SET revoked_at = now(), revoked_by = %s
                WHERE lower(created_by) = lower(%s)
                  AND revoked_at IS NULL AND expires_at > now()
             RETURNING link_uid""",
            (revoked_by, created_by))
        uids = [str(r[0]) for r in cur.fetchall()]
    conn.commit()
    return uids


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
