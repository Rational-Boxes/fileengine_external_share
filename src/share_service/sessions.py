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

"""Redemption sessions (spec §6.4, §7.3).

**A use is a session, not a request** — for every kind, without exception.
Counting per HTTP request breaks on the first real browser: a Range request, a
resumed download, or a retry after a dropped connection would each burn a use,
and a five-use link would be exhausted by one recipient having a bad commute.
Every byte transfer inside a session rides ``redemption_uid`` and consumes
nothing further.

For a folder link, opening the session is also where the **per-member authority
re-check** happens and where the surviving member list is **frozen** onto the
redemption row, together with the exact archive length that ``/content`` will
declare. Doing either later means discovering an omitted member after the
``Content-Length`` header is already on the wire.

In M1 this module is exercised directly by tests. M4 wires it to the public
route, which is also where the verified recipient address comes from — this
layer requires one to be supplied and refuses to invent it, because
``share_redemptions.verified_email`` being NOT NULL is the schema-level
statement that no session opens unverified.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from .archive import Member, archive_length
from .config import Config
from .core_client import READ, for_creator
from . import snapshot as snapshot_mod

log = logging.getLogger("share_service.sessions")


class SessionRefused(RuntimeError):
    """No session could be opened. The outside caller sees a uniform 404
    (spec §8.5); the reason goes to audit only."""

    def __init__(self, reason: str, message: str = ""):
        super().__init__(message or reason)
        self.reason = reason


@dataclass
class Session:
    redemption_uid: str
    link_uid: str
    verified_email: str
    expires_at: datetime
    members: List[Member]
    archive_bytes: Optional[int] = None
    members_served: int = 0
    members_omitted: int = 0


def _consume_use(conn, link_uid: str, email: str) -> Optional[dict]:
    """Consume one use from the shared pool *and* the recipient's own tally.

    One statement, one row lock. The ordering is the point: the **recipient**
    update gates the pool update, not the reverse. Reversing them increments
    the pool in the same snapshot and then discovers the recipient was over
    their personal cap — having already burnt a use that no rollback inside a
    single statement will return (spec §5.3).

    Returns the link's usable fields, or None if any budget or state check
    failed — which the caller must render as a uniform 404.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            WITH lim AS (
                SELECT max_uses, uses_consumed, max_uses_per_recipient
                  FROM share_links
                 WHERE link_uid = %(link)s
                   AND revoked_at IS NULL
                   AND expires_at > now()
                   AND (locked_until IS NULL OR locked_until < now())
                   FOR UPDATE
            ), rcpt AS (
                UPDATE share_link_recipients r
                   SET uses_consumed = r.uses_consumed + 1, last_used_at = now()
                  FROM lim
                 WHERE r.link_uid = %(link)s AND r.email = %(email)s
                   AND r.removed_at IS NULL
                   AND (lim.max_uses = 0 OR lim.uses_consumed < lim.max_uses)
                   AND (lim.max_uses_per_recipient = 0
                        OR r.uses_consumed < lim.max_uses_per_recipient)
                RETURNING r.email
            ), pool AS (
                UPDATE share_links
                   SET uses_consumed = uses_consumed + 1
                 WHERE link_uid = %(link)s AND EXISTS (SELECT 1 FROM rcpt)
                RETURNING kind, resource_uid, created_by, pinned_version,
                          max_bytes, bytes_consumed, include_subdirs
            )
            SELECT * FROM pool
            """,
            {"link": link_uid, "email": email})
        row = cur.fetchone()
    conn.commit()
    if not row:
        return None
    return {"kind": row[0], "resource_uid": str(row[1]), "created_by": row[2],
            "pinned_version": row[3], "max_bytes": row[4],
            "bytes_consumed": row[5], "include_subdirs": row[6]}


def open_session(conn, cfg: Config, *, link_uid: str, verified_email: str,
                 tenant: str, roles: List[str], source_addr: str = "",
                 user_agent: str = "") -> Session:
    """Open a redemption session, consuming exactly one use.

    ``roles`` must already be the creator's live, admin-stripped roles
    (:mod:`share_service.ldap_roles`) — this layer never resolves them itself,
    so the stripping stays in one place.
    """
    if not verified_email:
        # Not a validation nicety: it is the invariant that no session opens
        # for an unverified address.
        raise SessionRefused("unverified", "a verified recipient address is required")

    link = _consume_use(conn, link_uid, verified_email)
    if link is None:
        raise SessionRefused("budget_or_state",
                             "revoked, expired, exhausted, locked, or not a "
                             "listed recipient")

    redemption_uid = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=cfg.session_ttl_seconds)

    members: List[Member] = []
    frozen: List[str] = []
    omitted = 0
    exact_bytes: Optional[int] = None

    if link["kind"] == 2:
        stored = snapshot_mod.load(conn, link_uid)
        with for_creator(cfg, created_by=link["created_by"], roles=roles,
                         tenant=tenant, source_addr=source_addr,
                         redemption_uid=redemption_uid) as core:
            for m in stored:
                if m.is_dir:
                    members.append(m)          # structure, not content
                    continue
                try:
                    # can_reach, not check_permission: read-by-default grants
                    # on a uid that no longer exists, so the permission check
                    # alone would serve a vanished member as a zero-byte entry
                    # instead of omitting it (spec §6.3).
                    allowed = core.can_reach(m.member_uid, READ)
                except Exception as e:  # noqa: BLE001 - treat as not readable
                    log.warning("member re-check failed for %s: %s", m.member_uid, e)
                    allowed = False
                if allowed:
                    members.append(m)
                    frozen.append(m.member_uid)
                else:
                    # Omitted, not fatal: failing the whole download because one
                    # file gained a DENY would make the feature unusable in
                    # exactly the deployments that manage ACLs carefully.
                    omitted += 1
        exact_bytes = archive_length(members)

    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO share_redemptions
                 (redemption_uid, link_uid, expires_at, verified_email,
                  source_addr, user_agent, frozen_members, archive_bytes)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (redemption_uid, link_uid, expires_at, verified_email, source_addr,
             user_agent, frozen or None, exact_bytes))
    conn.commit()

    return Session(redemption_uid=redemption_uid, link_uid=link_uid,
                   verified_email=verified_email, expires_at=expires_at,
                   members=members, archive_bytes=exact_bytes,
                   members_served=len(frozen), members_omitted=omitted)


def close_session(conn, redemption_uid: str, *, bytes_moved: int = 0,
                  files_moved: int = 0, result_uid: Optional[str] = None) -> None:
    """Mark the session finished and roll its totals onto the link."""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_redemptions
                  SET completed_at = now(), bytes_moved = %s, files_moved = %s,
                      result_uid = %s
                WHERE redemption_uid = %s""",
            (bytes_moved, files_moved, result_uid, redemption_uid))
        cur.execute(
            """UPDATE share_links l
                  SET bytes_consumed = l.bytes_consumed + %s
                 FROM share_redemptions r
                WHERE r.redemption_uid = %s AND l.link_uid = r.link_uid""",
            (bytes_moved, redemption_uid))
    conn.commit()
