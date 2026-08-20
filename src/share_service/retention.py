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

"""Retention sweep (spec §5.5).

Dead links are **kept**, not deleted on expiry — they are audit evidence, and
"who did we ever share this with" is a question that arrives months later. They
are purged after `SHARE_RETENTION_DAYS`, which exists chiefly because the
recipient table holds addresses of people outside the organisation: keeping
those forever is the actual harm, not the disk.

Two properties worth stating plainly, because they shape everything here:

**Nothing about correctness depends on this sweep.** Every check — expiry,
revocation, budget, lockout — is evaluated at redemption time against the live
row. A sweeper that never runs costs disk and some PII retention; it can never
cost enforcement. So this is allowed to be slow, restartable, and to give up
mid-pass.

**The purge is fail-closed.** A row whose deletion cannot be audited is not
deleted, and comes back on the next pass. Deleting the only record of a link
without recording that it existed is precisely the failure this whole service is
built to prevent.
"""
from __future__ import annotations

import logging
from typing import Optional

from . import db
from .audit import AuditUnavailable, get_emitter
from .config import Config

log = logging.getLogger("share_service.retention")


def sweep_tenant(config: Config, tenant: str, *, limit: int = 500) -> dict:
    """Purge one tenant's expired rows. Returns a small report.

    Bounded per call rather than "delete everything eligible": the first sweep
    after this ships could face a year of accumulated rows, and a single
    unbounded DELETE holding locks across the whole table is how a background
    tidy-up becomes an outage. Whatever is left is picked up next pass.
    """
    if config.retention_days <= 0:
        return {"tenant": tenant, "purged": 0, "skipped": 0, "disabled": True}

    emitter = get_emitter(config)
    conn = db.connect_for_tenant(config, tenant, provision=True)
    purged, skipped = 0, 0
    try:
        with conn.cursor() as cur:
            # Eligible = definitively dead AND older than the window. `expires_at`
            # is the clock for both cases: a revoked link still has one, and it
            # is always <= the moment it was minted plus the deployment cap.
            cur.execute(
                """SELECT link_uid, kind, resource_uid, created_by, expires_at,
                          revoked_at, uses_consumed
                     FROM share_links
                    WHERE (revoked_at IS NOT NULL OR expires_at < now())
                      AND expires_at < now() - make_interval(days => %s)
                    ORDER BY expires_at ASC
                    LIMIT %s""",
                (config.retention_days, limit))
            candidates = cur.fetchall()

        for row in candidates:
            link_uid = str(row[0])
            try:
                # Audit FIRST, then delete. The other order can lose the only
                # record that a link ever existed: if the emit fails after the
                # delete there is nothing left to retry from.
                emitter.emit_or_raise(
                    action="share_link_expired", outcome="ok", category="admin",
                    actor="system:share-retention", tenant=tenant,
                    target_uid=str(row[2]), request_id=link_uid,
                    detail={"link_uid": link_uid, "kind": row[1],
                            "created_by": row[3],
                            "expires_at": row[4].isoformat() if row[4] else None,
                            "was_revoked": row[5] is not None,
                            "uses_consumed": row[6],
                            "reason": "retention",
                            "retention_days": config.retention_days})
            except AuditUnavailable:
                # Fail-closed: keep the row, try again next pass.
                skipped += 1
                continue

            with conn.cursor() as cur:
                # Children first — recipients and redemptions have FK references
                # and hold the PII this sweep exists for.
                cur.execute("DELETE FROM share_link_recipients WHERE link_uid = %s",
                            (link_uid,))
                cur.execute("DELETE FROM share_redemptions WHERE link_uid = %s",
                            (link_uid,))
                cur.execute("DELETE FROM share_link_members WHERE link_uid = %s",
                            (link_uid,))
                cur.execute("DELETE FROM share_links WHERE link_uid = %s",
                            (link_uid,))
                # ...and its cross-tenant directory entry, or the directory
                # accumulates rows pointing at links that no longer exist.
                cur.execute("DELETE FROM public.share_link_directory "
                            "WHERE link_uid = %s", (link_uid,))
            # Committed per link, so an interruption leaves whole links purged
            # rather than a link stripped of its recipients but still listed.
            conn.commit()
            purged += 1
    finally:
        conn.close()

    if skipped:
        log.error("retention sweep kept %d row(s) in %s: audit unavailable",
                  skipped, tenant)
    if purged:
        log.info("retention sweep purged %d link(s) from %s", purged, tenant)
    return {"tenant": tenant, "purged": purged, "skipped": skipped,
            "remaining": len(candidates) == limit}


def sweep(config: Config, tenants: Optional[list] = None) -> list:
    """Sweep every tenant named, or the configured default.

    Deliberately takes the tenant list rather than discovering it: this service
    provisions a schema on first use, so "every schema that exists" is a
    different set from "every tenant that should be swept", and guessing wrong
    means either missing PII or touching a schema that is not ours.
    """
    names = tenants or [config.default_tenant]
    out = []
    for tenant in names:
        try:
            out.append(sweep_tenant(config, tenant))
        except Exception as e:  # noqa: BLE001 - one bad tenant must not stop the rest
            log.exception("retention sweep failed for %s", tenant)
            out.append({"tenant": tenant, "error": str(e)})
    return out
