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

"""The audience sidecar — who watched, as a CSV beside the video (MEDIA_SHARE.md §8).

*"Fetching the sidecar file is a simple integration."* So it is a hidden child of
the SOURCE file — where renditions live — which buys the two properties that make
it a good idea rather than a hack: it inherits the source's ACL (exactly the
people who can see the video can see who watched it), and it is deleted with the
source (the PII does not outlive the thing it is about).

* ``audience.csv`` — the ROLLUP, always, whenever the file has a media link:
  every link's rows, with ``link_uid``, ``link_note`` and ``mode`` columns. The
  one an integration reads.
* ``audience-<link_uid>.csv`` — per link, only while the file has fewer than
  ``audience_csv_per_link_max`` live media links. Past that (the one-link-per-
  recipient case can mean two hundred links on one video) only the rollup is
  written and the per-link files are removed, so crossing the threshold never
  leaves a half-populated set of stale files.

**A projection, never an append.** Postgres is the system of record; the file is
regenerated in full, debounced (``audience_csv_interval_seconds``), immediately
on revoke and on demand, and skipped when its content hash has not changed — so
viewers do not race each other, and an idle link does not accrue identical
versions. Written as a link creator (an ordinary delegated write by a real
principal), never by a service identity — this service has none, by design.

**Neither name parses as a rendition.** ``parse_rendition_name`` splits on the
last ``-`` and requires a known format: ``audience.csv`` has no ``-`` and the
per-link name ends in a UUID group. CSAI's renditions.py documents the namespace
and tests it.

Every field is RFC 4180-escaped **and** guarded against formula injection: a
claimed address is text an unauthenticated stranger typed, and a CSV is exactly
where ``=cmd|' /c calc'!A1`` becomes code in someone's spreadsheet.
"""
from __future__ import annotations

import csv
import hashlib
import io
import logging
from typing import Callable, Iterable, List, Optional

from . import db, ldap_roles, links
from .audit import get_emitter
from .config import Config
from .core_client import for_creator
from .playback import dropoff_seconds
from .schema import KIND_MEDIA

log = logging.getLogger("share_service.audience")

ROLLUP = "audience.csv"
COLUMNS = ["email", "verified", "on_allowlist", "first_seen_utc", "last_seen_utc",
           "sessions", "plays", "bytes_served", "coverage_pct", "furthest_pct",
           "completed", "completed_utc", "completion_basis", "dropoff_seconds",
           "device_class", "referer_host", "link_uid", "link_note", "mode"]

_FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def per_link_name(link_uid: str) -> str:
    return f"audience-{link_uid}.csv"


def guard(value) -> str:
    """One cell: never a formula. A leading = + - @ TAB or CR gets a quote."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(_FORMULA_LEADS) else s


def _iso(t) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ") if t else ""


def rows(conn, resource_uid: str, link_uid: Optional[str] = None) -> List[dict]:
    """The audience of one file's media links (or of one link), oldest first."""
    sql = """SELECT a.email_norm, a.verified, a.on_allowlist, a.first_seen_at,
                    a.last_seen_at, a.sessions, a.plays, a.bytes_served,
                    a.coverage_pct, a.furthest_pct, a.completed_at,
                    a.completion_basis, a.coverage::text, l.duration_ms,
                    (SELECT p.device_class FROM share_media_playback p
                      WHERE p.audience_uid = a.audience_uid
                      ORDER BY p.last_beacon_at DESC LIMIT 1),
                    a.referer_host, l.link_uid, l.note, l.access_mode
               FROM share_link_audience a
               JOIN share_links l ON l.link_uid = a.link_uid
              WHERE l.resource_uid = %s AND l.kind = %s"""
    args: list = [resource_uid, KIND_MEDIA]
    if link_uid:
        sql += " AND l.link_uid = %s"
        args.append(link_uid)
    sql += " ORDER BY a.first_seen_at, a.audience_uid"
    with conn.cursor() as cur:
        cur.execute(sql, args)
        out = []
        for r in cur.fetchall():
            out.append({
                "email": r[0] or "", "verified": bool(r[1]), "on_allowlist": bool(r[2]),
                "first_seen_utc": _iso(r[3]), "last_seen_utc": _iso(r[4]),
                "sessions": r[5], "plays": r[6], "bytes_served": r[7],
                "coverage_pct": r[8], "furthest_pct": r[9],
                "completed": r[10] is not None, "completed_utc": _iso(r[10]),
                "completion_basis": r[11] or "",
                "dropoff_seconds": dropoff_seconds(r[12] or "", r[13]),
                "device_class": r[14] or "", "referer_host": r[15] or "",
                "link_uid": str(r[16]), "link_note": r[17] or "", "mode": r[18],
            })
    return out


def render(rs: Iterable[dict]) -> bytes:
    """RFC 4180, UTF-8 with a BOM (Excel), CRLF, header row."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(COLUMNS)
    for r in rs:
        w.writerow([guard(_cell(r[c])) for c in COLUMNS])
    return b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")


def _cell(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else v


def mark_dirty(conn, resource_uid: str, *, force: bool = False) -> None:
    """Something about this file's audience changed. Cheap, and coalesced."""
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO share_audience_dirty (resource_uid, force)
                       VALUES (%s, %s)
                       ON CONFLICT (resource_uid) DO UPDATE
                          SET force = share_audience_dirty.force OR EXCLUDED.force""",
                    (resource_uid, force))
    conn.commit()


def _writer_link(conn, resource_uid: str) -> Optional[links.Link]:
    """Whose authority writes the file: the oldest LIVE media link's creator, else
    the newest link's — a real principal who shared this video."""
    live = links.live_media_links(conn, resource_uid)
    if live:
        return live[0]
    with conn.cursor() as cur:
        cur.execute("""SELECT link_uid FROM share_links WHERE resource_uid = %s AND kind = %s
                        ORDER BY created_at DESC LIMIT 1""", (resource_uid, KIND_MEDIA))
        row = cur.fetchone()
    return links.get(conn, str(row[0])) if row else None


def project(cfg: Config, tenant: str, resource_uid: str, *,
            core_factory: Optional[Callable] = None, roles_for: Optional[Callable] = None) -> dict:
    """Regenerate this file's sidecars from Postgres. Returns a report; raises
    nothing — a failed write is recorded and retried on the next pass."""
    # Resolved at call time, not bound as defaults at import.
    core_factory = core_factory or for_creator
    roles_for = roles_for or (lambda user: ldap_roles.resolve_share_roles(cfg, user))
    report = {"resource_uid": resource_uid, "written": [], "removed": [], "unchanged": [],
              "error": None}
    conn = db.connect_for_tenant(cfg, tenant, provision=True)
    try:
        writer = _writer_link(conn, resource_uid)
        if writer is None:
            return report
        n_live = len(links.live_media_links(conn, resource_uid))
        with conn.cursor() as cur:
            cur.execute("SELECT link_uid FROM share_links WHERE resource_uid = %s AND kind = %s",
                        (resource_uid, KIND_MEDIA))
            all_links = [str(r[0]) for r in cur.fetchall()]
            cur.execute("SELECT name, content_sha FROM share_audience_sidecars "
                        "WHERE resource_uid = %s", (resource_uid,))
            known = {r[0]: bytes(r[1]) if r[1] else None for r in cur.fetchall()}
        wanted = {ROLLUP: render(rows(conn, resource_uid))}
        if n_live < cfg.audience_csv_per_link_max:
            for lu in all_links:
                wanted[per_link_name(lu)] = render(rows(conn, resource_uid, lu))
        try:
            roles = roles_for(writer.created_by)
            with core_factory(cfg, created_by=writer.created_by, roles=roles,
                              tenant=tenant) as core:
                existing = {str(getattr(e, "name", "")): str(e.uid)
                            for e in (core.client.dir(resource_uid) or [])}
                for name, body in wanted.items():
                    sha = hashlib.sha256(body).digest()
                    if known.get(name) == sha and name in existing:
                        report["unchanged"].append(name)
                        continue
                    uid = existing.get(name) or core.client.touch(resource_uid, name)
                    core.client.put_stream(uid, iter([body]))
                    _remember(conn, resource_uid, name, sha, None)
                    report["written"].append(name)
                # Per-link files that should no longer exist: past the threshold,
                # or for a link that is gone. Never anything that is not ours.
                for name, uid in existing.items():
                    if (name.startswith("audience-") and name.endswith(".csv")
                            and name not in wanted):
                        core.client.remove(uid)
                        _forget(conn, resource_uid, name)
                        report["removed"].append(name)
        except Exception as e:  # noqa: BLE001 - recorded, retried next pass
            report["error"] = f"{type(e).__name__}: {e}"
            log.warning("audience sidecar for %s not written: %s", resource_uid, report["error"])
            _remember(conn, resource_uid, ROLLUP, known.get(ROLLUP), report["error"])
            # Retry at the debounce cadence, not every sweep: a file that is gone
            # or a creator without WRITE would otherwise be retried every minute.
            with conn.cursor() as cur:
                cur.execute("""UPDATE share_audience_dirty SET dirty_since = now(), force = false
                                WHERE resource_uid = %s""", (resource_uid,))
            conn.commit()
            return report
        with conn.cursor() as cur:
            cur.execute("DELETE FROM share_audience_dirty WHERE resource_uid = %s",
                        (resource_uid,))
        conn.commit()
    finally:
        conn.close()
    if report["written"]:
        # A PII disclosure into a file other people can read: in the chain.
        get_emitter(cfg).emit(action="share_audience_exported", outcome="ok",
                              category="access", actor=f"share:{writer.link_uid}",
                              tenant=tenant, target_uid=resource_uid,
                              request_id=resource_uid,
                              detail={"files": report["written"], "via": "sidecar",
                                      "written_as": writer.created_by})
    return report


def _remember(conn, resource_uid, name, sha, error) -> None:
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO share_audience_sidecars
                         (resource_uid, name, content_sha, written_at, last_error)
                       VALUES (%s,%s,%s, CASE WHEN %s::text IS NULL THEN now() END, %s)
                       ON CONFLICT (resource_uid, name) DO UPDATE
                          SET content_sha = EXCLUDED.content_sha,
                              written_at = COALESCE(EXCLUDED.written_at,
                                                    share_audience_sidecars.written_at),
                              last_error = EXCLUDED.last_error""",
                    (resource_uid, name, sha, error, error))
    conn.commit()


def _forget(conn, resource_uid, name) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM share_audience_sidecars WHERE resource_uid = %s AND name = %s",
                    (resource_uid, name))
    conn.commit()


def run_due(cfg: Config, tenants: Iterable[str], **kw) -> List[dict]:
    """Project every file whose audience changed at least one interval ago (or
    was forced). Bounded per pass; the rest wait for the next."""
    if not cfg.audience_csv_enabled:
        return []
    out = []
    for tenant in tenants:
        try:
            conn = db.connect_for_tenant(cfg, tenant)
        except Exception:  # noqa: BLE001
            continue
        try:
            with conn.cursor() as cur:
                cur.execute("""SELECT resource_uid FROM share_audience_dirty
                                WHERE force OR dirty_since <= now() - make_interval(secs => %s)
                                ORDER BY dirty_since LIMIT 50""",
                            (cfg.audience_csv_interval_seconds,))
                due = [str(r[0]) for r in cur.fetchall()]
        except Exception:  # noqa: BLE001 - a tenant without the table yet
            conn.rollback()
            due = []
        finally:
            conn.close()
        for resource_uid in due:
            out.append({"tenant": tenant, **project(cfg, tenant, resource_uid, **kw)})
    return out


def erase_address(cfg: Config, tenant: str, email: str, **kw) -> dict:
    """An erasure request naming an address (§8.4): its audience rows and their
    playback go, and every sidecar that held it is regenerated immediately."""
    email = links.normalize_email(email)
    conn = db.connect_for_tenant(cfg, tenant, provision=True)
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT a.audience_uid, l.resource_uid FROM share_link_audience a
                             JOIN share_links l ON l.link_uid = a.link_uid
                            WHERE a.email_norm = %s""", (email,))
            found = cur.fetchall()
            ids = [str(r[0]) for r in found]
            resources = sorted({str(r[1]) for r in found})
            if ids:
                cur.execute("DELETE FROM share_media_playback WHERE audience_uid = ANY(%s::uuid[])",
                            (ids,))
                cur.execute("DELETE FROM share_link_audience WHERE audience_uid = ANY(%s::uuid[])",
                            (ids,))
        conn.commit()
        for r in resources:
            mark_dirty(conn, r, force=True)
    finally:
        conn.close()
    reports = [project(cfg, tenant, r, **kw) for r in resources]
    return {"rows": len(ids), "files": resources, "reports": reports}
