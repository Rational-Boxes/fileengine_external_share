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

"""Playback telemetry — did they watch the whole thing? (MEDIA_SHARE.md §7.4)

Three rules hold everything here up:

1. **The beacon carries the session's CUMULATIVE state, never a delta**, and it
   is merged by union (coverage ``|``) and maximum. A lost beacon costs nothing —
   the next carries everything — and a duplicated one is a no-op. A delta
   protocol drifts, invisibly, and always in the flattering direction.
2. **No client-supplied percentage is ever stored.** The client sends a bitmap;
   the server counts it. ``coverage_pct`` is popcount / width with the trailing
   bucket discounted (``ended`` fires early on some encodes).
3. **Completion carries its basis**, and bytes served are the floor a client
   cannot fake downward: a beacon claiming full coverage of a 40 MB rendition
   that was sent 4 MB is recorded as ``beacon`` (unconfirmed), never as
   ``beacon+bytes``. The converse never holds — a browser buffers ahead — so
   bytes bound the claim from below only. With no usable beacon at all, enough
   bytes make a ``bytes-floor`` completion: "probably watched", never confirmed.

Coverage is the headline because "did they watch it" is a question about the
content, not the playhead: scrubbing to the end is 100% furthest point and ~2%
coverage, and both are kept because they are different signals.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Optional

from .config import Config

log = logging.getLogger("share_service.playback")

MAX_BEACON_BYTES = 4096


class BadBeacon(ValueError):
    pass


@dataclass
class Beacon:
    session: Optional[str]
    buckets: int
    bits: str                   # '0'/'1' * buckets — the coverage bitmap
    furthest_ms: int
    watch_ms: int
    plays: int
    rate_max: float
    ended: bool
    quality: Optional[str]
    duration_ms: int


def _int(v, lo=0, hi=2 ** 62) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise BadBeacon("not an integer")
    if n < lo or n > hi:
        raise BadBeacon("out of range")
    return n


def parse(body: dict, cfg: Config) -> Beacon:
    """Validate a beacon. Anything malformed is refused, not repaired."""
    buckets = _int(body.get("buckets"), 1, cfg.playback_max_buckets)
    raw = body.get("coverage")
    if not isinstance(raw, str) or len(raw) > 400:
        raise BadBeacon("coverage must be a base64 bitmap")
    try:
        blob = base64.b64decode(raw, validate=True)
    except Exception:  # noqa: BLE001
        raise BadBeacon("coverage is not base64")
    if len(blob) != (buckets + 7) // 8:
        raise BadBeacon("coverage width does not match buckets")
    bits = "".join(f"{b:08b}" for b in blob)[:buckets]
    rate = body.get("rate_max", 1.0)
    try:
        rate = float(rate)
    except (TypeError, ValueError):
        raise BadBeacon("rate_max")
    if not 0 < rate <= 16:
        raise BadBeacon("rate_max")
    quality = body.get("quality")
    if quality not in (None, "hd", "sd", "opus", "mp3"):
        raise BadBeacon("quality")
    return Beacon(session=body.get("session") if isinstance(body.get("session"), str) else None,
                  buckets=buckets, bits=bits,
                  furthest_ms=_int(body.get("furthest_ms", 0)),
                  watch_ms=_int(body.get("watch_ms", 0)),
                  plays=_int(body.get("plays", 0), 0, 10_000),
                  rate_max=rate, ended=bool(body.get("ended")), quality=quality,
                  duration_ms=_int(body.get("duration_ms", 0)))


def coverage_pct(bits: str) -> int:
    """popcount / width, the trailing bucket discounted — so a video whose last
    fraction of a second never reports as played still reaches 100%."""
    if not bits:
        return 0
    if len(bits) > 1 and bits[-1] == "0":
        bits = bits[:-1]                     # an unplayed final bucket is not held against them
    return min(100, round(100 * bits.count("1") / len(bits)))


def dropoff_seconds(bits: str, duration_ms: Optional[int]) -> Optional[int]:
    """'Stopped at 1:47': the start of the first bucket after the last watched one."""
    if not bits or "1" not in bits or not duration_ms:
        return None
    last = bits.rindex("1")
    if last >= len(bits) - 1:
        return None                          # reached the end
    return int((last + 1) * duration_ms / len(bits) / 1000)


def device_class(user_agent: str) -> str:
    """Coarse on purpose: a user-agent string stored per named viewer is
    fingerprinting; three buckets answer 'they watched on their phone'."""
    ua = user_agent or ""
    if "iPad" in ua or "Tablet" in ua or ("Android" in ua and "Mobile" not in ua):
        return "tablet"
    if "Mobi" in ua or "iPhone" in ua or "Android" in ua:
        return "mobile"
    return "desktop"


def record(conn, cfg: Config, *, session_uid: str, link, audience_uid: Optional[str],
           beacon: Beacon, user_agent: str, rendition_size: Optional[int]) -> Optional[str]:
    """Merge one beacon into its session and the viewer's rollup. Returns the
    completion basis if THIS beacon completed the viewing, else None."""
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO share_media_playback
                 (session_uid, link_uid, audience_uid, buckets, coverage, furthest_ms,
                  watch_ms, plays, rate_max, ended, quality, device_class)
               VALUES (%s,%s,%s,%s,%s::bit varying,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (session_uid) DO UPDATE SET
                 coverage = CASE WHEN share_media_playback.buckets = EXCLUDED.buckets
                                 THEN share_media_playback.coverage | EXCLUDED.coverage
                                 ELSE share_media_playback.coverage END,
                 furthest_ms = GREATEST(share_media_playback.furthest_ms, EXCLUDED.furthest_ms),
                 watch_ms = GREATEST(share_media_playback.watch_ms, EXCLUDED.watch_ms),
                 plays = GREATEST(share_media_playback.plays, EXCLUDED.plays),
                 rate_max = GREATEST(share_media_playback.rate_max, EXCLUDED.rate_max),
                 ended = share_media_playback.ended OR EXCLUDED.ended,
                 quality = COALESCE(EXCLUDED.quality, share_media_playback.quality),
                 last_beacon_at = now()""",
            (session_uid, link.link_uid, audience_uid, beacon.buckets, beacon.bits,
             min(beacon.furthest_ms, max(beacon.duration_ms, link.duration_ms or 0) or 2 ** 62),
             beacon.watch_ms, beacon.plays, beacon.rate_max, beacon.ended, beacon.quality,
             device_class(user_agent)))
        if not audience_uid:
            conn.commit()
            return None
        # The viewer's rollup: the union of every session of the same width.
        cur.execute(
            """SELECT bit_or(coverage)::text, max(furthest_ms), sum(plays)
                 FROM share_media_playback
                WHERE audience_uid = %s AND buckets = %s""",
            (audience_uid, beacon.buckets))
        bits, furthest, plays = cur.fetchone()
        pct = coverage_pct(bits or "")
        duration = link.duration_ms or beacon.duration_ms or 0
        furthest_pct = min(100, round(100 * (furthest or 0) / duration)) if duration else 0
        cur.execute(
            """UPDATE share_link_audience
                  SET coverage = %s::bit varying, coverage_pct = %s, furthest_pct = %s,
                      plays = %s, last_seen_at = now()
                WHERE audience_uid = %s
            RETURNING completed_at""",
            (bits, pct, furthest_pct, int(plays or 0), audience_uid))
        row = cur.fetchone()
        basis = None
        if row and row[0] is None and pct >= cfg.playback_complete_pct:
            cur.execute("SELECT bytes_served FROM share_media_sessions WHERE session_uid = %s",
                        (session_uid,))
            served = int((cur.fetchone() or [0])[0] or 0)
            # Consistent with the claim: at least the configured share of the
            # bytes the claimed coverage needs. Anything less, or no size to
            # judge by, is the weaker basis — never the flattering one.
            need = (rendition_size or 0) * pct / 100 * cfg.playback_bytes_complete_pct / 100
            basis = "beacon+bytes" if rendition_size and served >= need else "beacon"
            cur.execute("""UPDATE share_link_audience
                              SET completed_at = now(), completion_basis = %s
                            WHERE audience_uid = %s AND completed_at IS NULL""",
                        (basis, audience_uid))
    conn.commit()
    return basis


def bytes_floor(conn, cfg: Config, *, session_uid: str, audience_uid: Optional[str],
                rendition_size: int) -> bool:
    """No usable beacon (blocked, or an old player), but enough of the rendition
    was delivered in this session: 'probably watched'. True if it completed now."""
    if not audience_uid or not rendition_size:
        return False
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE share_link_audience a
                  SET completed_at = now(), completion_basis = 'bytes-floor'
                 FROM share_media_sessions s
                WHERE a.audience_uid = %s AND s.session_uid = %s
                  AND a.completed_at IS NULL
                  AND s.bytes_served >= %s
                  AND NOT EXISTS (SELECT 1 FROM share_media_playback p
                                   WHERE p.session_uid = s.session_uid)
            RETURNING a.audience_uid""",
            (audience_uid, session_uid,
             int(rendition_size * cfg.playback_bytes_complete_pct / 100)))
        done = cur.fetchone() is not None
    conn.commit()
    return done


def retention_curve(conn, link_uid: str) -> list:
    """Percentage of viewers still watching at each bucket — a column-wise
    popcount over every session bitmap of the dominant width. Needs no further
    collection (§7.4 'Across viewers')."""
    with conn.cursor() as cur:
        cur.execute("""SELECT buckets, coverage::text FROM share_media_playback
                        WHERE link_uid = %s""", (link_uid,))
        rows = cur.fetchall()
    if not rows:
        return []
    widths: dict = {}
    for w, _b in rows:
        widths[w] = widths.get(w, 0) + 1
    width = max(widths, key=widths.get)
    maps = [b for w, b in rows if w == width and b]
    return [round(100 * sum(1 for m in maps if m[i] == "1") / len(maps)) for i in range(width)]
