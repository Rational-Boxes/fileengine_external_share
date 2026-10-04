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

"""MS4 end to end: an outside viewer watches a shared video through the RUNNING
media door (MEDIA_SHARE.md §6.3-6.9).

The creator uploads and mints through the bridge and share_service as the SPA
would; the viewer then has nothing but the link: peek, claim, a session, and
ranged reads — compared byte for byte with the published rendition read through
the bridge as the creator. Then the link is revoked mid-viewing.

Skips unless the chain is reachable; run with ``-m live``. Same env as
test_live_media_links.py.
"""
from __future__ import annotations

import os
import urllib.parse

import pytest

from tests.test_live_media_links import (BRIDGE, CSAI, ROOT, SHARE, TENANT, _SKIP, _clip,
                                         _login, _req, _wait)

pytestmark = [pytest.mark.live] + ([pytest.mark.skip(reason=_SKIP)] if _SKIP else [])


@pytest.fixture(scope="module")
def v():
    import shutil
    import tempfile
    tok = _login()
    h = {"Authorization": f"Bearer {tok}", "X-Tenant": TENANT}
    work = tempfile.mkdtemp(prefix="share_media_door_live_")
    src = os.path.join(work, "clip.mp4")
    _clip(src, 60)
    _c, f = _req("POST", f"{BRIDGE}/v1/dirs/{ROOT}/files", headers=h,
                 body={"name": f"media-door-live-{os.getpid()}.mp4"})
    uid = f["uid"]
    code, _ = _req("PUT", f"{BRIDGE}/v1/files/{uid}/content",
                   headers={**h, "Content-Type": "application/octet-stream"},
                   raw=open(src, "rb").read())
    assert code in (200, 201, 204)
    code, link = _req("POST", f"{SHARE}/share/v1/nodes/{uid}/links", headers=h,
                      body={"kind": 3, "access_mode": "claimed", "display_name": "Door test",
                            "recipients": ["expected@example.com"]})
    assert code == 201, link
    ns = type("V", (), {})()
    ns.h, ns.uid, ns.link = h, uid, link["link_uid"]
    ns.secret = urllib.parse.urlsplit(link["url"]).path.rsplit("/", 1)[1].split(".", 1)[1]
    _wait("the link to become ready", 300,
          lambda: _req("GET", f"{SHARE}/share/v1/links/{ns.link}", headers=h)[1]
          .get("media_state") == "ready")
    _wait("every publish job", 300,
          lambda: all(j["status"] in ("succeeded", "skipped")
                      for j in _req("GET", f"{CSAI}/documents/{uid}/media", headers=h)[1]["jobs"]))
    yield ns
    _req("DELETE", f"{SHARE}/share/v1/links/{ns.link}", headers=h)
    _req("DELETE", f"{BRIDGE}/v1/files/{uid}", headers=h)
    shutil.rmtree(work, ignore_errors=True)


def _door(v, path, method="GET", **kw):
    return _req(method, f"{SHARE}/media/v1/{v.link}{path}", **kw)


def _raw(url, rng=None):
    import urllib.request
    req = urllib.request.Request(url, headers={"Range": rng} if rng else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, {k.lower(): x for k, x in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): x for k, x in e.headers.items()}, e.read()


def test_the_viewer_sees_what_the_player_needs_and_nothing_else(v):
    code, peek = _door(v, f"?k={v.secret}")
    assert code == 200, peek
    assert peek["state"] == "ready" and peek["requires"] == "email"
    assert peek["title"] == "Door test" and peek["kind"] == "video"
    assert [s["quality"] for s in peek["sources"]] == ["hd", "sd"]
    assert v.uid not in str(peek)
    assert _door(v, "?k=wrong")[0] == 404


def test_claim_opens_a_session_and_the_bytes_match_the_published_rendition(v):
    code, s = _door(v, f"/claim?k={v.secret}", "POST",
                    body={"email": "expected@example.com", "consent": True})
    assert code == 200, s
    v.session = s["session"]
    hd = next(x for x in s["sources"] if x["quality"] == "hd")
    url = f"{SHARE}{hd['url']}"
    # The truth, read through the bridge as the creator.
    _c, kids = _req("GET", f"{BRIDGE}/v1/files/{v.uid}/renditions", headers=v.h)
    rend = next(e for e in kids["entries"] if e["name"].endswith("-media.webm"))
    total = int(rend["size"])
    for rng, start, end in (("bytes=0-1023", 0, 1023),
                            (f"bytes={total // 2}-{total // 2 + 65535}", total // 2, total // 2 + 65535),
                            ("bytes=-4096", total - 4096, total - 1)):
        code, hdr, body = _raw(url, rng)
        assert code == 206, (rng, code)
        assert hdr["content-range"] == f"bytes {start}-{end}/{total}"
        assert hdr["content-type"] == "video/webm"
        assert hdr["x-content-type-options"] == "nosniff"
        assert hdr["content-disposition"] == "inline"
        _c, ref = _req("GET", f"{BRIDGE}/v1/files/{rend['uid']}/content",
                       headers={**v.h, "Range": f"bytes={start}-{end}"})
        assert body == ref, f"bytes differ for {rng}"
    v.charged = 1024 + 65536 + 4096


def test_the_link_was_charged_for_exactly_what_was_sent(v):
    _c, link = _req("GET", f"{SHARE}/share/v1/links/{v.link}", headers=v.h)
    assert link["bytes_consumed"] == v.charged


def test_the_session_token_is_the_only_way_in(v):
    assert _raw(f"{SHARE}/media/v1/{v.link}/content?q=hd&t=forged", "bytes=0-9")[0] == 404
    assert _raw(f"{SHARE}/media/v1/{v.link}/content?q=preview&t={v.session}", "bytes=0-9")[0] == 404


def test_a_beacon_is_merged_and_the_roster_reports_it(v):
    import base64
    bits = "1" * 60 + "0" * 40                       # watched 60% of the clip
    raw = int(bits.ljust(104, "0"), 2).to_bytes(13, "big")
    code, _ = _req("POST", f"{SHARE}/media/v1/{v.link}/playback?t={v.session}",
                   body={"buckets": 100, "coverage": base64.b64encode(raw).decode(),
                         "duration_ms": 4000, "furthest_ms": 2400, "plays": 1, "quality": "hd"})
    assert code == 200
    code, roster = _req("GET", f"{SHARE}/share/v1/links/{v.link}/audience", headers=v.h)
    assert code == 200, roster
    row = roster["audience"][0]
    assert row["email"] == "expected@example.com"
    assert row["verified"] is False and row["on_allowlist"] is True
    # 60 of the 99 counted buckets: the unplayed last bucket is not held against them
    assert row["coverage_pct"] == 61 and row["furthest_pct"] == 60
    assert row["completed"] is False and row["dropoff_seconds"] == 2
    assert roster["unverified_note"] and roster["totals"]["retention"][:1] == [100]


def test_the_sidecar_lands_beside_the_video_and_reads_back_through_the_bridge(v):
    import csv
    import io
    code, rep = _req("POST", f"{SHARE}/share/v1/links/{v.link}/audience/flush", headers=v.h)
    assert code == 200, rep
    assert rep["error"] is None, rep
    assert "audience.csv" in rep["written"] + rep["unchanged"]
    _c, kids = _req("GET", f"{BRIDGE}/v1/files/{v.uid}/renditions", headers=v.h)
    names = {e["name"]: e["uid"] for e in kids["entries"]}
    assert "audience.csv" in names and f"audience-{v.link}.csv" in names
    _c, body = _req("GET", f"{BRIDGE}/v1/files/{names['audience.csv']}/content", headers=v.h)
    assert body[:3] == b"\xef\xbb\xbf"
    rows = list(csv.DictReader(io.StringIO(body[3:].decode())))
    mine = [r for r in rows if r["link_uid"] == v.link]
    assert mine and mine[0]["email"] == "expected@example.com"
    assert mine[0]["verified"] == "false" and mine[0]["coverage_pct"] == "61"
    v.sidecar_versions = len(_req("GET", f"{BRIDGE}/v1/files/{names['audience.csv']}/versions",
                                  headers=v.h)[1].get("versions", []))
    # Nothing changed, so a second flush writes no new version.
    _req("POST", f"{SHARE}/share/v1/links/{v.link}/audience/flush", headers=v.h)
    again = len(_req("GET", f"{BRIDGE}/v1/files/{names['audience.csv']}/versions",
                     headers=v.h)[1].get("versions", []))
    assert again == v.sidecar_versions


def test_revoking_the_link_stops_the_viewing_on_the_next_request(v):
    url = f"{SHARE}/media/v1/{v.link}/content?q=hd&t={v.session}"
    assert _raw(url, "bytes=0-9")[0] == 206
    code, _ = _req("DELETE", f"{SHARE}/share/v1/links/{v.link}", headers=v.h)
    assert code in (200, 204)
    assert _raw(url, "bytes=0-9")[0] == 404
    assert _door(v, f"?k={v.secret}")[0] == 404
