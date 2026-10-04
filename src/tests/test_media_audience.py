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

"""MS5 / MS5b — the audience sidecar and playback telemetry (MEDIA_SHARE.md §7.4, §8).

Same doubles as test_media_door.py (real Postgres; the core, authority, OTP and
Redis at their seams), plus a core that can hold the sidecar files.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import uuid

import pytest

from share_service import audience, db, links, playback, retention
from tests.test_media_door import (CREATOR, PAYLOAD, TENANT, VERSION, _get, _mint, _row,  # noqa: F401
                                   _session, cfg, w)


# ── a core that holds the sidecars ───────────────────────────────────────────

class Files:
    def __init__(self, source):
        self.source = source
        self.files = {}               # name -> (uid, [versions])
        self.writes = 0
        self.fail = False

    def factory(self, *a, **k):
        outer = self

        class C:
            client = None

            def __enter__(self):
                self.client = self
                return self

            def __exit__(self, *e):
                return False

            def dir(self, uid):
                assert uid == outer.source
                return [type("E", (), {"name": n, "uid": u})() for n, (u, _v) in outer.files.items()]

            def touch(self, parent, name):
                if outer.fail:
                    raise PermissionError("creator cannot write here")
                uid = str(uuid.uuid4())
                outer.files[name] = (uid, [])
                return uid

            def put_stream(self, uid, chunks):
                if outer.fail:
                    raise PermissionError("creator cannot write here")
                body = b"".join(chunks)
                for n, (u, vs) in outer.files.items():
                    if u == uid:
                        vs.append(body)
                outer.writes += 1

            def remove(self, uid):
                if outer.fail:
                    raise PermissionError("cannot remove")
                for n in [n for n, (u, _v) in outer.files.items() if u == uid]:
                    del outer.files[n]
        return C()

    def csv(self, name):
        body = self.files[name][1][-1]
        assert body.startswith(b"\xef\xbb\xbf") and b"\r\n" in body
        return list(csv.DictReader(io.StringIO(body[3:].decode())))


@pytest.fixture
def side(w, monkeypatch):
    f = Files(w.source)
    monkeypatch.setattr(audience, "for_creator", f.factory)
    monkeypatch.setattr(audience.ldap_roles, "resolve_share_roles", lambda c, u: ["users"])
    monkeypatch.setattr(audience, "get_emitter", lambda c: w.em)
    return f


def _due(w):
    """run_due, restricted to this test's file (the tenant is shared)."""
    return [r for r in audience.run_due(w.cfg, [TENANT]) if r["resource_uid"] == w.source]


def _bits(s: str) -> str:
    n = len(s)
    raw = int(s.ljust((n + 7) // 8 * 8, "0"), 2).to_bytes((n + 7) // 8, "big")
    return base64.b64encode(raw).decode()


def _beacon(w, link, token, bits, **kw):
    body = {"buckets": len(bits), "coverage": _bits(bits), "duration_ms": 63_500,
            "quality": "hd", **kw}
    return w.client.post(f"/media/v1/{link}/playback?t={token}", content=json.dumps(body),
                         headers={"Content-Type": "text/plain"})


def _aud(w, link):
    return _row(w, """SELECT coverage_pct, furthest_pct, completed_at IS NOT NULL,
                             completion_basis, plays
                        FROM share_link_audience WHERE link_uid = %s""", link)


# ── MS5b: the beacon ─────────────────────────────────────────────────────────

def test_scrubbing_to_the_end_is_full_furthest_and_almost_no_coverage(w):
    link, _s, s = _session(w)
    bits = "1" + "0" * 98 + "1"
    assert _beacon(w, link, s["session"], bits, furthest_ms=63_500, ended=True).status_code == 200
    cov, furthest, done, _b, _p = _aud(w, link)
    assert cov == 2 and furthest == 100 and not done


def test_lost_and_duplicated_beacons_store_the_same_coverage(w):
    """Cumulative, merged by union: the property, driven directly."""
    first_half = "1" * 50 + "0" * 50
    link, _s, s = _session(w)
    _beacon(w, link, s["session"], first_half)
    _beacon(w, link, s["session"], first_half)                  # duplicated
    _beacon(w, link, s["session"], "1" * 70 + "0" * 30)         # a later one; one between was lost
    a = _aud(w, link)
    link2, _s2, s2 = _session(w)
    _beacon(w, link2, s2["session"], "1" * 70 + "0" * 30)       # just the last one
    # 70 of the 99 counted buckets (the unplayed last one is not held against them)
    assert a[0] == _aud(w, link2)[0] == playback.coverage_pct("1" * 70 + "0" * 30) == 71


def test_a_client_supplied_percentage_is_never_stored(w):
    link, _s, s = _session(w)
    _beacon(w, link, s["session"], "1" * 10 + "0" * 90, coverage_pct=100, completed=True)
    assert _aud(w, link)[0] == 10


def test_full_coverage_with_too_few_bytes_is_recorded_with_the_weaker_basis(w):
    link, _s, s = _session(w)
    _get(w, link, s["session"], rng="bytes=0-99999")            # ~10% of the rendition
    _beacon(w, link, s["session"], "1" * 100, ended=True)
    _c, _f, done, basis, _p = _aud(w, link)
    assert done and basis == "beacon"
    assert "share_media_completed" in w.em.actions()


def test_full_coverage_with_the_bytes_behind_it_is_the_strong_basis(w):
    link, _s, s = _session(w)
    assert _get(w, link, s["session"]).status_code == 200       # the whole rendition
    _beacon(w, link, s["session"], "1" * 100, ended=True)
    assert _aud(w, link)[3] == "beacon+bytes"


def _expire(w, link):
    from share_service import media_door
    _row(w, "UPDATE share_media_sessions SET expires_at = now() - interval '1 second' "
            "WHERE link_uid = %s RETURNING 1", link)
    media_door.end_expired_sessions(w.cfg, [TENANT])


def test_loading_a_clip_is_not_watching_it(w):
    """A browser fetches a short clip whole as soon as it loads. While the
    session is open that says nothing about watching."""
    link, _s, s = _session(w, output_bytes=len(PAYLOAD))
    assert _get(w, link, s["session"]).status_code == 200
    assert _aud(w, link)[2] is False


def test_bytes_alone_make_probably_watched_never_confirmed(w):
    link, _s, s = _session(w, output_bytes=len(PAYLOAD))
    assert _get(w, link, s["session"]).status_code == 200       # no beacon, ever
    _expire(w, link)
    _c, _f, done, basis, _p = _aud(w, link)
    assert done and basis == "bytes-floor"
    item = [k for ev, k in w.published if ev == "media_completed"][0]
    assert "probably finished" in item["detail"] and "unverified" in item["detail"]


def test_a_session_that_beaconed_never_falls_back_to_bytes(w):
    link, _s, s = _session(w, output_bytes=len(PAYLOAD))
    _get(w, link, s["session"])
    _beacon(w, link, s["session"], "1" * 10 + "0" * 90)          # watched 10%
    _expire(w, link)
    assert _aud(w, link)[2] is False


def test_completion_notifies_for_gated_links_only(w):
    link, _s, s = _session(w, "open")
    _get(w, link, s["session"])
    _beacon(w, link, s["session"], "1" * 100, ended=True)
    assert "share_media_completed" in w.em.actions()
    assert not [ev for ev, _k in w.published if ev == "media_completed"]


def test_a_beacon_for_another_session_is_refused_not_merged(w):
    link, _s, s = _session(w)
    other_link, _so, other = _session(w)
    r = _beacon(w, link, s["session"], "1" * 100, session=other["session"])
    assert r.status_code == 403
    assert _beacon(w, link, other["session"], "1" * 100).status_code == 404   # wrong link
    assert _aud(w, link)[0] == 0 and _aud(w, other_link)[0] == 0


@pytest.mark.parametrize("body", [
    {"buckets": 0, "coverage": ""}, {"buckets": 1001, "coverage": "AA=="},
    {"buckets": 16, "coverage": "AA=="}, {"buckets": 8, "coverage": "not base64!"},
    {"buckets": 8, "coverage": "AA==", "rate_max": 99}, {"buckets": 8, "coverage": "AA==", "quality": "x"},
    {"buckets": 8, "coverage": "AA==", "furthest_ms": -1}])
def test_malformed_beacons_are_refused(w, body):
    link, _s, s = _session(w)
    r = w.client.post(f"/media/v1/{link}/playback?t={s['session']}", json=body)
    assert r.status_code == 400


def test_with_tracking_off_there_is_no_route_and_no_rows(w):
    w.cfg.playback_tracking = False
    link, secret, s = _session(w)
    assert s["tracking"] is False and "beacon" not in s
    assert w.client.get(f"/media/v1/{link}?k={secret}").json()["tracking"] is False
    assert _beacon(w, link, s["session"], "1" * 10).status_code == 404
    assert _row(w, "SELECT count(*) FROM share_media_playback WHERE link_uid = %s", link)[0] == 0


def test_the_retention_curve_is_a_column_popcount(w):
    link, _s0, _ = _session(w, "open")
    conn = db.connect_for_tenant(w.cfg, TENANT)
    lk = links.get(conn, link)
    conn.close()
    maps = ["1111", "1110", "1100", "1000"]
    for m in maps:
        r = w.client.post(f"/media/v1/{link}/session?k={_secret(w, link)}")
        _beacon(w, link, r.json()["session"], m)
    conn = db.connect_for_tenant(w.cfg, TENANT)
    assert playback.retention_curve(conn, link) == [100, 75, 50, 25]
    conn.close()
    assert lk.link_uid == link


def _secret(w, link):
    return w._secrets[link]


@pytest.fixture(autouse=True)
def _keep_secrets(w, monkeypatch):
    """Remember each minted link's secret, so a test can open more sessions."""
    import tests.test_media_door as door
    w._secrets = {}
    orig = door._mint

    def mint(world, mode="claimed", **kw):
        link, secret = orig(world, mode, **kw)
        world._secrets[link] = secret
        return link, secret
    monkeypatch.setattr(door, "_mint", mint)
    globals()["_mint"] = mint


def test_dropoff_is_phrased_in_time():
    assert playback.dropoff_seconds("1" * 50 + "0" * 50, 100_000) == 50
    assert playback.dropoff_seconds("1" * 100, 100_000) is None
    assert playback.device_class("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)") == "mobile"
    assert playback.device_class("Mozilla/5.0 (iPad; CPU OS 17_0)") == "tablet"
    assert playback.device_class("Mozilla/5.0 (X11; Linux x86_64)") == "desktop"


# ── MS5: the sidecar ──────────────────────────────────────────────────────────

def test_the_csv_is_rfc4180_with_a_bom_and_formula_guarded():
    body = audience.render([{**{c: "" for c in audience.COLUMNS},
                             "email": "=HYPERLINK(\"http://x\")@evil.example",
                             "link_note": "+cmd|' /c calc'!A1", "verified": False,
                             "referer_host": "a,b\"c"}])
    assert body.startswith(b"\xef\xbb\xbf")
    text = body[3:].decode()
    assert text.split("\r\n")[0] == ",".join(audience.COLUMNS)
    row = list(csv.DictReader(io.StringIO(text)))[0]
    assert row["email"].startswith("'=") and row["link_note"].startswith("'+")
    assert row["referer_host"] == 'a,b"c' and row["verified"] == "false"


def test_a_claimed_address_is_neutralized_in_the_file(w, side):
    link, secret = _mint(w, "claimed")
    # The door refuses formula characters outright; the guard still applies to
    # anything that reaches the table, so write one past the door.
    _row(w, """INSERT INTO share_link_audience (audience_uid, link_uid, email, email_norm)
               VALUES (%s, %s, %s, %s) RETURNING 1""",
         str(uuid.uuid4()), link, "@SUM(1+1)@x.example", "@sum(1+1)@x.example")
    audience.project(w.cfg, TENANT, w.source)
    assert side.csv(audience.ROLLUP)[0]["email"].startswith("'@")


def test_the_projection_writes_the_rollup_and_per_link_files_and_skips_when_unchanged(w, side):
    a, _sa, sa = _session(w)
    b, _sb, sb = _session(w, "open")
    rep = audience.project(w.cfg, TENANT, w.source)
    assert set(rep["written"]) == {audience.ROLLUP, audience.per_link_name(a),
                                   audience.per_link_name(b)}
    rollup = side.csv(audience.ROLLUP)
    assert {r["link_uid"] for r in rollup} == {a, b}
    assert {r["mode"] for r in rollup} == {"claimed", "open"}
    assert [r["email"] for r in rollup if r["mode"] == "open"] == [""]
    assert [r["verified"] for r in rollup if r["mode"] == "claimed"] == ["false"]
    writes = side.writes
    again = audience.project(w.cfg, TENANT, w.source)
    assert again["written"] == [] and side.writes == writes        # no identical versions
    assert "share_audience_exported" in w.em.actions()


def test_past_the_threshold_only_the_rollup_remains(w, side):
    w.cfg.audience_csv_per_link_max = 3
    made = [_session(w)[0] for _ in range(2)]
    audience.project(w.cfg, TENANT, w.source)
    assert len([n for n in side.files if n.startswith("audience-")]) == 2
    made += [_session(w)[0] for _ in range(2)]                       # now 4 live links
    rep = audience.project(w.cfg, TENANT, w.source)
    assert sorted(side.files) == [audience.ROLLUP]
    assert len(rep["removed"]) == 2
    assert {r["link_uid"] for r in side.csv(audience.ROLLUP)} == set(made)


def test_a_thousand_viewers_are_one_write_per_debounce_window(w, side):
    link, secret = _mint(w, "open")
    conn = db.connect_for_tenant(w.cfg, TENANT)
    for _ in range(1000):
        audience.mark_dirty(conn, w.source)
    conn.close()
    assert _due(w) == []                                             # inside the window
    _row(w, "UPDATE share_audience_dirty SET dirty_since = now() - interval '1 hour' "
            "WHERE resource_uid = %s RETURNING 1", w.source)
    done = _due(w)
    assert len(done) == 1 and side.writes == 2                       # rollup + the link's
    assert _due(w) == []


def test_revoking_projects_immediately(w, side, monkeypatch):
    """Through the owner route, not by calling the projection: revoke must
    regenerate the sidecar now, not at the next debounce."""
    import hashlib
    import hmac
    import time
    from share_service import api
    monkeypatch.setattr(api, "get_emitter", lambda c: w.em)
    link, _s, s = _session(w)
    assert audience.ROLLUP not in side.files
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")  # noqa: E731
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": CREATOR, "tenant": TENANT, "roles": {TENANT: ["users"]},
                           "exp": int(time.time()) + 600}).encode())
    sig = b64(hmac.new(w.cfg.jwt_secret.encode(), f"{head}.{body}".encode(),
                       hashlib.sha256).digest())
    r = w.client.delete(f"/share/v1/links/{link}",
                        headers={"Authorization": f"Bearer {head}.{body}.{sig}",
                                 "X-Tenant": TENANT})
    assert r.status_code == 200, r.text
    assert audience.ROLLUP in side.files and audience.per_link_name(link) in side.files


def test_a_creator_who_cannot_write_is_recorded_and_retried(w, side):
    _session(w)
    side.fail = True
    rep = audience.project(w.cfg, TENANT, w.source)
    assert rep["error"] and "PermissionError" in rep["error"]
    assert _row(w, "SELECT last_error FROM share_audience_sidecars WHERE resource_uid = %s "
                   "AND name = 'audience.csv'", w.source)[0]
    assert _row(w, "SELECT count(*) FROM share_audience_dirty WHERE resource_uid = %s",
                w.source)[0] == 1                                     # still due
    side.fail = False
    assert audience.project(w.cfg, TENANT, w.source)["written"]


def test_erasing_an_address_clears_its_rows_and_rewrites_the_file(w, side):
    link, secret = _mint(w, "claimed")
    keep, gone = f"keep-{uuid.uuid4().hex[:8]}@example.com", f"erase-{uuid.uuid4().hex[:8]}@example.com"
    for email in (keep, gone):
        r = w.client.post(f"/media/v1/{link}/claim?k={secret}",
                          json={"email": email, "consent": True})
        token = r.json()["session"]
        _beacon(w, link, token, "1" * 10)
    audience.project(w.cfg, TENANT, w.source)
    assert {r["email"] for r in side.csv(audience.ROLLUP)} == {keep, gone}
    out = audience.erase_address(w.cfg, TENANT, gone.upper())
    assert out["rows"] == 1
    assert {r["email"] for r in side.csv(audience.ROLLUP)} == {keep}
    assert _row(w, """SELECT count(*) FROM share_media_playback p
                       JOIN share_media_sessions s ON s.session_uid = p.session_uid
                      WHERE s.link_uid = %s""", link)[0] == 1


def test_retention_removes_the_sidecar_before_the_rows_and_keeps_the_row_if_it_cannot(w, side, monkeypatch):
    link, _s, s = _session(w)
    audience.project(w.cfg, TENANT, w.source)
    assert audience.per_link_name(link) in side.files
    _row(w, "UPDATE share_links SET revoked_at = now(), expires_at = now() - interval '400 days' "
            "WHERE link_uid = %s RETURNING 1", link)
    monkeypatch.setattr(retention, "get_emitter", lambda c: w.em)
    monkeypatch.setattr("share_service.core_client.for_creator", side.factory)
    w.cfg.retention_days = 365
    side.fail = True
    rep = retention.sweep_tenant(w.cfg, TENANT)
    assert rep["skipped"] >= 1
    assert _row(w, "SELECT count(*) FROM share_links WHERE link_uid = %s", link)[0] == 1
    side.fail = False
    retention.sweep_tenant(w.cfg, TENANT)
    assert _row(w, "SELECT count(*) FROM share_links WHERE link_uid = %s", link)[0] == 0
    assert audience.per_link_name(link) not in side.files
    assert _row(w, "SELECT count(*) FROM share_link_audience WHERE link_uid = %s", link)[0] == 0
