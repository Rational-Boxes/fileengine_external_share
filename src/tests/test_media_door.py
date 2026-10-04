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

"""MS4 — the media door (MEDIA_SHARE.md §6.3-6.9), against the §13 review list.

Postgres is real (sessions, budgets and the viewer cap are its job); the core,
the creator's authority, the OTP service and Redis are doubles at their seams,
so each §13 property can be driven directly — including the ones a live stack
cannot easily be made to exhibit (a revocation mid-session, Redis gone, a second
replica). The live version is test_live_media_door.py.
"""
from __future__ import annotations

import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from share_service import db, links, media_door, media_meter, otp_client, preflight, public
from share_service.app import create_app
from share_service.config import Config
from share_service.schema import KIND_MEDIA

TENANT = "default"
CREATOR = "media-door-fixture@rationalboxes.com"
VERSION = "20261004_050000.000"
PAYLOAD = bytes(range(256)) * 4096                     # 1 MiB, every offset distinct
SD = bytes(reversed(PAYLOAD))[: 400_000]


# ── doubles ────────────────────────────────────────────────────────────────────

class FakeRedis:
    """Only what the meter uses. Shared between two Meters = two replicas."""

    def __init__(self):
        self.kv = {}
        self.down = False

    def _chk(self):
        if self.down:
            raise ConnectionError("redis down")

    def get(self, k):
        self._chk()
        return self.kv.get(k)

    def mget(self, keys):
        self._chk()
        return [self.kv.get(k) for k in keys]

    def set(self, k, v, nx=False, ex=None):
        self._chk()
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True

    def incr(self, k):
        return self.incrby(k, 1)

    def incrby(self, k, n):
        self._chk()
        self.kv[k] = int(self.kv.get(k) or 0) + n
        return self.kv[k]

    def decr(self, k):
        return self.incrby(k, -1)

    def expire(self, k, s):
        self._chk()
        return True

    def delete(self, k):
        self._chk()
        self.kv.pop(k, None)

    def pipeline(self):
        outer = self

        class P:
            def __init__(self):
                self.ops = []

            def __getattr__(self, name):
                return lambda *a, **k: self.ops.append((name, a, k))

            def execute(self):
                return [getattr(outer, n)(*a, **k) for n, a, k in self.ops]
        return P()


class Core:
    """The creator's delegated core: the source, its published children, a poster."""

    def __init__(self, world):
        self.w = world
        self.client = self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def dir(self, uid):
        assert uid == self.w.source, "listed something other than the link's own source"
        return [types.SimpleNamespace(name=n, uid=u, size=len(self.w.blobs[u]))
                for n, u in self.w.children.items()]

    def get_stream(self, uid, offset=0, length=0):
        self.w.reads.append((uid, offset, length))
        data = self.w.blobs[uid]
        end = len(data) if not length else offset + length
        for i in range(offset, end, 65536):
            yield data[i:min(i + 65536, end)]

    def stat(self, uid):
        name = next(n for n, u in self.w.children.items() if u == uid)
        return types.SimpleNamespace(parent_uid=self.w.source, name=name,
                                     size=len(self.w.blobs[uid]))


class Emitter:
    available = True

    def __init__(self):
        self.events = []
        self.fail = False

    def emit(self, **kw):
        self.events.append(kw)
        return True

    def emit_or_raise(self, **kw):
        if self.fail:
            from share_service.audit import AuditUnavailable
            raise AuditUnavailable("down")
        self.events.append(kw)

    def actions(self):
        return [e["action"] for e in self.events]


# ── the world ───────────────────────────────────────────────────────────────────

@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.enabled = True
    c.media_enabled = True
    c.media_meter_flush_bytes = 1          # flush every chunk: assertions see exact bytes
    c.media_recheck_seconds = 300
    return c


@pytest.fixture
def w(cfg, monkeypatch):
    try:
        conn = db.connect_for_tenant(cfg, TENANT, provision=True)
        conn.close()
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"share_service Postgres not reachable: {e}")
    world = types.SimpleNamespace()
    world.source = str(uuid.uuid4())
    world.children, world.blobs = {}, {}
    for fmt, ext, data in (("media", "webm", PAYLOAD), ("media_sd", "webm", SD),
                           ("poster", "webp", b"RIFF....WEBPVP8 "),
                           ("preview", "webm", b"not published")):
        uid = str(uuid.uuid4())
        world.children[f"{VERSION}-{fmt}.{ext}"] = uid
        world.blobs[uid] = data
    world.reads = []
    world.allowed = True
    world.checks = 0
    world.em = Emitter()
    world.redis = FakeRedis()
    world.now = [time.time()]
    world.published = []

    core = Core(world)
    monkeypatch.setattr(media_door, "for_creator", lambda *a, **k: core)

    def check(c, **k):
        world.checks += 1
        assert k["resource_uid"] == world.source
        return preflight.PreflightResult(world.allowed, "ok" if world.allowed else "no_access",
                                         roles=["users"])
    monkeypatch.setattr(preflight, "check", check)
    monkeypatch.setattr(public, "_tenant_admits", lambda c, t: True)
    for mod in (public, media_door):
        monkeypatch.setattr(mod, "get_emitter", lambda c: world.em)
    monkeypatch.setattr(media_door, "get_publisher",
                        lambda c: types.SimpleNamespace(
                            publish=lambda ev, **k: world.published.append((ev, k))))
    monkeypatch.setattr(otp_client, "check_token",
                        lambda c, link_uid, email, token: token == "good-token")
    meter = media_meter.Meter(cfg, redis=world.redis, clock=lambda: world.now[0])
    monkeypatch.setattr(media_meter, "_meter", meter)
    monkeypatch.setattr(media_door.time, "time", lambda: world.now[0])
    media_door.forget_authority()
    media_door._set_cache.clear()
    world.meter = meter
    world.cfg = cfg
    world.client = TestClient(create_app(cfg), raise_server_exceptions=False)
    yield world
    # The source is a fake; leave nothing in the shared dev database that a
    # running service's sweeper would try (and fail) to project.
    _row(world, "DELETE FROM share_audience_dirty WHERE resource_uid = %s RETURNING 1",
         world.source)


def _mint(w, mode="claimed", **kw):
    conn = db.connect_for_tenant(w.cfg, TENANT, provision=True)
    try:
        link, secret = links.create(
            conn, kind=KIND_MEDIA, resource_uid=w.source, created_by=CREATOR,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            recipients=kw.pop("recipients", []), tenant=TENANT, access_mode=mode,
            media_state=kw.pop("media_state", "ready"), media_version=VERSION,
            duration_ms=63_500, display_name="Walkthrough",
            poster_uid=w.children[f"{VERSION}-poster.webp"], **kw)
    finally:
        conn.close()
    return link.link_uid, secret


def _row(w, sql, *args):
    conn = db.connect_for_tenant(w.cfg, TENANT)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            got = cur.fetchone()
        conn.commit()
        return got
    finally:
        conn.close()


def _claim(w, link, secret, email="viewer@example.com", **body):
    return w.client.post(f"/media/v1/{link}/claim?k={secret}",
                         content=__import__("json").dumps({"email": email, "consent": True, **body}),
                         headers={"Content-Type": "text/plain"})


def _session(w, mode="claimed", **kw):
    link, secret = _mint(w, mode, **kw)
    if mode == "claimed":
        r = _claim(w, link, secret)
    elif mode == "open":
        r = w.client.post(f"/media/v1/{link}/session?k={secret}")
    else:
        r = w.client.post(f"/media/v1/{link}/session?k={secret}",
                          json={"email": "v@example.com"},
                          headers={"X-Recipient-Token": "good-token"})
    assert r.status_code == 200, r.text
    return link, secret, r.json()


def _get(w, link, token, q="hd", rng=None, **headers):
    h = dict(headers)
    if rng:
        h["Range"] = rng
    return w.client.get(f"/media/v1/{link}/content?q={q}&t={token}", headers=h)


# ── §13.1-2: the origin's headers and its MIME allowlist ─────────────────────────────

def _assert_hardened(r):
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-disposition"] == "inline"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers.get("access-control-allow-origin") != "*"
    assert r.headers["x-robots-tag"] == "noindex"


def test_every_response_is_hardened_errors_included(w):
    link, secret, s = _session(w)
    for r in (w.client.get(f"/media/v1/{link}?k={secret}"),          # peek
              w.client.get(f"/media/v1/{link}?k=wrong"),              # 404
              _get(w, link, s["session"]),                             # bytes
              _get(w, link, "forged"),                                 # 404
              _get(w, link, s["session"], rng="bytes=99999999-")):     # 416
        _assert_hardened(r)
        if r.status_code != 200 or r.headers["content-type"].startswith("application/json"):
            assert r.headers["cache-control"] == "no-store"


def test_a_non_media_type_is_never_served(w):
    from fastapi.responses import HTMLResponse
    app = create_app(w.cfg)

    @app.get("/media/v1/test-only/html")
    def html():
        return HTMLResponse("<script>alert(1)</script>")
    r = TestClient(app).get("/media/v1/test-only/html")
    assert r.status_code == 500 and "<script>" not in r.text
    assert r.headers["content-type"].startswith("application/json")


def test_bytes_carry_the_media_type_a_private_lifetime_and_the_links_frame_ancestors(w):
    link, _s, s = _session(w, allowed_embed_origins=["https://client.example"])
    r = _get(w, link, s["session"], Origin="https://client.example")
    assert r.status_code == 200 and r.content == PAYLOAD
    assert r.headers["content-type"] == "video/webm"
    assert r.headers["cache-control"].startswith("private, max-age=")
    assert "frame-ancestors https://client.example" in r.headers["content-security-policy"]
    assert r.headers["access-control-allow-origin"] == "https://client.example"
    other = _get(w, link, s["session"], Origin="https://evil.example")
    assert "access-control-allow-origin" not in other.headers


# ── Range (§6.6's contract, served from the core's seek) ───────────────────────────────

def test_ranges_are_exact_and_read_only_the_window(w):
    link, _s, s = _session(w)
    w.reads.clear()
    r = _get(w, link, s["session"], rng="bytes=500000-599999")
    assert r.status_code == 206 and r.content == PAYLOAD[500000:600000]
    assert r.headers["content-range"] == f"bytes 500000-599999/{len(PAYLOAD)}"
    assert r.headers["content-length"] == "100000"
    assert w.reads == [(w.children[f"{VERSION}-media.webm"], 500000, 100000)]
    r = _get(w, link, s["session"], rng="bytes=-1000")
    assert r.status_code == 206 and r.content == PAYLOAD[-1000:]
    r = _get(w, link, s["session"], rng=f"bytes={len(PAYLOAD)}-")
    assert r.status_code == 416 and r.headers["content-range"] == f"bytes */{len(PAYLOAD)}"
    r = _get(w, link, s["session"], rng="bytes=0-1,5-9")
    assert r.status_code == 200 and len(r.content) == len(PAYLOAD)


# ── §13.4: the rendition comes only from the link record ─────────────────────────────────

def test_quality_is_an_enum_and_nothing_else_reaches_the_core(w):
    link, _s, s = _session(w)
    w.reads.clear()
    preview_uid = w.children[f"{VERSION}-preview.webm"]
    for q in ("preview", "media", preview_uid, "../x", "hd&q=preview"):
        assert _get(w, link, s["session"], q=q).status_code == 404
    assert w.reads == []
    r = _get(w, link, s["session"], q="sd")
    assert r.status_code == 200 and r.content == SD


def test_peek_lists_only_published_qualities_in_order(w):
    link, secret = _mint(w, "claimed")
    body = w.client.get(f"/media/v1/{link}?k={secret}").json()
    assert [s["quality"] for s in body["sources"]] == ["hd", "sd"]
    assert body["requires"] == "email" and body["state"] == "ready"
    assert body["title"] == "Walkthrough" and body["duration_ms"] == 63_500
    assert all("t=" not in s["url"] for s in body["sources"])        # no credential yet
    assert "resource_uid" not in str(body) and w.source not in str(body)


def test_a_link_still_encoding_says_preparing_and_opens_no_session(w):
    link, secret = _mint(w, "claimed", media_state="pending_media")
    assert w.client.get(f"/media/v1/{link}?k={secret}").json()["state"] == "preparing"
    r = _claim(w, link, secret)
    assert r.status_code == 202 and r.json() == {"state": "preparing"}
    assert _row(w, "SELECT count(*) FROM share_media_sessions WHERE link_uid = %s", link)[0] == 0


# ── §13.5 / §13.11: authorize, then serve; revocation lands within the bound ───────────

def test_an_unauthorized_caller_never_causes_a_core_read(w):
    link, secret = _mint(w, "claimed")
    w.reads.clear()
    assert _get(w, link, "not-a-session").status_code == 404
    assert _get(w, str(uuid.uuid4()), "x").status_code == 404
    w.allowed = False
    assert _claim(w, link, secret).status_code == 404               # creator lost access
    assert w.reads == []


def test_revoking_the_link_stops_the_very_next_request(w):
    link, _s, s = _session(w)
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206
    conn = db.connect_for_tenant(w.cfg, TENANT)
    links.revoke(conn, link, "creator")
    conn.close()
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 404


def test_lost_access_stops_playback_within_the_recheck_window(w):
    link, _s, s = _session(w)
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206
    w.allowed = False
    # Within the window and with no ACL event: still the cached answer.
    w.now[0] += w.cfg.media_recheck_seconds - 5
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206
    # Past it: re-checked, refused, and the session is over.
    w.now[0] += 10
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 404
    assert _row(w, "SELECT end_reason FROM share_media_sessions WHERE link_uid = %s",
                link)[0] == "revoked"
    assert "share_media_session_end" in w.em.actions()


def test_an_acl_event_makes_revocation_immediate(w):
    link, _s, s = _session(w)
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206
    w.allowed = False
    w.now[0] += 1
    w.meter.bump_acl_epoch(TENANT)               # what the consumer does on acl.changed
    w.now[0] += 1
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 404


# ── §13.7: budgets on bytes actually written ─────────────────────────────────────────────

def test_bytes_are_metered_as_written_and_ranges_cannot_evade_the_budget(w):
    link, _s, s = _session(w)
    for rng in ("bytes=0-99", "bytes=0-99", "bytes=1000-1999"):
        _get(w, link, s["session"], rng=rng)
    used = _row(w, "SELECT bytes_consumed FROM share_links WHERE link_uid = %s", link)[0]
    assert used == 100 + 100 + 1000               # a re-sent range is charged twice
    assert _row(w, "SELECT bytes_served FROM share_media_sessions WHERE link_uid = %s",
                link)[0] == used
    assert _row(w, "SELECT bytes_served FROM share_link_audience WHERE link_uid = %s",
                link)[0] == used


def test_an_abandoned_stream_is_charged_only_for_what_left(w):
    """TestClient reads every body to the end, so it cannot close a tab. The
    generator is driven directly instead: take one chunk, then close it, which is
    what the server does when the socket goes away."""
    link, _s, s = _session(w)
    conn = db.connect_for_tenant(w.cfg, TENANT)
    lk = links.get(conn, link)
    sess = _row(w, "SELECT session_uid, audience_uid FROM share_media_sessions WHERE link_uid = %s", link)
    conn.close()
    ticket = w.meter.admit(TENANT, link, str(sess[0])).ticket
    gen = media_door._stream(w.cfg, TENANT, lk, ["users"], w.children[f"{VERSION}-media.webm"],
                             0, len(PAYLOAD), str(sess[0]), str(sess[1]), ticket)
    first = next(gen)
    next(gen)                      # the first chunk has been taken for the socket
    gen.close()                    # ...and the viewer goes away
    used = _row(w, "SELECT bytes_consumed FROM share_links WHERE link_uid = %s", link)[0]
    assert used == len(first) < len(PAYLOAD)
    assert ticket.released                         # the concurrency slot came back


def test_the_budget_lets_the_response_in_flight_finish_and_refuses_the_next(w):
    link, _s, s = _session(w, max_bytes=150)
    assert _get(w, link, s["session"], rng="bytes=0-99").status_code == 206
    assert _get(w, link, s["session"], rng="bytes=0-99").status_code == 206   # crosses 150
    r = _get(w, link, s["session"], rng="bytes=0-99")
    assert r.status_code == 404                 # gated: uniform, even when parked
    assert "share_media_parked" in w.em.actions()
    assert any(ev == "media_parked" for ev, _ in w.published)


# ── §13.14: rung 3 explains itself for OPEN links only ───────────────────────────────────

def test_a_parked_open_link_says_why_and_a_gated_one_does_not(w):
    link, secret, s = _session(w, "open", max_bytes=10)
    _get(w, link, s["session"], rng="bytes=0-99")
    r = _get(w, link, s["session"], rng="bytes=0-9")
    assert r.status_code == 503 and "very popular" in r.json()["message"]
    assert int(r.headers["retry-after"]) > 0
    assert w.client.get(f"/media/v1/{link}?k={secret}").status_code == 503
    glink, gsecret, gs = _session(w, "claimed", max_bytes=10)
    _get(w, glink, gs["session"], rng="bytes=0-99")
    assert _get(w, glink, gs["session"], rng="bytes=0-9").status_code == 404
    assert w.client.get(f"/media/v1/{glink}?k={gsecret}").status_code == 404


# ── §6.9: the ladder, and §13.12-13: shared counters, degraded Redis ─────────────────────

def test_link_concurrency_throttles_with_retry_after_and_audits_once(w):
    w.cfg.media_max_concurrent_per_link = 1
    link, _s, s = _session(w)
    w.redis.kv[f"share:media:conc:link:{TENANT}:{link}"] = 1     # one stream in flight
    for _ in range(3):
        r = _get(w, link, s["session"], rng="bytes=0-9")
        assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert w.em.actions().count("share_media_throttled") == 1


def test_sustained_throttling_parks_the_link(w):
    w.cfg.media_max_concurrent_per_link = 1
    link, _s, s = _session(w, "open")
    w.redis.kv[f"share:media:conc:link:{TENANT}:{link}"] = 1
    assert _get(w, link, s["session"]).status_code == 429
    w.now[0] += w.cfg.media_park_after_minutes * 60 + 1
    r = _get(w, link, s["session"])
    assert r.status_code == 503 and "share_media_parked" in w.em.actions()


def test_the_hourly_link_window_throttles_and_the_soft_ceiling_advises_once(w):
    w.cfg.media_max_egress_per_hour = 1000
    link, _s, s = _session(w)
    assert _get(w, link, s["session"], rng="bytes=0-849").status_code == 206   # 85%
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206     # advises
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206     # not again
    assert [ev for ev, _ in w.published].count("media_popular") == 1
    assert "PeerTube" in dict(w.published)["media_popular"]["detail"]
    _get(w, link, s["session"], rng="bytes=0-199")                              # past 1000
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 429


def test_counters_are_shared_between_replicas(w):
    a = media_meter.Meter(w.cfg, redis=w.redis)
    b = media_meter.Meter(w.cfg, redis=w.redis)
    w.cfg.media_max_concurrent_per_link = 2
    t1 = a.admit(TENANT, "L", "c1").ticket
    t2 = b.admit(TENANT, "L", "c2").ticket
    assert t1 and t2
    refused = a.admit(TENANT, "L", "c3")
    assert not refused.ok and refused.reason == "link_concurrency"
    b.release(t2)
    assert a.admit(TENANT, "L", "c3").ok


def test_losing_redis_degrades_metering_but_not_authorization(w):
    link, _s, s = _session(w)
    w.redis.down = True
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 206
    assert w.meter.degraded
    from share_service.metrics import Metrics
    m = Metrics("share_service")
    media_door.collect_media(m)
    assert "fileengine_media_meter_degraded{service=\"share_service\"} 1" in m.render()
    w.allowed = False
    w.now[0] += w.cfg.media_recheck_seconds + 1
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 404
    w.redis.down = False


def test_degraded_metering_tightens_the_instance_cap(w):
    w.cfg.media_max_concurrent_streams = 8
    w.redis.down = True
    held = [w.meter.admit(TENANT, "L", f"c{i}") for i in range(2)]
    assert all(d.ok for d in held)
    assert not w.meter.admit(TENANT, "L", "c3").ok          # 8 // 4 == 2
    for d in held:
        w.meter.release(d.ticket)
    w.redis.down = False


# ── the three modes, and §13.6: /claim ───────────────────────────────────────────────────

def test_claimed_records_an_unverified_address_and_flags_the_expected_one(w):
    link, secret = _mint(w, "claimed", recipients=["expected@example.com"])
    assert _claim(w, link, secret, email="Expected@Example.com").status_code == 200
    assert _claim(w, link, secret, email="stranger@example.com").status_code == 200
    assert _claim(w, link, secret, email="expected@example.com").status_code == 200
    conn = db.connect_for_tenant(w.cfg, TENANT)
    with conn.cursor() as cur:
        cur.execute("""SELECT email_norm, verified, on_allowlist, sessions
                         FROM share_link_audience WHERE link_uid = %s ORDER BY email_norm""",
                    (link,))
        rows = cur.fetchall()
    conn.close()
    assert rows == [("expected@example.com", False, True, 2),
                    ("stranger@example.com", False, False, 1)]
    claims = [e for e in w.em.events if e["action"] == "share_media_claim"]
    assert claims[0]["actor"] == f"share:{link}|claimed:expected@example.com"


@pytest.mark.parametrize("email", [
    "=cmd|' /c calc'!A1@example.com", "+1@example.com", "a@b", "a b@example.com",
    "x" * 400 + "@example.com", "a@example.com\nBcc: b@example.com", ""])
def test_claim_accepts_an_address_and_nothing_else(w, email):
    link, secret = _mint(w, "claimed")
    assert _claim(w, link, secret, email=email).status_code == 400


def test_claim_needs_consent_and_is_rate_limited_per_ip(w):
    link, secret = _mint(w, "claimed")
    r = w.client.post(f"/media/v1/{link}/claim?k={secret}", json={"email": "a@example.com"})
    assert r.status_code == 400 and r.json()["error"] == "consent_required"
    codes = [_claim(w, link, secret, email=f"v{i}@example.com").status_code
             for i in range(w.cfg.claim_rate_per_hour + 1)]
    assert codes[:-1] == [200] * w.cfg.claim_rate_per_hour and codes[-1] == 429


def test_claim_is_only_for_claimed_links(w):
    link, secret = _mint(w, "open")
    assert _claim(w, link, secret).status_code == 404


def test_open_needs_nothing_and_each_session_is_an_anonymous_viewer(w):
    link, _s, s = _session(w, "open")
    assert s["sources"][0]["url"].endswith(f"&t={s['session']}")
    ev = [e for e in w.em.events if e["action"] == "share_media_open_view"][0]
    assert ev["actor"].startswith(f"share:{link}|anon:")


def test_verified_needs_the_recipient_token(w):
    link, secret = _mint(w, "verified", recipients=["v@example.com"])
    bad = w.client.post(f"/media/v1/{link}/session?k={secret}", json={"email": "v@example.com"},
                        headers={"X-Recipient-Token": "forged"})
    assert bad.status_code == 404
    ok = w.client.post(f"/media/v1/{link}/session?k={secret}", json={"email": "v@example.com"},
                       headers={"X-Recipient-Token": "good-token"})
    assert ok.status_code == 200
    assert [e for e in w.em.events if e["action"] == "share_media_session"][0]["actor"] == \
        f"share:{link}|v@example.com"


def test_max_viewers_counts_people_not_sessions(w):
    link, secret = _mint(w, "claimed", max_viewers=1)
    assert _claim(w, link, secret, email="a@example.com").status_code == 200
    assert _claim(w, link, secret, email="a@example.com").status_code == 200   # same person
    assert _claim(w, link, secret, email="b@example.com").status_code == 404


def test_a_session_does_not_open_unaudited(w):
    link, secret = _mint(w, "claimed")
    w.em.fail = True
    assert _claim(w, link, secret).status_code == 404
    assert _row(w, "SELECT count(*) FROM share_media_sessions WHERE link_uid = %s", link)[0] == 0


def test_one_audit_event_per_session_never_per_range(w):
    link, _s, s = _session(w)
    before = len(w.em.events)
    for i in range(20):
        _get(w, link, s["session"], rng=f"bytes={i * 1000}-{i * 1000 + 99}")
    assert len(w.em.events) == before


def test_an_expired_session_is_closed_with_what_it_did(w):
    link, _s, s = _session(w)
    _get(w, link, s["session"], rng="bytes=0-99")
    _row(w, "UPDATE share_media_sessions SET expires_at = now() - interval '1 second' "
            "WHERE link_uid = %s RETURNING 1", link)
    assert _get(w, link, s["session"], rng="bytes=0-9").status_code == 404
    assert media_door.end_expired_sessions(w.cfg, [TENANT]) >= 1
    ends = [e for e in w.em.events if e["action"] == "share_media_session_end"
            and e["detail"]["link_uid"] == link]
    assert ends and ends[0]["detail"]["bytes"] == 100 and ends[0]["detail"]["ended"] == "expired"


def test_a_session_token_opens_only_its_own_link(w):
    link_a, _s, s = _session(w)
    link_b, _sb, _ = _session(w)
    assert _get(w, link_b, s["session"]).status_code == 404


def test_the_poster_streams_unaudited_and_only_a_child_of_the_source(w):
    link, secret = _mint(w, "claimed")
    before = list(w.em.actions())
    r = w.client.get(f"/media/v1/{link}/poster?k={secret}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/webp"
    assert w.em.actions() == before
    assert w.client.get(f"/media/v1/{link}/poster?k=wrong").status_code == 404


def test_media_links_are_off_unless_enabled(w):
    link, secret = _mint(w, "claimed")
    w.cfg.media_enabled = False
    assert w.client.get(f"/media/v1/{link}?k={secret}").status_code == 404


def test_the_media_door_serves_no_other_kind(w):
    conn = db.connect_for_tenant(w.cfg, TENANT, provision=True)
    link, secret = links.create(conn, kind=0, resource_uid=w.source, created_by=CREATOR,
                                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                                recipients=["a@example.com"], tenant=TENANT)
    conn.close()
    assert w.client.get(f"/media/v1/{link.link_uid}?k={secret}").status_code == 404


# ── MS7: download, the landing page's peek, and the poster is not a view ─────────

def test_download_is_offered_only_where_allowed_and_serves_the_720p_as_an_attachment(w):
    link, _s, s = _session(w, allow_download=True)
    r = w.client.get(f"/media/v1/{link}/download?t={s['session']}")
    assert r.status_code == 200 and r.content == PAYLOAD
    assert r.headers["content-type"] == "video/webm"
    assert r.headers["content-disposition"] == 'attachment; filename="Walkthrough.webm"'
    assert r.headers["x-content-type-options"] == "nosniff"
    # Metered exactly like play: it is the same bytes leaving.
    assert _row(w, "SELECT bytes_consumed FROM share_links WHERE link_uid = %s",
                link)[0] == len(PAYLOAD)
    shut, _s2, s2 = _session(w, allow_download=False)
    assert w.client.get(f"/media/v1/{shut}/download?t={s2['session']}").status_code == 404
    assert w.client.get(f"/media/v1/{link}/download?t=forged").status_code == 404


def test_only_the_download_route_may_say_attachment(w):
    link, _s, s = _session(w, allow_download=True)
    assert _get(w, link, s["session"]).headers["content-disposition"] == "inline"


def test_peek_says_whether_download_is_allowed(w):
    link, secret = _mint(w, "verified", recipients=["v@example.com"], allow_download=True)
    assert w.client.get(f"/media/v1/{link}?k={secret}").json()["allow_download"] is True


def test_the_landing_peek_for_a_media_link_names_the_door_and_nothing_else(w):
    w.cfg.media_base_url = "https://{tenant}-media.example.com"
    link, secret = _mint(w, "claimed")
    r = w.client.get(f"/share/v1/public/{link}", headers={"X-Share-Secret": secret})
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == 3 and body["media_base"] == f"https://{TENANT}-media.example.com"
    assert set(body) == {"kind", "expires_at", "media_base", "media_enabled"}


def test_the_generic_share_routes_never_serve_a_media_link(w):
    link, secret = _mint(w, "verified", recipients=["v@example.com"])
    h = {"X-Share-Secret": secret, "X-Recipient-Token": "good-token"}
    assert w.client.post(f"/share/v1/public/{link}/session", json={"email": "v@example.com"},
                         headers=h).status_code == 404
    assert w.client.get(f"/share/v1/public/{link}/content?k={secret}&redemption=x").status_code == 404


def test_a_poster_fetch_is_never_counted_as_a_view(w):
    """Mail-privacy proxies fetch every image in a message. A poster fetch opens
    no session, adds no viewer and writes no audit event (§9.4, §12.1)."""
    link, secret = _mint(w, "claimed")
    before = list(w.em.actions())
    for _ in range(5):
        assert w.client.get(f"/media/v1/{link}/poster?k={secret}").status_code == 200
    assert _row(w, "SELECT count(*) FROM share_media_sessions WHERE link_uid = %s", link)[0] == 0
    assert _row(w, "SELECT count(*) FROM share_link_audience WHERE link_uid = %s", link)[0] == 0
    assert w.em.actions() == before


# ── MS8: the embed — script, player page, oEmbed (§9) ─────────────────────────────

def test_the_embed_script_is_served_as_javascript_and_nothing_else_is(w):
    r = w.client.get("/media/v1/embed/fe-media-share.js")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/javascript")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"].startswith("public")
    # Any host must be able to load it cross-origin (it carries no credential);
    # this is the only place under the door a literal "*" survives.
    assert r.headers["access-control-allow-origin"] == "*"
    assert "customElements" in r.text or "defineFeMediaShare" in r.text
    for bad in ("../app.py", "nope.js", "%2e%2e%2fapp.py", "player.html"):
        assert w.client.get(f"/media/v1/embed/{bad}").status_code == 404


def test_the_served_script_is_the_kit_component_verbatim():
    """share_service serves a VENDORED copy of commercial_embedding's component;
    this keeps the two identical (skipped where the sibling repo is absent)."""
    import pathlib
    here = pathlib.Path(__file__).resolve()
    kit = here.parents[3] / "commercial_embedding" / "packages" / "components" / "src"
    if not kit.is_dir():
        pytest.skip("commercial_embedding not checked out beside share_service")
    ours = here.parents[1] / "share_service" / "embed"
    for name in ("fe-media-share.js", "media-share-model.js"):
        assert (ours / name).read_bytes() == (kit / name).read_bytes(), f"{name} drifted from the kit"


def test_the_player_page_is_framable_only_by_the_links_allowlist(w):
    link, secret = _mint(w, "claimed", allowed_embed_origins=["https://client.example"])
    r = w.client.get(f"/media/v1/player/{link}?k={secret}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors https://client.example" in csp
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert f'name="fe-link" content="{link}"' in r.text
    assert "https://client.example" in r.text                  # the data meta tag
    assert "<script>" not in r.text                            # no inline script at all
    none_link, s2 = _mint(w, "claimed")
    assert "frame-ancestors 'none'" in w.client.get(
        f"/media/v1/player/{none_link}?k={s2}").headers["content-security-policy"]
    bad = w.client.get(f"/media/v1/player/{link}?k=wrong")
    assert bad.status_code == 404 and "frame-ancestors 'none'" in bad.headers["content-security-policy"]


def test_html_is_still_refused_everywhere_but_the_player(w):
    link, _s, s = _session(w)
    assert _get(w, link, s["session"]).headers["content-type"] == "video/webm"
    assert w.client.get(f"/media/v1/{link}?k=x").headers["content-type"].startswith("application/json")


def test_oembed_returns_an_iframe_for_an_embeddable_link_only(w):
    w.cfg.media_base_url = "https://{tenant}-media.example.com"
    link, secret = _mint(w, "claimed", allowed_embed_origins=["https://client.example"])
    url = f"https://default-media.example.com/media/v1/{link}?k={secret}"
    r = w.client.get("/media/v1/oembed", params={"url": url, "maxwidth": 640})
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "video" and body["version"] == "1.0" and body["width"] == 640
    assert f"https://default-media.example.com/media/v1/player/{link}?k={secret}" in body["html"]
    assert body["html"].startswith("<iframe") and "Walkthrough" in body["title"]
    assert body["thumbnail_url"].endswith(f"/media/v1/{link}/poster?k={secret}")
    # The /s/ form works too.
    assert w.client.get("/media/v1/oembed", params={
        "url": f"https://acme.example.com/s/{link}.{secret}"}).status_code == 200
    # No allowlist: not embeddable, so no oEmbed.
    plain, s2 = _mint(w, "claimed")
    assert w.client.get("/media/v1/oembed", params={
        "url": f"https://m/media/v1/{plain}?k={s2}"}).status_code == 404
    assert w.client.get("/media/v1/oembed", params={"url": url.replace(secret, "x")}).status_code == 404


def test_an_open_link_embeddable_anywhere_echoes_the_origin_never_star(w):
    link, secret = _mint(w, "open", allowed_embed_origins=["*"])
    r = w.client.get(f"/media/v1/{link}?k={secret}", headers={"Origin": "https://anyone.example"})
    assert r.headers["access-control-allow-origin"] == "https://anyone.example"
    assert "frame-ancestors *" in w.client.get(
        f"/media/v1/player/{link}?k={secret}").headers["content-security-policy"]
