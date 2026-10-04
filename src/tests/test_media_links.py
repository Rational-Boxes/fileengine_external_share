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

"""MS3 — media links, owner side (MEDIA_SHARE.md §5, §6.1–6.2, §7.1).

CSAI and LDAP are replaced at their module seams; Postgres is real when it is
reachable, because two of the rules here are deliberately enforced BY the
database (§5 rules 1 and 2) and a fake cannot show that. The end-to-end version
against the real core, CSAI and media worker is test_live_media_links.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

from share_service import api, core_client, db, links, media_client, media_events, preflight
from share_service.app import create_app
from share_service.config import Config
from share_service.schema import KIND_MEDIA

USER = "media-fixture@rationalboxes.com"
POSTER = str(uuid.uuid4())
TENANT = "default"
SECRET = "media-internal-test-secret"


# --- fixtures ------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(cfg: Config) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub": USER, "tenant": TENANT, "roles": {TENANT: ["users"]},
        "exp": int(time.time()) + 600}).encode())
    sig = hmac.new(cfg.jwt_secret.encode(), f"{header}.{payload}".encode(),
                   hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    if not c.jwt_secret:
        pytest.skip("FILEENGINE_JWT_SECRET not configured")
    c.enabled = True
    c.media_enabled = True
    c.allow_open_mode = True
    c.media_internal_secret = SECRET
    c.media_base_url = ""
    c.tenant_base_domain = "example.com"
    return c


@pytest.fixture
def conn(cfg):
    try:
        c = db.connect_for_tenant(cfg, TENANT, provision=True)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"share_service Postgres not reachable: {e}")
    # connect_for_tenant SETs search_path inside the first transaction; commit it
    # so the tests that roll back an expected violation keep the tenant schema.
    c.commit()
    yield c
    c.rollback()
    c.close()


class _Emitter:
    available = True

    def __init__(self):
        self.events = []

    def emit(self, **kw):
        self.events.append(kw)
        return True

    def emit_or_raise(self, **kw):
        self.events.append(kw)


class _Core:
    """The creator's delegated core, as creation uses it."""

    def __init__(self, *, is_dir=False, poster=POSTER):
        self._is_dir, self._poster = is_dir, poster

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def is_dir(self, uid):
        return self._is_dir

    def locate(self, uid):
        return 2, "/videos/intro.mp4"

    def poster_uid(self, uid):
        return self._poster


def _state(status="succeeded", *, profile="video-720p-vp9", version="v7",
           output_bytes=22_000_000, duration_ms=63_500):
    return media_client.PublishState(
        source_version=version, mime="video/mp4",
        jobs=[{"profile": profile, "status": status, "output_bytes": output_bytes,
               "duration_ms": duration_ms}] if status else [])


@pytest.fixture
def world(cfg, monkeypatch):
    """The creation route with LDAP, the core and CSAI at their seams."""
    em = _Emitter()
    monkeypatch.setattr(api, "get_emitter", lambda c: em)
    w = types.SimpleNamespace(em=em, open_group=True, share_group=True,
                              state=_state(), published=[], refuse=None, core=_Core())
    monkeypatch.setattr(api, "in_share_group", lambda c, u: w.share_group)
    monkeypatch.setattr(api, "in_open_group", lambda c, u: w.open_group)
    monkeypatch.setattr(api.preflight, "check",
                        lambda *a, **k: preflight.PreflightResult(True, roles=["users"]))
    monkeypatch.setattr(api.core_client, "for_creator", lambda *a, **k: w.core)

    def state(c, **k):
        if w.refuse:
            raise w.refuse
        return w.state

    def publish(c, **k):
        if w.refuse:
            raise w.refuse
        w.published.append(k)
        return _state("queued")
    monkeypatch.setattr(api.media_client, "state", state)
    monkeypatch.setattr(api.media_client, "publish", publish)
    w.client = TestClient(create_app(cfg), raise_server_exceptions=False)
    w.auth = {"Authorization": f"Bearer {_token(cfg)}", "X-Tenant": TENANT}
    return w


def _create(w, **body):
    payload = {"kind": KIND_MEDIA, "recipients": ["viewer@example.com"], **body}
    return w.client.post(f"/share/v1/nodes/{uuid.uuid4()}/links", json=payload, headers=w.auth)


# --- creation: the three modes (§5) ---------------------------------------------

def test_a_verified_media_link_on_a_published_file_is_ready_and_described(world, conn):
    r = _create(world, display_name="Welcome", allowed_embed_origins=["https://Client.Example/"])
    assert r.status_code == 201, r.text
    b = r.json()
    assert b["access_mode"] == "verified" and b["media_state"] == "ready"
    assert b["media_version"] == "v7" and b["duration_ms"] == 63_500
    assert b["output_bytes"] == 22_000_000 and b["poster_uid"] == POSTER
    assert b["allowed_embed_origins"] == ["https://client.example"]
    assert b["display_name"] == "Welcome" and b["max_uses"] == 0
    # The embed address is on the MEDIA origin, never the tenant's.
    assert "-media." in b["media_url"] and "/media/v1/" + b["link_uid"] + "?k=" in b["media_url"]
    assert world.published == []                 # nothing to publish
    assert world.em.events[-1]["detail"]["access_mode"] == "verified"


def test_an_unpublished_file_is_published_as_the_creator_and_minted_pending(world, conn):
    world.state = _state(status=None)
    r = _create(world)
    assert r.status_code == 201 and r.json()["media_state"] == "pending_media"
    assert world.published and world.published[0]["bearer"]   # the creator's own bearer


def test_publish_false_refuses_rather_than_spending(world, conn):
    world.state = _state(status=None)
    r = _create(world, publish=False)
    assert r.status_code == 409 and world.published == []


def test_a_reader_who_cannot_publish_is_told_why(world, conn):
    world.state = _state(status=None)
    world.refuse = media_client.MediaRefused(403, "publishing requires write access")
    r = _create(world)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "publish_not_permitted"


def test_a_document_is_not_a_media_link(world, conn):
    world.refuse = media_client.MediaRefused(415, "application/pdf is not audio or video")
    assert _create(world).status_code == 400


def test_a_rendition_over_the_size_cap_is_refused(world, cfg, conn):
    cfg.media_max_bytes = 1000
    assert _create(world).status_code == 400


def test_csai_down_is_a_503_not_a_link(world, conn):
    world.refuse = media_client.MediaUnavailable("down")
    assert _create(world).status_code == 503


def test_media_links_need_the_feature_switch(world, cfg):
    cfg.media_enabled = False
    assert _create(world).status_code == 403


def test_a_folder_is_not_a_media_link(world, conn):
    world.core = _Core(is_dir=True)
    assert _create(world).status_code == 400


def test_verified_needs_recipients(world):
    assert _create(world, recipients=[]).status_code == 400


def test_claimed_takes_an_optional_advisory_list(world, conn):
    assert _create(world, access_mode="claimed", recipients=[]).status_code == 201
    assert _create(world, access_mode="claimed").status_code == 201


def test_open_needs_all_three_gates(world, cfg, conn):
    ok = dict(access_mode="open", recipients=[], confirm_public=True, display_name="Walkthrough")
    assert _create(world, **ok).status_code == 201
    r = _create(world, **{**ok, "confirm_public": False})
    assert r.status_code == 400 and "anyone with this link" in r.json()["detail"]["message"]
    world.open_group = False
    assert _create(world, **ok).status_code == 403
    world.open_group = True
    cfg.allow_open_mode = False
    assert _create(world, **ok).status_code == 403


def test_an_open_link_needs_a_public_title_and_others_default_to_the_file_name(world, conn):
    r = _create(world, access_mode="open", recipients=[], confirm_public=True)
    assert r.status_code == 400 and r.json()["detail"]["error"] == "display_name_required"
    assert _create(world).json()["display_name"] == "intro.mp4"     # from the path


def test_open_refuses_a_recipient_list(world):
    assert _create(world, access_mode="open", confirm_public=True).status_code == 400


def test_claimed_and_open_are_refused_for_every_other_kind(world):
    for kind in (0, 1, 2):
        for mode in ("claimed", "open"):
            r = world.client.post(f"/share/v1/nodes/{uuid.uuid4()}/links", headers=world.auth,
                                  json={"kind": kind, "recipients": ["a@example.com"],
                                        "access_mode": mode, "confirm_public": True})
            assert r.status_code == 400, (kind, mode)


def test_an_unknown_mode_is_refused(world):
    assert _create(world, access_mode="public").status_code == 400


def test_media_links_are_metered_by_viewers_and_bytes_not_uses(world, conn):
    assert _create(world, max_uses=5).status_code == 400
    assert _create(world, max_viewers=-1).status_code == 400
    r = _create(world, max_viewers=40)
    assert r.status_code == 201 and r.json()["max_viewers"] == 40


def test_a_default_egress_budget_applies(world, cfg, conn):
    assert _create(world).json()["max_bytes"] == cfg.media_default_max_bytes


@pytest.mark.parametrize("origin", [
    "http://client.example", "https://*.client.example", "https://client.example/embed",
    "client.example", "https://user@client.example", "https://client.example/?x=1"])
def test_embed_origins_must_be_bare_https_origins(world, origin):
    assert _create(world, allowed_embed_origins=[origin]).status_code == 400


def test_an_open_link_cannot_gain_a_recipient_list_later(world, conn):
    link_uid = _create(world, access_mode="open", recipients=[], confirm_public=True,
                       display_name="Walkthrough").json()["link_uid"]
    r = world.client.post(f"/share/v1/links/{link_uid}/recipients",
                          json={"email": "x@example.com"}, headers=world.auth)
    assert r.status_code == 400


# --- the database enforces §5 rules 1 and 2 ---------------------------------------

def _insert(conn, kind, mode):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO share_links (link_uid, kind, resource_uid, secret_hash,
                                                created_by, expires_at, access_mode)
                       VALUES (%s,%s,%s,%s,%s, now() + interval '1 day', %s)""",
                    (str(uuid.uuid4()), kind, str(uuid.uuid4()), b"x", USER, mode))


def test_the_database_refuses_claimed_or_open_for_kinds_0_to_2(conn):
    for kind in (0, 1, 2):
        for mode in ("claimed", "open"):
            with pytest.raises(psycopg.errors.CheckViolation):
                _insert(conn, kind, mode)
            conn.rollback()
    with pytest.raises(psycopg.errors.CheckViolation):
        _insert(conn, KIND_MEDIA, "public")
    conn.rollback()
    _insert(conn, KIND_MEDIA, "open")            # the one legal combination
    conn.rollback()


def _media_link(conn, mode="verified", **kw):
    link, _ = links.create(conn, kind=KIND_MEDIA, resource_uid=kw.pop("resource", str(uuid.uuid4())),
                           created_by=kw.pop("by", USER),
                           expires_at=kw.pop("expires", datetime.now(timezone.utc) + timedelta(days=7)),
                           recipients=[] if mode != "verified" else ["v@example.com"],
                           tenant=TENANT, access_mode=mode, **kw)
    return link


def test_access_mode_and_kind_are_immutable(conn):
    link = _media_link(conn)
    for sql in ("UPDATE share_links SET access_mode = 'open' WHERE link_uid = %s",
                "UPDATE share_links SET kind = 0 WHERE link_uid = %s"):
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(sql, (link.link_uid,))
        conn.rollback()
    # ...while everything a link legitimately does to itself still works.
    assert links.revoke(conn, link.link_uid, "someone")


def test_the_audience_is_one_row_per_address_per_link(conn):
    link = _media_link(conn, "claimed")
    ins = """INSERT INTO share_link_audience (audience_uid, link_uid, email, email_norm)
             VALUES (%s,%s,%s,%s)"""
    with conn.cursor() as cur:
        cur.execute(ins, (str(uuid.uuid4()), link.link_uid, "A@x.com", "a@x.com"))
    conn.commit()
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.cursor() as cur:
            cur.execute(ins, (str(uuid.uuid4()), link.link_uid, "a@X.com ", "a@x.com"))
    conn.rollback()


# --- live links and the published description -------------------------------------

def test_live_media_links_are_the_ones_that_can_still_play(conn):
    res = str(uuid.uuid4())
    live = _media_link(conn, resource=res)
    dead = _media_link(conn, resource=res)
    links.revoke(conn, dead.link_uid, "x")
    with conn.cursor() as cur:            # an expired one, written past the clamp
        cur.execute("UPDATE share_links SET expires_at = now() - interval '1 minute' "
                    "WHERE link_uid = %s", (_media_link(conn, resource=res).link_uid,))
    conn.commit()
    assert [l.link_uid for l in links.live_media_links(conn, res)] == [live.link_uid]


def test_a_newer_published_set_readies_links_and_an_older_one_never_rolls_back(conn):
    res = str(uuid.uuid4())
    link = _media_link(conn, resource=res, media_state="pending_media")
    assert links.record_media_published(conn, res, version="20261004_010000.000",
                                        duration_ms=5000, output_bytes=900) == [link.link_uid]
    got = links.get(conn, link.link_uid)
    assert (got.media_state, got.media_version, got.duration_ms) == ("ready", "20261004_010000.000", 5000)
    assert links.record_media_published(conn, res, version="20261003_010000.000",
                                        duration_ms=1, output_bytes=1) == []
    assert links.get(conn, link.link_uid).media_version == "20261004_010000.000"


def test_a_failed_publish_only_fails_a_link_with_nothing_to_play(conn):
    res = str(uuid.uuid4())
    pending = _media_link(conn, resource=res, media_state="pending_media")
    playing = _media_link(conn, resource=res, media_state="ready", media_version="v1")
    assert links.record_media_failed(conn, res, version="v2") == [pending.link_uid]
    assert links.get(conn, playing.link_uid).media_state == "ready"


# --- media-refs, the internal seam CSAI asks before removing a copy ------------------

def _refs(client, uid, secret=SECRET, tenant=TENANT):
    h = {}
    if secret is not None:
        h["X-Internal-Auth"] = secret
    if tenant is not None:
        h["X-Tenant"] = tenant
    return client.get(f"/share/v1/internal/media-refs/{uid}", headers=h)


def test_media_refs_counts_live_media_links(cfg, conn):
    res = str(uuid.uuid4())
    c = TestClient(create_app(cfg))
    assert _refs(c, res).json() == {"file_uid": res, "live_links": 0}
    a = _media_link(conn, resource=res)
    _media_link(conn, resource=res)
    assert _refs(c, res).json()["live_links"] == 2
    links.revoke(conn, a.link_uid, "x")
    assert _refs(c, res).json()["live_links"] == 1


def test_media_refs_is_closed_without_the_secret(cfg):
    c = TestClient(create_app(cfg))
    uid = str(uuid.uuid4())
    assert _refs(c, uid, secret="wrong").status_code == 403
    assert _refs(c, uid, secret=None).status_code == 403
    assert _refs(c, uid, tenant=None).status_code == 400
    cfg.media_internal_secret = ""
    assert _refs(TestClient(create_app(cfg)), uid).status_code == 404


def test_media_refs_takes_no_bearer_and_leaks_no_link_detail(cfg, conn):
    res = str(uuid.uuid4())
    _media_link(conn, resource=res)
    body = _refs(TestClient(create_app(cfg)), res).json()
    assert set(body) == {"file_uid", "live_links"}


# --- the consumer that keeps a link current ------------------------------------------

class _Conn:
    def close(self):
        pass


def _consumer(cfg, monkeypatch, *, live=(), verdicts=None, republish=None):
    calls = types.SimpleNamespace(republished=[], checked=[], published=[], failed=[])
    monkeypatch.setattr(links, "live_media_links", lambda conn, uid: list(live))
    monkeypatch.setattr(links, "record_media_published",
                        lambda conn, uid, **k: calls.published.append((uid, k)) or ["L"])
    monkeypatch.setattr(links, "record_media_failed",
                        lambda conn, uid, **k: calls.failed.append((uid, k)) or ["L"])
    verdicts = verdicts or {}

    def check(c, *, created_by, **k):
        calls.checked.append(created_by)
        return verdicts.get(created_by, preflight.PreflightResult(True, roles=["users"]))

    def rep(c, **k):
        if republish:
            raise republish
        calls.republished.append(k)
    em = _Emitter()
    con = media_events.MediaEventConsumer(cfg, redis=object(), republish=rep, check=check,
                                          connect=lambda *a, **k: _Conn(), emitter=em)
    return con, calls, em


def _link(by, version=None):
    return links.Link(link_uid=f"L-{by}", kind=KIND_MEDIA, resource_uid="f", created_by=by,
                      created_at=datetime.now(timezone.utc),
                      expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                      media_version=version)


def _updated(**k):
    return {"type": "file.updated", "tenant": TENANT, "file_uid": "f",
            "version": "20261004_020000.000", **k}


def test_a_new_version_of_a_shared_file_is_republished_as_its_creator(cfg, monkeypatch):
    con, calls, em = _consumer(cfg, monkeypatch, live=[_link("ann")])
    assert con.handle(_updated()) is True
    assert calls.republished == [{"tenant": TENANT, "file_uid": "f", "user": "ann",
                                  "roles": ["users"], "link_uid": "L-ann"}]
    assert em.events[-1]["action"] == "share_media_republish_requested"


def test_our_own_renditions_and_unshared_files_publish_nothing(cfg, monkeypatch):
    con, calls, _ = _consumer(cfg, monkeypatch, live=[_link("ann")])
    assert con.handle(_updated(is_rendition=True)) is True
    con2, calls2, _ = _consumer(cfg, monkeypatch, live=[])
    assert con2.handle(_updated()) is True
    assert calls.republished == [] and calls2.republished == [] and calls2.checked == []


def test_a_version_already_published_is_not_asked_for_again(cfg, monkeypatch):
    con, calls, _ = _consumer(cfg, monkeypatch, live=[_link("ann", "20261004_020000.000")])
    assert con.handle(_updated()) is True and calls.republished == []


def test_a_creator_who_lost_access_is_passed_over_for_one_who_has_it(cfg, monkeypatch):
    lost = preflight.PreflightResult(False, preflight.REASON_NO_ACCESS)
    con, calls, _ = _consumer(cfg, monkeypatch, live=[_link("ann"), _link("bob")],
                              verdicts={"ann": lost})
    assert con.handle(_updated()) is True
    assert calls.checked == ["ann", "bob"] and calls.republished[0]["user"] == "bob"


def test_when_no_creator_can_read_the_file_nothing_is_published_and_it_is_recorded(cfg, monkeypatch):
    lost = preflight.PreflightResult(False, preflight.REASON_NO_ACCESS)
    con, calls, em = _consumer(cfg, monkeypatch, live=[_link("ann")], verdicts={"ann": lost})
    assert con.handle(_updated()) is True and calls.republished == []
    assert em.events[-1]["action"] == "share_media_republish_refused"


def test_a_directory_outage_or_csai_outage_is_retried_not_dropped(cfg, monkeypatch):
    ldap = preflight.PreflightResult(False, preflight.REASON_LDAP)
    con, _, _ = _consumer(cfg, monkeypatch, live=[_link("ann")], verdicts={"ann": ldap})
    assert con.handle(_updated()) is False
    con, _, _ = _consumer(cfg, monkeypatch, live=[_link("ann")],
                          republish=media_client.MediaUnavailable("down"))
    assert con.handle(_updated()) is False


def test_only_the_primary_rendition_decides_readiness(cfg, monkeypatch):
    con, calls, _ = _consumer(cfg, monkeypatch)
    base = {"type": "media.published", "tenant": TENANT, "file_uid": "f", "version": "v2",
            "duration_ms": 4000, "output_bytes": 99}
    assert con.handle({**base, "profile": "video-480p-vp9"}) is True
    assert con.handle({**base, "profile": "video-emailposter"}) is True
    assert calls.published == []
    assert con.handle({**base, "profile": "video-720p-vp9"}) is True
    assert calls.published == [("f", {"version": "v2", "duration_ms": 4000, "output_bytes": 99})]
    assert con.handle({**base, "type": "media.publish_failed", "profile": "audio-mp3"}) is True
    assert calls.failed == [("f", {"version": "v2"})]


# --- the CSAI client --------------------------------------------------------------

class _R:
    def __init__(self, code, body):
        self.status_code, self._b, self.text = code, body, json.dumps(body)

    def json(self):
        return self._b


class _Http:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def request(self, method, url, headers, json, timeout):
        self.calls.append((method, url, headers, json))
        if isinstance(self.resp, Exception):
            raise self.resp
        return self.resp


def test_the_client_asks_as_the_creator_and_maps_refusals(cfg):
    http = _Http(_R(202, {"source_version": "v1", "jobs": [{"profile": "video-720p-vp9",
                                                            "status": "queued"}]}))
    st = media_client.publish(cfg, bearer="tok", tenant=TENANT, file_uid="f", http=http)
    method, url, headers, _ = http.calls[0]
    assert method == "POST" and url.endswith("/documents/f/media")
    assert headers == {"Authorization": "Bearer tok", "X-Tenant": TENANT}
    assert st.in_progress and not st.ready
    with pytest.raises(media_client.MediaRefused) as e:
        media_client.state(cfg, bearer="t", tenant=TENANT, file_uid="f", http=_Http(_R(403, {"detail": "no"})))
    assert e.value.status == 403
    for bad in (_R(500, {}), OSError("down")):
        with pytest.raises(media_client.MediaUnavailable):
            media_client.state(cfg, bearer="t", tenant=TENANT, file_uid="f", http=_Http(bad))


def test_republish_carries_the_secret_and_names_the_creator(cfg):
    http = _Http(_R(202, {"source_version": "v2", "jobs": []}))
    media_client.republish(cfg, tenant=TENANT, file_uid="f", user="ann", roles=["users"],
                           link_uid="L", http=http)
    _m, url, headers, body = http.calls[0]
    assert url.endswith("/internal/documents/f/media")
    assert headers == {"X-Internal-Auth": SECRET}
    assert body == {"tenant": TENANT, "user": "ann", "roles": ["users"], "link_uid": "L"}
    cfg.media_internal_secret = ""
    with pytest.raises(media_client.MediaUnavailable):
        media_client.republish(cfg, tenant=TENANT, file_uid="f", user="ann", roles=[],
                               link_uid="L", http=http)


def test_readiness_follows_the_primary_profile():
    assert _state("succeeded").ready
    assert not _state("running").ready and _state("running").in_progress
    assert _state("failed").failed and not _state("failed").in_progress
    audio = _state("succeeded", profile="audio-mp3")
    assert audio.ready
    assert not _state("succeeded", profile="video-480p-vp9").ready   # not the primary


def test_capabilities_say_what_the_share_tab_may_offer(world, cfg):
    got = world.client.get("/share/v1/capabilities", headers=world.auth).json()
    assert got["media"]["available"] is True and got["media"]["open_mode"] is True
    cfg.media_enabled = False
    assert world.client.get("/share/v1/capabilities",
                            headers=world.auth).json()["media"]["available"] is False
    assert world.client.get("/share/v1/capabilities").status_code == 401


def test_download_defaults_by_mode(world, conn):
    assert _create(world).json()["allow_download"] is True                      # verified
    assert _create(world, access_mode="claimed").json()["allow_download"] is False
    assert _create(world, access_mode="claimed", allow_download=True).json()["allow_download"] is True
