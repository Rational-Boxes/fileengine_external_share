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

"""MS3 end to end, against the RUNNING stack (MEDIA_SHARE.md §6.2, §4.3.1).

Every service is the real one, reached the way the SPA reaches it: a session
from the bridge, the clip uploaded through the bridge, the link minted through
share_service's own HTTP listener, the encode done by the stack's media worker,
and the link kept current by share_service's own event consumer.

  mint (claimed) → pending_media → CSAI encodes → media.published → ready
  → media-refs counts it → CSAI refuses to unpublish while it plays
  → a new version is uploaded → republished as the creator → the link
    describes the new version, the old published set is retired
  → revoke → media-refs 0 → CSAI unpublish removes the published copies.

Skips unless the whole chain is reachable and configured; run with ``-m live``.
Env: FE_USER / FE_PASS (a bridge login; email 2FA is completed via MailHog),
BRIDGE_URL, SHARE_URL, CSAI_URL, MAILHOG_URL.
"""
from __future__ import annotations

import base64
import json
import os
import quopri
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pytest

from share_service.config import Config

pytestmark = pytest.mark.live

BRIDGE = os.environ.get("BRIDGE_URL", "http://localhost:8090")
SHARE = os.environ.get("SHARE_URL", "http://localhost:8101")
CSAI = os.environ.get("CSAI_URL", "http://localhost:8092")
MAILHOG = os.environ.get("MAILHOG_URL", "http://localhost:8025")
USER = os.environ.get("FE_USER", "testuser@rationalboxes.com")
PASS = os.environ.get("FE_PASS", "")
TENANT = "default"
ROOT = "00000000-0000-0000-0000-000000000000"


# --- a tiny HTTP client -----------------------------------------------------------

def _req(method, url, *, headers=None, body=None, raw=None, timeout=60):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, method=method, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read()
            return r.status, (json.loads(text) if text and text[:1] in b"{[" else text)
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, text


def _login() -> str:
    basic = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
    code, body = _req("POST", f"{BRIDGE}/v1/auth/token",
                      headers={"Authorization": f"Basic {basic}", "X-Tenant": TENANT})
    if isinstance(body, dict) and body.get("token"):
        return body["token"]
    mfa = body.get("mfa_token") if isinstance(body, dict) else None
    assert mfa, f"login: {code} {body}"
    _req("DELETE", f"{MAILHOG}/api/v1/messages")
    _req("POST", f"{BRIDGE}/v1/auth/2fa", body={"mfa_token": mfa, "action": "send",
                                                "method": "email"})
    otp = ""
    for _ in range(20):
        time.sleep(0.5)
        _c, box = _req("GET", f"{MAILHOG}/api/v2/messages")
        items = (box or {}).get("items") or []
        if items:
            text = quopri.decodestring(items[0]["Content"]["Body"]).decode("utf-8", "ignore")
            otp = (re.findall(r"\b(\d{6})\b", text) or [""])[0]
            if otp:
                break
    assert otp, "no 2FA code in MailHog"
    _c, done = _req("POST", f"{BRIDGE}/v1/auth/2fa",
                    body={"mfa_token": mfa, "method": "email", "code": otp})
    assert isinstance(done, dict) and done.get("token"), f"2FA: {done}"
    return done["token"]


def _blocker() -> str:
    if not PASS:
        return "set FE_PASS (and FE_USER) for a bridge session"
    if not shutil.which("ffmpeg"):
        return "ffmpeg not found"
    cfg = Config()
    if not cfg.media_internal_secret:
        return "no SHARE_MEDIA_INTERNAL_SECRET / CSAI_INTERNAL_SECRET configured"
    for name, url in (("bridge", f"{BRIDGE}/v1/whoami"), ("share_service", f"{SHARE}/share/v1/links"),
                      ("csai", f"{CSAI}/documents/x/media")):
        try:
            _req("GET", url, timeout=5)
        except Exception as e:  # noqa: BLE001
            return f"{name} unreachable: {e}"
    try:
        import redis
        r = redis.Redis(host=cfg.redis_host, port=cfg.redis_port,
                        password=cfg.redis_password or None, db=cfg.redis_db)
        if not r.get("csai:media_worker:alive"):
            return "the CSAI media worker is not running"
    except Exception as e:  # noqa: BLE001
        return f"Redis unavailable: {e}"
    return ""


_SKIP = _blocker()
if _SKIP:
    pytestmark = [pytest.mark.live, pytest.mark.skip(reason=_SKIP)]


def _clip(path: str, hue: int) -> None:
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y",
                    "-f", "lavfi", "-i", f"testsrc2=size=1280x720:rate=30,hue=h={hue}",
                    "-f", "lavfi", "-i", "sine=frequency=330", "-t", "4",
                    "-c:v", "mpeg4", "-q:v", "4", "-c:a", "aac", "-shortest", path], check=True)


def _wait(what, secs, probe):
    end = time.time() + secs
    while time.time() < end:
        got = probe()
        if got:
            return got
        time.sleep(2)
    pytest.fail(f"gave up after {secs}s waiting for {what}")


# --- the scenario -------------------------------------------------------------------

@pytest.fixture(scope="module")
def s():
    cfg = Config()
    tok = _login()
    h = {"Authorization": f"Bearer {tok}", "X-Tenant": TENANT}
    work = tempfile.mkdtemp(prefix="share_media_live_")
    v1 = os.path.join(work, "v1.mp4")
    _clip(v1, 0)
    code, f = _req("POST", f"{BRIDGE}/v1/dirs/{ROOT}/files", headers=h,
                   body={"name": f"share-media-live-{os.getpid()}.mp4"})
    assert code in (200, 201), f
    uid = f["uid"]
    code, _ = _req("PUT", f"{BRIDGE}/v1/files/{uid}/content",
                   headers={**h, "Content-Type": "application/octet-stream"},
                   raw=open(v1, "rb").read())
    assert code in (200, 201, 204)
    ns = type("S", (), {})()
    ns.cfg, ns.h, ns.uid, ns.work, ns.links = cfg, h, uid, work, []
    yield ns
    for link_uid in ns.links:
        _req("DELETE", f"{SHARE}/share/v1/links/{link_uid}", headers=h)
    _req("DELETE", f"{BRIDGE}/v1/files/{uid}", headers=h)
    shutil.rmtree(work, ignore_errors=True)


def _refs(s):
    code, body = _req("GET", f"{SHARE}/share/v1/internal/media-refs/{s.uid}",
                      headers={"X-Internal-Auth": s.cfg.media_internal_secret, "X-Tenant": TENANT})
    assert code == 200, body
    return body["live_links"]


def _link(s, link_uid):
    code, body = _req("GET", f"{SHARE}/share/v1/links/{link_uid}", headers=s.h)
    assert code == 200, body
    return body.get("link", body)


def _published(s):
    _c, st = _req("GET", f"{CSAI}/documents/{s.uid}/media", headers=s.h)
    return st


def test_an_open_link_needs_the_switch_and_the_confirmation_on_the_running_service(s):
    # The running service's switch (a dev .env may turn open mode on for the
    # embed E2E). Off: refused outright. On: still refused without the
    # confirmation and a public title.
    code, body = _req("POST", f"{SHARE}/share/v1/nodes/{s.uid}/links", headers=s.h,
                      body={"kind": 3, "access_mode": "open", "recipients": []})
    if s.cfg.allow_open_mode:
        assert code == 400, body
    else:
        assert code == 403, body


def test_minting_publishes_and_the_consumer_makes_the_link_ready(s):
    code, body = _req("POST", f"{SHARE}/share/v1/nodes/{s.uid}/links", headers=s.h,
                      body={"kind": 3, "access_mode": "claimed", "display_name": "E2E clip"})
    assert code == 201, body
    s.links.append(body["link_uid"])
    s.link_uid = body["link_uid"]
    assert body["media_state"] in ("pending_media", "ready")
    assert body["url"]
    jobs = _published(s)["jobs"]
    assert {j["profile"] for j in jobs} >= {"video-720p-vp9"}
    assert all(j["requested_by"] == USER for j in jobs)      # as the creator

    link = _wait("the link to become ready", 300,
                 lambda: (lambda l: l if l.get("media_state") == "ready" else None)(_link(s, s.link_uid)))
    # The whole set (480p and the email GIF too), so what follows is not
    # racing an encode still in flight.
    st = _wait("every publish job to finish", 300,
               lambda: (lambda st: st if st["jobs"] and all(
                   j["status"] in ("succeeded", "skipped") for j in st["jobs"]) else None)(_published(s)))
    s.v1 = st["source_version"]
    assert link["media_version"] == s.v1
    assert link["duration_ms"] and abs(link["duration_ms"] - 4000) < 600
    assert link["output_bytes"] and link["output_bytes"] > 0


def test_media_refs_counts_the_link_and_csai_will_not_unpublish_under_it(s):
    assert _refs(s) == 1
    code, body = _req("DELETE", f"{CSAI}/documents/{s.uid}/media", headers=s.h)
    assert code == 409 and "1 live share link" in str(body), body


def test_a_new_version_is_republished_and_the_link_follows_it(s):
    v2 = os.path.join(s.work, "v2.mp4")
    _clip(v2, 180)
    code, _ = _req("PUT", f"{BRIDGE}/v1/files/{s.uid}/content",
                   headers={**s.h, "Content-Type": "application/octet-stream"},
                   raw=open(v2, "rb").read())
    assert code in (200, 201, 204)
    # The consumer asks CSAI on the creator's behalf; nobody calls publish here.
    st = _wait("a republish of the new version", 120,
               lambda: (lambda st: st if st["source_version"] != s.v1 and st["jobs"] else None)(_published(s)))
    assert all(j["requested_by"] == USER for j in st["jobs"])
    s.v2 = st["source_version"]
    link = _wait("the link to describe the new version", 300,
                 lambda: (lambda l: l if l.get("media_version") == s.v2 else None)(_link(s, s.link_uid)))
    assert link["media_state"] == "ready"
    names = _wait("the old published set to be retired", 60,
                  lambda: (lambda st: st["renditions"] if st["renditions"] else None)(_published(s)))
    assert all(n.startswith(s.v2.replace(":", "_")) or s.v2 in n for n in names), names


def test_revoking_the_last_link_lets_the_published_copies_go(s):
    code, _ = _req("DELETE", f"{SHARE}/share/v1/links/{s.link_uid}", headers=s.h)
    assert code in (200, 204)
    assert _refs(s) == 0
    code, body = _req("DELETE", f"{CSAI}/documents/{s.uid}/media", headers=s.h)
    assert code == 200, body
    assert any(n.endswith("-media.webm") for n in body["removed"]), body
    assert not any(n.endswith(("-preview.webm", "-poster.webp", "-poster.png")) for n in body["removed"])
