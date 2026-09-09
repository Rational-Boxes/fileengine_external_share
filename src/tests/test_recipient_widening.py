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

"""`POST /links/{uid}/recipients` — the whole liveness matrix, through the route.

Deliberately NOT in ``test_live_link_lifecycle.py``: widening a link touches
Postgres and nothing else — no core call, no pre-flight, no LDAP. Building the
fixture link through the creation route would drag the core in and make this
suite unrunnable whenever the dev core is unhappy, which is exactly what
happened to the lifecycle suite (a core demanding a service token the dev
`.env` does not carry). The rows go in directly instead, so the assertions are
about the guard rather than about the state of somebody else's service.

The end-to-end version of the revoked case still lives in the lifecycle suite;
this is the one that runs when only the database is up.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from share_service import db, links
from share_service.app import create_app
from share_service.config import Config

USER = "widen-fixture@rationalboxes.com"
TENANT = "default"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(cfg: Config) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub": USER, "tenant": TENANT,
        "roles": {TENANT: ["users", "contributors"]},
        "exp": int(time.time()) + 600,
    }).encode())
    sig = hmac.new(cfg.jwt_secret.encode(), f"{header}.{payload}".encode(),
                   hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    if not c.jwt_secret:
        pytest.skip("FILEENGINE_JWT_SECRET not configured")
    c.enabled = True
    return c


@pytest.fixture
def conn(cfg):
    try:
        c = db.connect_for_tenant(cfg, TENANT, provision=True)
    except Exception as e:                      # noqa: BLE001 - any driver error
        pytest.skip(f"share_service Postgres not reachable: {e}")
    yield c
    c.close()


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg), raise_server_exceptions=False)


@pytest.fixture
def auth(cfg) -> dict:
    return {"Authorization": f"Bearer {_token(cfg)}", "X-Tenant": TENANT}


def make_link(conn, **budgets):
    """A link owned by the fixture user, pointing at nothing in particular.

    `resource_uid` is never dereferenced on this route — the guard reads the
    stored row and the clock — so an unused uid keeps the core out of it.
    """
    link, _secret = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        recipients=["first@example.com"], tenant=TENANT, **budgets)
    return link


def roster(client, auth, link_uid) -> list[str]:
    r = client.get(f"/share/v1/links/{link_uid}/recipients?include_removed=true",
                   headers=auth)
    return [x["email"] for x in r.json()["recipients"]]


# --- the door that must stay open ----------------------------------------

def test_a_live_link_can_be_widened(conn, client, auth):
    """The case the guard could plausibly have broken. Asserted first, so a
    change that refuses everything fails here rather than looking like a pass."""
    link = make_link(conn)
    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "Second@Example.com"}, headers=auth)
    assert r.status_code == 201
    assert r.json()["email"] == "second@example.com"
    assert sorted(roster(client, auth, link.link_uid)) == [
        "first@example.com", "second@example.com"]


def test_a_locked_out_link_can_still_be_widened(conn, client, auth):
    """A lockout lifts on its own, so the link is a live grant that is merely
    waiting — adding an address to it starts working when the clock does."""
    link = make_link(conn)
    with conn.cursor() as cur:
        cur.execute("UPDATE share_links SET locked_until = now() + interval '15 minutes' "
                    "WHERE link_uid = %s", (link.link_uid,))
    conn.commit()

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "second@example.com"}, headers=auth)
    assert r.status_code == 201


# --- the doors that must close -------------------------------------------

def test_a_revoked_link_cannot_be_widened(conn, client, auth):
    """The production case, 2026-09-09: an address was added 28 seconds after
    the link was revoked and the call returned 201. The grant was inert — every
    redemption is gated on `status() == "active"` — but the roster then listed
    someone who could not reach the file, and a `permission` audit event said
    access had been widened when it had not."""
    link = make_link(conn, max_uses=5)
    links.revoke(conn, link.link_uid, USER)

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "late@example.com"}, headers=auth)
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "link_not_live"
    assert r.json()["detail"]["status"] == "revoked"

    # The refusal is the whole point, so assert the row is absent rather than
    # trusting the status code.
    assert roster(client, auth, link.link_uid) == ["first@example.com"]


def test_an_expired_link_cannot_be_widened(conn, client, auth):
    link = make_link(conn)
    with conn.cursor() as cur:
        cur.execute("UPDATE share_links SET expires_at = now() - interval '1 minute' "
                    "WHERE link_uid = %s", (link.link_uid,))
    conn.commit()

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "late@example.com"}, headers=auth)
    assert r.status_code == 409
    assert r.json()["detail"]["status"] == "expired"
    assert roster(client, auth, link.link_uid) == ["first@example.com"]


def test_an_exhausted_link_cannot_be_widened(conn, client, auth):
    link = make_link(conn, max_uses=2)
    with conn.cursor() as cur:
        cur.execute("UPDATE share_links SET uses_consumed = 2 WHERE link_uid = %s",
                    (link.link_uid,))
    conn.commit()

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "late@example.com"}, headers=auth)
    assert r.status_code == 409
    assert r.json()["detail"]["status"] == "exhausted"


def test_the_refusal_says_which_state_in_words_the_creator_can_act_on(conn, client, auth):
    """A bare 409 would leave the creator guessing. The reason and the way out
    both have to be in the body, because the UI shows this text verbatim."""
    link = make_link(conn)
    links.revoke(conn, link.link_uid, USER)
    detail = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                         json={"email": "late@example.com"},
                         headers=auth).json()["detail"]
    assert "revoked" in detail["message"]
    assert "create a new one" in detail["message"]


def test_readding_a_removed_address_to_a_dead_link_is_also_refused(conn, client, auth):
    """`add_recipient` UPSERTs — it un-removes an address that was partially
    revoked. That path must not become a way around the guard."""
    link = make_link(conn)
    client.delete(f"/share/v1/links/{link.link_uid}/recipients/first@example.com",
                  headers=auth)
    links.revoke(conn, link.link_uid, USER)

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "first@example.com"}, headers=auth)
    assert r.status_code == 409

    roster_now = client.get(
        f"/share/v1/links/{link.link_uid}/recipients", headers=auth).json()["recipients"]
    assert roster_now == []          # still removed, not quietly reinstated


def test_someone_elses_dead_link_is_still_404_not_409(conn, client, auth):
    """Ownership is checked first and must stay that way: answering 409 for a
    stranger's link would confirm it exists, which 404 exists to hide."""
    link, _ = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by="someone.else@example.com",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        recipients=["their@example.com"], tenant=TENANT)
    links.revoke(conn, link.link_uid, "someone.else@example.com")

    r = client.post(f"/share/v1/links/{link.link_uid}/recipients",
                    json={"email": "late@example.com"}, headers=auth)
    assert r.status_code == 404
