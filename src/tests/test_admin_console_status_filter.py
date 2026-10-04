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

"""The oversight console's status filter (spec §10.3) — applied BEFORE the cap.

The bug: `list_for_tenant` took the first 500 rows in risk order and only then
kept the ones matching `status`. Past 500 links — which a tenant reaches — a
filter for revoked or expired links searched only the riskiest 500 (mostly
active), so matches beyond them vanished; and when the filter emptied the page,
`truncated` was read from a row that no longer existed and said False. The
console showed "nothing revoked" as a complete answer.

Postgres only (no core, no LDAP); every link here is scoped to a fresh creator so
the shared dev tenant's thousands of other links cannot change the answer.
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

TENANT = "default"
ADMIN = "console-admin@rationalboxes.com"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _admin_token(cfg: Config) -> str:
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": ADMIN, "tenant": TENANT,
                            "roles": {TENANT: ["users", "administrators"]},
                            "exp": int(time.time()) + 600}).encode())
    sig = hmac.new(cfg.jwt_secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


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
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"share_service Postgres not reachable: {e}")
    c.commit()
    yield c
    c.close()


@pytest.fixture
def creator() -> str:
    return f"console-{uuid.uuid4().hex[:10]}@example.com"


def _mint(conn, creator, **budgets) -> str:
    link, _ = links.create(conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=creator,
                           expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                           recipients=["r@example.com"], tenant=TENANT, **budgets)
    return link.link_uid


def _set(conn, link_uid, sql):
    with conn.cursor() as cur:
        cur.execute(f"UPDATE share_links SET {sql} WHERE link_uid = %s", (link_uid,))
    conn.commit()


def _api(cfg, monkeypatch, limit, **params):
    real = links.list_for_tenant
    monkeypatch.setattr(links, "list_for_tenant", lambda conn, **kw: real(conn, **{**kw, "limit": limit}))
    c = TestClient(create_app(cfg), raise_server_exceptions=False)
    return c.get("/share/v1/links", params={"all": "true", **params},
                 headers={"Authorization": f"Bearer {_admin_token(cfg)}", "X-Tenant": TENANT})


def test_a_revoked_link_past_the_cap_is_still_found(cfg, conn, creator, monkeypatch):
    """The bug, reproduced. The revoked link is the OLDEST, so in risk order it
    sorts after the actives — exactly where a post-cap filter never looked."""
    dead = _mint(conn, creator)
    links.revoke(conn, dead, ADMIN)
    for _ in range(3):
        _mint(conn, creator)
    r = _api(cfg, monkeypatch, 2, live="false", status="revoked", creator=creator)
    assert r.status_code == 200, r.text
    assert [l["link_uid"] for l in r.json()["links"]] == [dead]
    assert all(l["status"] == "revoked" for l in r.json()["links"])
    assert r.json()["truncated"] is False


def test_a_capped_page_says_so_and_an_empty_one_does_not_claim_otherwise(cfg, conn, creator, monkeypatch):
    for _ in range(3):
        _mint(conn, creator)
    r = _api(cfg, monkeypatch, 2, live="false", status="active", creator=creator)
    assert len(r.json()["links"]) == 2 and r.json()["truncated"] is True
    r = _api(cfg, monkeypatch, 2, live="false", status="expired", creator=creator)
    assert r.json()["links"] == [] and r.json()["truncated"] is False


def test_status_sql_matches_link_status(conn, creator):
    """The two definitions of a link's state — the SQL that selects rows and the
    Link.status() that labels them — must agree for every state."""
    made = {
        "active": _mint(conn, creator),
        "revoked": _mint(conn, creator),
        "expired": _mint(conn, creator),
        "blocked": _mint(conn, creator),
        "exhausted": _mint(conn, creator, max_uses=2),
        # Precedence: revoked beats expired; blocked beats exhausted.
        "revoked_and_expired": _mint(conn, creator),
        "blocked_and_exhausted": _mint(conn, creator, max_uses=1),
        "lock_lifted": _mint(conn, creator),
    }
    links.revoke(conn, made["revoked"], ADMIN)
    links.revoke(conn, made["revoked_and_expired"], ADMIN)
    _set(conn, made["expired"], "expires_at = now() - interval '1 minute'")
    _set(conn, made["revoked_and_expired"], "expires_at = now() - interval '1 minute'")
    _set(conn, made["blocked"], "locked_until = now() + interval '10 minutes'")
    _set(conn, made["exhausted"], "uses_consumed = 2")
    _set(conn, made["blocked_and_exhausted"], "uses_consumed = 1, locked_until = now() + interval '10 minutes'")
    _set(conn, made["lock_lifted"], "locked_until = now() - interval '1 minute'")

    every = [links.get(conn, u) for u in made.values()]
    for state in links.STATUSES:
        got = {r["link"].link_uid for r in links.list_for_tenant(
            conn, live_only=False, creator=creator, status=state)}
        want = {l.link_uid for l in every if l.status() == state}
        assert got == want, f"{state}: sql={sorted(got)} python={sorted(want)}"
    # And every state is covered by exactly one predicate.
    assert sum(len(links.list_for_tenant(conn, live_only=False, creator=creator, status=s))
               for s in links.STATUSES) == len(made)


def test_an_unknown_status_is_refused_not_answered_with_nothing(cfg, monkeypatch, creator):
    r = _api(cfg, monkeypatch, 500, live="false", status="deleted", creator=creator)
    assert r.status_code == 400 and "revoked" in r.json()["detail"]
