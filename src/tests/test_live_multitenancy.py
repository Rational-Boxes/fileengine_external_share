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

"""Multitenancy.

Every other test in this suite runs on one tenant, which is exactly why a whole
class of bug survived to be found by hand: a link minted in a NON-default tenant
was unredeemable, because the public route had no way to discover which schema
held it and fell back to the default.

Two properties, and they pull in opposite directions:

  1. A recipient arrives with a uid and a secret and NO tenant context — no
     session, no X-Tenant on a cold navigation, and a Host that any proxy
     setting changeOrigin has already rewritten. The link must still resolve.

  2. Nothing else may cross the boundary. One tenant's admin console, inbox,
     provenance and ledger must not see another's, and a caller must not be
     able to reach into a tenant by naming it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest

from fastapi.testclient import TestClient

from share_service import db, links
from share_service.app import create_app
from share_service.config import Config

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
A = "default"
B = "mt_tenant_b"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(cfg, user=USER, tenant=A, roles=None, member_of=None):
    """A bridge-shaped token. `member_of` sets which tenants the roles map
    covers — the token's own statement of membership."""
    member_of = member_of or [tenant]
    roles = roles if roles is not None else ["users", "contributors", "administrators"]
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub": user, "tenant": tenant,
        "roles": {t: list(roles) for t in member_of},
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
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg), raise_server_exceptions=False)


@pytest.fixture
def conns(cfg):
    a = db.connect_for_tenant(cfg, A, provision=True)
    b = db.connect_for_tenant(cfg, B, provision=True)
    yield a, b
    a.close()
    b.close()


def _mint(cfg, conn, tenant, *, created_by=USER, recipients=("r@example.com",)):
    link, secret = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=created_by,
        expires_at=links.clamp_expiry(cfg, None, 1), recipients=list(recipients),
        max_uses=5, tenant=tenant)
    return link, secret


def _auth(cfg, tenant, **kw):
    return {"Authorization": f"Bearer {_token(cfg, tenant=tenant, **kw)}",
            "X-Tenant": tenant}


# --- 1. a recipient with no tenant context --------------------------------

def test_a_link_in_a_non_default_tenant_resolves_without_any_hint(client, cfg, conns):
    """THE bug this file exists for.

    A recipient clicking a link in their email sends no X-Tenant, and the Host
    has been rewritten by the proxy. Before the cross-tenant directory, the
    public route fell back to the default tenant, failed to find the link, and
    answered with the uniform "this link isn't available" — indistinguishable
    from an expired link, and therefore nearly impossible to diagnose.
    """
    _a, b = conns
    link, secret = _mint(cfg, b, B)
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers={"X-Share-Secret": secret})   # no X-Tenant, deliberately
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == 0


def test_the_default_tenant_still_resolves_the_same_way(client, cfg, conns):
    a, _b = conns
    link, secret = _mint(cfg, a, A)
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers={"X-Share-Secret": secret})
    assert r.status_code == 200


def test_an_explicit_tenant_header_still_wins(client, cfg, conns):
    """Kept as an override for callers that genuinely know — tests, and any
    future per-tenant edge that can supply it."""
    _a, b = conns
    link, secret = _mint(cfg, b, B)
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers={"X-Share-Secret": secret, "X-Tenant": B})
    assert r.status_code == 200


def test_naming_the_wrong_tenant_denies_uniformly(client, cfg, conns):
    """An explicit header that disagrees with the directory does NOT get
    silently corrected — it looks in the tenant it was told to."""
    _a, b = conns
    link, secret = _mint(cfg, b, B)
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers={"X-Share-Secret": secret, "X-Tenant": A})
    assert r.status_code == 404
    assert r.json()["detail"] == {"error": "not_found"}


def test_an_unknown_uid_is_the_same_uniform_denial(client, cfg):
    """The directory must not become a way to test whether a uid exists."""
    r = client.get(f"/share/v1/public/{uuid.uuid4()}",
                   headers={"X-Share-Secret": "whatever"})
    assert r.status_code == 404
    assert r.json()["detail"] == {"error": "not_found"}


def test_the_directory_never_holds_a_secret(cfg, conns):
    """It maps uid -> tenant and nothing else. A read of this table must not
    advance an attacker who has somehow obtained it."""
    _a, b = conns
    link, secret = _mint(cfg, b, B)
    with b.cursor() as cur:
        cur.execute("SELECT * FROM public.share_link_directory WHERE link_uid = %s",
                    (link.link_uid,))
        cols = [c[0] for c in cur.description]
        row = cur.fetchone()
    assert set(cols) == {"link_uid", "tenant", "created_at"}
    assert secret not in json.dumps(row, default=str)


# --- 2. nothing else crosses the boundary ---------------------------------

def test_one_tenants_admin_console_cannot_see_another(client, cfg, conns):
    a, b = conns
    in_a, _ = _mint(cfg, a, A)
    in_b, _ = _mint(cfg, b, B)
    rows = client.get("/share/v1/links?all=true", headers=_auth(cfg, B)).json()["links"]
    uids = {l["link_uid"] for l in rows}
    assert in_b.link_uid in uids
    assert in_a.link_uid not in uids, "the admin console must not span tenants"


def test_the_sharing_inbox_is_per_tenant(client, cfg, conns):
    a, b = conns
    in_a, _ = _mint(cfg, a, A)
    in_b, _ = _mint(cfg, b, B)
    body = client.get("/share/v1/links/mine/inbox", headers=_auth(cfg, B)).json()
    seen = {l["link_uid"] for g in body.values() for l in g}
    assert in_a.link_uid not in seen


def test_a_link_cannot_be_revoked_from_another_tenant(client, cfg, conns):
    """The same uid, asked for in the wrong tenant, is simply absent — the
    schema boundary does the work, not a check someone could forget."""
    a, b = conns
    in_b, _ = _mint(cfg, b, B)
    r = client.delete(f"/share/v1/links/{in_b.link_uid}", headers=_auth(cfg, A))
    assert r.status_code == 404
    assert not links.get(b, in_b.link_uid).is_revoked


def test_drop_provenance_does_not_cross_tenants(client, cfg, conns):
    a, b = conns
    in_b, _ = _mint(cfg, b, B)
    result_uid = str(uuid.uuid4())
    with b.cursor() as cur:
        cur.execute(
            """INSERT INTO share_redemptions
                 (redemption_uid, link_uid, expires_at, verified_email, result_uid)
               VALUES (%s,%s,now() + interval '1 hour',%s,%s)""",
            (str(uuid.uuid4()), in_b.link_uid, "outsider@example.com", result_uid))
    b.commit()
    r = client.post("/share/v1/files/provenance", json={"file_uids": [result_uid]},
                    headers=_auth(cfg, A))
    assert r.status_code == 200
    assert r.json()["provenance"] == {}, "tenant A must not learn about B's drops"


def test_revoke_all_stops_at_the_tenant_boundary(client, cfg, conns):
    """The most destructive action in the console, and the one where a missing
    boundary would be worst: one tenant's admin ending another's links."""
    a, b = conns
    leaver = f"leaver-{uuid.uuid4().hex[:8]}@example.com"
    in_a, _ = _mint(cfg, a, A, created_by=leaver)
    in_b, _ = _mint(cfg, b, B, created_by=leaver)
    r = client.post("/share/v1/admin/revoke-all", json={"creator": leaver},
                    headers=_auth(cfg, B))
    assert r.status_code == 200
    assert links.get(b, in_b.link_uid).is_revoked
    assert not links.get(a, in_a.link_uid).is_revoked, "A's link must be untouched"


def test_a_caller_cannot_reach_a_tenant_it_is_not_a_member_of(client, cfg, conns):
    """X-Tenant is attacker-controlled. The roles map in the signed token is the
    membership statement, so a tenant absent from it yields no roles — and an
    admin surface then refuses."""
    _a, b = conns
    _mint(cfg, b, B)
    headers = {"Authorization": f"Bearer {_token(cfg, tenant=A, member_of=[A])}",
               "X-Tenant": B}
    r = client.get("/share/v1/links?all=true", headers=headers)
    assert r.status_code == 403


# --- 3. the directory stays in step ---------------------------------------

def test_creating_a_link_records_its_tenant(cfg, conns):
    _a, b = conns
    link, _ = _mint(cfg, b, B)
    assert links.tenant_for_link(b, link.link_uid) == B


def test_purging_a_link_forgets_it(cfg, conns):
    """Or the directory accumulates rows pointing at links that no longer
    exist, and a recycled uid would route to the wrong schema."""
    _a, b = conns
    link, _ = _mint(cfg, b, B)
    assert links.tenant_for_link(b, link.link_uid) == B
    links.forget_link(b, link.link_uid)
    b.commit()
    assert links.tenant_for_link(b, link.link_uid) is None
