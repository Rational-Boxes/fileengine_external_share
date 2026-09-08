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

"""End-to-end link lifecycle (development plan §6, tests 7-13).

Needs the dev core, LDAP, Postgres and Redis. The caller is the dev fixture
user, who is in both ``share_external`` and ``administrators`` — so these also
exercise the case where the creation gate passes and the admin roles must still
never reach the core.
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
TENANT = "default"
RECIPIENT_A = "ledger-recipient@example.com"

# The origin a link minted in TENANT must carry. Composed from the TENANT, never
# from the host the creating request arrived on — TestClient arrives as
# `testserver`, and in the real stack the SPA arrives on whichever origin it was
# loaded from, which is not the active tenant once someone has switched (the
# switch sends X-Tenant without navigating). See `share_service.urls`.
ORIGIN = f"http://{TENANT}.example.com"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(cfg: Config, user: str = USER, tenant: str = TENANT,
           roles=None) -> str:
    """A bearer token shaped exactly like the ones http_bridge mints.

    `roles` matters since M7: `administrators` is an admin role, and an admin
    may reach any link in the tenant. A test about what an UNRELATED user can
    see must therefore pass a role set without it, or it silently tests the
    admin path instead (spec §10.3).
    """
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub": user, "tenant": tenant,
        "roles": {tenant: list(roles if roles is not None
                               else ["users", "contributors", "administrators"])},
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
    c.enabled = True          # the deployment kill switch is off by default
    # Pin where links point, so the URL assertions are about this code and not
    # about whatever .env the checkout carries — in practice a dev tunnel, a
    # single fixed origin that answers for every tenant at once and would hide
    # exactly the bug the assertions exist to catch.
    c.public_base_url = ""
    c.tenant_base_domain = "example.com"
    return c


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg), raise_server_exceptions=False)


@pytest.fixture
def auth(cfg) -> dict:
    return {"Authorization": f"Bearer {_token(cfg)}", "X-Tenant": TENANT}


@pytest.fixture
def root_dir(cfg) -> str:
    """A folder in the dev core the fixture user can write to."""
    from share_service import core_client, ldap_roles
    roles = ldap_roles.resolve_share_roles(cfg, USER)
    with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                 tenant=TENANT) as core:
        entries = core.client.dir("")
    # NB: DirectoryEntry exposes `is_container`; `is_dir` lives on FileInfo.
    # Asking for the wrong one returns None and silently finds no folders.
    for e in entries or []:
        if getattr(e, "is_container", False):
            return e.uid
    pytest.skip("no directory available in the dev core")


def test_create_list_get_revoke(cfg, client, auth, root_dir):
    body = {"kind": 2, "recipients": ["Someone@Example.COM", " someone@example.com "],
            "ttl_days": 3, "max_uses": 5, "note": "M0 lifecycle test"}
    r = client.post(f"/share/v1/nodes/{root_dir}/links", json=body, headers=auth)
    assert r.status_code == 201, r.text
    created = r.json()

    # The secret exists exactly once, in this response (spec §8.2).
    assert created["secret_shown_once"] is True
    link_uid = created["link_uid"]

    # The URL the creator copies, in full but for the secret: scheme, the
    # TENANT'S host, and the link it names. Asserting only that "/s/" appears
    # let a link go out on another tenant's origin and still pass — it stays
    # redeemable either way, because the public route resolves the tenant from
    # the cross-tenant directory rather than from the host.
    assert created["url"].startswith(f"{ORIGIN}/s/{link_uid}."), created["url"]
    assert "testserver" not in created["url"]

    assert created["status"] == "active"
    assert created["resource_uid"] == root_dir

    # Duplicate/differently-cased recipients normalize to one address.
    r = client.get(f"/share/v1/links/{link_uid}/recipients", headers=auth)
    roster = r.json()["recipients"]
    assert [x["email"] for x in roster] == ["someone@example.com"]
    # v1 mails no invite, so the first rung says nothing about delivery.
    assert roster[0]["status"] == "on_the_list"

    # Re-reading never yields the secret.
    r = client.get(f"/share/v1/links/{link_uid}", headers=auth)
    assert r.status_code == 200
    assert "secret" not in json.dumps(r.json()).lower().replace("secret_shown_once", "")

    r = client.get("/share/v1/links", headers=auth)
    assert link_uid in [l["link_uid"] for l in r.json()["links"]]

    # Revocation is idempotent: the second call succeeds and changes nothing.
    r = client.delete(f"/share/v1/links/{link_uid}", headers=auth)
    assert r.status_code == 200 and r.json()["changed"] is True
    r = client.delete(f"/share/v1/links/{link_uid}", headers=auth)
    assert r.status_code == 200 and r.json()["changed"] is False

    # A revoked link still lists — it is evidence (spec §5.5).
    r = client.get(f"/share/v1/links/{link_uid}", headers=auth)
    assert r.json()["status"] == "revoked"
    assert r.json()["revoked_by"] == USER


def test_only_the_hash_is_stored(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": ["a@example.com"], "max_uses": 1},
                    headers=auth)
    assert r.status_code == 201
    url = r.json()["url"]
    secret = url.rsplit("/s/", 1)[1].split(".", 1)[1]

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT secret_hash FROM share_links WHERE link_uid = %s",
                        (r.json()["link_uid"],))
            stored = bytes(cur.fetchone()[0])
    finally:
        conn.close()

    assert stored == links.hash_secret(secret)
    assert secret.encode() not in stored


def test_kind_must_match_the_resource_type(cfg, client, auth, root_dir):
    """A file-download link on a folder is refused (spec §6.1)."""
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 0, "recipients": ["a@example.com"], "max_uses": 1},
                    headers=auth)
    assert r.status_code == 400
    assert "kind" in r.text


def test_expiry_is_capped_at_the_deployment_maximum(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": ["a@example.com"],
                          "ttl_days": cfg.max_ttl_days + 90, "max_uses": 1},
                    headers=auth)
    assert r.status_code == 201
    from datetime import datetime, timedelta, timezone
    expires = datetime.fromisoformat(r.json()["expires_at"])
    assert expires <= datetime.now(timezone.utc) + timedelta(days=cfg.max_ttl_days, seconds=60)


def test_recipients_are_required_and_bounded(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": [], "max_uses": 1}, headers=auth)
    assert r.status_code == 422  # pydantic min_length

    too_many = [f"user{i}@example.com" for i in range(cfg.max_recipients + 1)]
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": too_many, "max_uses": 1}, headers=auth)
    assert r.status_code == 400


def test_max_uses_is_capped(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": ["a@example.com"],
                          "max_uses": cfg.max_uses_cap + 1}, headers=auth)
    assert r.status_code == 400


def test_a_node_may_carry_several_live_links(cfg, client, auth, root_dir):
    """No uniqueness constraint (spec §13-R8): a folder commonly holds a
    download link and a drop box at once."""
    made = []
    for kind in (2, 1):
        r = client.post(f"/share/v1/nodes/{root_dir}/links",
                        json={"kind": kind, "recipients": ["a@example.com"],
                              "max_uses": 1}, headers=auth)
        assert r.status_code == 201, r.text
        made.append(r.json()["link_uid"])

    r = client.get(f"/share/v1/nodes/{root_dir}/links", headers=auth)
    listed = {l["link_uid"] for l in r.json()["links"]}
    assert set(made) <= listed


def test_another_users_link_is_not_found_not_forbidden(cfg, client, auth, root_dir):
    """Whether a link exists is not something an unrelated user may probe."""
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": ["a@example.com"], "max_uses": 1},
                    headers=auth)
    link_uid = r.json()["link_uid"]

    other = {"Authorization": f"Bearer {_token(cfg, user='someone-else@example.com',
                                              roles=['users'])}",
             "X-Tenant": TENANT}
    assert client.get(f"/share/v1/links/{link_uid}", headers=other).status_code == 404
    assert client.delete(f"/share/v1/links/{link_uid}", headers=other).status_code == 404


def test_unknown_link_is_404(cfg, client, auth):
    assert client.get(f"/share/v1/links/{uuid.uuid4()}", headers=auth).status_code == 404


def test_recipient_add_and_partial_revoke(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": ["first@example.com"], "max_uses": 2},
                    headers=auth)
    link_uid = r.json()["link_uid"]

    r = client.post(f"/share/v1/links/{link_uid}/recipients",
                    json={"email": "Second@Example.com"}, headers=auth)
    assert r.status_code == 201 and r.json()["email"] == "second@example.com"

    r = client.delete(f"/share/v1/links/{link_uid}/recipients/first@example.com",
                      headers=auth)
    assert r.status_code == 200 and r.json()["changed"] is True

    # The link keeps working for everyone else, and the removal keeps its history.
    r = client.get(f"/share/v1/links/{link_uid}/recipients", headers=auth)
    assert [x["email"] for x in r.json()["recipients"]] == ["second@example.com"]
    r = client.get(f"/share/v1/links/{link_uid}/recipients?include_removed=true",
                   headers=auth)
    removed = [x for x in r.json()["recipients"] if x["email"] == "first@example.com"]
    assert removed and removed[0]["status"] == "removed"


def test_redemption_ledger_is_readable_by_the_creator(cfg, client, auth, root_dir):
    """"Did they actually get it?" has no other answer when there is no account
    on the far side. Read from this service's own rows, so an ordinary creator
    needs no AUDIT_READ scope (spec §10.2)."""
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": [RECIPIENT_A], "max_uses": 3},
                    headers=auth)
    link_uid = r.json()["link_uid"]

    r = client.get(f"/share/v1/links/{link_uid}/redemptions", headers=auth)
    assert r.status_code == 200
    assert r.json()["redemptions"] == []      # nobody has used it yet

    # A session is what a redemption IS, so open one directly.
    from share_service import sessions, ldap_roles
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        roles = ldap_roles.resolve_share_roles(cfg, USER)
        s = sessions.open_session(conn, cfg, link_uid=link_uid,
                                  verified_email=RECIPIENT_A, tenant=TENANT,
                                  roles=roles, source_addr="203.0.113.9")
    finally:
        conn.close()

    r = client.get(f"/share/v1/links/{link_uid}/redemptions", headers=auth)
    led = r.json()["redemptions"]
    assert len(led) == 1
    assert led[0]["verified_email"] == RECIPIENT_A
    assert led[0]["source_addr"] == "203.0.113.9"
    assert led[0]["redemption_uid"] == s.redemption_uid


def test_another_users_ledger_is_not_readable(cfg, client, auth, root_dir):
    r = client.post(f"/share/v1/nodes/{root_dir}/links",
                    json={"kind": 2, "recipients": [RECIPIENT_A], "max_uses": 1},
                    headers=auth)
    link_uid = r.json()["link_uid"]
    other = {"Authorization": f"Bearer {_token(cfg, user='someone-else@example.com',
                                              roles=['users'])}",
             "X-Tenant": TENANT}
    assert client.get(f"/share/v1/links/{link_uid}/redemptions",
                      headers=other).status_code == 404


def test_a_file_link_records_the_file_size_at_creation(cfg, client, auth, root_dir):
    """The recipient's "should I tap Download on this phone?" number.

    It is captured HERE, while a delegated core connection is already open for
    the kind check and the version pin, rather than stat'd when the link is
    peeked: /peek takes no credential, so a core call on that route would let
    anyone holding the URL drive delegated work as the creator.
    """
    from share_service import core_client, ldap_roles
    payload = b"x" * 4096
    roles = ldap_roles.resolve_share_roles(cfg, USER)
    with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                 tenant=TENANT) as core:
        f = core.client.touch(root_dir, f"size-{uuid.uuid4().hex[:8]}.bin")
        f = getattr(f, "uid", f)
        core.client.put(f, payload)

    r = client.post(f"/share/v1/nodes/{f}/links",
                    json={"kind": 0, "recipients": ["someone@example.com"],
                          "ttl_days": 1, "max_uses": 3},
                    headers=auth)
    assert r.status_code == 201, r.text

    # Surfaced on the unauthenticated peek, straight from the stored row.
    uid = r.json()["link_uid"]
    secret = r.json()["url"].rsplit(".", 1)[-1]
    p = client.get(f"/share/v1/public/{uid}",
                   headers={"X-Share-Secret": secret, "X-Tenant": TENANT})
    assert p.status_code == 200, p.text
    assert p.json()["size_bytes"] == len(payload)


def test_create_refuses_a_field_it_cannot_store(cfg, root_dir):
    """A guard on the guard.

    create() used to filter its kwargs down to the keys it knew, so a caller
    passing a field the INSERT does not carry got a link built from defaults and
    no indication anything had been dropped. That is how a budget silently is
    not enforced, and it cost a debugging session when archive_bytes was added.
    """
    from share_service import db, links
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        with pytest.raises(TypeError, match="max_usez"):
            links.create(conn, kind=2, resource_uid=root_dir, created_by=USER,
                         expires_at=links.clamp_expiry(cfg, None, 1),
                         recipients=["someone@example.com"], max_usez=5)
    finally:
        conn.close()
