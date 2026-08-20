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

"""The tenant-wide oversight console (spec §10.3), live against the dev stack.

The console adds exactly ONE power — revocation — on top of read. Most of what
follows tests the boundary rather than the feature: an admin must not be able to
mint, widen, or re-send, and the role that opens this console must never be the
role handed to the core on a delegated call.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest

from share_service.app import create_app
from share_service.config import Config
from share_service import db, links

from fastapi.testclient import TestClient

pytestmark = pytest.mark.live

ADMIN = "testuser@rationalboxes.com"
OTHER = "someone-else@rationalboxes.com"
TENANT = "default"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(cfg: Config, user: str, tenant: str = TENANT, roles=None) -> str:
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
    c.enabled = True
    return c


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg), raise_server_exceptions=False)


@pytest.fixture
def admin(cfg) -> dict:
    return {"Authorization": f"Bearer {_token(cfg, ADMIN)}", "X-Tenant": TENANT}


@pytest.fixture
def plain(cfg) -> dict:
    """A signed-in user with no admin role — same tenant, same everything else."""
    return {"Authorization": f"Bearer {_token(cfg, OTHER, roles=['users'])}",
            "X-Tenant": TENANT}


@pytest.fixture
def conn(cfg):
    c = db.connect_for_tenant(cfg, TENANT, provision=True)
    yield c
    c.close()


@pytest.fixture
def real_folder(cfg) -> str:
    """A folder that actually exists in the dev core, so the pre-flight passes."""
    from share_service import core_client, ldap_roles
    roles = ldap_roles.resolve_share_roles(cfg, ADMIN)
    with core_client.for_creator(cfg, created_by=ADMIN, roles=roles,
                                 tenant=TENANT) as core:
        for e in core.client.dir("") or []:
            if getattr(e, "is_container", False):
                return e.uid
    pytest.skip("no directory available in the dev core")


def _real_file(cfg, folder_uid: str) -> str:
    """A file that genuinely exists in the core, so the ACL check can pass."""
    from share_service import core_client, ldap_roles
    roles = ldap_roles.resolve_share_roles(cfg, ADMIN)
    with core_client.for_creator(cfg, created_by=ADMIN, roles=roles,
                                 tenant=TENANT) as core:
        f = core.client.touch(folder_uid, f"drop-{uuid.uuid4().hex[:8]}.bin")
        f = getattr(f, "uid", f)
        core.client.put(f, b"payload")
    return str(f)


def _mint(cfg, conn, *, created_by: str, recipients=("a@example.com",),
          depth=3, path="/projects/deep/file.txt", kind_override=0,
          resource_uid=None, **kw):
    """A link inserted directly, so a test can place several creators, depths
    and recipient sets without needing that many real resources in the core."""
    link, _secret = links.create(
        conn, kind=kind_override, resource_uid=resource_uid or str(uuid.uuid4()),
        created_by=created_by,
        expires_at=links.clamp_expiry(cfg, None, 1), recipients=list(recipients),
        max_uses=5, resource_depth=depth, resource_path=path, **kw)
    return link


# --- the gate -------------------------------------------------------------

def test_a_non_admin_is_refused_the_tenant_view(client, plain):
    """403, not an empty list.

    A silent empty result would read as "nothing is shared here", which is the
    most misleading possible answer to an oversight question.
    """
    r = client.get("/share/v1/links?all=true", headers=plain)
    assert r.status_code == 403
    assert "administrator" in r.text.lower()


def test_the_same_route_without_all_stays_the_callers_own_links(client, plain,
                                                                cfg, conn):
    mine = _mint(cfg, conn, created_by=OTHER)
    _mint(cfg, conn, created_by=ADMIN)
    r = client.get("/share/v1/links", headers=plain)
    assert r.status_code == 200
    uids = {l["link_uid"] for l in r.json()["links"]}
    assert mine.link_uid in uids
    assert all(l.get("creator") in (None, OTHER) for l in r.json()["links"])


def test_admin_of_one_tenant_is_not_admin_of_another(client, cfg):
    """Roles in the bridge token are keyed per tenant and scoped to the ACTIVE
    one, so switching tenants must not carry the power across."""
    tok = _token(cfg, ADMIN, tenant=TENANT)   # admin only in TENANT
    r = client.get("/share/v1/links?all=true",
                   headers={"Authorization": f"Bearer {tok}",
                            "X-Tenant": "some-other-tenant"})
    assert r.status_code == 403


def test_the_tenant_view_never_carries_a_secret(client, admin, cfg, conn):
    _mint(cfg, conn, created_by=OTHER)
    r = client.get("/share/v1/links?all=true", headers=admin)
    assert r.status_code == 200
    blob = json.dumps(r.json())
    assert "secret" not in blob.lower()
    assert "token" not in blob.lower()


# --- what it shows --------------------------------------------------------

def test_an_admin_sees_links_created_by_other_people(client, admin, cfg, conn):
    theirs = _mint(cfg, conn, created_by=OTHER)
    r = client.get("/share/v1/links?all=true", headers=admin)
    rows = {l["link_uid"]: l for l in r.json()["links"]}
    assert theirs.link_uid in rows
    assert rows[theirs.link_uid]["creator"] == OTHER
    assert rows[theirs.link_uid]["recipient_count"] == 1


def test_rows_are_ordered_by_risk_not_by_date(client, admin, cfg, conn):
    """A link on a project root outranks a link on one leaf file, whatever
    order they were created in — that ordering is the console's whole point."""
    # Scoped to this test's own creator. The tenant-wide list is CAPPED, and a
    # dev database accumulates rows across runs — an unscoped assertion here
    # passes until the fixtures fall off the end of the page, then fails for a
    # reason that has nothing to do with ordering.
    who = f"order-{uuid.uuid4().hex[:8]}@rationalboxes.com"
    tag = uuid.uuid4().hex[:8]
    deep = _mint(cfg, conn, created_by=who, depth=7,
                 path=f"/{tag}/a/b/c/d/e/leaf.txt")
    shallow = _mint(cfg, conn, created_by=who, depth=1, path=f"/{tag}")
    r = client.get(f"/share/v1/links?all=true&creator={who}", headers=admin)
    order = [l["link_uid"] for l in r.json()["links"]]
    assert order.index(shallow.link_uid) < order.index(deep.link_uid)
    # ...even though the deep one was created first.
    assert deep.created_at <= shallow.created_at


def test_more_recipients_outranks_fewer_at_the_same_depth(client, admin, cfg, conn):
    who = f"order-{uuid.uuid4().hex[:8]}@rationalboxes.com"
    tag = uuid.uuid4().hex[:8]
    few = _mint(cfg, conn, created_by=who, depth=4, path=f"/{tag}/x",
                recipients=["one@example.com"])
    many = _mint(cfg, conn, created_by=who, depth=4, path=f"/{tag}/y",
                 recipients=[f"r{i}@example.com" for i in range(5)])
    r = client.get(f"/share/v1/links?all=true&creator={who}", headers=admin)
    order = [l["link_uid"] for l in r.json()["links"]]
    assert order.index(many.link_uid) < order.index(few.link_uid)


# --- the filters that matter ----------------------------------------------

def test_filter_by_creator_is_the_departed_employee_query(client, admin, cfg, conn):
    tag = f"leaver-{uuid.uuid4().hex[:8]}@rationalboxes.com"
    theirs = _mint(cfg, conn, created_by=tag)
    _mint(cfg, conn, created_by=OTHER)
    r = client.get(f"/share/v1/links?all=true&creator={tag}", headers=admin)
    rows = r.json()["links"]
    assert [l["link_uid"] for l in rows] == [theirs.link_uid]


def test_filter_by_recipient_domain_answers_what_did_we_send_there(client, admin,
                                                                   cfg, conn):
    """The question that arrives when a relationship ends: substring, so a whole
    domain matches and not just one exact address."""
    dom = f"{uuid.uuid4().hex[:8]}.example"
    hit = _mint(cfg, conn, created_by=OTHER, recipients=[f"anna@{dom}"])
    _mint(cfg, conn, created_by=OTHER, recipients=["nobody@elsewhere.example"])
    r = client.get(f"/share/v1/links?all=true&recipient=@{dom}", headers=admin)
    assert [l["link_uid"] for l in r.json()["links"]] == [hit.link_uid]


def test_filter_by_subtree(client, admin, cfg, conn):
    tag = uuid.uuid4().hex[:8]
    inside = _mint(cfg, conn, created_by=OTHER, path=f"/projects/{tag}/plans.pdf")
    _mint(cfg, conn, created_by=OTHER, path="/projects/unrelated/other.pdf")
    r = client.get(f"/share/v1/links?all=true&subtree=/projects/{tag}",
                   headers=admin)
    assert [l["link_uid"] for l in r.json()["links"]] == [inside.link_uid]


def test_status_filter_finds_revoked_links_that_live_only_hides(client, admin,
                                                                cfg, conn):
    dead = _mint(cfg, conn, created_by=OTHER)
    links.revoke(conn, dead.link_uid, ADMIN)
    live_rows = client.get("/share/v1/links?all=true", headers=admin).json()["links"]
    assert dead.link_uid not in {l["link_uid"] for l in live_rows}
    all_rows = client.get("/share/v1/links?all=true&live=false&status=revoked",
                          headers=admin).json()["links"]
    assert dead.link_uid in {l["link_uid"] for l in all_rows}
    assert all(l["status"] == "revoked" for l in all_rows)


# --- the power boundary ---------------------------------------------------

def test_an_admin_may_revoke_someone_elses_link(client, admin, cfg, conn):
    theirs = _mint(cfg, conn, created_by=OTHER)
    r = client.delete(f"/share/v1/links/{theirs.link_uid}", headers=admin)
    assert r.status_code == 200 and r.json()["changed"] is True
    assert links.get(conn, theirs.link_uid).is_revoked


def test_a_non_admin_still_cannot_touch_someone_elses_link(client, plain, cfg, conn):
    theirs = _mint(cfg, conn, created_by=ADMIN)
    assert client.delete(f"/share/v1/links/{theirs.link_uid}",
                         headers=plain).status_code == 404
    assert not links.get(conn, theirs.link_uid).is_revoked


def test_an_admin_may_remove_a_recipient_but_not_add_one(client, admin, cfg, conn):
    """The console's powers stop at revocation.

    Removing narrows access and is oversight; adding widens it and would make
    the console a new way to enlarge the blast radius rather than shrink it.
    """
    theirs = _mint(cfg, conn, created_by=OTHER, recipients=["keep@example.com"])
    gone = client.delete(
        f"/share/v1/links/{theirs.link_uid}/recipients/keep@example.com",
        headers=admin)
    assert gone.status_code == 200

    added = client.post(f"/share/v1/links/{theirs.link_uid}/recipients",
                        json={"email": "new@example.com"}, headers=admin)
    assert added.status_code == 404, added.text
    roster = links.recipients(conn, theirs.link_uid, include_removed=True)
    assert not any(r["email"] == "new@example.com" for r in roster)


def test_an_admin_may_read_someone_elses_ledger(client, admin, cfg, conn):
    theirs = _mint(cfg, conn, created_by=OTHER)
    assert client.get(f"/share/v1/links/{theirs.link_uid}/redemptions",
                      headers=admin).status_code == 200
    assert client.get(f"/share/v1/links/{theirs.link_uid}/recipients",
                      headers=admin).status_code == 200


# --- revoke all -----------------------------------------------------------

def test_revoke_all_ends_one_creators_live_links_and_nobody_elses(client, admin,
                                                                  cfg, conn):
    leaver = f"leaver-{uuid.uuid4().hex[:8]}@rationalboxes.com"
    a = _mint(cfg, conn, created_by=leaver)
    b = _mint(cfg, conn, created_by=leaver)
    bystander = _mint(cfg, conn, created_by=OTHER)

    r = client.post("/share/v1/admin/revoke-all", json={"creator": leaver},
                    headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] == 2
    assert set(r.json()["link_uids"]) == {a.link_uid, b.link_uid}
    assert links.get(conn, a.link_uid).is_revoked
    assert links.get(conn, b.link_uid).is_revoked
    assert not links.get(conn, bystander.link_uid).is_revoked


def test_revoke_all_is_refused_to_a_non_admin(client, plain, cfg, conn):
    victim = _mint(cfg, conn, created_by=ADMIN)
    r = client.post("/share/v1/admin/revoke-all", json={"creator": ADMIN},
                    headers=plain)
    assert r.status_code == 403
    assert not links.get(conn, victim.link_uid).is_revoked


def test_revoke_all_requires_a_creator(client, admin):
    r = client.post("/share/v1/admin/revoke-all", json={"creator": "  "},
                    headers=admin)
    assert r.status_code == 400


def test_revoke_all_is_idempotent(client, admin, cfg, conn):
    leaver = f"leaver-{uuid.uuid4().hex[:8]}@rationalboxes.com"
    _mint(cfg, conn, created_by=leaver)
    first = client.post("/share/v1/admin/revoke-all", json={"creator": leaver},
                        headers=admin).json()
    second = client.post("/share/v1/admin/revoke-all", json={"creator": leaver},
                         headers=admin).json()
    assert first["revoked"] == 1
    assert second["revoked"] == 0


def test_the_list_says_so_when_it_hits_its_cap(client, admin, cfg, conn, monkeypatch):
    """Completeness is the console's whole value.

    "Here is what is reachable from outside this tenant" that silently stops at
    the row cap is worse than one showing fewer rows and saying so — an admin
    would close the review believing they had seen everything.
    """
    real = links.list_for_tenant
    monkeypatch.setattr(links, "list_for_tenant",
                        lambda conn, **kw: real(conn, **{**kw, "limit": 2}))
    for _ in range(3):
        _mint(cfg, conn, created_by=OTHER)
    r = client.get("/share/v1/links?all=true", headers=admin)
    assert r.status_code == 200
    assert len(r.json()["links"]) == 2
    assert r.json()["truncated"] is True


def test_an_uncapped_list_does_not_claim_truncation(client, admin, cfg, conn,
                                                    monkeypatch):
    real = links.list_for_tenant
    monkeypatch.setattr(links, "list_for_tenant",
                        lambda conn, **kw: real(conn, **{**kw, "limit": 5000}))
    _mint(cfg, conn, created_by=OTHER)
    r = client.get("/share/v1/links?all=true", headers=admin)
    assert r.json()["truncated"] is False


# --- the Dashboard's Sharing panel (spec §10.6) ---------------------------

def test_the_inbox_groups_by_what_the_user_should_do_about_it(client, admin,
                                                              cfg, conn):
    """Three groups because they want three different reactions: something is
    wrong, something arrived, everything else is fine."""
    r = client.get("/share/v1/links/mine/inbox", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"needs_attention", "drop_boxes", "active"}


def test_the_inbox_is_only_the_callers_own_links(client, plain, cfg, conn):
    """Not the tenant's. The admin console is a separate surface."""
    mine = _mint(cfg, conn, created_by=OTHER)
    _mint(cfg, conn, created_by=ADMIN)
    body = client.get("/share/v1/links/mine/inbox", headers=plain).json()
    seen = {l["link_uid"] for g in body.values() for l in g}
    assert mine.link_uid in seen
    assert all(l["created_by"] == OTHER for g in body.values() for l in g)


def test_a_drop_box_is_not_filed_under_active_links(client, admin, cfg, conn,
                                                    real_folder):
    """A drop box is a thing you are WAITING ON — the one share shape with an
    inbox character — so it does not belong in the outbound list.

    Uses the directory-resident user and a REAL resource, because the pre-flight
    runs for real here: a fabricated uid, or a creator LDAP has never heard of,
    both land the row in needs_attention. Both are correct behaviour and neither
    is what this test is about.
    """
    box = _mint(cfg, conn, created_by=ADMIN, kind_override=1,
                resource_uid=real_folder)
    body = client.get("/share/v1/links/mine/inbox", headers=admin).json()
    assert box.link_uid in {l["link_uid"] for l in body["drop_boxes"]}
    assert box.link_uid not in {l["link_uid"] for l in body["active"]}


def test_a_creator_the_directory_does_not_know_has_every_link_flagged(client,
                                                                      plain,
                                                                      cfg, conn):
    """The departed-employee state seen from the other side.

    Their links keep existing but none of them would redeem, and the panel says
    so per row rather than showing a green list that lies.
    """
    _mint(cfg, conn, created_by=OTHER)
    body = client.get("/share/v1/links/mine/inbox", headers=plain).json()
    assert body["active"] == [] and body["drop_boxes"] == []
    assert body["needs_attention"]
    assert all(l["status"] == "not_working" for l in body["needs_attention"])


def test_a_dead_link_lands_in_needs_attention_with_a_reason(client, plain,
                                                            cfg, conn):
    """The resource uid is fabricated, so the pre-flight finds it gone — which
    is the state the creator otherwise learns about from their recipient."""
    dead = _mint(cfg, conn, created_by=OTHER)      # random uid, not in the core
    body = client.get("/share/v1/links/mine/inbox", headers=plain).json()
    row = next((l for l in body["needs_attention"] if l["link_uid"] == dead.link_uid),
               None)
    assert row is not None, "a link to a non-existent resource must be flagged"
    assert row["status"] == "not_working"
    assert row["not_working_message"]


# --- drop provenance in the file list (durable marker) --------------------

def _record_drop(conn, cfg, *, link, email, result_uid):
    """A completed drop, as sessions.record_drop leaves it."""
    from share_service import sessions
    import datetime as dt
    red = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO share_redemptions
                 (redemption_uid, link_uid, expires_at, verified_email, result_uid)
               VALUES (%s,%s,now() + interval '1 hour',%s,%s)""",
            (red, link.link_uid, email, result_uid))
    conn.commit()
    return red


def test_provenance_marks_a_file_that_came_from_outside(client, admin, cfg, conn,
                                                        real_folder):
    box = _mint(cfg, conn, created_by=ADMIN, kind_override=1,
                resource_uid=real_folder)
    dropped = _real_file(cfg, real_folder)
    _record_drop(conn, cfg, link=box, email="bob@contractor.example",
                 result_uid=dropped)

    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": [dropped]}, headers=admin)
    assert r.status_code == 200, r.text
    got = r.json()["provenance"]
    assert got[dropped]["email"] == "bob@contractor.example"
    assert got[dropped]["shared_by"] == ADMIN


def test_an_ordinary_file_has_no_provenance(client, admin, cfg, real_folder):
    """Absence is the common case and must be cheap and silent."""
    plain_file = _real_file(cfg, real_folder)
    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": [plain_file]}, headers=admin)
    assert r.json()["provenance"] == {}


def test_the_marker_is_exactly_as_visible_as_the_file(client, plain, cfg, conn,
                                                      real_folder):
    """The filter tracks the FILE's visibility, and that is the whole rule.

    Worth stating plainly, because it is weaker than it first looks: the core is
    read-by-default (`default_read_ = true`), so an unrelated signed-in user can
    reach most files and therefore sees the marker too. That is the intended
    posture rather than a hole — if you may read the file, knowing it arrived
    from outside is not an escalation, and it is precisely the fact a colleague
    browsing the folder most needs.

    What the filter does stop is the endpoint answering for uids the caller
    cannot reach at all — see the deleted-resource test below, which is the case
    that actually bites.
    """
    box = _mint(cfg, conn, created_by=ADMIN, kind_override=1,
                resource_uid=real_folder)
    dropped = _real_file(cfg, real_folder)
    _record_drop(conn, cfg, link=box, email="bob@contractor.example",
                 result_uid=dropped)
    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": [dropped]}, headers=plain)
    assert r.status_code == 200
    # Readable by this caller => marked for this caller.
    assert r.json()["provenance"][dropped]["email"] == "bob@contractor.example"


def test_a_uid_that_does_not_exist_yields_nothing(client, admin, cfg, conn,
                                                  real_folder):
    """can_reach, not check_permission: read-by-default means a MISSING uid
    passes a bare permission check, so a stale row would be served."""
    box = _mint(cfg, conn, created_by=ADMIN, kind_override=1,
                resource_uid=real_folder)
    ghost = str(uuid.uuid4())
    _record_drop(conn, cfg, link=box, email="bob@contractor.example",
                 result_uid=ghost)
    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": [ghost]}, headers=admin)
    assert r.json()["provenance"] == {}


def test_provenance_survives_a_move(client, admin, cfg, conn, real_folder):
    """The marker is keyed on the file uid, so relocating the file keeps it —
    a path-keyed marker would lose exactly the file someone tidied away."""
    from share_service import core_client, ldap_roles
    box = _mint(cfg, conn, created_by=ADMIN, kind_override=1,
                resource_uid=real_folder)
    dropped = _real_file(cfg, real_folder)
    _record_drop(conn, cfg, link=box, email="bob@contractor.example",
                 result_uid=dropped)

    roles = ldap_roles.resolve_share_roles(cfg, ADMIN)
    with core_client.for_creator(cfg, created_by=ADMIN, roles=roles,
                                 tenant=TENANT) as core:
        elsewhere = core.client.mkdir(real_folder, f"moved-{uuid.uuid4().hex[:6]}")
        elsewhere = getattr(elsewhere, "uid", elsewhere)
        moved = getattr(core.client, "move", None)
        if moved is None:
            pytest.skip("this client build has no move()")
        moved(dropped, elsewhere)

    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": [dropped]}, headers=admin)
    assert r.json()["provenance"].get(dropped, {}).get("email") \
        == "bob@contractor.example"


def test_the_batch_is_capped(client, admin, cfg):
    """Bounds the ACL work a single request can ask the core to do."""
    many = [str(uuid.uuid4()) for _ in range(cfg.provenance_batch_max + 50)]
    r = client.post("/share/v1/files/provenance",
                    json={"file_uids": many}, headers=admin)
    assert r.status_code == 200
