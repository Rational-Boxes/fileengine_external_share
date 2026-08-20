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

"""The public door (M4 — the review gate).

Needs the dev core, LDAP, Postgres, Redis **and a running ldap_manager** for
the OTP seam. The OTP calls are stubbed at the `otp_client` boundary where a
test only needs a verified recipient; the tests that are *about* verification
exercise the real thing.

What is tested here is not "can a recipient download a file" — it is the five
properties that make an unauthenticated door acceptable: uniform failure, no
recipient-list oracle, header hardening on every response, a use consumed only
at session open, and a target uid that cannot be redirected.
"""
from __future__ import annotations

import io
import uuid
import zipfile

import pytest
from fastapi.testclient import TestClient

from share_service import core_client, db, ldap_roles, links, otp_client
from share_service import snapshot as snapshot_mod
from share_service.app import create_app
from share_service.config import Config

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
TENANT = "default"
RECIPIENT = "recipient@example.com"
STRANGER = "stranger@example.com"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.enabled = True
    return c


@pytest.fixture
def roles(cfg):
    return ldap_roles.resolve_share_roles(cfg, USER)


@pytest.fixture
def client(cfg) -> TestClient:
    return TestClient(create_app(cfg), raise_server_exceptions=False)


@pytest.fixture
def tree(cfg, roles):
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        c = core.client
        root = c.mkdir("", f"m4-{uuid.uuid4().hex[:8]}"); root = getattr(root, "uid", root)
        f = c.touch(root, "doc.txt"); f = getattr(f, "uid", f)
        c.put(f, b"the payload")
    return root, f


def _mint(cfg, roles, resource_uid, kind=2, **kw):
    """A live link + its plaintext secret, made directly (the owner-side route
    is M0's territory; these tests are about the public door)."""
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, secret = links.create(
            conn, kind=kind, resource_uid=resource_uid, created_by=USER,
            expires_at=links.clamp_expiry(cfg, None, 1),
            recipients=[RECIPIENT], max_uses=kw.pop("max_uses", 5), **kw)
        if kind == 2:
            with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                         tenant=TENANT) as core:
                snap = snapshot_mod.walk(core, cfg, resource_uid)
            snapshot_mod.store(conn, link.link_uid, snap)
        return link, secret
    finally:
        conn.close()


def _h(secret, **extra):
    return {"X-Share-Secret": secret, "X-Tenant": TENANT, **extra}


@pytest.fixture
def verified(monkeypatch):
    """Stub the OTP seam: a recipient who has already proved control."""
    monkeypatch.setattr(otp_client, "check_token",
                        lambda cfg, **kw: kw.get("email") == RECIPIENT)
    return "stub-recipient-token"


# --- 1. uniform failure ---------------------------------------------------

def test_every_failure_is_the_same_failure(client, cfg, roles, tree):
    """Unknown link, bad secret, revoked, expired — one response, or the door is
    an oracle (spec §8.5)."""
    root, _ = tree
    link, secret = _mint(cfg, roles, root)

    revoked, revoked_secret = _mint(cfg, roles, root)
    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        links.revoke(conn, revoked.link_uid, USER)
    finally:
        conn.close()

    cases = [
        ("unknown link", f"/share/v1/public/{uuid.uuid4()}", _h(secret)),
        ("bad secret", f"/share/v1/public/{link.link_uid}", _h("wrong-secret")),
        ("no secret", f"/share/v1/public/{link.link_uid}", {"X-Tenant": TENANT}),
        ("revoked", f"/share/v1/public/{revoked.link_uid}", _h(revoked_secret)),
    ]
    seen = set()
    for label, path, headers in cases:
        r = client.get(path, headers=headers)
        assert r.status_code == 404, f"{label}: {r.status_code}"
        seen.add(r.text)
    assert len(seen) == 1, f"failures are distinguishable: {seen}"


def test_a_valid_link_peeks_without_consuming_anything(client, cfg, roles, tree):
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.get(f"/share/v1/public/{link.link_uid}", headers=_h(secret))
    assert r.status_code == 200
    body = r.json()
    assert body["verification_required"] is True
    assert body["member_count"] >= 1

    # Peek must never expose the resource, the creator, or the recipients.
    blob = r.text.lower()
    assert root.lower() not in blob
    assert USER.lower() not in blob
    assert RECIPIENT not in blob

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        assert links.get(conn, link.link_uid).uses_consumed == 0
    finally:
        conn.close()


# --- 2. no recipient-list oracle -----------------------------------------

def test_identify_answers_identically_for_listed_and_unlisted(client, cfg, roles, tree,
                                                              monkeypatch):
    """The endpoint that would otherwise enumerate the allowlist (spec §6.9)."""
    sent = []
    monkeypatch.setattr(otp_client, "send_code",
                        lambda cfg, **kw: sent.append(kw["email"])
                        or otp_client.ChallengeResult(sent=True))
    root, _ = tree
    link, secret = _mint(cfg, roles, root)

    a = client.post(f"/share/v1/public/{link.link_uid}/identify",
                    headers=_h(secret), json={"email": RECIPIENT})
    b = client.post(f"/share/v1/public/{link.link_uid}/identify",
                    headers=_h(secret), json={"email": STRANGER})
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()
    # ...but only the listed address was actually mailed.
    assert sent == [RECIPIENT]


def test_a_failed_otp_send_still_answers_uniformly(client, cfg, roles, tree, monkeypatch):
    """The creator must find out (via audit); the recipient must not."""
    monkeypatch.setattr(otp_client, "send_code",
                        lambda cfg, **kw: otp_client.ChallengeResult(
                            sent=False, error="SMTPException: refused"))
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.post(f"/share/v1/public/{link.link_uid}/identify",
                    headers=_h(secret), json={"email": RECIPIENT})
    assert r.status_code == 200
    assert r.json()["status"] == "sent_if_authorized"
    assert "refused" not in r.text and "SMTP" not in r.text


def test_an_unreachable_identity_service_denies(client, cfg, roles, tree, monkeypatch):
    def boom(cfg, **kw):
        raise otp_client.OtpUnavailable("connection refused")
    monkeypatch.setattr(otp_client, "send_code", boom)
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.post(f"/share/v1/public/{link.link_uid}/identify",
                    headers=_h(secret), json={"email": RECIPIENT})
    assert r.status_code == 404          # fail closed, uniformly


# --- 3. header hardening --------------------------------------------------

@pytest.mark.parametrize("path_suffix,method,body", [
    ("", "get", None),
    ("/identify", "post", {"email": RECIPIENT}),
    ("/verify", "post", {"email": RECIPIENT, "code": "000000"}),
])
def test_hardening_headers_on_every_public_response(client, cfg, roles, tree,
                                                    path_suffix, method, body,
                                                    monkeypatch):
    """Set once for the whole router, including on errors — the anti-XSS
    boundary (spec §8.3). A shared .html on the SPA's origin would otherwise run
    script there and read the bearer token out of localStorage."""
    monkeypatch.setattr(otp_client, "send_code",
                        lambda cfg, **kw: otp_client.ChallengeResult(sent=True))
    monkeypatch.setattr(otp_client, "verify_code",
                        lambda cfg, **kw: otp_client.VerifyResult(ok=False))
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    url = f"/share/v1/public/{link.link_uid}{path_suffix}"
    r = getattr(client, method)(url, headers=_h(secret), **({"json": body} if body else {}))

    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "sandbox"
    assert r.headers["cache-control"] == "no-store"
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["x-robots-tag"] == "noindex, nofollow"


def test_hardening_headers_are_present_on_a_404_too(client):
    r = client.get(f"/share/v1/public/{uuid.uuid4()}", headers={"X-Tenant": TENANT})
    assert r.status_code == 404
    assert r.headers["content-security-policy"] == "sandbox"
    assert r.headers["x-content-type-options"] == "nosniff"


# --- 4. the use is consumed at session open, and only there ---------------

def test_no_session_without_a_recipient_token(client, cfg, roles, tree, monkeypatch):
    monkeypatch.setattr(otp_client, "check_token", lambda cfg, **kw: False)
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret), json={"email": RECIPIENT})
    assert r.status_code == 404
    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        assert links.get(conn, link.link_uid).uses_consumed == 0
    finally:
        conn.close()


def test_session_consumes_exactly_one_use_and_serves_the_zip(client, cfg, roles,
                                                             tree, verified):
    root, _ = tree
    link, secret = _mint(cfg, roles, root)

    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    assert r.status_code == 200, r.text
    session = r.json()
    assert session["archive_bytes"] > 0

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        assert links.get(conn, link.link_uid).uses_consumed == 1
    finally:
        conn.close()

    hdr = _h(secret, **{"X-Redemption-Uid": session["redemption_uid"]})
    r = client.get(f"/share/v1/public/{link.link_uid}/content", headers=hdr)
    assert r.status_code == 200
    # The declared length must equal what was actually produced, or every
    # folder download is a corrupt archive (spec §6.5).
    assert int(r.headers["content-length"]) == len(r.content) == session["archive_bytes"]
    assert r.headers["accept-ranges"] == "none"

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert zf.testzip() is None
    assert zf.read("doc.txt") == b"the payload"

    # Transfers within the session consume nothing further.
    assert client.get(f"/share/v1/public/{link.link_uid}/content",
                      headers=hdr).status_code == 200
    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        assert links.get(conn, link.link_uid).uses_consumed == 1
    finally:
        conn.close()


def test_content_requires_a_session(client, cfg, roles, tree):
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    assert client.get(f"/share/v1/public/{link.link_uid}/content",
                      headers=_h(secret)).status_code == 404


# --- 5. the session cannot be borrowed -----------------------------------

def test_a_session_from_one_link_does_not_open_another(client, cfg, roles, tree,
                                                       verified):
    """The target uid comes only from the link record; a redemption on link A
    must not be usable to pull link B (spec §4.3)."""
    root, _ = tree
    a, a_secret = _mint(cfg, roles, root)
    b, b_secret = _mint(cfg, roles, root)

    r = client.post(f"/share/v1/public/{a.link_uid}/session",
                    headers=_h(a_secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    redemption = r.json()["redemption_uid"]

    r = client.get(f"/share/v1/public/{b.link_uid}/content",
                   headers=_h(b_secret, **{"X-Redemption-Uid": redemption}))
    assert r.status_code == 404


def test_the_public_router_never_reads_a_bearer_token(client, cfg, roles, tree):
    """A logged-in browser is still session-less here, so a redemption can never
    be misattributed to a passing authenticated user (spec §7.2)."""
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers=_h(secret, Authorization="Bearer anything-at-all"))
    assert r.status_code == 200          # the bearer is simply irrelevant here
    r = client.get(f"/share/v1/public/{link.link_uid}",
                   headers={"X-Tenant": TENANT, "Authorization": "Bearer x"})
    assert r.status_code == 404          # ...and cannot substitute for the secret


# --- 6. version pinning: the link shares (entity uuid, version timestamp) ---

def _file_link(cfg, roles, file_uid, follow_latest=False):
    """A kind=0 link through the real creation path, so pinning is exercised
    where it actually happens."""
    from share_service import core_client as cc
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        pinned = None
        if not follow_latest:
            with cc.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
                pinned = core.current_version(file_uid)
        link, secret = links.create(
            conn, kind=0, resource_uid=file_uid, created_by=USER,
            expires_at=links.clamp_expiry(cfg, None, 1),
            recipients=[RECIPIENT], max_uses=9, pinned_version=pinned)
        return link, secret
    finally:
        conn.close()


def _fetch(client, link, secret, verified):
    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    assert r.status_code == 200, r.text
    return client.get(f"/share/v1/public/{link.link_uid}/content",
                      headers=_h(secret, **{"X-Redemption-Uid":
                                            r.json()["redemption_uid"]}))


def test_a_pinned_file_link_does_not_follow_later_edits(client, cfg, roles, tree,
                                                        verified):
    """The property §6.2 exists for: a document shared for review in March must
    not silently expose whatever it becomes in September."""
    root, doc = tree
    link, secret = _file_link(cfg, roles, doc)
    assert link.pinned_version, "creation must record the version timestamp"

    assert _fetch(client, link, secret, verified).content == b"the payload"

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        core.client.put(doc, b"RENEGOTIATED TERMS -- much later, much longer")

    # The recipient still receives what the link was minted for.
    assert _fetch(client, link, secret, verified).content == b"the payload"


def test_follow_latest_is_the_explicit_opt_in(client, cfg, roles, tree, verified):
    root, doc = tree
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        core.client.put(doc, b"first")
    link, secret = _file_link(cfg, roles, doc, follow_latest=True)
    assert link.pinned_version is None

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        core.client.put(doc, b"second, and this link should follow it")
    assert _fetch(client, link, secret, verified).content == \
        b"second, and this link should follow it"


def test_pinning_survives_several_intervening_versions(client, cfg, roles, tree,
                                                       verified):
    """`get(back=N)` selects positionally, so an offset shifts every time anyone
    saves. Storing the version NAME is what makes the pin stable."""
    root, doc = tree
    link, secret = _file_link(cfg, roles, doc)
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        for i in range(4):
            core.client.put(doc, f"revision {i}".encode())
    assert _fetch(client, link, secret, verified).content == b"the payload"


def test_a_culled_pinned_version_kills_the_link(client, cfg, roles, tree, verified):
    """Never a silent substitution: if the pinned version is gone the link is
    dead, uniformly (spec §6.2)."""
    root, doc = tree
    link, secret = _file_link(cfg, roles, doc)

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE share_links SET pinned_version = %s WHERE link_uid = %s",
                        ("19700101_000000.000", link.link_uid))
        conn.commit()
        link = links.get(conn, link.link_uid)
    finally:
        conn.close()

    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    # The pre-flight catches it at session open, before any budget moves.
    assert r.status_code == 404


def test_folder_members_pin_their_version_too(client, cfg, roles, tree, verified):
    """`DirectoryEntry` carries no version, so reading it off the listing pinned
    nothing — members silently followed the head."""
    root, doc = tree
    link, secret = _mint(cfg, roles, root)

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        stored = snapshot_mod.load(conn, link.link_uid)
    finally:
        conn.close()
    assert all(m.version_name for m in stored if not m.is_dir), \
        "every member must record a version timestamp"

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        core.client.put(doc, b"changed after the snapshot was taken")

    r = _fetch(client, link, secret, verified)
    assert r.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert zf.read("doc.txt") == b"the payload"
