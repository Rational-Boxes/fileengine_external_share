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


# --- 7. the drop box ------------------------------------------------------

def _drop_link(cfg, roles, folder_uid, **kw):
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        return links.create(
            conn, kind=1, resource_uid=folder_uid, created_by=USER,
            expires_at=links.clamp_expiry(cfg, None, 1),
            recipients=[RECIPIENT], max_uses=kw.pop("max_uses", 5),
            max_files=kw.pop("max_files", 3), **kw)
    finally:
        conn.close()


def _open(client, link, secret, verified):
    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    assert r.status_code == 200, r.text
    return r.json()["redemption_uid"]


def _drop(client, link, secret, redemption, name, body, **extra):
    return client.post(
        f"/share/v1/public/{link.link_uid}/files",
        headers=_h(secret, **{"X-Redemption-Uid": redemption,
                              "X-File-Name": name, **extra}),
        content=body)


def test_a_drop_lands_owned_by_the_creator_with_its_origin_recorded(
        client, cfg, roles, tree, verified):
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root)
    redemption = _open(client, link, secret, verified)

    r = _drop(client, link, secret, redemption, "delivery.txt", b"from outside",
              **{"X-Claimed-Name": "Bob from Contractor Ltd"})
    assert r.status_code == 201, r.text
    assert r.json()["stored_name"] == "delivery.txt"

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        entry = next(e for e in core.client.dir(root) if e.name == "delivery.txt")
        assert core.client.get(entry.uid).getvalue() == b"from outside"
        meta = core.client.get_metadata_values(entry.uid)
        # Owned by the creator so inherited ACLs behave normally; the outside
        # origin lives in metadata instead (spec §6.8).
        assert meta["share.verified_email"] == RECIPIENT
        assert meta["share.link_uid"] == link.link_uid
        assert meta["share.claimed_name"] == "Bob from Contractor Ltd"


def test_a_drop_never_versions_an_existing_file(client, cfg, roles, tree, verified):
    """An outside sender must not be able to inject a revision into a document's
    history -- poisoning the "latest" of a file others trust (spec §6.7)."""
    root, doc = tree
    link, secret = _drop_link(cfg, roles, root)
    redemption = _open(client, link, secret, verified)

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        before = len(core.client.revisions(doc))

    r = _drop(client, link, secret, redemption, "doc.txt", b"REPLACEMENT")
    assert r.status_code == 201
    assert r.json()["stored_name"] == "doc.txt (1)" or \
        r.json()["stored_name"].startswith("doc (1)")

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        assert len(core.client.revisions(doc)) == before      # untouched
        assert core.client.get(doc).getvalue() == b"the payload"


def test_the_file_budget_binds_and_is_not_the_session_budget(client, cfg, roles,
                                                             tree, verified):
    """max_files counts files; max_uses counts sessions (spec §6.4)."""
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root, max_files=2, max_uses=5)
    redemption = _open(client, link, secret, verified)

    for i in range(2):
        assert _drop(client, link, secret, redemption,
                     f"f{i}.txt", b"x").status_code == 201
    r = _drop(client, link, secret, redemption, "f2.txt", b"x")
    assert r.status_code == 409

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        live = links.get(conn, link.link_uid)
        assert live.files_consumed == 2
        assert live.uses_consumed == 1        # one session, two files
    finally:
        conn.close()


def test_an_oversized_file_is_refused_and_costs_no_slot(client, cfg, roles, tree,
                                                        verified):
    """The slot is released when the store does not happen, so a rejected upload
    does not silently spend the sender's budget."""
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root, max_files=2, max_file_bytes=16)
    redemption = _open(client, link, secret, verified)

    r = _drop(client, link, secret, redemption, "big.bin", b"x" * 5000)
    assert r.status_code == 413

    conn = db.connect_for_tenant(cfg, TENANT)
    try:
        assert links.get(conn, link.link_uid).files_consumed == 0
    finally:
        conn.close()
    # ...and the budget really is intact.
    assert _drop(client, link, secret, redemption, "ok.txt", b"small").status_code == 201


def test_the_extension_allowlist_is_applied_to_the_claimed_name(client, cfg, roles,
                                                                tree, verified):
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root, ext_allowlist=["pdf", "txt"])
    redemption = _open(client, link, secret, verified)
    assert _drop(client, link, secret, redemption, "x.exe", b"MZ").status_code == 400
    assert _drop(client, link, secret, redemption, "x.txt", b"hi").status_code == 201


@pytest.mark.parametrize("hostile", [
    "../../escape.txt", "/etc/passwd", "..", ".hidden", "a/b.txt", "x\x00.txt",
])
def test_a_sender_cannot_steer_where_the_file_lands(client, cfg, roles, tree,
                                                    verified, hostile):
    """The destination comes from the link record; the name is only a name."""
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root)
    redemption = _open(client, link, secret, verified)
    r = _drop(client, link, secret, redemption, hostile, b"payload")
    if r.status_code == 201:
        stored = r.json()["stored_name"]
        assert "/" not in stored and "\\" not in stored
        assert not stored.startswith(".")
        with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                     tenant=TENANT) as core:
            assert stored in {e.name for e in core.client.dir(root)}
    else:
        assert r.status_code == 400


def test_a_drop_requires_an_open_session(client, cfg, roles, tree):
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root)
    r = client.post(f"/share/v1/public/{link.link_uid}/files",
                    headers=_h(secret, **{"X-File-Name": "x.txt"}), content=b"x")
    assert r.status_code == 404


def test_a_download_link_does_not_accept_drops(client, cfg, roles, tree, verified):
    root, _ = tree
    link, secret = _mint(cfg, roles, root)          # kind = 2
    redemption = _open(client, link, secret, verified)
    assert _drop(client, link, secret, redemption, "x.txt", b"x").status_code == 404


def test_the_landing_prefix_quarantines_drops(client, cfg, roles, tree, verified):
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root, landing_prefix="inbox")
    redemption = _open(client, link, secret, verified)
    assert _drop(client, link, secret, redemption, "note.txt", b"x").status_code == 201

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        inbox = next(e for e in core.client.dir(root)
                     if e.name == "inbox" and e.is_container)
        assert "note.txt" in {e.name for e in core.client.dir(inbox.uid)}


# --- 8. streaming: nothing holds a whole file -----------------------------

def test_a_drop_larger_than_the_old_unary_ceiling_now_works(client, cfg, roles,
                                                            tree, verified):
    """80 MiB: impossible when the drop path buffered and sent one PutFile
    message (64 MiB channel cap), routine once it spools and streams."""
    root, _ = tree
    link, secret = _drop_link(cfg, roles, root, max_files=2,
                              max_file_bytes=200 * 1024 * 1024)
    redemption = _open(client, link, secret, verified)

    body = b"\xa5" * (80 * 1024 * 1024)
    r = _drop(client, link, secret, redemption, "large.bin", body)
    assert r.status_code == 201, r.text
    assert r.json()["size_bytes"] == len(body)

    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        entry = next(e for e in core.client.dir(root) if e.name == "large.bin")
        assert core.client.stat(entry.uid).size == len(body)
        # Read it back the same way -- streamed, never assembled.
        seen = sum(len(c) for c in core.stream_pinned(entry.uid))
        assert seen == len(body)


def test_a_file_link_streams_rather_than_materialising(client, cfg, roles, tree,
                                                       verified):
    root, doc = tree
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        big = b"z" * (12 * 1024 * 1024)
        core.client.put_stream(doc, [big])
    link, secret = _file_link(cfg, roles, doc)

    r = _fetch(client, link, secret, verified)
    assert r.status_code == 200
    assert int(r.headers["content-length"]) == len(r.content) == 12 * 1024 * 1024


def test_folder_members_stream_into_the_archive(client, cfg, roles, tree, verified):
    """The zip framer consumes an iterable per member, so peak memory is one
    chunk rather than the largest file in the folder."""
    root, doc = tree
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        core.client.put_stream(doc, [b"m" * (9 * 1024 * 1024)])
    link, secret = _mint(cfg, roles, root)

    r = _fetch(client, link, secret, verified)
    assert r.status_code == 200
    assert int(r.headers["content-length"]) == len(r.content)
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert zf.testzip() is None
    assert len(zf.read("doc.txt")) == 9 * 1024 * 1024


def test_content_accepts_the_redemption_as_a_query_parameter(client, cfg, roles,
                                                             tree, verified):
    """A browser navigation cannot set headers, and the payload must be a plain
    navigation so the download streams rather than passing through XHR."""
    root, _ = tree
    link, secret = _mint(cfg, roles, root)
    r = client.post(f"/share/v1/public/{link.link_uid}/session",
                    headers=_h(secret, **{"X-Recipient-Token": verified}),
                    json={"email": RECIPIENT})
    redemption = r.json()["redemption_uid"]

    # Header form and query form must be equivalent.
    by_header = client.get(f"/share/v1/public/{link.link_uid}/content",
                           headers=_h(secret, **{"X-Redemption-Uid": redemption}))
    by_query = client.get(
        f"/share/v1/public/{link.link_uid}/content?k={secret}&redemption={redemption}",
        headers={"X-Tenant": TENANT})
    assert by_header.status_code == by_query.status_code == 200
    assert by_header.content == by_query.content

    # A bogus redemption in the query is still the uniform 404.
    bad = client.get(
        f"/share/v1/public/{link.link_uid}/content?k={secret}&redemption={uuid.uuid4()}",
        headers={"X-Tenant": TENANT})
    assert bad.status_code == 404
