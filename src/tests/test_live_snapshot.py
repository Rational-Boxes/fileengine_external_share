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

"""Folder snapshots against a real core (M1).

Builds a small fixture tree, then checks the two properties that make a folder
link safe rather than merely working: the member set is **frozen at creation**
(so files added later are never exposed), and a member the creator can no
longer read is **omitted at session open rather than fatal** (so one DENY does
not break the whole download).
"""
from __future__ import annotations

import uuid

import pytest

from share_service import core_client, db, ldap_roles, links, sessions
from share_service import snapshot as snapshot_mod
from share_service.archive import archive_length
from share_service.config import Config

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
TENANT = "default"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.enabled = True
    return c


@pytest.fixture
def roles(cfg):
    return ldap_roles.resolve_share_roles(cfg, USER)


@pytest.fixture
def tree(cfg, roles):
    """A fixture tree:  <root>/  a.txt (11B)  sub/b.txt (5B)  sub/deep/c.txt (3B)

    Returns (root_uid, {name: uid}). Left in place — the dev core is a scratch
    environment and a uniquely-named root keeps runs independent.
    """
    made = {}
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        c = core.client
        root_uid = c.mkdir("", f"m1-fixture-{uuid.uuid4().hex[:8]}")
        if hasattr(root_uid, "uid"):
            root_uid = root_uid.uid
        sub = c.mkdir(root_uid, "sub")
        sub = getattr(sub, "uid", sub)
        deep = c.mkdir(sub, "deep")
        deep = getattr(deep, "uid", deep)

        for parent, name, payload in ((root_uid, "a.txt", b"hello world"),
                                      (sub, "b.txt", b"world"),
                                      (deep, "c.txt", b"abc")):
            f = c.touch(parent, name)
            f = getattr(f, "uid", f)
            c.put(f, payload)
            made[name] = f
    return root_uid, made


def _walk(cfg, roles, root_uid, include_subdirs=True):
    with core_client.for_creator(cfg, created_by=USER, roles=roles, tenant=TENANT) as core:
        return snapshot_mod.walk(core, cfg, root_uid, include_subdirs=include_subdirs)


# --- the walk -------------------------------------------------------------

def test_walk_captures_the_subtree(cfg, roles, tree):
    root_uid, _ = tree
    snap = _walk(cfg, roles, root_uid)
    paths = sorted(m.archive_path for m in snap.members if not m.is_dir)
    assert paths == ["a.txt", "sub/b.txt", "sub/deep/c.txt"]
    assert snap.total_bytes == 11 + 5 + 3


def test_include_subdirs_false_takes_only_the_folders_own_files(cfg, roles, tree):
    """The difference between two of the three share shapes (spec §13-R8)."""
    root_uid, _ = tree
    snap = _walk(cfg, roles, root_uid, include_subdirs=False)
    assert sorted(m.archive_path for m in snap.members) == ["a.txt"]


def test_archive_bytes_is_computed_from_the_walk(cfg, roles, tree):
    root_uid, _ = tree
    snap = _walk(cfg, roles, root_uid)
    assert snap.archive_bytes == archive_length(snap.members)
    # Sanity: the archive is bigger than its payload but not wildly so.
    assert snap.archive_bytes > snap.total_bytes


def test_member_order_is_deterministic(cfg, roles, tree):
    """Two walks of an unchanged folder must produce the same archive, or the
    declared length stops being reproducible."""
    root_uid, _ = tree
    first = _walk(cfg, roles, root_uid)
    second = _walk(cfg, roles, root_uid)
    assert [m.archive_path for m in first.members] == [m.archive_path for m in second.members]
    assert first.archive_bytes == second.archive_bytes


# --- snapshot semantics ---------------------------------------------------

def test_snapshot_excludes_files_added_later(cfg, roles, tree):
    """The property the whole design rests on: a folder link keeps serving what
    it was minted for, not whatever lands in the folder next month (spec §6.5)."""
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        snap = _walk(cfg, roles, root_uid)
        link, _secret = links.create(
            conn, kind=2, resource_uid=root_uid, created_by=USER,
            expires_at=links.clamp_expiry(cfg, None, 1),
            recipients=["r@example.com"], max_uses=5)
        snapshot_mod.store(conn, link.link_uid, snap)

        # Now add a file the link must never expose.
        with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                     tenant=TENANT) as core:
            f = core.client.touch(root_uid, "added-later.txt")
            core.client.put(getattr(f, "uid", f), b"secret-after-the-fact")

        stored = snapshot_mod.load(conn, link.link_uid)
        assert "added-later.txt" not in [m.archive_path for m in stored]

        # And a fresh walk *would* have included it — proving the exclusion is
        # the snapshot doing its job, not the file failing to be created.
        assert "added-later.txt" in [m.archive_path for m in _walk(cfg, roles, root_uid).members]
    finally:
        conn.close()


def test_stored_members_round_trip(cfg, roles, tree):
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        snap = _walk(cfg, roles, root_uid)
        link, _ = links.create(conn, kind=2, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=5)
        snapshot_mod.store(conn, link.link_uid, snap)

        loaded = snapshot_mod.load(conn, link.link_uid)
        assert ([(m.archive_path, m.size_bytes, m.is_dir) for m in loaded]
                == [(m.archive_path, m.size_bytes, m.is_dir) for m in snap.members])
        assert archive_length(loaded) == snap.archive_bytes

        # archive_bytes is written onto the link for the creation response.
        assert links.get(conn, link.link_uid).archive_bytes == snap.archive_bytes
    finally:
        conn.close()


def test_oversized_folder_is_refused_with_numbers(cfg, roles, tree):
    root_uid, _ = tree
    tiny = Config()
    tiny.zip_max_members = 1
    with pytest.raises(snapshot_mod.SnapshotTooLarge) as exc:
        _walk(tiny, roles, root_uid)
    # The creator needs the actual count to act on, not just a refusal.
    assert exc.value.members >= 1


# --- session open ---------------------------------------------------------

def test_session_open_freezes_members_and_length(cfg, roles, tree):
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        snap = _walk(cfg, roles, root_uid)
        link, _ = links.create(conn, kind=2, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=5)
        snapshot_mod.store(conn, link.link_uid, snap)

        session = sessions.open_session(
            conn, cfg, link_uid=link.link_uid, verified_email="r@example.com",
            tenant=TENANT, roles=roles, source_addr="203.0.113.7")

        assert session.members_omitted == 0
        assert session.archive_bytes == archive_length(session.members)
        # One use consumed -- by the session, not by any request within it.
        assert links.get(conn, link.link_uid).uses_consumed == 1

        with conn.cursor() as cur:
            cur.execute("""SELECT verified_email, archive_bytes, frozen_members
                             FROM share_redemptions WHERE redemption_uid = %s""",
                        (session.redemption_uid,))
            email, archive_bytes, frozen = cur.fetchone()
        assert email == "r@example.com"
        assert archive_bytes == session.archive_bytes
        assert len(frozen) == session.members_served
    finally:
        conn.close()


def test_session_refuses_an_unverified_address(cfg, roles, tree):
    """`share_redemptions.verified_email` is NOT NULL for a reason: no session
    opens unverified (spec §5.3)."""
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, _ = links.create(conn, kind=2, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=5)
        with pytest.raises(sessions.SessionRefused):
            sessions.open_session(conn, cfg, link_uid=link.link_uid, verified_email="",
                                  tenant=TENANT, roles=roles)
    finally:
        conn.close()


def test_an_unlisted_address_consumes_nothing(cfg, roles, tree):
    """The allowlist is enforced in the same statement that consumes the use,
    so a stranger cannot burn a link's budget by trying (spec §5.3)."""
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, _ = links.create(conn, kind=2, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["listed@example.com"], max_uses=5)
        with pytest.raises(sessions.SessionRefused):
            sessions.open_session(conn, cfg, link_uid=link.link_uid,
                                  verified_email="stranger@example.com",
                                  tenant=TENANT, roles=roles)
        assert links.get(conn, link.link_uid).uses_consumed == 0
    finally:
        conn.close()


def test_use_budget_is_enforced_and_exhaustion_is_terminal(cfg, roles, tree):
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, _ = links.create(conn, kind=1, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=2, max_files=3)
        for _ in range(2):
            sessions.open_session(conn, cfg, link_uid=link.link_uid,
                                  verified_email="r@example.com",
                                  tenant=TENANT, roles=roles)
        with pytest.raises(sessions.SessionRefused):
            sessions.open_session(conn, cfg, link_uid=link.link_uid,
                                  verified_email="r@example.com",
                                  tenant=TENANT, roles=roles)
        assert links.get(conn, link.link_uid).status() == "exhausted"
    finally:
        conn.close()


def test_per_recipient_cap_does_not_burn_the_shared_pool(cfg, roles, tree):
    """The R12 correction, as a behaviour: a recipient refused by their personal
    cap must consume nothing from the shared pool (spec §5.3)."""
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, _ = links.create(conn, kind=1, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["a@example.com", "b@example.com"],
                               max_uses=10, max_uses_per_recipient=1)
        sessions.open_session(conn, cfg, link_uid=link.link_uid,
                              verified_email="a@example.com", tenant=TENANT, roles=roles)
        assert links.get(conn, link.link_uid).uses_consumed == 1

        with pytest.raises(sessions.SessionRefused):
            sessions.open_session(conn, cfg, link_uid=link.link_uid,
                                  verified_email="a@example.com",
                                  tenant=TENANT, roles=roles)
        # The refusal cost the pool nothing...
        assert links.get(conn, link.link_uid).uses_consumed == 1
        # ...and the other recipient is unaffected.
        sessions.open_session(conn, cfg, link_uid=link.link_uid,
                              verified_email="b@example.com", tenant=TENANT, roles=roles)
        assert links.get(conn, link.link_uid).uses_consumed == 2
    finally:
        conn.close()


def test_revoked_link_opens_no_session(cfg, roles, tree):
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        link, _ = links.create(conn, kind=1, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=5)
        links.revoke(conn, link.link_uid, USER)
        with pytest.raises(sessions.SessionRefused):
            sessions.open_session(conn, cfg, link_uid=link.link_uid,
                                  verified_email="r@example.com",
                                  tenant=TENANT, roles=roles)
    finally:
        conn.close()


def test_a_member_the_creator_cannot_read_is_omitted_not_fatal(cfg, roles, tree):
    """One DENY must not break the whole download (spec §6.5).

    Simulated by pointing a snapshot row at a uid that is not readable — the
    same shape the re-check sees when an ACL changes after minting.
    """
    root_uid, _ = tree
    conn = db.connect_for_tenant(cfg, TENANT, provision=True)
    try:
        snap = _walk(cfg, roles, root_uid)
        link, _ = links.create(conn, kind=2, resource_uid=root_uid, created_by=USER,
                               expires_at=links.clamp_expiry(cfg, None, 1),
                               recipients=["r@example.com"], max_uses=5)
        snapshot_mod.store(conn, link.link_uid, snap)
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO share_link_members
                             (link_uid, member_uid, archive_path, version_name, size_bytes)
                           VALUES (%s,%s,%s,%s,%s)""",
                        (link.link_uid, str(uuid.uuid4()), "gone.txt", "", 123))
        conn.commit()

        session = sessions.open_session(
            conn, cfg, link_uid=link.link_uid, verified_email="r@example.com",
            tenant=TENANT, roles=roles)

        assert session.members_omitted == 1
        assert "gone.txt" not in [m.archive_path for m in session.members]
        assert session.members_served == len([m for m in snap.members if not m.is_dir])
        # The frozen length reflects what will actually be served, so the
        # Content-Length stays honest.
        assert session.archive_bytes == archive_length(session.members)
    finally:
        conn.close()


def test_check_permission_alone_fails_open_on_a_missing_uid(cfg, roles):
    """Regression guard for the platform-wide fail-open this milestone found.

    `CheckPermission` answers "do the ACL rules forbid this?", and read-by-default
    (`default_read_ = true`) means a uid with no rules — including one that does
    not exist — takes the default and comes back permitted. Every access
    decision must therefore pair it with an existence check, which is what
    `can_reach` is for.

    If a core change ever makes `check_permission` false for a missing uid, this
    test fails loudly. That is the intent: the change would be welcome, but it
    should be noticed rather than silently relied upon.
    """
    ghost = str(uuid.uuid4())
    with core_client.for_creator(cfg, created_by=USER, roles=roles,
                                 tenant=TENANT) as core:
        assert core.check_permission(ghost, "READ") is True, (
            "core behaviour changed — re-read the fail-open note in can_reach()")
        assert core.exists(ghost) is False
        assert core.can_reach(ghost, "READ") is False
