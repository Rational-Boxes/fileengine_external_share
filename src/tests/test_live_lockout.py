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

"""Rung 2 of the abuse escalation (spec §8.4) — the LINK's own budget.

Rung 1 caps attempts per address and lives in `ldap_manager`, which owns the
code. It is sidestepped by simply varying the address, so the link — the thing
actually under attack — carries its own rolling count. These tests are about
that count: how it accumulates, how it ages out, what clears it, and that a
lockout expires rather than revoking.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest

from share_service import db, links
from share_service.config import Config

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
TENANT = "default"


@pytest.fixture
def cfg() -> Config:
    c = Config()
    if not c.pg_host:
        pytest.skip("no Postgres configured")
    c.enabled = True
    return c


@pytest.fixture
def conn(cfg):
    c = db.connect_for_tenant(cfg, TENANT, provision=True)
    yield c
    c.close()


@pytest.fixture
def link(cfg, conn):
    made, _secret = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=links.clamp_expiry(cfg, None, 1),
        recipients=["someone@example.com"], max_uses=5)
    return made


def _fail(conn, link_uid, email, *, address_locked=False, threshold=15,
          distinct=3, window=60, lock=15):
    return links.record_failed_verification(
        conn, link_uid, email, address_locked=address_locked,
        threshold=threshold, distinct_threshold=distinct,
        window_minutes=window, lock_minutes=lock)


# --- accumulating ---------------------------------------------------------

def test_failures_accumulate_against_the_link_not_the_address(conn, link):
    """The whole reason rung 2 exists: a different address every time walks
    straight past rung 1, but the link's count keeps rising."""
    for i in range(5):
        got = _fail(conn, link.link_uid, f"attacker{i}@example.com")
    assert got["attempts"] == 5
    assert got["locked"] is False


def test_enough_failures_lock_the_link(conn, link):
    for i in range(4):
        got = _fail(conn, link.link_uid, f"a{i}@example.com", threshold=4)
    assert got["locked"] is True
    assert links.get(conn, link.link_uid).status() == "blocked"


def test_distinct_addresses_hitting_rung_one_lock_it_sooner(conn, link):
    """Three addresses each exhausting their own budget is the spread pattern a
    per-address counter cannot see — and it should trip well before the raw
    failure threshold does."""
    for i in range(3):
        got = _fail(conn, link.link_uid, f"spread{i}@example.com",
                    address_locked=True, threshold=999, distinct=3)
    assert got["distinct"] == 3
    assert got["locked"] is True


def test_one_address_failing_repeatedly_is_not_three_addresses(conn, link):
    """Guard on the guard: the distinct count must be DISTINCT, or a single
    persistent typo would trip the spread rule."""
    for _ in range(5):
        got = _fail(conn, link.link_uid, "same@example.com",
                    address_locked=True, threshold=999, distinct=3)
    assert got["distinct"] == 1
    assert got["locked"] is False


def test_addresses_are_not_stored_in_the_clear(conn, link):
    """Most of these belong to people who are not recipients and never consented
    to appear in this tenant's data. Distinctness is all that is needed."""
    _fail(conn, link.link_uid, "private@example.com", address_locked=True)
    with conn.cursor() as cur:
        cur.execute("SELECT failed_addresses FROM share_links WHERE link_uid = %s",
                    (link.link_uid,))
        stored = cur.fetchone()[0]
    assert stored
    assert "private@example.com" not in stored
    assert not any("@" in m for m in stored)


def test_the_same_address_hashes_differently_per_link(cfg, conn, link):
    """Salted with the link uid, so the column cannot be correlated across
    links to reconstruct who was probing what."""
    other, _ = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=links.clamp_expiry(cfg, None, 1),
        recipients=["x@example.com"], max_uses=1)
    assert links.address_marker(link.link_uid, "bob@example.com") \
        != links.address_marker(other.link_uid, "bob@example.com")


# --- ageing out and clearing ---------------------------------------------

def test_counts_older_than_the_window_are_discarded(conn, link):
    """A ROLLING count, not a lifetime total. Otherwise ordinary typos
    accumulate over months into a permanent lockout of a link nobody attacked."""
    for i in range(3):
        _fail(conn, link.link_uid, f"old{i}@example.com", threshold=5)
    # Age the window out.
    with conn.cursor() as cur:
        cur.execute("""UPDATE share_links
                          SET failed_window_start = now() - interval '2 hours'
                        WHERE link_uid = %s""", (link.link_uid,))
    conn.commit()

    got = _fail(conn, link.link_uid, "new@example.com", threshold=5, window=60)
    assert got["attempts"] == 1, "the stale window must restart, not continue"
    assert got["locked"] is False


def test_a_verified_redemption_clears_the_count(conn, link):
    """Someone got in legitimately, so whatever had accumulated was noise."""
    for i in range(3):
        _fail(conn, link.link_uid, f"t{i}@example.com", threshold=5)
    links.clear_failed_verifications(conn, link.link_uid)
    got = _fail(conn, link.link_uid, "after@example.com", threshold=5)
    assert got["attempts"] == 1
    assert got["distinct"] == 0


# --- the lockout itself ---------------------------------------------------

def test_a_lockout_expires_rather_than_revoking(conn, link):
    """Revoking would punish the CREATOR permanently for someone else's
    behaviour — and the URL cannot be re-issued to people already holding it."""
    for i in range(3):
        _fail(conn, link.link_uid, f"b{i}@example.com", threshold=3, lock=15)
    row = links.get(conn, link.link_uid)
    assert row.status() == "blocked"
    assert row.revoked_at is None, "a lockout must never revoke"
    assert row.locked_until is not None

    # Wind the clock forward past the lockout: the link is live again, untouched.
    with conn.cursor() as cur:
        cur.execute("""UPDATE share_links SET locked_until = now() - interval '1 minute'
                        WHERE link_uid = %s""", (link.link_uid,))
    conn.commit()
    assert links.get(conn, link.link_uid).status() == "active"


def test_a_locked_link_refuses_every_redemption_path(cfg, conn, link):
    """The lock is enforced where a USE IS CONSUMED, not merely displayed.

    A badge that says "blocked" while the consume path still serves bytes would
    be the worst of both: visible reassurance and no protection.
    """
    from share_service import sessions
    for i in range(3):
        _fail(conn, link.link_uid, f"c{i}@example.com", threshold=3)
    with pytest.raises(sessions.SessionRefused):
        sessions.open_session(conn, cfg, link_uid=link.link_uid,
                              verified_email="someone@example.com",
                              tenant=TENANT, roles=["users"],
                              source_addr="203.0.113.9", user_agent="")


def test_locking_one_link_does_not_touch_another(cfg, conn, link):
    other, _ = links.create(
        conn, kind=0, resource_uid=str(uuid.uuid4()), created_by=USER,
        expires_at=links.clamp_expiry(cfg, None, 1),
        recipients=["y@example.com"], max_uses=1)
    for i in range(3):
        _fail(conn, link.link_uid, f"d{i}@example.com", threshold=3)
    assert links.get(conn, link.link_uid).status() == "blocked"
    assert links.get(conn, other.link_uid).status() == "active"
