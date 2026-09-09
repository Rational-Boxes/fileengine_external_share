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

"""`Link.is_dead` — which states a link can still be widened from.

This is the decision behind the 409 on `POST /links/{uid}/recipients`, and it is
worth its own unit test because getting it wrong is silent in both directions:
too broad and a legitimate add starts failing for a link that is merely locked
out; too narrow and the service goes back to writing `permission` audit events
for grants that give nobody anything.

No stack needed — `status()` reads the row and the clock, nothing else.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from share_service.links import Link

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


def link(**kw) -> Link:
    base = dict(
        link_uid=str(uuid.uuid4()), kind=0, resource_uid=str(uuid.uuid4()),
        created_by="creator@example.com", created_at=NOW() - timedelta(hours=1),
        expires_at=NOW() + timedelta(days=7),
    )
    base.update(kw)
    return Link(**base)


def test_a_working_link_is_not_dead():
    assert link().status() == "active"
    assert link().is_dead is False


def test_a_revoked_link_is_dead():
    # The production case: revoked, still inside its expiry window, budget
    # untouched. Nothing but `revoked_at` marks it.
    l = link(revoked_at=NOW() - timedelta(seconds=28), revoked_by="creator@example.com",
             max_uses=5, uses_consumed=0)
    assert l.status() == "revoked"
    assert l.is_dead is True


def test_an_expired_link_is_dead():
    l = link(expires_at=NOW() - timedelta(minutes=1))
    assert l.status() == "expired"
    assert l.is_dead is True


def test_an_exhausted_link_is_dead():
    l = link(max_uses=2, uses_consumed=2)
    assert l.status() == "exhausted"
    assert l.is_dead is True


def test_a_locked_out_link_is_NOT_dead():
    """The one that must stay addable.

    A lockout is the failed-code brake and it lifts on its own, so the link is a
    live grant that is merely waiting. Adding an address to it is a real grant
    that starts working when the clock does — refusing would be wrong.
    """
    l = link(locked_until=NOW() + timedelta(minutes=15))
    assert l.status() == "blocked"
    assert l.is_dead is False


def test_unlimited_uses_never_exhausts():
    # max_uses == 0 means unlimited; a link that has been used a hundred times
    # is still live. Reading 0 as "no uses left" would kill every unlimited link.
    l = link(max_uses=0, uses_consumed=100)
    assert l.status() == "active"
    assert l.is_dead is False


def test_revoked_wins_over_a_lockout():
    # status() short-circuits on revoked, so a link that was locked out and then
    # revoked must still read as dead rather than as merely blocked.
    l = link(revoked_at=NOW(), locked_until=NOW() + timedelta(minutes=15))
    assert l.status() == "revoked"
    assert l.is_dead is True
