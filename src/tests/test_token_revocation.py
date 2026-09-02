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

"""The revoked-token denylist reader (copied verbatim across services).

What is worth testing here is not that redis-py works, but the two decisions
this file makes on its own: that an unreachable denylist REFUSES rather than
waves the token through, and that the cache never turns "we could not ask" into
a lasting "yes". Both are easy to get quietly backwards, and both would fail
silently — the service would keep serving, exactly as it did before the fix.
"""
import pytest

from share_service.token_revocation import RevocationChecker


class FakeDenylist:
    """A stand-in whose contents and reachability the test controls."""

    def __init__(self):
        self.revoked = set()
        self.reachable = True
        self.lookups = 0

    def __call__(self, jti):
        self.lookups += 1
        if not self.reachable:
            return None  # could not be established
        return jti in self.revoked


def make(fake, **kw):
    kw.setdefault("cache_ttl", 0)  # ask every time, so tests are not clock-bound
    return RevocationChecker(lookup=fake, **kw)


def test_permits_a_token_nobody_signed_out():
    fake = FakeDenylist()
    assert make(fake).permits("jti-live") is True


def test_refuses_a_token_the_bridge_revoked():
    # The whole point. Before this, the service kept honouring it because the
    # signature and exp still checked out.
    fake = FakeDenylist()
    fake.revoked.add("jti-1")
    assert make(fake).permits("jti-1") is False


def test_revocation_is_per_token():
    fake = FakeDenylist()
    fake.revoked.add("jti-1")
    c = make(fake)
    assert c.permits("jti-1") is False
    assert c.permits("jti-2") is True


def test_a_token_with_no_jti_is_permitted():
    # Not every bridge credential carries one; refusing those would break them,
    # and they cannot be revoked by jti in any case.
    fake = FakeDenylist()
    c = make(fake)
    assert c.permits("") is True
    assert fake.lookups == 0


def test_refuses_when_the_denylist_cannot_be_reached():
    # FAIL CLOSED. A verdict we could not obtain is not permission. Failing open
    # here would restore the original bug and do it invisibly.
    fake = FakeDenylist()
    fake.reachable = False
    assert make(fake).permits("jti-1") is False


def test_fail_open_honours_an_unknown_verdict_when_asked_to():
    fake = FakeDenylist()
    fake.reachable = False
    assert make(fake, fail_open=True).permits("jti-1") is True


def test_disabled_means_disabled():
    fake = FakeDenylist()
    c = make(fake, enabled=False)
    assert c.permits("jti-1") is True
    assert fake.lookups == 0


def test_caches_a_verdict_instead_of_asking_every_request():
    # Without this every authenticated request would make a Redis round-trip.
    fake = FakeDenylist()
    c = make(fake, cache_ttl=60)
    assert c.permits("jti-1") is True
    assert c.permits("jti-1") is True
    assert c.permits("jti-1") is True
    assert fake.lookups == 1


def test_zero_cache_ttl_asks_every_time():
    fake = FakeDenylist()
    c = make(fake, cache_ttl=0)
    c.permits("jti-1")
    c.permits("jti-1")
    assert fake.lookups == 2


def test_never_caches_an_unknown():
    # "Could not ask" must not become a cached answer: it would stretch one
    # unreachable moment across the whole window, and under fail_open it would
    # keep honouring a token Redis could by then have reported as revoked.
    fake = FakeDenylist()
    c = make(fake, cache_ttl=300)
    fake.reachable = False
    assert c.permits("jti-1") is False
    assert fake.lookups == 1

    fake.reachable = True
    fake.revoked.add("jti-1")
    assert c.permits("jti-1") is False
    assert fake.lookups == 2  # asked again rather than reusing the non-answer


def test_a_cached_allow_does_expire(monkeypatch):
    import share_service.token_revocation as tr

    fake = FakeDenylist()
    c = make(fake, cache_ttl=5)
    now = [1000.0]
    monkeypatch.setattr(tr.time, "time", lambda: now[0])

    assert c.permits("jti-1") is True
    assert fake.lookups == 1
    now[0] += 6                      # past the window
    fake.revoked.add("jti-1")        # meanwhile the bridge revoked it
    assert c.permits("jti-1") is False
    assert fake.lookups == 2


def test_from_env_defaults_to_enabled_and_fail_closed(monkeypatch):
    # The defaults are the security posture. A deployment that sets nothing must
    # get revocation ON and unknown-means-refused.
    for k in ("AUTH_REVOCATION_ENABLED", "AUTH_REVOCATION_FAIL_OPEN",
              "AUTH_REVOCATION_CACHE_TTL_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    c = RevocationChecker.from_env(lookup=FakeDenylist())
    assert c.enabled is True
    assert c.fail_open is False
    assert c.cache_ttl == 5


@pytest.mark.parametrize("raw,expected", [("true", True), ("1", True), ("on", True),
                                          ("false", False), ("0", False), ("", True)])
def test_from_env_reads_the_enable_flag(monkeypatch, raw, expected):
    # "" is not "off" — an empty variable is an unset one, and unsetting must not
    # silently disable revocation.
    monkeypatch.setenv("AUTH_REVOCATION_ENABLED", raw)
    assert RevocationChecker.from_env(lookup=FakeDenylist()).enabled is expected
