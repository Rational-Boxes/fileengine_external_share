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

"""Role resolution against a real directory (development plan §6, tests 1 & 4).

The unit tests prove the filter is correct on a list. These prove it is correct
on what LDAP actually returns — which is the part that matters, since the
failure mode is an admin role arriving from a source the unit tests never see.

The dev fixture user is deliberately a member of BOTH ``administrators`` and
``share_external``, so a run that fails to strip is caught here rather than in
production.

Requires the dev OpenLDAP with the ``share_external`` group seeded
(``docker_unified/init/ldap-seed.sh``).
"""
from __future__ import annotations

import pytest

from share_service.config import Config
from share_service import ldap_roles as lr

pytestmark = pytest.mark.live

USER = "testuser@rationalboxes.com"
ADMIN_ROLES = {"system_admin", "tenant_admin", "administrators"}


@pytest.fixture
def cfg() -> Config:
    return Config()


def test_fixture_user_really_is_an_admin(cfg):
    """Guards the guard: if the fixture stops being an administrator, the
    stripping test below would pass for the wrong reason."""
    raw = {r.lower() for r in lr.resolve_raw_roles(cfg, USER)}
    assert "administrators" in raw, (
        "dev fixture no longer has an admin user — the stripping test below "
        "would then prove nothing")


def test_no_admin_role_survives_into_a_delegated_call(cfg):
    roles = lr.resolve_share_roles(cfg, USER)
    leaked = ADMIN_ROLES & {r.lower() for r in roles}
    assert not leaked, f"admin roles reached a delegated call: {leaked}"


def test_ordinary_roles_do_survive(cfg):
    """Stripping must not be over-broad: a link inside a gated section depends
    on the creator's ordinary roles reaching the core (spec §6.3, R5)."""
    roles = {r.lower() for r in lr.resolve_share_roles(cfg, USER)}
    assert "users" in roles
    assert "share_external" in roles


def test_share_group_membership_is_visible(cfg):
    """The per-user half of the creation gate (spec §8.1)."""
    assert lr.in_share_group(cfg, USER) is True


def test_unknown_user_denies(cfg):
    with pytest.raises(lr.UnknownUser):
        lr.resolve_share_roles(cfg, "definitely-not-a-user@example.invalid")


def test_unreachable_ldap_denies_rather_than_returning_no_roles(cfg):
    """The distinction that matters: an empty role list is a legitimate answer
    that silently strips access inside a gated section, so a directory failure
    must not be able to produce one."""
    broken = Config()
    broken.ldap_uri = "ldap://127.0.0.1:1"
    broken.ldap_replica_enabled = False
    with pytest.raises(lr.LdapUnavailable):
        lr.resolve_share_roles(broken, USER)
