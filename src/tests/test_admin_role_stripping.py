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

"""The admin-role stripping invariant (development plan §4.2, test 1).

This is the invariant with no backstop. The core trusts the roles it is handed
and ``system_admin`` bypasses every ACL check, so if an admin role reaches a
delegated call the resulting link redeems against the bypass instead of against
real ACLs — an unauthenticated URL with admin reach. Since sharing moved out of
the core (spec §13-R13) nothing behind this filter would catch it.

Note the sibling helper these tests exist to guard against: folder_actions'
``ldap_auth.py`` *appends* ``system_admin`` when the user is in
``administrators``. Copying that file without noticing is the specific mistake
this module is here to fail on.
"""
from __future__ import annotations

import pytest

from share_service.config import Config
from share_service.core_client import DelegatedCore
from share_service.ldap_roles import strip_admin_roles


@pytest.fixture
def cfg() -> Config:
    return Config()


def test_strips_every_default_admin_role(cfg):
    roles = ["users", "contributors", "system_admin", "tenant_admin", "administrators"]
    assert strip_admin_roles(cfg, roles) == ["users", "contributors"]


def test_strips_case_insensitively(cfg):
    # LDAP cn values are not case-normalized, and a bypass that depends on
    # capitalization is not a bypass anyone would find in review.
    assert strip_admin_roles(cfg, ["System_Admin", "ADMINISTRATORS", "users"]) == ["users"]


def test_keeps_ordinary_roles_untouched(cfg):
    roles = ["users", "contributors", "share_external", "project-acme"]
    assert strip_admin_roles(cfg, roles) == roles


def test_empty_and_all_admin_cases(cfg):
    assert strip_admin_roles(cfg, []) == []
    assert strip_admin_roles(cfg, ["system_admin"]) == []


def test_admin_role_set_is_configurable(cfg, monkeypatch):
    monkeypatch.setenv("SHARE_ADMIN_ROLES", "root,superuser")
    custom = Config()
    assert strip_admin_roles(custom, ["root", "superuser", "users"]) == ["users"]


def test_never_derives_system_admin_from_administrators(cfg):
    """The exact inversion of folder_actions/ldap_auth.py:121-122.

    That helper adds ``system_admin`` when it sees ``administrators``; here the
    presence of ``administrators`` must *remove* both, never add anything.
    """
    out = strip_admin_roles(cfg, ["administrators", "users"])
    assert "system_admin" not in out
    assert "administrators" not in out
    assert out == ["users"]


def test_delegated_core_carries_only_the_roles_it_is_given(cfg):
    """The client must not re-resolve or augment roles.

    Stripping lives in exactly one place (ldap_roles). If the client resolved
    roles itself there would be a second path, and the second path is where the
    bug goes.
    """
    core = DelegatedCore(cfg, user="alice", roles=["users"], tenant="default")
    assert core.roles == ["users"]
    assert core.user == "alice"


def test_delegated_core_refuses_an_empty_identity(cfg):
    """No anonymous or synthetic delegation — the identity is the whole
    mechanism (spec §4.1)."""
    with pytest.raises(ValueError):
        DelegatedCore(cfg, user="", roles=[], tenant="default")


def test_redemption_uid_travels_as_a_claim(cfg):
    """Correlation with the core's own audit events (spec §12): the core
    records the operation against the creator, so this claim is what joins its
    event to ours. Absent when there is no redemption in flight."""
    with_uid = DelegatedCore(cfg, user="alice", roles=[], tenant="default",
                             redemption_uid="r-123")
    assert with_uid._claims() == ["share.redemption_uid=r-123"]
    assert DelegatedCore(cfg, user="alice", roles=[], tenant="default")._claims() == []


# --- administrators may MINT, but never REDEEM with admin reach -----------

def test_an_administrator_passes_the_share_gate_without_the_group(cfg, monkeypatch):
    """Administrators get every feature; needing to add yourself to a group to
    see a tab is an invisible gate that reads as a broken build."""
    from share_service import ldap_roles
    monkeypatch.setattr(ldap_roles, "resolve_raw_roles",
                        lambda c, u: ["users", "administrators"])
    assert ldap_roles.in_share_group(cfg, "an-admin") is True


def test_an_ordinary_user_still_needs_the_group(cfg, monkeypatch):
    """Guard on the guard: admitting admins must not open the gate generally."""
    from share_service import ldap_roles
    monkeypatch.setattr(ldap_roles, "resolve_raw_roles",
                        lambda c, u: ["users", "engineering"])
    assert ldap_roles.in_share_group(cfg, "someone") is False


def test_the_group_still_admits_a_non_admin(cfg, monkeypatch):
    from share_service import ldap_roles
    monkeypatch.setattr(ldap_roles, "resolve_raw_roles",
                        lambda c, u: ["users", "share_external"])
    assert ldap_roles.in_share_group(cfg, "someone") is True


def test_admitting_admins_to_the_gate_does_not_leak_admin_roles_downstream(cfg, monkeypatch):
    """THE property that makes the above safe.

    Whether an admin may MINT is a policy question. What stops their link
    carrying admin reach is the stripping applied at REDEMPTION — a separate
    mechanism, applied at the other end. If these two ever became one decision,
    admitting admins to the gate would hand admin reach to every recipient.
    """
    from share_service import ldap_roles
    monkeypatch.setattr(ldap_roles, "resolve_raw_roles",
                        lambda c, u: ["users", "administrators", "tenant_admin",
                                      "engineering"])
    assert ldap_roles.in_share_group(cfg, "an-admin") is True
    delegated = ldap_roles.resolve_share_roles(cfg, "an-admin")
    assert "administrators" not in delegated
    assert "tenant_admin" not in delegated
    assert "system_admin" not in delegated
    assert "engineering" in delegated, "ordinary roles must survive"
