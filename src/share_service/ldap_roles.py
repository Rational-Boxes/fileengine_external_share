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

"""Creator role resolution for delegated calls (spec §6.3).

**This module is the only way roles may reach a delegated core call.** If a
second path appears, that is the bug.

Two things make this different from every other service's LDAP helper:

1. **It resolves an absent user.** At redemption the creator is not present and
   supplies no credentials, so roles come from a service-bind lookup of their
   `groupOfNames` memberships — never from a session.

2. **It strips the admin roles rather than deriving them.** The equivalent
   helper in folder_actions (`ldap_auth.py:121-122`) does the opposite::

       if "administrators" in roles and "system_admin" not in roles:
           roles.append("system_admin")

   That is right for an ordinary door and catastrophic here. The core trusts
   the roles it is handed and `system_admin` bypasses every ACL check
   (`acl_manager.cpp:214-220`), so a link minted by an administrator would
   redeem against the bypass instead of against real ACLs — an unauthenticated
   URL with admin reach. Since R13 moved this out of the core there is no
   second line of defence behind this filter.

LDAP being unreachable **denies**; it never degrades to "no roles". An empty
role list is a legitimate answer that silently strips access inside a gated
section, so it must stay distinguishable from a failure.
"""
from __future__ import annotations

import logging
from typing import List

from ldap3 import ALL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

from .config import Config

log = logging.getLogger("share_service.ldap_roles")


class LdapUnavailable(RuntimeError):
    """The directory could not be reached or bound. Callers must deny."""


class UnknownUser(LookupError):
    """No such user in the directory — a creator who no longer exists."""


def _targets(cfg: Config) -> list[str]:
    if cfg.ldap_replica_enabled:
        return [cfg.ldap_uri, cfg.ldap_uri_replica]
    return [cfg.ldap_uri]


def _resolve_against(uri: str, cfg: Config, username: str) -> List[str]:
    server = Server(uri, get_info=ALL)
    try:
        svc = Connection(server, cfg.ldap_bind_dn, cfg.ldap_bind_password, auto_bind=True)
    except LDAPException as e:
        raise LdapUnavailable(f"{uri}: {e}") from e

    try:
        # Match uid OR mail: the platform hands services an EMAIL as their
        # identity (FILEENGINE_*_USER all come from fileengine_ldap_admin_email),
        # so a uid-only filter matches nothing and the caller sees a flat 401
        # indistinguishable from a wrong password.
        svc.search(cfg.ldap_user_base, f"(|(uid={username})(mail={username}))",
                   search_scope=SUBTREE, attributes=["cn"])
        if not svc.entries:
            raise UnknownUser(username)
        user_dn = svc.entries[0].entry_dn

        roles: List[str] = []
        svc.search(cfg.ldap_tenant_base,
                   f"(&(objectClass=groupOfNames)(member={user_dn}))",
                   search_scope=SUBTREE, attributes=["cn"])
        for entry in svc.entries:
            cn = str(entry.cn)
            if cn and cn not in roles:
                roles.append(cn)
        return roles
    finally:
        try:
            svc.unbind()
        except LDAPException:
            pass


def resolve_raw_roles(cfg: Config, username: str) -> List[str]:
    """Every group the user belongs to, verbatim — including the admin groups.

    Used for the *creation gate* (spec §8.1), which asks whether the caller is in
    the `share_external` group. Never pass this to a delegated call; use
    :func:`resolve_share_roles`.
    """
    last: Exception | None = None
    for uri in _targets(cfg):
        try:
            return _resolve_against(uri, cfg, username)
        except LdapUnavailable as e:
            last = e
            continue
    raise LdapUnavailable(str(last) if last else "no LDAP target configured")


def strip_admin_roles(cfg: Config, roles: List[str]) -> List[str]:
    """Remove every role that would trigger the core's ACL bypass (spec §6.3)."""
    banned = {r.lower() for r in cfg.admin_roles}
    return [r for r in roles if r.lower() not in banned]


def resolve_share_roles(cfg: Config, username: str) -> List[str]:
    """The roles a delegated call may carry for ``username``.

    Live from LDAP (never snapshotted, so removing a departed employee from a
    group kills their links on the next redemption) and admin-stripped.

    Raises :class:`LdapUnavailable` or :class:`UnknownUser` — both of which the
    caller must treat as a denial, never as "no roles".
    """
    roles = strip_admin_roles(cfg, resolve_raw_roles(cfg, username))
    log.debug("resolved %d share roles for %s", len(roles), username)
    return roles


def in_share_group(cfg: Config, username: str) -> bool:
    """The per-user half of the creation gate (spec §8.1): membership of the
    `share_external` group. Asked of the *caller*, who is present and
    authenticated — not of an absent creator.

    Administrators pass without being in the group: an administrator is expected
    to have every feature available, and having to add oneself to a group to see
    a tab is exactly the kind of invisible gate that reads as a broken build.

    **This is a policy gate, not a security one, and the distinction is the
    whole reason admitting admins here is safe.** What stops an admin's link
    becoming admin reach is `resolve_share_roles`, which STRIPS admin roles from
    the identity used at redemption (spec §4.2) — and that stripping is applied
    at the redemption end, independently of who was allowed to mint. So an
    admin's link redeems with their ORDINARY roles, exactly like anyone else's.

    The visible consequence, which is correct and worth knowing: an admin who
    can reach a resource *only* through the admin bypass will have the link
    refused at creation by the pre-flight, because the stripped identity cannot
    read it. That is the design working, not a bug — see `creator_message`.
    """
    roles = {r.lower() for r in resolve_raw_roles(cfg, username)}
    if roles & {r.lower() for r in cfg.admin_roles}:
        return True
    return cfg.ldap_group.lower() in roles
