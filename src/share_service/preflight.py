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

"""The authority re-check, run at creation and at redemption (spec §6.3).

**One function, two callers.** The pre-flight at creation runs the *exact*
check a redemption will run — same creator, same LDAP-resolved roles, same
admin stripping, no claims, no bypass — so a link that would be born dead is
refused with a reason instead of 404-ing a recipient weeks later. Sharing the
code is not a tidiness preference: two implementations that drift is precisely
how "it worked when I made it" becomes a support case nobody can reproduce.

In M0 only the creation caller exists. Redemption arrives in M4 and must call
this, not a copy of it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from .config import Config
from . import core_client, ldap_roles

log = logging.getLogger("share_service.preflight")

# Why a link is not (or would not be) redeemable. These strings reach the
# creator, never an outside caller — an outside caller gets a uniform 404
# (spec §8.5).
REASON_OK = "ok"
REASON_NO_ACCESS = "creator_no_longer_has_access"
REASON_GONE = "resource_gone"
REASON_LDAP = "directory_unavailable"
REASON_UNKNOWN_CREATOR = "creator_not_in_directory"
REASON_VERSION_GONE = "pinned_version_culled"


@dataclass
class PreflightResult:
    ok: bool
    reason: str = REASON_OK
    roles: Optional[List[str]] = None
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


def check(config: Config, *, created_by: str, tenant: str, resource_uid: str,
          permission: str = core_client.READ, pinned_version: str = "",
          source_addr: str = "") -> PreflightResult:
    """Would a redemption of this link succeed right now?

    Resolves the creator's roles live from LDAP (admin-stripped), then asks the
    core whether that principal still holds ``permission`` on the resource.

    Every failure is a denial. In particular a directory outage denies rather
    than proceeding with an empty role list, because empty roles is a
    legitimate answer that silently strips access inside a gated section — the
    two must not be confusable.
    """
    try:
        roles = ldap_roles.resolve_share_roles(config, created_by)
    except ldap_roles.UnknownUser:
        return PreflightResult(False, REASON_UNKNOWN_CREATOR,
                               detail=f"{created_by} is not in the directory")
    except ldap_roles.LdapUnavailable as e:
        # Fail closed, consistent with every other door in the platform.
        log.warning("preflight denied: LDAP unavailable resolving %s: %s", created_by, e)
        return PreflightResult(False, REASON_LDAP, detail=str(e))

    try:
        with core_client.for_creator(config, created_by=created_by, roles=roles,
                                     tenant=tenant, source_addr=source_addr) as core:
            # Existence FIRST. Read-by-default means a missing uid passes the
            # permission check, so checking permission alone fails open and a
            # link to a deleted file would pre-flight clean (spec §6.3).
            if not core.exists(resource_uid):
                return PreflightResult(False, REASON_GONE, roles=roles,
                                       detail=f"{resource_uid} no longer exists")
            if not core.check_permission(resource_uid, permission):
                return PreflightResult(False, REASON_NO_ACCESS, roles=roles,
                                       detail=f"{created_by} lacks {permission} "
                                              f"on {resource_uid}")
            # A link records (entity uuid, version timestamp). If that version
            # has been culled the link is dead -- and the creator should learn
            # it from their own Share tab, not from a recipient reporting a 404
            # (spec §6.2).
            if pinned_version and not core.has_version(resource_uid, pinned_version):
                return PreflightResult(False, REASON_VERSION_GONE, roles=roles,
                                       detail=f"version {pinned_version} of "
                                              f"{resource_uid} has been culled")
    except Exception as e:  # noqa: BLE001 - a core failure must deny, not leak
        log.warning("preflight denied: core check failed for %s on %s: %s",
                    created_by, resource_uid, e)
        return PreflightResult(False, REASON_GONE, roles=roles, detail=str(e))

    return PreflightResult(True, REASON_OK, roles=roles)


def check_many(config: Config, *, created_by: str, tenant: str,
               targets, source_addr: str = "") -> dict:
    """`check` across several of one creator's links, sharing the expensive work.

    `targets` is an iterable of ``(key, resource_uid, pinned_version)``. Returns
    ``{key: PreflightResult}``.

    Same answers as calling `check` per link, but the creator's roles are
    resolved from LDAP ONCE and a single core connection serves every resource —
    otherwise a Dashboard load becomes N directory round-trips plus N gRPC
    channels for a panel that is usually all-green.

    The per-RESOURCE checks are still per resource, deliberately. The most
    common way a link dies is an ACL change on its own resource, so collapsing
    those into one answer for the whole set would miss precisely the case this
    exists to catch.
    """
    targets = list(targets)
    if not targets:
        return {}
    try:
        roles = ldap_roles.resolve_share_roles(config, created_by)
    except ldap_roles.UnknownUser:
        r = PreflightResult(False, REASON_UNKNOWN_CREATOR,
                            detail=f"{created_by} is not in the directory")
        return {k: r for k, _uid, _v in targets}
    except ldap_roles.LdapUnavailable as e:
        log.warning("preflight denied: LDAP unavailable resolving %s: %s", created_by, e)
        r = PreflightResult(False, REASON_LDAP, detail=str(e))
        return {k: r for k, _uid, _v in targets}

    out = {}
    try:
        with core_client.for_creator(config, created_by=created_by, roles=roles,
                                     tenant=tenant, source_addr=source_addr) as core:
            for key, resource_uid, pinned in targets:
                try:
                    # Existence FIRST — read-by-default means a missing uid
                    # passes the permission check (spec §6.3).
                    if not core.exists(resource_uid):
                        out[key] = PreflightResult(False, REASON_GONE, roles=roles)
                    elif not core.check_permission(resource_uid, core_client.READ):
                        out[key] = PreflightResult(False, REASON_NO_ACCESS, roles=roles)
                    elif pinned and not core.has_version(resource_uid, pinned):
                        out[key] = PreflightResult(False, REASON_VERSION_GONE, roles=roles)
                    else:
                        out[key] = PreflightResult(True, REASON_OK, roles=roles)
                except Exception as e:  # noqa: BLE001
                    # One bad resource must not blank the whole panel.
                    log.warning("preflight failed for %s on %s: %s",
                                created_by, resource_uid, e)
                    out[key] = PreflightResult(False, REASON_GONE, roles=roles)
    except Exception as e:  # noqa: BLE001 - core unreachable: deny, do not leak
        log.warning("preflight denied: core unavailable for %s: %s", created_by, e)
        r = PreflightResult(False, REASON_GONE, roles=roles, detail=str(e))
        return {k: out.get(k, r) for k, _uid, _v in targets}
    return out


def creator_message(result: PreflightResult) -> str:
    """A sentence the creator can act on. Not for outside callers."""
    return {
        REASON_NO_ACCESS: "You no longer have access to this item, so the link "
                          "would not work. Ask for access, or share something "
                          "you can still open.",
        REASON_GONE: "This item is no longer available.",
        REASON_LDAP: "The directory is unavailable, so your permissions cannot "
                     "be confirmed right now. Try again shortly.",
        REASON_UNKNOWN_CREATOR: "The link's creator is no longer in the directory.",
        REASON_VERSION_GONE: "The version this link shares has been purged, so "
                             "the link no longer works. Share the file again to "
                             "send the current version.",
    }.get(result.reason, "")
