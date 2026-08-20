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


@dataclass
class PreflightResult:
    ok: bool
    reason: str = REASON_OK
    roles: Optional[List[str]] = None
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


def check(config: Config, *, created_by: str, tenant: str, resource_uid: str,
          permission: str = core_client.READ,
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
    except Exception as e:  # noqa: BLE001 - a core failure must deny, not leak
        log.warning("preflight denied: core check failed for %s on %s: %s",
                    created_by, resource_uid, e)
        return PreflightResult(False, REASON_GONE, roles=roles, detail=str(e))

    return PreflightResult(True, REASON_OK, roles=roles)


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
    }.get(result.reason, "")
