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

"""Caller identity for the owner-side routes (development plan step 4).

The SPA authenticates against ``http_bridge``, which mints an HS256 bearer token
signed with the shared ``FILEENGINE_JWT_SECRET``. This service verifies that
signature locally — no introspection round-trip — exactly as the other feature
services do.

**This is the *caller*, not the delegated identity.** The caller's roles gate
what they may do here (spec §8.1); the identity that reaches the core is always
the link's *creator*, resolved separately and admin-stripped
(:mod:`share_service.ldap_roles`). Keeping the two apart in the type system is
deliberate: they are the same value only at creation time, and conflating them
is how an admin's session roles would end up on a delegated call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from .config import Config
from .jwt_verify import identity_from_claims, verify_hs256


@dataclass
class Caller:
    """An authenticated SPA user acting on their own links."""
    user: str
    tenant: str
    roles: List[str] = field(default_factory=list)
    source_addr: str = ""

    def has_role(self, role: str) -> bool:
        return any(r.lower() == role.lower() for r in self.roles)


def client_addr(request: Request) -> str:
    """The caller's IP, honouring one forwarded hop.

    nginx sits in front of this service, so the socket peer is the proxy. The
    left-most X-Forwarded-For entry is the client. This is recorded in audit,
    not used for any authorization decision.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def get_caller(request: Request,
               authorization: Optional[str] = Header(default=None),
               x_tenant: Optional[str] = Header(default=None)) -> Caller:
    """FastAPI dependency: the verified caller, or 401.

    Mounted on the owner-side router only. The public router (M4) must never
    depend on this — a redemption is not, and must never be, attributable to a
    passing authenticated browser (spec §7).
    """
    config: Config = request.app.state.config

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required",
                            headers={"WWW-Authenticate": "Bearer"})
    token = authorization.split(None, 1)[1].strip()

    claims = verify_hs256(token, config.jwt_secret)
    if not claims:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})

    got = identity_from_claims(claims, x_tenant or "")
    if not got:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token carries no subject",
                            headers={"WWW-Authenticate": "Bearer"})
    user, roles = got
    tenant = x_tenant or claims.get("tenant") or "default"
    return Caller(user=user, tenant=tenant, roles=list(roles),
                  source_addr=client_addr(request))


CallerDep = Depends(get_caller)
