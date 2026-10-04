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

"""Service-to-service routes (MEDIA_SHARE.md §6.2, §4.3.1).

Mounted as its OWN router, like the public one — no bearer dependency, and no
allowlisted exception inside the owner router. Every route requires the shared
internal secret; an unset secret disables the router rather than opening it,
and the edge must 404 ``/share/v1/internal/`` (as it does CSAI's).

What crosses here is deliberately thin: a COUNT of live media links on a file,
which is all CSAI needs to decide whether a published copy may be removed. No
link uid, creator, address or secret leaves this service this way.
"""
from __future__ import annotations

import secrets
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, status

from . import db, links
from .config import Config

router = APIRouter(prefix="/share/v1/internal")


def require_internal(cfg: Config, presented: Optional[str]) -> None:
    if not cfg.media_internal_secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if not presented or not secrets.compare_digest(presented, cfg.media_internal_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")


@router.get("/media-refs/{file_uid}")
def media_refs(file_uid: str, request: Request,
               x_internal_auth: Optional[str] = Header(default=None),
               x_tenant: Optional[str] = Header(default=None)) -> dict:
    """How many LIVE media links play this file. CSAI keeps every published copy
    while this is non-zero, and treats any failure to answer as "keep"."""
    cfg: Config = request.app.state.config
    require_internal(cfg, x_internal_auth)
    if not x_tenant:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "X-Tenant is required")
    conn = db.connect_for_tenant(cfg, x_tenant, provision=True)
    try:
        live = links.live_media_links(conn, file_uid)
    finally:
        conn.close()
    return {"file_uid": file_uid, "live_links": len(live)}
