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

"""Local HS256 JWT verification — no external dependency (copied from folder_actions,
which mirrors CSAI's; keep the three in step).

The http_bridge signs bearer session tokens as HS256 JWTs whose ``roles`` claim is
a ``{tenant: [roles]}`` map. This verifies the signature + ``exp`` locally using the
shared ``FILEENGINE_JWT_SECRET``, so the service authorizes straight from the signed
claims without an introspection round-trip.

Security: the algorithm is pinned to HS256 (``alg: none`` / RS-confusion tokens are
rejected), the signature is compared in constant time, and ``exp`` is enforced.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Optional


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def verify_hs256(token: str, secret: str, leeway: int = 0) -> Optional[dict]:
    """Decoded claims if the token is a valid, unexpired HS256 JWT signed with
    ``secret``; otherwise None."""
    if not token or not secret:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h_seg, p_seg, s_seg = parts
    try:
        header = json.loads(_b64url_decode(h_seg))
    except Exception:
        return None
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None

    expected = hmac.new(secret.encode("utf-8"), f"{h_seg}.{p_seg}".encode("ascii"),
                        hashlib.sha256).digest()
    try:
        signature = _b64url_decode(s_seg)
    except Exception:
        return None
    if not hmac.compare_digest(expected, signature):
        return None

    try:
        claims = json.loads(_b64url_decode(p_seg))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    if exp is not None:
        try:
            if time.time() > float(exp) + leeway:
                return None
        except (TypeError, ValueError):
            return None
    return claims


def identity_from_claims(claims: dict, tenant: str) -> Optional[tuple[str, list[str]]]:
    """Extract (user, roles) from verified claims, scoping roles to ``tenant``
    (falling back to the token's default ``tenant`` claim). None if no subject."""
    user = claims.get("sub")
    if not user:
        return None
    active = tenant or claims.get("tenant") or "default"
    roles_map = claims.get("roles")
    roles: list[str] = []
    if isinstance(roles_map, dict):
        roles = list(roles_map.get(active) or [])
    return user, roles
