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

"""Which origin a minted link points at (spec §8.3).

A share URL's origin is a property of **the tenant the link is minted in**, not
of the origin the creating request happened to arrive on. Those are not the same
thing: the SPA switches tenant by sending an ``X-Tenant`` header and does NOT
navigate while doing it (``frontend/src/stores/auth.ts``, ``switchTenant``), and
off a tenant host it pins ``default`` outright. So a creator working in tenant
``acme`` can be doing it from a browser still sitting on the default tenant's
subdomain — and building the URL from ``request.base_url`` then hands out a link
on the wrong tenant's origin.

That failure is quiet, which is why it survived: the public route resolves a
link's tenant from the cross-tenant directory rather than from the host
(:mod:`share_service.public`), so a wrong-origin link still *redeems*. It just
sends the recipient to another tenant's front door to do it, which is exactly
the boundary the rest of this service is careful about.

The origin is resolved here, in one place, in this order:

1. ``SHARE_PUBLIC_BASE_URL`` carrying a ``{tenant}`` placeholder — the explicit
   and fully general answer (``https://{tenant}.example.com``, or
   ``https://dl.{tenant}.example.com`` for the §8.3 download-host split).
2. ``SHARE_PUBLIC_BASE_URL`` without one — a single fixed origin for the whole
   deployment. Still honoured unchanged: it is the §8.3 escape hatch, and a
   single-tenant deployment is entitled to it.
3. ``SHARE_TENANT_BASE_DOMAIN`` (or the stack-wide ``BASE_DOMAIN``) — compose
   ``<tenant>.<base domain>``, keeping this request's scheme and port.
4. Nothing configured: this request's own origin, as before. It is the only
   branch that can still name the wrong tenant, so it says so in the log
   instead of doing it quietly.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger("share_service.urls")

# A tenant becomes a DNS label when it is spliced into a hostname. Tenant names
# arrive on the X-Tenant header and are never shape-checked (`auth.get_caller`
# takes the header as given), so anything that is not a label is refused a
# composed origin rather than being pasted into one.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

_PLACEHOLDER = "{tenant}"


def _request_origin(request: Any) -> str:
    """Scheme + authority as the OUTSIDE world sees them.

    ``request.base_url`` would serve for the host but not for the scheme: nginx
    terminates TLS and forwards over plain http, and uvicorn only trusts
    ``X-Forwarded-Proto`` from ``forwarded_allow_ips`` — 127.0.0.1 by default,
    which a proxy on a container network is not. Left to itself the service
    mints ``http://`` links for an ``https://`` deployment.
    """
    host = request.headers.get("host") or request.url.netloc
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    return f"{proto or request.url.scheme}://{host}"


def _port_of(authority: str) -> str:
    """``":8101"`` for an authority that carries a port, else ``""``.

    Split from the right and digit-checked so an IPv6 literal (``[::1]``, full
    of colons and ending in ``]``) is not mistaken for a host:port pair.
    """
    _, sep, tail = authority.rpartition(":")
    return f":{tail}" if sep and tail.isdigit() else ""


def tenant_origin(cfg: Any, request: Any, tenant: str) -> str:
    """The origin share links for ``tenant`` are handed out on, without a
    trailing slash."""
    fallback = _request_origin(request).rstrip("/")
    configured = (cfg.public_base_url or "").strip().rstrip("/")
    base_domain = (getattr(cfg, "tenant_base_domain", "") or "").strip().strip(".")

    label = (tenant or "").strip().lower()
    if not _LABEL.match(label):
        if _PLACEHOLDER in configured or base_domain:
            log.warning("tenant %r is not a hostname label, so its origin cannot "
                        "be composed; the link falls back to %s", tenant, fallback)
        label = ""

    if _PLACEHOLDER in configured:
        return configured.replace(_PLACEHOLDER, label) if label else fallback

    if configured:
        # One fixed origin for every tenant, chosen deliberately (§8.3).
        return configured

    if base_domain and label:
        scheme, _, authority = fallback.partition("://")
        return f"{scheme}://{label}.{base_domain}{_port_of(authority)}"

    if label:
        host = fallback.partition("://")[2].partition(":")[0]
        if host.partition(".")[0].lower() != label:
            log.warning(
                "minting a share link for tenant %r on %s, which is not that "
                "tenant's origin: set SHARE_TENANT_BASE_DOMAIN, or put a "
                "{tenant} placeholder in SHARE_PUBLIC_BASE_URL", tenant, fallback)
    return fallback
