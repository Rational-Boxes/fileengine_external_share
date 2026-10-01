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

"""Which tenant states admit a login, for this door (§3.4c) — share_service, copied from the MCP door.

A MIRROR, NOT A COPY, and the difference is the point. The two C++ doors share
`tenant_state_policy.h` verbatim — §3.4c asks for "shared code rather than N
implementations wherever the doors' languages allow it", and between
http_bridge and webdav_bridge it does. It does not reach Python, so this is the
third implementation, which is exactly the situation §3.4c warns about:

    "Adding a check to N doors is N chances to add it subtly differently, and one
    chance to forget a door entirely."

So the state names and the admit rule are pinned against the C++ header by a
test that PARSES it (`tests/test_tenant_state.py`). If a state is added or a
name changed on that side and not here, the test fails rather than this door
quietly admitting something the others refuse.
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Protocol

log = logging.getLogger("share_service.tenant_state")

# The lifecycle. Spellings must match the core's tenant_state_name() and the
# C++ doors' policy header exactly — these strings cross a wire.
REQUESTED = "requested"
AWAITING_DNS = "awaiting_dns"
PROVISIONING = "provisioning"
LIVE = "live"
SUSPENDED = "suspended"
DECOMMISSIONING = "decommissioning"
DECOMMISSIONED = "decommissioned"

KNOWN_STATES = (REQUESTED, AWAITING_DNS, PROVISIONING, LIVE, SUSPENDED,
                DECOMMISSIONING, DECOMMISSIONED)

#: How long a verdict is trusted. Asymmetric, as in the C++ doors: restoring a
#: tenant to service should not wait on a cache, while a suspension already bit
#: the moment it was read.
ADMIT_TTL_S = 60.0
REFUSE_TTL_S = 10.0


def admits(state: str) -> bool:
    """Only `live` admits.

    An allowlist of one rather than a denylist of six: a state added to the
    registry later must be REFUSED until this door learns about it, and a
    denylist would admit it by default.
    """
    return state == LIVE


def known(state: str) -> bool:
    return state in KNOWN_STATES


def refusal_reason(state: str, lookup_succeeded: bool) -> str:
    """Why, said honestly. §3.4c property 4.

    A failed lookup must NOT claim a suspension: an operator reading it needs to
    know the lookup failed, not to go hunting for a suspension that does not
    exist.
    """
    if not lookup_succeeded:
        return "tenant status could not be determined; access is refused until it can"
    if state == SUSPENDED:
        return "this tenant is suspended"
    if state == PROVISIONING:
        return "this tenant is still being provisioned"
    if state in (REQUESTED, AWAITING_DNS):
        return "this tenant is not yet provisioned"
    if state == DECOMMISSIONING:
        return "this tenant is being decommissioned"
    if state == DECOMMISSIONED:
        return "this tenant has been decommissioned"
    if not known(state):
        return "tenant status is not recognised by this build; access is refused"
    return ""


class StateSource(Protocol):
    """Reads the tenant's state. Injectable so the gate is testable without a core."""

    def tenant_state(self, tenant: str) -> dict: ...


class TenantStateGate:
    """The check, with its cache. FAILS CLOSED on everything."""

    def __init__(self, source: Optional[StateSource] = None, *, clock=time.monotonic):
        self._source = source
        self._clock = clock
        self._cache: dict[str, tuple[float, bool, str]] = {}

    def set_source(self, source: StateSource) -> None:
        self._source = source

    def admits(self, tenant: str) -> tuple[bool, str]:
        """(admits, reason). Reason is empty when it admits."""
        if not tenant:
            return False, refusal_reason("", False)

        now = self._clock()
        hit = self._cache.get(tenant)
        if hit and now < hit[0]:
            return hit[1], hit[2]

        if self._source is None:
            # NOT a silent allow. A door with no way to ask must refuse, or the
            # check is decorative on exactly the deployment that forgot to wire
            # it.
            log.error("tenant-state gate has no source configured — refusing %s", tenant)
            return False, refusal_reason("", False)

        state, ok = "", False
        try:
            info = self._source.tenant_state(tenant)
            if info.get("found"):
                state, ok = str(info.get("state") or ""), True
        except Exception as e:  # noqa: BLE001 — any failure is a refusal
            log.warning("tenant-state lookup failed for %s: %s", tenant, e)

        verdict = ok and known(state) and admits(state)
        reason = "" if verdict else refusal_reason(state, ok)
        if not verdict:
            log.warning("tenant-state gate REFUSED %s: %s", tenant, reason)
        self._cache[tenant] = (now + (ADMIT_TTL_S if verdict else REFUSE_TTL_S),
                              verdict, reason)
        return verdict, reason
