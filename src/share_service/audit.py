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

"""Audit emission for share_service (spec §12).

Uses the shared ``AuditPublisher`` from the audit_service package, with the
sibling-checkout fallback the other services use.

**This service deviates from the platform's usual emitter convenience, on
purpose.** ``ldap_manager``'s emitter returns True when auditing is disabled so
a guarded operation "never blocks" on an unconfigured service. share_service
must not inherit that: since R13 moved sharing out of the core, the core
attributes every delegated operation to the *creator* and the audit chain is the
only place recording that an access was external (spec §4.3). So "auditing is
off" and "share links work" are not compatible states — the result would be
external downloads with no record anywhere that they were external, which is the
exact hole the fail-closed rule exists to prevent.

Therefore: **no publisher, no sharing.** :func:`available` is false, ``/readyz``
is not ready, and link creation and redemption both refuse. Audit is a hard
dependency here, like Postgres — not an optional feature.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, Optional

from .config import Config

log = logging.getLogger("share_service.audit")

# This service's door identifier, recorded as source_iface on every entry.
IFACE = "share"


def _import_publisher():
    try:
        from audit_service.publisher import AuditPublisher
        return AuditPublisher
    except ModuleNotFoundError:
        here = os.path.dirname(os.path.abspath(__file__))
        sibling = os.path.normpath(
            os.path.join(here, "..", "..", "..", "audit_service", "src"))
        if os.path.isdir(sibling) and sibling not in sys.path:
            sys.path.insert(0, sibling)
        from audit_service.publisher import AuditPublisher
        return AuditPublisher


class AuditUnavailable(RuntimeError):
    """The event could not be durably recorded. The guarded operation must not
    proceed (spec §4.3)."""


class AuditEmitter:
    def __init__(self, config: Config, *, publisher=None):
        self._enabled = config.audit_enabled
        self._pub = publisher
        if publisher is None and self._enabled:
            try:
                self._pub = _import_publisher().from_env()
            except Exception:
                log.exception(
                    "audit publisher unavailable — share links are DISABLED "
                    "(the audit chain is the only record that an access is "
                    "external; see spec §4.3)")
                self._pub = None

    @property
    def available(self) -> bool:
        """True when events can actually be published.

        Note this is False when auditing is *disabled by configuration* too.
        That is not an oversight: for this service, disabled auditing disables
        the feature rather than silently disabling the recording.
        """
        return self._pub is not None

    def emit(self, *, action: str, outcome: str, actor: str, category: str,
             tenant: str, **fields: Any) -> bool:
        """Publish one entry. Returns True iff durably accepted.

        Callers guarding a fail-closed action should use :meth:`emit_or_raise`
        rather than checking the return value, so a missed check cannot let an
        unrecorded operation through.
        """
        if self._pub is None:
            return False
        return bool(self._pub.publish(category=category, action=action,
                                      outcome=outcome, actor=actor,
                                      tenant=tenant, source_iface=IFACE,
                                      **fields))

    def emit_or_raise(self, **kwargs: Any) -> None:
        """Emit, or raise :class:`AuditUnavailable`.

        Every share event that grants or exercises outside access is
        fail-closed (spec §12) — including ``share_link_redeem``, which
        overrides its category default because there is no second copy of the
        record inside the core.
        """
        if not self.emit(**kwargs):
            raise AuditUnavailable(
                f"audit entry {kwargs.get('action')!r} not durable; "
                "operation refused")


_emitter: Optional[AuditEmitter] = None


def get_emitter(config: Config) -> AuditEmitter:
    global _emitter
    if _emitter is None:
        _emitter = AuditEmitter(config)
    return _emitter
