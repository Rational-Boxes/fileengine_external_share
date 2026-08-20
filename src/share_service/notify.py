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

"""Creator notifications — publishing share events onto the core's event stream
(spec §10.6).

The creator posts the link themselves and then has no channel back: v1 sends no
mail except the recipient's OTP. The Dashboard attention feed is that channel,
and it is owned by `discussion`, whose consumer already reads this stream. So a
share event is one `XADD` and no new transport.

**This is not audit, and the two must not be confused.** Audit is fail-closed
and blocking, because the chain is the only record that an access was external.
A notification is a courtesy: if Redis is down the creator misses a Dashboard
item, which must never be a reason to refuse a redemption that has already been
audited. Every function here swallows its errors and logs.

Selection lives here (`SHARE_ATTENTION_EVENTS`), not in the consumer, so an
operator enabling an event sees it take effect rather than meeting a second gate
they did not know about.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from .config import Config

log = logging.getLogger("share_service.notify")

# The event names this service can publish, without the "share." prefix. They
# map 1:1 onto discussion's notification kinds (share.drop_received ->
# share_drop_received), which is why the names must not drift.
DROP_RECEIVED = "drop_received"
LINK_DEAD = "link_dead"
OTP_SEND_FAILED = "otp_send_failed"
FIRST_REDEMPTION = "first_redemption"
LINK_LOCKED = "link_locked"


class EventPublisher:
    """XADDs share events. Lazily connected, and never fatal."""

    def __init__(self, config: Config):
        self.config = config
        self._r = None

    def _redis(self):
        if self._r is None:
            import redis  # lazy, as elsewhere in this codebase
            self._r = redis.Redis(
                host=self.config.redis_host, port=self.config.redis_port,
                password=self.config.redis_password or None, db=self.config.redis_db)
        return self._r

    def publish(self, event: str, *, tenant: str, creator: str, link_uid: str,
                file_uid: str = "", actor: str = "", detail: str = "") -> bool:
        """Publish one share event. Returns whether it went out.

        `actor` must NEVER be the creator: discussion's `add()` suppresses
        self-notification, so a creator's own link could otherwise never notify
        them. The consumer defends against this too, but the caller is where the
        right value is actually known.

        `detail` is the human text the feed renders WITHOUT resolving the
        resource — which is the point, since "your link stopped working" usually
        means the creator can no longer read it.
        """
        if event not in self.config.attention_events:
            return False
        if not creator:
            log.warning("share.%s has no creator; not published", event)
            return False

        payload = {
            "type": f"share.{event}",
            "tenant": tenant or "default",
            "creator": creator,
            "link_uid": link_uid,
            "file_uid": file_uid,
            "actor": actor or "",
            "detail": detail,
        }
        try:
            # One JSON `payload` field — the wire shape the core uses and
            # discussion's consumer parses. A different shape here would decode
            # to {} and be silently ignored.
            self._redis().xadd(self.config.events_stream,
                               {"payload": json.dumps(payload)})
            return True
        except Exception:  # noqa: BLE001
            # Deliberately swallowed. A missed Dashboard item must not fail a
            # redemption that is already recorded in the audit chain.
            log.warning("could not publish share.%s for link %s",
                        event, link_uid, exc_info=True)
            return False


_publisher: Optional[EventPublisher] = None


def get_publisher(config: Config) -> EventPublisher:
    global _publisher
    if _publisher is None:
        _publisher = EventPublisher(config)
    return _publisher


def reset_publisher() -> None:
    """Tests only."""
    global _publisher
    _publisher = None
