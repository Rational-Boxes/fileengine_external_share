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

"""Keeping a media link current, from the shared events stream (MEDIA_SHARE.md §6.2).

A link plays the NEWEST version of its file that has finished publishing, so a
correction uploaded after the link was sent is what the outside viewer sees.
Two events make that work:

* ``file.updated`` (the core) for a file with a live media link — a new version
  exists, so ask CSAI to publish it. On whose authority: the link's CREATOR,
  re-checked live (LDAP roles, admin-stripped; READ and existence in the core)
  exactly as a redemption would be. If no live link's creator still passes,
  nothing is published — a creator who lost access cannot keep a link fed.
* ``media.published`` / ``media.publish_failed`` (CSAI) — the newest set is
  ready, so links describe it; or a publish failed, which only affects a link
  that has nothing else to play.

Delivery is a consumer group, so instances share the work. A message is
acknowledged once handled or deliberately dropped; a TRANSIENT failure (CSAI or
the directory unreachable) leaves it pending, and pending entries are retried
with a backoff — otherwise an outage would silently cost a correction.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from typing import Callable, Optional

from . import core_client, db, links, media_client, preflight
from .audit import get_emitter
from .config import Config

log = logging.getLogger("share_service.media_events")

RETRY_PENDING_SECONDS = 30


class MediaEventConsumer:
    def __init__(self, cfg: Config, *, redis=None, consumer: str = "",
                 republish: Callable = media_client.republish,
                 check: Callable = preflight.check, connect: Callable = db.connect_for_tenant,
                 emitter=None, clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self._redis = redis
        self.consumer = consumer or f"{socket.gethostname()}-{id(self):x}"
        self.republish = republish
        self.check = check
        self.connect = connect
        self.emitter = emitter
        self.clock = clock
        self._last_pending = None
        self._stop = threading.Event()

    # -- plumbing -----------------------------------------------------------
    def _client(self):
        if self._redis is None:
            import redis
            self._redis = redis.Redis(host=self.cfg.redis_host, port=self.cfg.redis_port,
                                      password=self.cfg.redis_password or None,
                                      db=self.cfg.redis_db, decode_responses=True)
        return self._redis

    def ensure_group(self) -> None:
        try:
            # '$': a new group starts at NOW. Replaying a week of history on
            # first start would republish files nobody asked about recently.
            self._client().xgroup_create(self.cfg.events_stream, self.cfg.events_group,
                                         id="$", mkstream=True)
        except Exception as e:  # noqa: BLE001
            if "BUSYGROUP" not in str(e):
                raise

    def _audit(self, action: str, outcome: str, actor: str, tenant: str, **detail) -> None:
        em = self.emitter or get_emitter(self.cfg)
        try:
            em.emit(action=action, outcome=outcome, actor=actor, category="system",
                    tenant=tenant, detail=detail)
        except Exception:  # noqa: BLE001 - recording the republish is best-effort
            log.warning("could not audit %s", action, exc_info=True)

    # -- the decisions --------------------------------------------------------
    def handle(self, event: dict) -> bool:
        """Act on one event. True = done (ack); False = transient, retry later."""
        etype = event.get("type") or ""
        tenant = event.get("tenant") or ""
        file_uid = event.get("file_uid") or ""
        if not tenant:
            return True
        if not file_uid and not (etype == "acl.changed" or etype.startswith("role.")):
            return True
        if etype == "acl.changed" or etype.startswith("role."):
            # The media door re-checks a creator's authority at most every
            # media_recheck_seconds; this makes a revocation the NEXT request's
            # problem instead (§6.7). Tenant-wide and shared via Redis, since the
            # consumer group hands this event to ONE replica.
            from .media_meter import get_meter
            get_meter(self.cfg).bump_acl_epoch(tenant)
            return True
        if etype == "file.updated":
            if event.get("is_rendition") or event.get("is_folder"):
                return True         # our own renditions, and CSAI's, land here too
            return self._republish(tenant, file_uid, str(event.get("version") or ""))
        if etype in ("media.published", "media.publish_failed"):
            if event.get("profile") not in media_client.PRIMARY_PROFILES:
                return True         # the 480p, the GIF: not what decides readiness
            conn = self.connect(self.cfg, tenant, provision=True)
            try:
                version = str(event.get("version") or "")
                if etype == "media.published":
                    changed = links.record_media_published(
                        conn, file_uid, version=version,
                        duration_ms=event.get("duration_ms"),
                        output_bytes=event.get("output_bytes"))
                else:
                    changed = links.record_media_failed(conn, file_uid, version=version)
            finally:
                conn.close()
            from .media_door import forget_published
            forget_published(tenant, file_uid)
            if changed:
                log.info("%s %s@%s -> %d link(s)", etype, file_uid, version, len(changed))
            return True
        return True

    def _republish(self, tenant: str, file_uid: str, version: str) -> bool:
        conn = self.connect(self.cfg, tenant, provision=True)
        try:
            live = links.live_media_links(conn, file_uid)
        finally:
            conn.close()
        if not live:
            return True
        if version and any(l.media_version and l.media_version >= version for l in live):
            return True             # already published at (or past) this version
        transient = False
        for link in live:           # oldest first: the longest-standing grant
            verdict = self.check(self.cfg, created_by=link.created_by, tenant=tenant,
                                 resource_uid=file_uid, permission=core_client.READ)
            if not verdict:
                if verdict.reason == preflight.REASON_LDAP:
                    transient = True
                continue
            try:
                self.republish(self.cfg, tenant=tenant, file_uid=file_uid,
                               user=link.created_by, roles=verdict.roles or [],
                               link_uid=link.link_uid)
            except media_client.MediaRefused as e:
                log.info("republish of %s refused for %s: %s", file_uid, link.created_by, e.detail)
                continue
            except media_client.MediaUnavailable as e:
                log.warning("republish of %s deferred: %s", file_uid, e)
                return False
            self._audit("share_media_republish_requested", "ok", link.created_by, tenant,
                        file_uid=file_uid, link_uid=link.link_uid, version=version,
                        live_links=len(live))
            return True
        if transient:
            return False
        self._audit("share_media_republish_refused", "denied", "share_service", tenant,
                    file_uid=file_uid, version=version, live_links=len(live),
                    reason="no live link's creator can still read the file")
        return True

    # -- the loop -------------------------------------------------------------
    def _consume(self, entries) -> int:
        n = 0
        for _stream, messages in entries or []:
            for msg_id, fields in messages:
                try:
                    event = json.loads(fields.get("payload") or "{}")
                except (TypeError, ValueError):
                    event = {}
                try:
                    done = self.handle(event)
                except Exception:  # noqa: BLE001 - one bad event must not stop the rest
                    log.exception("media event %s failed", msg_id)
                    done = False
                if done:
                    self._client().xack(self.cfg.events_stream, self.cfg.events_group, msg_id)
                n += 1
        return n

    def run_once(self, block_ms: int = 5000) -> int:
        r = self._client()
        n = 0
        now = self.clock()
        if self._last_pending is None or now - self._last_pending >= RETRY_PENDING_SECONDS:
            self._last_pending = now
            n += self._consume(r.xreadgroup(self.cfg.events_group, self.consumer,
                                            {self.cfg.events_stream: "0"}, count=50))
        n += self._consume(r.xreadgroup(self.cfg.events_group, self.consumer,
                                        {self.cfg.events_stream: ">"}, count=50,
                                        block=block_ms))
        return n

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        self.ensure_group()
        log.info("media event consumer started (group %s)", self.cfg.events_group)
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                log.exception("media event consumer pass failed; retrying")
                self._stop.wait(5)


def start_session_sweeper(cfg: Config, interval: int = 60) -> Optional[threading.Thread]:
    """Close expired viewing sessions, each with its share_media_session_end."""
    if not cfg.media_enabled:
        return None

    def loop():
        from .media_door import end_expired_sessions, media_tenants
        while True:
            time.sleep(interval)
            try:
                tenants = media_tenants(cfg)
                end_expired_sessions(cfg, tenants)
                from .audience import run_due
                run_due(cfg, tenants)
            except Exception:  # noqa: BLE001
                log.exception("media session / audience sweep failed")

    t = threading.Thread(target=loop, name="share-media-sessions", daemon=True)
    t.start()
    return t


def start(cfg: Config) -> Optional[threading.Thread]:
    if not (cfg.media_enabled and cfg.media_events_enabled):
        return None
    consumer = MediaEventConsumer(cfg)
    t = threading.Thread(target=consumer.run_forever, name="share-media-events", daemon=True)
    t.start()
    return t
