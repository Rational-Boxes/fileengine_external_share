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

"""Media metering: rolling windows, concurrency, and the response ladder (MEDIA_SHARE.md §6.9).

Bytes, concurrency and time — not attempts. Three scopes:

* **link** — the creator's budget: an hourly burst window here, the durable
  ``max_bytes`` in Postgres (the caller checks that one);
* **tenant** — an hour and a day, the only scope that sees a distributed
  low-and-slow pull where every link is individually fine;
* **instance** — concurrent streams, in-process, protecting this box and the
  core behind it.

Rolling windows and concurrency live in **Redis**, shared by every replica: a
per-process counter hands a puller one fresh allowance per replica (the trap the
outside-share spec names twice). If Redis is unavailable this DEGRADES rather
than refusing — the one deliberate departure from fail-closed in the feature,
because what it protects is a comfort bound, not an authorization decision.
Authorization and the durable budgets are not here and are unaffected; the
instance cap tightens to a quarter, ``degraded`` is raised, and the caller
records it.

The rungs: 0 observe (metrics), 1 advise (a soft ceiling crossed — the caller
tells the creator once per window), 2 throttle (429 + Retry-After; in-flight
responses finish), 3 park (rung 2 sustained, or a long window spent).
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .config import Config

log = logging.getLogger("share_service.media_meter")

HOUR = 3600
DAY = 86400
_CONC_TTL = 6 * HOUR      # a counter a crashed process never decremented ages out


@dataclass
class Decision:
    ok: bool
    rung: int = 0                         # 0 observe .. 3 park
    reason: str = ""                      # which window/cap decided
    retry_after: int = 0                  # seconds, for a 429
    advise: List[str] = field(default_factory=list)   # windows past the soft ceiling
    park: bool = False                    # rung 2 has been sustained: park the link
    ticket: Optional["Ticket"] = None


@dataclass
class Ticket:
    """One admitted stream. Release it exactly once."""
    keys: List[str]
    local: bool
    released: bool = False


class Meter:
    def __init__(self, cfg: Config, *, redis=None, clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self._redis = redis
        self.clock = clock
        self._lock = threading.Lock()
        self._active = 0                   # streams on THIS instance
        self.degraded = False
        self.on_degraded: Optional[Callable[[bool], None]] = None

    # -- plumbing -------------------------------------------------------------
    def _r(self):
        if self._redis is None:
            import redis
            self._redis = redis.Redis(host=self.cfg.redis_host, port=self.cfg.redis_port,
                                      password=self.cfg.redis_password or None,
                                      db=self.cfg.redis_db, socket_timeout=1,
                                      socket_connect_timeout=1)
        return self._redis

    def _set_degraded(self, value: bool) -> None:
        if value != self.degraded:
            self.degraded = value
            (log.error if value else log.warning)(
                "media metering %s", "DEGRADED: Redis windows unavailable — static caps only"
                if value else "recovered: Redis windows available again")
            if self.on_degraded:
                try:
                    self.on_degraded(value)
                except Exception:  # noqa: BLE001
                    log.warning("degraded callback failed", exc_info=True)

    def _bucket(self, span: int) -> int:
        return int(self.clock()) // span

    def _keys(self, tenant: str, link: str):
        h, d = self._bucket(HOUR), self._bucket(DAY)
        return {
            "link_hour": (f"share:media:egress:link:{tenant}:{link}:{h}", HOUR,
                          self.cfg.media_max_egress_per_hour),
            "tenant_hour": (f"share:media:egress:tenant:{tenant}:{h}", HOUR,
                            self.cfg.media_tenant_egress_per_hour),
            "tenant_day": (f"share:media:egress:tenant-day:{tenant}:{d}", DAY,
                           self.cfg.media_tenant_egress_per_day),
        }

    def _until_next(self, span: int) -> int:
        now = self.clock()
        return max(1, int(span - (now % span)))

    # -- admission ------------------------------------------------------------
    def admit(self, tenant: str, link: str, client: str) -> Decision:
        """May one more stream start for this (link, client)? Never raises."""
        cap = self.cfg.media_max_concurrent_streams
        with self._lock:
            local_cap = max(1, cap // 4) if self.degraded else cap
            if self._active >= local_cap:
                return Decision(False, 2, "instance_concurrency", retry_after=5)
            self._active += 1
        try:
            d = self._admit_shared(tenant, link, client)
        except Exception as e:  # noqa: BLE001 - Redis down: degrade, never refuse for it
            log.debug("redis unavailable for metering: %s", e)
            self._set_degraded(True)
            with self._lock:
                if self._active > max(1, cap // 4):
                    self._active -= 1
                    return Decision(False, 2, "instance_concurrency", retry_after=5)
            return Decision(True, 0, "degraded", ticket=Ticket([], local=True))
        self._set_degraded(False)
        if not d.ok:
            with self._lock:
                self._active -= 1
        return d

    def _admit_shared(self, tenant: str, link: str, client: str) -> Decision:
        r = self._r()
        windows = self._keys(tenant, link)
        values = r.mget([k for k, _s, _c in windows.values()])
        advise: List[str] = []
        for (name, (_k, span, limit)), raw in zip(windows.items(), values):
            used = int(raw or 0)
            if limit and used >= limit:
                return self._throttled(tenant, link, name, self._until_next(span),
                                       park=(name == "tenant_day"))
            if limit and used >= limit * self.cfg.media_soft_ceiling_ratio:
                advise.append(name)

        lk = f"share:media:conc:link:{tenant}:{link}"
        ck = f"share:media:conc:client:{tenant}:{link}:{client}"
        pipe = r.pipeline()
        pipe.incr(lk)
        pipe.expire(lk, _CONC_TTL)
        pipe.incr(ck)
        pipe.expire(ck, _CONC_TTL)
        n_link, _e1, n_client, _e2 = pipe.execute()
        if n_link > self.cfg.media_max_concurrent_per_link:
            r.decr(lk)
            r.decr(ck)
            return self._throttled(tenant, link, "link_concurrency", 5)
        if n_client > self.cfg.media_max_concurrent_per_client:
            r.decr(lk)
            r.decr(ck)
            # Per-client, so it does not count toward parking the link: one
            # greedy client must not take everyone else's video away.
            return Decision(False, 2, "client_concurrency", retry_after=5)
        return Decision(True, 1 if advise else 0, "", advise=advise,
                        ticket=Ticket([lk, ck], local=True))

    def _throttled(self, tenant: str, link: str, reason: str, retry_after: int,
                   park: bool = False) -> Decision:
        """Rung 2, and whether it has now been sustained long enough for rung 3."""
        r = self._r()
        since_key = f"share:media:throttle-since:{tenant}:{link}"
        now = int(self.clock())
        r.set(since_key, now, nx=True, ex=2 * HOUR)
        since = int(r.get(since_key) or now)
        sustained = now - since >= self.cfg.media_park_after_minutes * 60
        return Decision(False, 2, reason, retry_after=retry_after,
                        park=park or sustained)

    def release(self, ticket: Optional[Ticket]) -> None:
        if ticket is None or ticket.released:
            return
        ticket.released = True
        if ticket.local:
            with self._lock:
                self._active = max(0, self._active - 1)
        if ticket.keys:
            try:
                r = self._r()
                for k in ticket.keys:
                    r.decr(k)
            except Exception:  # noqa: BLE001 - TTL ages the counter out
                self._set_degraded(True)

    def throttle_cleared(self, tenant: str, link: str) -> None:
        """A request was served without throttling: rung 2 is not sustained."""
        try:
            self._r().delete(f"share:media:throttle-since:{tenant}:{link}")
        except Exception:  # noqa: BLE001
            self._set_degraded(True)

    # -- bytes ----------------------------------------------------------------
    def add_bytes(self, tenant: str, link: str, n: int) -> None:
        if n <= 0:
            return
        try:
            pipe = self._r().pipeline()
            for k, span, _limit in self._keys(tenant, link).values():
                pipe.incrby(k, n)
                pipe.expire(k, span * 2)
            pipe.execute()
            self._set_degraded(False)
        except Exception:  # noqa: BLE001 - Postgres still holds the durable budget
            self._set_degraded(True)

    def first_in_window(self, tenant: str, link: str, what: str, span: int = HOUR) -> bool:
        """True exactly once per (link, what, window) across every replica — the
        guard that keeps one advisory / one audit event per window rather than one
        per request. False when it cannot be decided (degraded): staying quiet is
        the right failure for a notification."""
        try:
            key = f"share:media:once:{what}:{tenant}:{link}:{self._bucket(span)}"
            return bool(self._r().set(key, 1, nx=True, ex=span * 2))
        except Exception:  # noqa: BLE001
            self._set_degraded(True)
            return False

    def count_in_window(self, tenant: str, link: str, what: str, span: int = HOUR) -> Optional[int]:
        """Increment and return this window's count for (link, what) — shared by
        every replica. None when it cannot be counted (degraded): the caller
        then admits, since this is a comfort bound, not authorization."""
        try:
            key = f"share:media:count:{what}:{tenant}:{link}:{self._bucket(span)}"
            pipe = self._r().pipeline()
            pipe.incr(key)
            pipe.expire(key, span * 2)
            n, _ = pipe.execute()
            return int(n)
        except Exception:  # noqa: BLE001
            self._set_degraded(True)
            return None

    # -- the re-check epoch (§6.7) ----------------------------------------------
    def acl_epoch(self, tenant: str) -> float:
        """When the tenant's ACLs or roles last changed, per the core's events.
        0 when unknown — the interval bound then applies on its own."""
        try:
            return float(self._r().get(f"share:media:acl-epoch:{tenant}") or 0)
        except Exception:  # noqa: BLE001
            self._set_degraded(True)
            return 0.0

    def bump_acl_epoch(self, tenant: str) -> None:
        try:
            self._r().set(f"share:media:acl-epoch:{tenant}", self.clock(), ex=DAY)
        except Exception:  # noqa: BLE001
            self._set_degraded(True)


_meter: Optional[Meter] = None


def get_meter(cfg: Config) -> Meter:
    global _meter
    if _meter is None:
        _meter = Meter(cfg)
    return _meter
