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

"""Honour http_bridge's revoked-token denylist (copied verbatim across services).

WHY EVERY DOOR NEEDS THIS, not just the bridge. Bridge session tokens are
stateless HS256 JWTs, and every service here verifies them LOCALLY against the
shared ``FILEENGINE_JWT_SECRET`` — the ``/v1/auth/introspect`` call in
``bridge_auth`` is only the fallback for when no secret is configured, and every
deployment configures one. So a signature and an ``exp`` were the whole test, and
a token that had been signed out went on working here even after the bridge
itself had begun refusing it. Measured on the dev stack: after a logout the
bridge answered 401 while discussion, csai and share all still answered 200.

The bridge writes the revoked ``jti`` to Redis as ``auth:revoked:{jti}`` with an
expiry equal to the token's own remaining life. This reads the same key. Nothing
writes it here — revocation stays the bridge's decision; these services only
stop honouring what it revoked.

FAIL-CLOSED, matching the bridge. A lookup that cannot reach Redis is *unknown*,
and unknown is refused. Honouring a token we cannot vouch for restores exactly
the behaviour this exists to remove, and does it silently.
``AUTH_REVOCATION_FAIL_OPEN=true`` inverts that for a deployment that would
rather serve requests than enforce sign-out.

THE CACHE IS WHAT MAKES A PER-REQUEST CHECK AFFORDABLE, and it is also the
revocation LATENCY: a signed-out token keeps working here for at most
``AUTH_REVOCATION_CACHE_TTL_SECONDS`` (default 5), against the whole token
lifetime it used to get. Set it to 0 to ask Redis every time.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

try:  # redis is a dependency of every service that ships this file
    import redis  # type: ignore
except Exception:  # pragma: no cover - exercised only where redis is absent
    redis = None  # type: ignore


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


class RevocationChecker:
    """Is a bridge token bearing this ``jti`` still honoured?

    ``lookup`` returns True (revoked), False (not revoked) or None (could not be
    established). It is injectable so the caching and the fail-closed policy —
    the parts that decide whether a signed-out token still works — are testable
    without a Redis.
    """

    KEY_PREFIX = "auth:revoked:"

    def __init__(
        self,
        *,
        enabled: bool = True,
        cache_ttl: int = 5,
        fail_open: bool = False,
        max_cache_entries: int = 100_000,
        lookup: Optional[Callable[[str], Optional[bool]]] = None,
        host: str = "localhost",
        port: int = 6379,
        password: str = "",
        db: int = 0,
    ) -> None:
        self.enabled = enabled
        self.cache_ttl = cache_ttl
        self.fail_open = fail_open
        self.max_cache_entries = max_cache_entries
        self._host, self._port, self._password, self._db = host, port, password, db
        self._lookup = lookup or self._redis_lookup
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[bool, float]] = {}
        self._client = None

    @classmethod
    def from_env(cls, lookup: Optional[Callable[[str], Optional[bool]]] = None) -> "RevocationChecker":
        return cls(
            enabled=_flag("AUTH_REVOCATION_ENABLED", True),
            cache_ttl=_int("AUTH_REVOCATION_CACHE_TTL_SECONDS", 5),
            fail_open=_flag("AUTH_REVOCATION_FAIL_OPEN", False),
            lookup=lookup,
            host=os.environ.get("FILEENGINE_REDIS_HOST", "localhost"),
            port=_int("FILEENGINE_REDIS_PORT", 6379),
            password=os.environ.get("FILEENGINE_REDIS_PASSWORD", ""),
            db=_int("FILEENGINE_REDIS_DB", 0),
        )

    # -- policy ------------------------------------------------------------

    def permits(self, jti: str) -> bool:
        """May a token bearing this ``jti`` be honoured?

        A token with no ``jti`` cannot be revoked and is permitted — refusing
        those would break every credential the bridge issues without one.
        """
        if not self.enabled or not jti:
            return True
        revoked = self._check(jti)
        if revoked is None:
            return self.fail_open  # unknown: refuse unless told otherwise
        return not revoked

    def _check(self, jti: str) -> Optional[bool]:
        now = time.time()
        if self.cache_ttl > 0:
            with self._lock:
                hit = self._cache.get(jti)
                if hit is not None and hit[1] > now:
                    return hit[0]
        verdict = self._lookup(jti)
        # Never cache "unknown": it is the absence of an answer, not an answer,
        # and remembering it would stretch one unreachable moment across the
        # whole window.
        if verdict is not None and self.cache_ttl > 0:
            with self._lock:
                if len(self._cache) >= self.max_cache_entries:
                    self._prune_locked(now)
                self._cache[jti] = (verdict, now + self.cache_ttl)
        return verdict

    def _prune_locked(self, now: float) -> None:
        for k in [k for k, v in self._cache.items() if v[1] <= now]:
            del self._cache[k]
        # Everything left is live, so there is no principled entry to evict.
        # Dropping the lot only costs a re-fetch; unbounded growth would not.
        if len(self._cache) >= self.max_cache_entries:
            self._cache.clear()

    # -- redis backend -----------------------------------------------------

    def _redis_lookup(self, jti: str) -> Optional[bool]:
        if redis is None:
            return None  # no client: unknown, which fail-closed refuses
        try:
            if self._client is None:
                self._client = redis.Redis(
                    host=self._host, port=self._port,
                    password=self._password or None, db=self._db,
                    socket_timeout=2, socket_connect_timeout=2,
                    decode_responses=True,
                )
            return bool(self._client.exists(self.KEY_PREFIX + jti))
        except Exception:
            # Connection refused, timeout, auth failure — all "we do not know".
            # Drop the client so the next call rebuilds it rather than reusing a
            # broken one.
            self._client = None
            return None

    def healthy(self) -> bool:
        """True if the denylist answers. For a readiness probe / startup log."""
        if not self.enabled:
            return True
        if redis is None:
            return False
        try:
            if self._client is None:
                self._client = redis.Redis(
                    host=self._host, port=self._port,
                    password=self._password or None, db=self._db,
                    socket_timeout=2, socket_connect_timeout=2,
                    decode_responses=True,
                )
            return bool(self._client.ping())
        except Exception:
            self._client = None
            return False

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()


# Process-wide default, built lazily so importing this module never touches the
# network and never reads the environment before the app has configured it.
_default: Optional[RevocationChecker] = None
_default_lock = threading.Lock()


def default_checker() -> RevocationChecker:
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = RevocationChecker.from_env()
    return _default


def permits(jti: str) -> bool:
    """Convenience wrapper over the process-wide checker."""
    return default_checker().permits(jti)


def reset_default() -> None:
    """Test seam — forget the process-wide checker."""
    global _default
    with _default_lock:
        _default = None
