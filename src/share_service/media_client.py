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

"""convert_search_ai's publish surface, as this service uses it (MEDIA_SHARE.md §4.3).

Two ways in, and the difference is whose authority is exercised:

* **As the creator, with their own bearer** — minting a link. CSAI checks the
  caller itself (WRITE to publish, READ to look), so this service never lends
  anyone an authority they lack. A reader who may share but not edit gets a
  link only to something somebody already published.
* **Internally, naming the creator** — a new version of a file with a live link.
  There is no browser in that moment, so the call carries the shared internal
  secret and the creator's name and roles; CSAI re-checks READ as that creator.

Nothing here decides access. A failure is reported, never papered over.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from .config import Config

log = logging.getLogger("share_service.media_client")

# The rendition a link plays, per kind of source: video first, audio-only else.
PRIMARY_PROFILES = ("video-720p-vp9", "audio-mp3")
TERMINAL = ("succeeded", "skipped", "failed", "cancelled")


class MediaUnavailable(RuntimeError):
    """CSAI could not be asked, or answered with something unusable."""


class MediaRefused(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class PublishState:
    source_version: str
    mime: str
    jobs: List[dict] = field(default_factory=list)
    renditions: List[str] = field(default_factory=list)

    @property
    def primary(self) -> Optional[dict]:
        for p in PRIMARY_PROFILES:
            for j in self.jobs:
                if j.get("profile") == p:
                    return j
        return None

    @property
    def ready(self) -> bool:
        """The current version's playable rendition exists."""
        p = self.primary
        return bool(p and p.get("status") == "succeeded")

    @property
    def failed(self) -> bool:
        p = self.primary
        return bool(p and p.get("status") in ("failed", "cancelled"))

    @property
    def in_progress(self) -> bool:
        return any(j.get("status") not in TERMINAL for j in self.jobs)


def _parse(body) -> PublishState:
    if not isinstance(body, dict):
        raise MediaUnavailable("unintelligible answer from convert_search_ai")
    return PublishState(source_version=str(body.get("source_version") or ""),
                        mime=str(body.get("mime") or ""),
                        jobs=list(body.get("jobs") or []),
                        renditions=list(body.get("renditions") or []))


def _detail(r) -> str:
    try:
        d = r.json().get("detail")
        return d if isinstance(d, str) else str(d)
    except Exception:  # noqa: BLE001
        return r.text[:200]


def _call(cfg: Config, method: str, path: str, *, headers: dict, json=None, http=None):
    client = http or httpx
    try:
        return client.request(method, f"{cfg.csai_url}{path}", headers=headers, json=json,
                              timeout=cfg.csai_timeout_s)
    except Exception as e:  # noqa: BLE001
        raise MediaUnavailable(f"convert_search_ai unreachable: {e}") from e


def _caller_headers(bearer: str, tenant: str) -> dict:
    return {"Authorization": f"Bearer {bearer}", "X-Tenant": tenant}


def state(cfg: Config, *, bearer: str, tenant: str, file_uid: str, http=None) -> PublishState:
    """The publish state of the file's current version, as the creator sees it."""
    r = _call(cfg, "GET", f"/documents/{file_uid}/media",
              headers=_caller_headers(bearer, tenant), http=http)
    if r.status_code == 200:
        return _parse(r.json())
    if r.status_code in (400, 403, 404, 415):
        raise MediaRefused(r.status_code, _detail(r))
    raise MediaUnavailable(f"convert_search_ai answered {r.status_code}")


def publish(cfg: Config, *, bearer: str, tenant: str, file_uid: str, http=None) -> PublishState:
    """Ask for the current version to be published, as the creator. Idempotent."""
    r = _call(cfg, "POST", f"/documents/{file_uid}/media",
              headers=_caller_headers(bearer, tenant), json={}, http=http)
    if r.status_code in (200, 202):
        return _parse(r.json())
    if r.status_code in (400, 403, 404, 415):
        raise MediaRefused(r.status_code, _detail(r))
    raise MediaUnavailable(f"convert_search_ai answered {r.status_code}")


def republish(cfg: Config, *, tenant: str, file_uid: str, user: str, roles: List[str],
              link_uid: str, http=None) -> PublishState:
    """Ask for the current version to be published on a link creator's behalf."""
    if not cfg.media_internal_secret:
        raise MediaUnavailable("no internal secret configured for convert_search_ai")
    r = _call(cfg, "POST", f"/internal/documents/{file_uid}/media",
              headers={"X-Internal-Auth": cfg.media_internal_secret},
              json={"tenant": tenant, "user": user, "roles": list(roles),
                    "link_uid": link_uid}, http=http)
    if r.status_code in (200, 202):
        return _parse(r.json())
    if r.status_code in (400, 403, 404, 415):
        raise MediaRefused(r.status_code, _detail(r))
    raise MediaUnavailable(f"convert_search_ai answered {r.status_code}")
