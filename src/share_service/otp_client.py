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

"""Client for `ldap_manager`'s recipient-OTP endpoints (spec §6.9).

The split: `ldap_manager` owns the code and the recipient token — generation,
delivery, storage, single-use verification, the attempt and send limits, and the
timing checks. This service orchestrates and enforces the **recipient
allowlist**, which is the half the identity service has no business knowing
about.

Every call fails **closed**: an unreachable identity service denies the
redemption rather than letting one through unverified.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from .config import Config

log = logging.getLogger("share_service.otp_client")


@dataclass
class ChallengeResult:
    sent: bool
    error: Optional[str] = None
    retry_after_s: int = 0

    @property
    def rate_limited(self) -> bool:
        return self.error == "rate_limited"

    @property
    def send_failed(self) -> bool:
        """A real delivery failure, as opposed to a throttle.

        Worth distinguishing because they need opposite responses: a throttle is
        the recipient's own doing and self-heals, while a send failure is the
        deployment's problem and must reach the link's creator (spec §6.9).
        """
        return bool(self.error) and not self.rate_limited


@dataclass
class VerifyResult:
    ok: bool
    locked: bool = False
    recipient_token: Optional[str] = None
    expires_in: int = 0


class OtpUnavailable(RuntimeError):
    """The identity service could not be reached. Callers must deny."""


def _post(cfg: Config, path: str, payload: dict) -> dict:
    url = cfg.ldap_manager_url.rstrip("/") + path
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Internal-Auth": cfg.share_internal_secret,
    })
    try:
        with urllib.request.urlopen(req, timeout=cfg.otp_timeout_s) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        # 403/404 here means the internal seam is misconfigured, not that the
        # recipient did anything wrong. Loud, and still a denial.
        log.error("share OTP call %s rejected: HTTP %s", path, e.code)
        raise OtpUnavailable(f"{path}: HTTP {e.code}") from e
    except Exception as e:  # noqa: BLE001
        log.error("share OTP call %s failed: %s", path, e)
        raise OtpUnavailable(f"{path}: {e}") from e


def send_code(cfg: Config, *, link_uid: str, email: str, tenant: str,
              sender: str = "") -> ChallengeResult:
    data = _post(cfg, "/internal/share/email-challenge", {
        "link_uid": link_uid, "email": email, "tenant": tenant, "sender": sender})
    return ChallengeResult(sent=bool(data.get("sent")),
                           error=data.get("error"),
                           retry_after_s=int(data.get("retry_after_s") or 0))


def verify_code(cfg: Config, *, link_uid: str, email: str, tenant: str,
                code: str) -> VerifyResult:
    data = _post(cfg, "/internal/share/email-verify", {
        "link_uid": link_uid, "email": email, "tenant": tenant, "code": code})
    return VerifyResult(ok=bool(data.get("ok")),
                        locked=bool(data.get("locked")),
                        recipient_token=data.get("recipient_token"),
                        expires_in=int(data.get("expires_in") or 0))


def check_token(cfg: Config, *, link_uid: str, email: str, token: str) -> bool:
    """Is this recipient token live and bound to this (link, address)?"""
    if not token:
        return False
    data = _post(cfg, "/internal/share/token-check", {
        "link_uid": link_uid, "email": email, "token": token})
    return bool(data.get("ok"))
