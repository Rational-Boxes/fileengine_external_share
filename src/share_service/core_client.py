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

"""Delegated FileEngine core access (spec §4.1).

Every core call on a share path runs **as the link creator** — a real principal,
with roles resolved live from LDAP and admin roles stripped, evaluated against
real ACLs. There is no synthetic ``share:*`` user anywhere in this system, and
**there is no service principal**: unlike folder_actions, this service holds no
agent account, because an agent identity would outlive any particular creator's
access, which is the lingering-grant problem the authority re-check exists to
prevent.

That design is what lets the core stay unchanged (spec §4): "give the core the
creator's real identity" is the whole mechanism, so there is no special
evaluation path for the core to implement.

``fileengine`` (from ../python_interface) is imported lazily so config, auth and
health import without the gRPC stack present.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from .config import Config

log = logging.getLogger("share_service.core_client")

# Proto Permission enum *names* (proto/fileservice.proto:102-115). The core's
# internal bitmask is a different numbering entirely; the client takes names.
READ = "READ"
WRITE = "WRITE"


def _managed_files():
    from fileengine.client import ManagedFiles  # noqa: PLC0415 - lazy on purpose
    return ManagedFiles


class DelegatedCore:
    """A core client bound to one creator's identity, for one tenant.

    Construct it only from a stored link row (or from a validated creation
    request), never from caller-supplied identity fields.
    """

    def __init__(self, config: Config, *, user: str, roles: List[str], tenant: str,
                 source_addr: str = "", redemption_uid: Optional[str] = None):
        if not user:
            raise ValueError("delegated calls require a creator identity")
        self._cfg = config
        self.user = user
        self.roles = list(roles)
        self.tenant = tenant
        self.source_addr = source_addr
        # Correlation with the core's own audit events (spec §12): the core
        # records this operation against the CREATOR, so the redemption_uid is
        # what joins its "Alice read X" to our "bob@ redeemed link Y". Carried
        # as a claim because AuthenticationContext already has a claims map and
        # the core needs no change to accept it.
        self.redemption_uid = redemption_uid
        self._client = None

    # -- lifecycle ---------------------------------------------------------
    def _claims(self) -> list:
        return ([f"share.redemption_uid={self.redemption_uid}"]
                if self.redemption_uid else [])

    def __enter__(self):
        self._client = _managed_files()(
            server_address=self._cfg.grpc_address,
            user_name=self.user,
            user_roles=self.roles,
            tenant=self.tenant,
            user_claims=self._claims(),
            source_addr=self.source_addr,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None
        return False

    @property
    def client(self):
        if self._client is None:
            raise RuntimeError("DelegatedCore must be used as a context manager")
        return self._client

    # -- the calls M0 needs ------------------------------------------------
    def check_permission(self, resource_uid: str, permission: str = READ) -> bool:
        """Does the creator hold ``permission`` on ``resource_uid`` *right now*?

        This is the authority re-check (spec §6.3) and the creation pre-flight,
        and it is an ordinary core RPC — which is precisely why the core needs
        no share-specific code.
        """
        return bool(self.client.check_permission(resource_uid, permission))

    def stat(self, resource_uid: str):
        """FileInfo for the target — used to match the link kind against the
        resource type at creation (spec §6.1)."""
        return self.client.stat(resource_uid)

    def is_dir(self, resource_uid: str) -> bool:
        return bool(self.client.is_dir(resource_uid))


def for_creator(config: Config, *, created_by: str, roles: List[str], tenant: str,
                source_addr: str = "", redemption_uid: Optional[str] = None) -> DelegatedCore:
    """The only constructor callers should use.

    ``roles`` must already have come from ``ldap_roles.resolve_share_roles`` —
    i.e. live, and admin-stripped. This function deliberately does not resolve
    them itself, so that the stripping lives in exactly one place and a caller
    cannot bypass it by passing its own list without noticing.
    """
    return DelegatedCore(config, user=created_by, roles=roles, tenant=tenant,
                         source_addr=source_addr, redemption_uid=redemption_uid)


def healthy(config: Config) -> tuple[bool, Optional[str]]:
    """(ok, error) — used by /readyz. Probes the gRPC channel only; it does not
    assert any identity."""
    try:
        client = _managed_files()(server_address=config.grpc_address,
                                  user_name="readyz", tenant="default")
        try:
            client.entity_exists("00000000-0000-0000-0000-000000000000")
        finally:
            client.close()
        return True, None
    except Exception as e:  # pragma: no cover - exercised by @live tests
        return False, str(e)
