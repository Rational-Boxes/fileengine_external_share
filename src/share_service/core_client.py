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


class VersionGone(RuntimeError):
    """The version a link was pinned to has been culled (spec §6.2)."""


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
        """Raw permission check. **Almost never what you want** — see
        :meth:`can_reach`.

        The core answers this from ACL rules alone, and `AclManager` ships with
        `default_read_ = true`: a principal with no matching rule holds READ.
        A uid that does not exist has no matching rule either, so this returns
        **True for a resource that is not there**. Verified against the dev
        core, not inferred.
        """
        return bool(self.client.check_permission(resource_uid, permission))

    def exists(self, resource_uid: str) -> bool:
        """Does the resource exist and is it not deleted?"""
        return bool(self.client.entity_exists(resource_uid))

    def can_reach(self, resource_uid: str, permission: str = READ) -> bool:
        """The authority re-check as spec §6.3 actually defines it: the creator
        holds ``permission`` **and** the resource still exists and is not
        deleted.

        Both halves are required, and the existence half is the one that is
        easy to omit — because omitting it fails *open*: read-by-default makes
        a missing or deleted uid look permitted, so a link to a deleted file
        would pre-flight clean and a member that vanished would be served as a
        zero-byte entry rather than omitted.
        """
        return self.exists(resource_uid) and self.check_permission(resource_uid, permission)

    def current_version(self, resource_uid: str) -> str:
        """The version name a file is at right now — what a link pins to.

        One RPC: `FileInfo.version` carries it, so this does not need a full
        revision listing.
        """
        return str(getattr(self.stat(resource_uid), "version", "") or "")

    def stream_pinned(self, resource_uid: str, version_name: str = ""):
        """Yield ``version_name``'s bytes in bounded chunks, or the current
        version's when empty. **The way share content should be read.**

        The version travels on the request, so the core serves exactly that
        revision straight from storage without either side holding the file.
        Two things this replaces:

        * ``get()``, which accumulates the whole file into a ``BytesIO`` — fine
          for a note, wrong for a 4 GiB model, and the reason a folder archive
          used to buffer one member at a time.
        * ``get(back=N)``, which selects a version *positionally*, newest-first.
          ``back`` is not a stable handle: it shifts by one every time anyone
          saves the file. A link resolving a pin that way would quietly start
          serving a different revision than it was minted for — the exact
          failure pinning exists to prevent. Version names are immutable, so
          the name is what travels.

        A culled version raises :class:`VersionGone`: the link is dead (spec
        §6.2), never "serve the nearest revision".
        """
        from fileengine.exceptions import NotFoundError  # noqa: PLC0415
        try:
            for chunk in self.client.get_stream(resource_uid, version=version_name or ""):
                if chunk:
                    yield chunk
        except NotFoundError as e:
            if version_name:
                raise VersionGone(
                    f"{resource_uid}: version {version_name} is no longer "
                    f"present") from e
            raise

    def get_pinned(self, resource_uid: str, version_name: str = "") -> bytes:
        """The whole of :meth:`stream_pinned`, assembled.

        Kept for callers that genuinely need one buffer. Anything writing to a
        socket should use ``stream_pinned`` instead — this one's memory cost
        scales with the largest file anyone shares.
        """
        return b"".join(self.stream_pinned(resource_uid, version_name))

    def has_version(self, resource_uid: str, version_name: str) -> bool:
        """Is the pinned version still there? Used by the pre-flight so a culled
        version surfaces to the creator as "not working" rather than as a 404
        for the recipient."""
        if not version_name:
            return True
        try:
            return version_name in [r.version
                                    for r in self.client.revisions(resource_uid)]
        except Exception:  # noqa: BLE001 - unreadable means not usable
            return False

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
