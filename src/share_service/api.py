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

"""Owner-side routes — bearer-authenticated (spec §7.1).

Every route here requires a caller token by construction: the dependency is on
the router, not on individual handlers, so a new route inherits the gate or does
not ship. The unauthenticated public router (M4) will be a **separate** router
with different dependencies — never an allowlisted exception inside this one,
which is the pattern that made the bridge's auth gate one forgotten `else` away
from exposure (spec §7).

Note what is absent: no route takes a resource uid for an *existing* link. The
target is always read from the stored row (spec §4.3). That containment used to
be the core's job.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from . import audience, core_client, db, links, media_client, preflight, snapshot as snapshot_mod
from .audit import AuditUnavailable, get_emitter
from .auth import Caller, get_caller
from .config import Config
from .ldap_roles import LdapUnavailable, UnknownUser, in_open_group, in_share_group
from .schema import (ACCESS_MODES, ACCESS_OPEN, ACCESS_VERIFIED,
                     KIND_FILE_DOWNLOAD, KIND_FOLDER_DOWNLOAD, KIND_MEDIA, KIND_UPLOAD,
                     KINDS, MEDIA_PENDING, MEDIA_READY)
from .urls import media_origin, tenant_origin

log = logging.getLogger("share_service.api")

router = APIRouter(prefix="/share/v1", dependencies=[Depends(get_caller)])


# --- request / response models -------------------------------------------

class CreateLinkRequest(BaseModel):
    """Note there is no `resource_uid`: the target comes from the path, and for
    every later call from the stored row. Nor a `send_invite`: v1 sends no
    invite mail — the creator composes their own (spec §13-R9)."""
    kind: int = Field(..., description="0 file download, 1 upload, 2 folder download, 3 media")
    # Required for 'verified' links (every kind but media is verified), advisory
    # for 'claimed', refused for 'open' (MEDIA_SHARE.md §5 rule 3).
    recipients: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    ttl_days: Optional[int] = None
    max_uses: int = 0
    max_uses_per_recipient: int = 0
    max_bytes: int = 0
    max_file_bytes: int = 0
    max_files: int = Field(0, description="upload only: total files, NOT sessions (spec §6.4)")
    follow_latest: bool = False
    follow_folder: bool = False
    include_subdirs: bool = True
    landing_prefix: Optional[str] = None
    ext_allowlist: Optional[List[str]] = None
    note: Optional[str] = None
    # --- kind 3 (MEDIA_SHARE.md §5, §6.2) ---
    access_mode: str = ACCESS_VERIFIED
    # The creator typed that anyone with the URL, and anyone they forward it
    # to, can watch. Required for an open link (§5 rule 4).
    confirm_public: bool = False
    # Ask for the transcode if the current version is not published yet; false
    # refuses instead, for a caller that only wants a link to existing bytes.
    publish: bool = True
    max_viewers: int = 0
    allowed_embed_origins: Optional[List[str]] = None
    display_name: Optional[str] = None
    # May viewers save a copy? Unset = by mode: yes for verified, no otherwise.
    allow_download: Optional[bool] = None


#: What the creator of an open link is shown and must acknowledge (§5 rule 4).
OPEN_LINK_WARNING = ("anyone with this link, and anyone they forward it to, "
                     "can watch this")


def _embed_origins(raw: Optional[List[str]], *, mode: str = ACCESS_VERIFIED,
                   cfg: Optional[Config] = None) -> Optional[List[str]]:
    """Normalize to bare https origins (scheme://host[:port]). Anything else —
    a path, a partial wildcard, http — is refused rather than trimmed: this list
    becomes frame-ancestors, and a silently widened CSP is the failure to avoid.

    Exactly ``["*"]`` (embeddable anywhere — what WordPress/Notion oEmbed needs)
    is accepted for an OPEN link only (§9.3), which already carries the
    confirm_public acknowledgement. ``http://localhost`` / ``127.0.0.1`` origins
    are accepted only with SHARE_MEDIA_EMBED_ALLOW_LOOPBACK (dev and tests)."""
    from urllib.parse import urlsplit
    if not raw:
        return None
    if [o.strip() for o in raw] == ["*"]:
        if mode != ACCESS_OPEN:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "allowed_embed_origins '*' is only for an open link")
        return ["*"]
    loopback_ok = bool(cfg and cfg.media_embed_allow_loopback)
    out: List[str] = []
    for o in raw:
        o = (o or "").strip()
        u = urlsplit(o)
        loopback = (u.scheme == "http" and loopback_ok
                    and (u.hostname or "") in ("localhost", "127.0.0.1"))
        if ((u.scheme != "https" and not loopback) or not u.hostname or "*" in o or u.username
                or u.path not in ("", "/") or u.query or u.fragment):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"allowed_embed_origins: {o!r} is not an https origin")
        origin = f"{u.scheme}://{u.hostname.lower()}" + (f":{u.port}" if u.port else "")
        if origin not in out:
            out.append(origin)
    return out


class AddRecipientRequest(BaseModel):
    email: str


def _link_json(link: links.Link, *, status_override: Optional[str] = None) -> dict:
    return {
        "link_uid": link.link_uid,
        "kind": link.kind,
        "resource_uid": link.resource_uid,
        "created_by": link.created_by,
        "created_at": link.created_at,
        "expires_at": link.expires_at,
        "revoked_at": link.revoked_at,
        "revoked_by": link.revoked_by,
        "status": status_override or link.status(),
        "max_uses": link.max_uses,
        "uses_consumed": link.uses_consumed,
        "max_uses_per_recipient": link.max_uses_per_recipient,
        "max_bytes": link.max_bytes,
        "bytes_consumed": link.bytes_consumed,
        "max_file_bytes": link.max_file_bytes,
        "max_files": link.max_files,
        "files_consumed": link.files_consumed,
        "pinned_version": link.pinned_version,
        "follow_folder": link.follow_folder,
        "include_subdirs": link.include_subdirs,
        "archive_bytes": link.archive_bytes,
        "note": link.note,
        "access_mode": link.access_mode,
        # Never the secret. It existed once, in the creation response.
        **({"max_viewers": link.max_viewers,
            "allowed_embed_origins": link.allowed_embed_origins,
            "display_name": link.display_name, "media_state": link.media_state,
            "media_version": link.media_version, "duration_ms": link.duration_ms,
            "output_bytes": link.output_bytes, "poster_uid": link.poster_uid,
            "allow_download": link.allow_download}
           if link.kind == KIND_MEDIA else {}),
    }


# --- helpers --------------------------------------------------------------

def _config(request: Request) -> Config:
    return request.app.state.config

def _require_enabled(cfg: Config) -> None:
    emitter = get_emitter(cfg)
    if not cfg.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "share links are disabled here")
    if not emitter.available:
        # Auditing off means sharing off (spec §4.3): the audit chain is the
        # only record that an access was external.
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "audit unavailable; share links refuse to operate")


def is_tenant_admin(cfg: Config, caller: Caller) -> bool:
    """Whether this caller may use the oversight console (spec §10.3).

    Read from the roles the bridge put in the signed token, scoped to the ACTIVE
    tenant by `identity_from_claims` — so an administrator of tenant A is an
    ordinary user in tenant B, and switching tenants cannot carry the power
    across.

    NB this deliberately does NOT go through `ldap_roles.resolve_share_roles`,
    which strips exactly these roles. That stripping governs what this service
    hands the CORE on a delegated call, where an admin role would become an ACL
    bypass on behalf of an absent creator. Asking "may this human open the
    console?" is the opposite question, and answering it from the stripped list
    would make the console permanently empty for everyone.
    """
    return any(caller.has_role(r) for r in cfg.admin_roles)


def _require_admin(cfg: Config, caller: Caller) -> None:
    if not is_tenant_admin(cfg, caller):
        # 403, not 404: unlike a link uid, the existence of the console is not
        # a secret, and a silent empty list would read as "nothing is shared".
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "tenant administrator role required")


def _owned_link(conn, link_uid: str, caller: Caller,
                cfg: Optional[Config] = None) -> links.Link:
    """Fetch a link the caller may act on, or 404.

    404 rather than 403 for someone else's link: whether a link exists is not
    something an unrelated user should be able to probe.

    A tenant admin may act on any link in their tenant — but only when `cfg` is
    passed, so admin reach is something a route opts INTO rather than something
    every existing caller of this helper silently inherits.
    """
    try:
        link = links.get(conn, link_uid)
    except links.LinkNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if link.created_by != caller.user:
        if cfg is None or not is_tenant_admin(cfg, caller):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return link


class RevokeAllRequest(BaseModel):
    creator: str


def _public_url(cfg: Config, request: Request, tenant: str,
                link_uid: str, secret: str) -> str:
    """The link as the recipient will receive it.

    Built from the tenant the link is minted IN, never from the origin the
    creating request arrived on — the SPA switches tenant with a header and
    without navigating, so those routinely disagree (:mod:`share_service.urls`).
    """
    return f"{tenant_origin(cfg, request, tenant)}/s/{link_uid}.{secret}"


# --- routes ---------------------------------------------------------------

def _bearer(request: Request) -> str:
    h = request.headers.get("authorization") or ""
    return h.split(None, 1)[1].strip() if h.lower().startswith("bearer ") else ""


def _resolve_media(cfg: Config, request: Request, caller: Caller, resource_uid: str,
                   publish: bool) -> dict:
    """The media columns for a new link: ready if the current version is
    published, else ask CSAI to publish (as the CREATOR — their own bearer, so
    CSAI's WRITE check is theirs) and mint in ``pending_media``.

    A reader who may share but not edit gets a link only to something already
    published: lending them this service's authority to spend the tenant's CPU
    would be the escalation the delegated model exists to prevent."""
    bearer = _bearer(request)
    try:
        st = media_client.state(cfg, bearer=bearer, tenant=caller.tenant,
                                file_uid=resource_uid)
        if not st.ready and not st.in_progress:
            if not publish:
                raise HTTPException(status.HTTP_409_CONFLICT, {
                    "error": "not_published",
                    "message": "this file has no published copy yet (publish=false)"})
            st = media_client.publish(cfg, bearer=bearer, tenant=caller.tenant,
                                      file_uid=resource_uid)
    except media_client.MediaRefused as e:
        if e.status == 415:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                {"error": "not_media", "message": e.detail})
        if e.status == 403:
            raise HTTPException(status.HTTP_403_FORBIDDEN, {
                "error": "publish_not_permitted",
                "message": "this video has not been published yet, and publishing it "
                           "needs edit access to the file — ask someone who can edit "
                           "it to share it, or to publish it first"})
        raise HTTPException(status.HTTP_400_BAD_REQUEST, {"error": "media", "message": e.detail})
    except media_client.MediaUnavailable as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            f"media publishing unavailable: {e}")

    if st.ready:
        primary = st.primary or {}
        size = primary.get("output_bytes")
        if size and size > cfg.media_max_bytes:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, {
                "error": "media_too_large",
                "message": f"the published copy is {size} bytes; links are limited to "
                           f"{cfg.media_max_bytes}"})
        return {"media_state": MEDIA_READY, "media_version": st.source_version,
                "duration_ms": primary.get("duration_ms"), "output_bytes": size}
    if not publish:
        raise HTTPException(status.HTTP_409_CONFLICT, {
            "error": "not_published",
            "message": "this file is still being published (publish=false)"})
    return {"media_state": MEDIA_PENDING}


@router.get("/capabilities")
def capabilities(request: Request, caller: Caller = Depends(get_caller)) -> dict:
    """What this deployment's share links can do, so the Share tab offers only
    what will work (MEDIA_SHARE.md §10). `open_mode` is the deployment switch
    only — whether THIS caller may mint one also needs the share_public group,
    which the create call checks and explains."""
    cfg = _config(request)
    return {"enabled": bool(cfg.enabled),
            "media": {"available": bool(cfg.enabled and cfg.media_enabled),
                      "open_mode": bool(cfg.allow_open_mode),
                      "playback_tracking": bool(cfg.playback_tracking),
                      "max_bytes": cfg.media_max_bytes,
                      "default_max_bytes": cfg.media_default_max_bytes}}


@router.post("/nodes/{resource_uid}/links", status_code=status.HTTP_201_CREATED)
def create_link(resource_uid: str, body: CreateLinkRequest, request: Request,
                caller: Caller = Depends(get_caller)) -> dict:
    """Mint a link. The response carries the only copy of the secret."""
    cfg = _config(request)
    _require_enabled(cfg)

    if body.kind not in KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown kind {body.kind}")
    is_media = body.kind == KIND_MEDIA
    mode = (body.access_mode or ACCESS_VERIFIED).strip().lower()
    if mode not in ACCESS_MODES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown access_mode {mode!r}")
    # The database refuses this too (a CHECK constraint); answering here gives
    # the caller a reason instead of a 500.
    if not is_media and mode != ACCESS_VERIFIED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "only media links may be claimed or open")
    if is_media and not cfg.media_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "media links are disabled here")

    # --- gate 1 (per-user): the share_external LDAP group (spec §8.1) ------
    try:
        if not in_share_group(cfg, caller.user):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "you are not permitted to create outside share links")
    except UnknownUser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "unknown user")
    except LdapUnavailable:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "directory unavailable; cannot confirm permissions")

    # --- an open link needs all three gates (MEDIA_SHARE.md §5) -----------
    if mode == ACCESS_OPEN:
        if not cfg.allow_open_mode:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "open links are not permitted on this deployment")
        if not body.confirm_public:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                {"error": "confirm_public_required",
                                 "message": f"confirm that {OPEN_LINK_WARNING}"})
        try:
            if not in_open_group(cfg, caller.user):
                raise HTTPException(status.HTTP_403_FORBIDDEN,
                                    f"publishing an open link needs membership of "
                                    f"{cfg.open_ldap_group!r}")
        except UnknownUser:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "unknown user")
        except LdapUnavailable:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "directory unavailable; cannot confirm permissions")

    # --- recipients + expiry ----------------------------------------------
    emails: list[str] = []
    for raw in body.recipients:
        e = links.normalize_email(raw)
        if e and e not in emails:
            emails.append(e)
    if mode == ACCESS_OPEN and emails:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "an open link has no recipient list")
    if mode == ACCESS_VERIFIED and not emails:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "at least one recipient is required")
    if len(emails) > cfg.max_recipients:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"at most {cfg.max_recipients} recipients")
    try:
        expires_at = links.clamp_expiry(cfg, body.expires_at, body.ttl_days)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    # A media link is metered by viewers and bytes, not by uses (§6.4): a
    # session per seek would exhaust any use cap in one viewing.
    if is_media and body.max_uses:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "a media link is limited by max_viewers and max_bytes, not max_uses")
    if body.max_viewers < 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "max_viewers must be 0 or more")
    embed_origins = (_embed_origins(body.allowed_embed_origins, mode=mode, cfg=cfg)
                     if is_media else None)
    # The public title (§6.8). Defaulting it to the file name would publish
    # whatever the internal naming says — "ACME-Q3-teardown-CONFIDENTIAL-v4" —
    # so an OPEN link must be given one; the others default below.
    display_name = (body.display_name or "").strip()[:200] or None
    if is_media and mode == ACCESS_OPEN and not display_name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            {"error": "display_name_required",
                             "message": "an open link needs a public title"})
    if (not is_media and cfg.max_uses_cap
            and (body.max_uses == 0 or body.max_uses > cfg.max_uses_cap)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"max_uses must be between 1 and {cfg.max_uses_cap}")

    # --- gate 2 (per-resource) + the pre-flight ---------------------------
    # These are the same check: the pre-flight runs exactly what a redemption
    # will run, so a link that would be born dead is refused here (spec §6.3).
    permission = core_client.WRITE if body.kind == KIND_UPLOAD else core_client.READ
    result = preflight.check(cfg, created_by=caller.user, tenant=caller.tenant,
                             resource_uid=resource_uid, permission=permission,
                             source_addr=caller.source_addr)
    if not result:
        detail = {"error": result.reason, "message": preflight.creator_message(result)}
        code = (status.HTTP_503_SERVICE_UNAVAILABLE
                if result.reason == preflight.REASON_LDAP
                else status.HTTP_403_FORBIDDEN)
        raise HTTPException(code, detail)

    # --- the kind must match the resource type, and (kind 2) the snapshot --
    # Both need a delegated client, so they share one.
    snap = None
    pinned_version = None
    file_bytes = None
    depth = None
    path = ""
    poster_uid = None
    try:
        with core_client.for_creator(cfg, created_by=caller.user, roles=result.roles or [],
                                     tenant=caller.tenant,
                                     source_addr=caller.source_addr) as core:
            is_dir = core.is_dir(resource_uid)
            # Where this sits in the tree, captured once. The admin console
            # sorts by it (spec §10.3) and cannot afford a core round-trip per
            # row across a whole tenant.
            depth, path = core.locate(resource_uid)
            if not links.kind_matches_resource(body.kind, is_dir):
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    "kind does not match the resource type "
                                    "(file for kinds 0 and 3, folder for kinds 1 and 2)")
            if is_media:
                poster_uid = core.poster_uid(resource_uid)
                if not display_name:
                    display_name = (path.rsplit("/", 1)[-1] or None) if path else None
            # A file link records the ENTITY UUID AND THE VERSION TIMESTAMP, so
            # it keeps serving what it was minted for. Unpinned is the explicit
            # opt-in: without this a document shared for review in March
            # silently exposes whatever it becomes in September (spec §6.2).
            if body.kind == KIND_FILE_DOWNLOAD:
                # Recorded now, into the same column a folder link uses for its
                # archive total, so /peek stays a pure DB read: that route is
                # unauthenticated, and it must not turn an anonymous visitor
                # into a delegated core call.
                try:
                    file_bytes = int(core.stat(resource_uid).size)
                except Exception:  # noqa: BLE001
                    file_bytes = None
                if not body.follow_latest:
                    pinned_version = core.current_version(resource_uid)
                    if not pinned_version:
                        raise HTTPException(
                            status.HTTP_400_BAD_REQUEST,
                            "this file has no saved version yet, so there is "
                            "nothing to share")
            # A folder-download link captures its members now (spec §6.5).
            # `follow_folder` opts into live semantics and takes no snapshot.
            if body.kind == KIND_FOLDER_DOWNLOAD and not body.follow_folder:
                snap = snapshot_mod.walk(core, cfg, resource_uid,
                                         include_subdirs=body.include_subdirs)
    except HTTPException:
        raise
    except snapshot_mod.SnapshotTooLarge as e:
        # Refused here, with the numbers, so the recipient never discovers the
        # limit mid-download (spec §6.1).
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            {"error": "folder_too_large", "message": str(e),
                             "members": e.members, "total_bytes": e.total_bytes,
                             "max_members": cfg.zip_max_members,
                             "max_bytes": cfg.zip_max_bytes})
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"core unavailable: {e}")

    # --- media: resolve the published rendition, or ask for it (§6.2 rule 2)
    media_fields: dict = {}
    if is_media:
        media_fields = _resolve_media(cfg, request, caller, resource_uid, body.publish)

    # --- mint --------------------------------------------------------------
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link, secret = links.create(
            conn, kind=body.kind, resource_uid=resource_uid, created_by=caller.user,
            expires_at=expires_at, recipients=emails,
            max_uses=body.max_uses, max_uses_per_recipient=body.max_uses_per_recipient,
            # A media link always carries an egress budget (§6.9): an
            # unbounded one is how a viral clip becomes the tenant's bill.
            max_bytes=body.max_bytes or (cfg.media_default_max_bytes if is_media else 0),
            max_file_bytes=body.max_file_bytes,
            max_files=body.max_files or (cfg.upload_max_files if body.kind == KIND_UPLOAD else 0),
            # Recorded in the cross-tenant directory too, so a recipient — who
            # arrives with no tenant context at all — can be routed to the right
            # schema. Without it a link outside the default tenant is unfindable.
            tenant=caller.tenant,
            pinned_version=pinned_version,
            follow_folder=body.follow_folder, include_subdirs=body.include_subdirs,
            landing_prefix=body.landing_prefix, ext_allowlist=body.ext_allowlist,
            archive_bytes=file_bytes, resource_depth=depth, resource_path=path,
            note=body.note,
            **({"access_mode": mode, "max_viewers": body.max_viewers,
                "allowed_embed_origins": embed_origins,
                "display_name": display_name,
                "poster_uid": poster_uid,
                "allow_download": (body.allow_download if body.allow_download is not None
                                   else mode == ACCESS_VERIFIED),
                **media_fields} if is_media else {}))

        if snap is not None:
            snapshot_mod.store(conn, link.link_uid, snap)
            link = links.get(conn, link.link_uid)

        # Fail-closed: creation is a grant of access, so it does not stand if it
        # cannot be recorded (spec §12).
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_create", outcome="ok", category="permission",
                actor=caller.user, tenant=caller.tenant, target_uid=resource_uid,
                source_addr=caller.source_addr, request_id=link.link_uid,
                detail={"link_uid": link.link_uid, "kind": link.kind,
                        "recipients": len(emails), "expires_at": expires_at.isoformat(),
                        "max_uses": link.max_uses, "access_mode": link.access_mode,
                        **({"media_state": link.media_state,
                            "embed_origins": len(link.allowed_embed_origins or []),
                            "max_viewers": link.max_viewers}
                           if link.kind == KIND_MEDIA else {})})
        except AuditUnavailable:
            links.revoke(conn, link.link_uid, revoked_by="system:audit-unavailable")
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "link not created: the audit record could not be written")
    finally:
        conn.close()

    payload = _link_json(link)
    payload["url"] = _public_url(cfg, request, caller.tenant, link.link_uid, secret)
    if link.kind == KIND_MEDIA:
        # The media door's own address, for an embed (MEDIA_SHARE.md §9). Carries
        # the secret like the landing URL does; absent when no media origin is
        # configured rather than pointing at the wrong one.
        origin = media_origin(cfg, request, caller.tenant)
        if origin:
            payload["media_url"] = f"{origin}/media/v1/{link.link_uid}?k={secret}"
    payload["secret_shown_once"] = True
    if snap is not None:
        # The numbers the creator pastes into their own email (spec §13-R9),
        # and the ones that make the archive size a decision rather than a
        # surprise on a phone.
        payload["member_count"] = snap.file_count
        payload["archive_bytes"] = snap.archive_bytes
        payload["worst_case_egress_bytes"] = (
            snap.archive_bytes * link.max_uses if link.max_uses else None)
        if snap.skipped:
            payload["skipped"] = snap.skipped
    return payload


@router.get("/nodes/{resource_uid}/links")
def list_node_links(resource_uid: str, request: Request,
                    caller: Caller = Depends(get_caller)) -> dict:
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        found = [l for l in links.list_for_resource(conn, resource_uid)
                 if l.created_by == caller.user]
    finally:
        conn.close()
    return {"links": [_link_json(l) for l in found]}


@router.get("/links")
def list_my_links(request: Request, live: bool = True, all: bool = False,
                  creator: str = "", recipient: str = "", subtree: str = "",
                  status_filter: str = Query("", alias="status"),
                  caller: Caller = Depends(get_caller)) -> dict:
    """The caller's own links, or — with `all=true` and the admin role — the
    tenant-wide oversight view (spec §10.3).

    One route rather than two because the shape is identical and the ONLY
    difference is scope; a separate /admin/links would invite the two to drift
    into disagreeing about what "expired" means.
    """
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        if not all:
            found = links.list_for_creator(conn, caller.user, live_only=live)
            return {"links": [_link_json(l) for l in found]}

        _require_admin(cfg, caller)
        rows = links.list_for_tenant(
            conn, live_only=live, creator=creator, recipient=recipient,
            subtree=subtree, status=status_filter)
    finally:
        conn.close()

    return {"links": [
        # The extra columns exist only on this view. `creator` is the
        # departed-employee query's pivot, so it is first-class here while the
        # owner-side view has no use for it.
        {**_link_json(r["link"]),
         "creator": r["link"].created_by,
         "recipient_count": r["recipient_count"],
         "last_activity": r["last_activity"],
         "resource_path": r["link"].resource_path,
         "resource_depth": r["link"].resource_depth}
        for r in rows],
        "scope": "tenant",
        # Surfaced, never silent: see links.list_for_tenant.
        "truncated": bool(rows and rows[0].get("truncated"))}


class ProvenanceRequest(BaseModel):
    file_uids: List[str] = Field(default_factory=list)


@router.post("/files/provenance")
def file_provenance(body: ProvenanceRequest, request: Request,
                    caller: Caller = Depends(get_caller)) -> dict:
    """Batch: which of these files came from outside, and from whom.

    Answers the file list's "this was dropped by someone external" marker in one
    query per page. Read from the redemption ledger, NOT from the core's
    `share.*` metadata: the core reserves no namespace there, so anyone with
    WRITE can rewrite those keys, which disqualifies them as evidence. The
    ledger mirrors the audit chain, which is the source of truth and outlives
    these rows when retention prunes them.

    Keyed on the file uid, so a move or rename does not lose the marker.

    **ACL-filtered as the CALLER** — the one place this service asks the core a
    question as the caller rather than delegating as a link creator.

    Be clear about how strong that filter is: the core is read-by-default, so an
    unrelated signed-in user can reach most files and will see the marker too.
    That is the intended posture, not a hole — if you may read the file, knowing
    it came from outside is not an escalation, and it is exactly what a
    colleague browsing the folder needs to know. What the filter genuinely stops
    is answering for uids the caller cannot reach AT ALL: deleted resources, and
    anything under an explicit DENY.

    Batched over one connection, and only files that actually have provenance
    reach the core — the common case (no drops on the page) costs nothing.
    """
    cfg = _config(request)
    uids = [u for u in dict.fromkeys(body.file_uids) if u][:cfg.provenance_batch_max]
    if not uids:
        return {"provenance": {}}

    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        found = links.provenance_for_files(conn, uids)
    finally:
        conn.close()
    if not found:
        return {"provenance": {}}

    visible = {}
    try:
        with core_client.for_creator(cfg, created_by=caller.user,
                                     roles=list(caller.roles), tenant=caller.tenant,
                                     source_addr=caller.source_addr) as core:
            for uid, row in found.items():
                # can_reach, not check_permission: read-by-default means a
                # missing uid PASSES a bare permission check, so existence has
                # to be part of the question (spec §6.3).
                if core.can_reach(uid):
                    visible[uid] = row
    except Exception as e:  # noqa: BLE001 - unable to check means show nothing
        log.warning("provenance ACL check failed for %s: %s", caller.user, e)
        return {"provenance": {}}

    return {"provenance": {
        # `stored_name` is the name the file ARRIVED as. Usually identical to
        # its current name, and useful exactly when it is not — a collision
        # renamed it on the way in, or someone renamed it since.
        uid: {"email": r["email"], "at": r["at"], "shared_by": r["shared_by"],
              "stored_name": r.get("stored_name")}
        for uid, r in visible.items()}}


@router.get("/links/mine/inbox")
def sharing_inbox(request: Request,
                  caller: Caller = Depends(get_caller)) -> dict:
    """The Dashboard's Sharing panel: "what have I got open right now" (§10.6).

    Grouped rather than flat, because the three groups want different reactions:
    something is wrong, something arrived, and everything else is fine.

    This is ALSO where "your link stopped working" is detected. That state has no
    triggering event — nothing happens when an ACL three folders up is edited —
    so rather than build a watcher, the pre-flight is evaluated here, bounded by
    the caller's own live-link count. A link that is dead but unnoticed costs
    nothing until someone looks, and this is the moment someone looks.
    """
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        live = links.list_for_creator(conn, caller.user, live_only=True)
        counts = {l.link_uid: links.count_recipients(conn, l.link_uid) for l in live}
    finally:
        conn.close()

    # Per LINK, not once for the caller: the most common way a link dies is an
    # ACL change on its own resource, so one answer for the whole set would miss
    # exactly the case this exists to catch. check_many resolves the creator's
    # LDAP roles once and shares a single core connection, so the cost is one
    # directory round-trip plus one gRPC call per link rather than N of each.
    verdicts = preflight.check_many(
        cfg, created_by=caller.user, tenant=caller.tenant,
        targets=[(l.link_uid, l.resource_uid, l.pinned_version or "") for l in live],
        source_addr=caller.source_addr)

    needs, drops_, active = [], [], []
    for l in live:
        row = _link_json(l)
        row["recipient_count"] = counts.get(l.link_uid, 0)
        verdict = verdicts.get(l.link_uid)
        if verdict is not None and not verdict.ok:
            row["status"] = "not_working"
            row["not_working_reason"] = verdict.reason
            row["not_working_message"] = preflight.creator_message(verdict)
        if row["status"] == "not_working" or l.status() == "blocked":
            needs.append(row)
        elif l.kind == KIND_UPLOAD:
            drops_.append(row)
        else:
            active.append(row)

    # "Needs attention" is empty most days, and that emptiness is the point.
    return {"needs_attention": needs, "drop_boxes": drops_, "active": active}


@router.post("/admin/revoke-all")
def admin_revoke_all(body: RevokeAllRequest, request: Request,
                     caller: Caller = Depends(get_caller)) -> dict:
    """End every live link one creator left open — the departed-employee action.

    Audited one event per link, with the acting ADMIN as actor and the creator
    recorded in the detail. A single "revoked 14 links" event is not a record
    anyone can later answer questions from, and the person who pushed the button
    is the fact an oversight trail most needs.
    """
    cfg = _config(request)
    _require_admin(cfg, caller)
    target = (body.creator or "").strip()
    if not target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "creator is required")

    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        # Read the rows BEFORE revoking: the audit event wants each link's
        # resource_uid, and after the update they no longer match "live".
        doomed = {r["link"].link_uid: r["link"]
                  for r in links.list_for_tenant(conn, live_only=True,
                                                 creator=target, limit=10000)}
        revoked = links.revoke_all_for_creator(conn, target, caller.user)
    finally:
        conn.close()

    unaudited = []
    for uid in revoked:
        link = doomed.get(uid)
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_revoke", outcome="ok", category="permission",
                actor=caller.user, tenant=caller.tenant,
                target_uid=link.resource_uid if link else "",
                source_addr=caller.source_addr, request_id=uid,
                detail={"link_uid": uid, "creator": target,
                        "by": "admin_revoke_all"})
        except AuditUnavailable:
            unaudited.append(uid)

    if unaudited:
        # Same rule as the single revoke: the safe direction already happened,
        # so report the gap loudly rather than rolling access back open.
        log.error("admin_revoke_all NOT audited for %s", unaudited)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            f"{len(revoked)} links revoked, but {len(unaudited)} "
                            "audit records could not be written — report this")
    return {"creator": target, "revoked": len(revoked), "link_uids": revoked}


@router.get("/links/{link_uid}")
def get_link(link_uid: str, request: Request,
             caller: Caller = Depends(get_caller)) -> dict:
    """One link's live status — including the re-run pre-flight.

    This is what surfaces "not working: you no longer have access" (spec
    §10.2). A link can stop working with nothing about the link having changed,
    and without this the creator's experience is "my recipient says it's broken
    and everything looks fine to me".
    """
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link = _owned_link(conn, link_uid, caller, cfg)
    finally:
        conn.close()

    payload = _link_json(link)
    if link.status() == "active":
        permission = core_client.WRITE if link.kind == KIND_UPLOAD else core_client.READ
        result = preflight.check(cfg, created_by=link.created_by, tenant=caller.tenant,
                                 resource_uid=link.resource_uid, permission=permission,
                                 pinned_version=link.pinned_version or "",
                                 source_addr=caller.source_addr)
        if not result:
            payload["status"] = "not_working"
            payload["not_working_reason"] = result.reason
            payload["not_working_message"] = preflight.creator_message(result)
    return payload


@router.delete("/links/{link_uid}")
def revoke_link(link_uid: str, request: Request,
                caller: Caller = Depends(get_caller)) -> dict:
    """Revoke. Idempotent — revoking an already-revoked link is a success."""
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        # cfg passed => a tenant admin may revoke someone else's link. This is
        # the ONE power the console adds; it cannot mint, cannot re-send (the
        # plaintext secret does not exist server-side), and cannot read content.
        link = _owned_link(conn, link_uid, caller, cfg)
        changed = links.revoke(conn, link_uid, caller.user)
        if changed and link.kind == KIND_MEDIA:
            # The sidecar is projected immediately on revoke (§8.2), not at the
            # next debounce: the last word on who watched should not wait.
            audience.mark_dirty(conn, link.resource_uid, force=True)
    finally:
        conn.close()
    on_behalf = link.created_by != caller.user
    if changed and link.kind == KIND_MEDIA and cfg.audience_csv_enabled:
        try:
            audience.project(cfg, caller.tenant, link.resource_uid)
        except Exception:  # noqa: BLE001 - the sweep retries; a revoke never fails on it
            log.exception("audience projection after revoke failed for %s", link_uid)

    if changed:
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_revoke", outcome="ok", category="permission",
                actor=caller.user, tenant=caller.tenant, target_uid=link.resource_uid,
                source_addr=caller.source_addr, request_id=link_uid,
                detail={"link_uid": link_uid,
                        **({"creator": link.created_by, "by": "admin"}
                           if on_behalf else {})})
        except AuditUnavailable:
            # The revocation already happened and is the safe direction; do not
            # roll it back over an audit failure. Report the gap loudly instead.
            log.error("share_link_revoke NOT audited for %s", link_uid)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "link revoked, but the audit record could not be "
                                "written — report this")
    return {"link_uid": link_uid, "revoked": True, "changed": changed}


@router.get("/links/{link_uid}/recipients")
def list_recipients(link_uid: str, request: Request, include_removed: bool = False,
                    caller: Caller = Depends(get_caller)) -> dict:
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        _owned_link(conn, link_uid, caller, cfg)
        roster = links.recipients(conn, link_uid, include_removed=include_removed)
    finally:
        conn.close()
    return {"recipients": roster}


@router.get("/links/{link_uid}/redemptions")
def list_redemptions(link_uid: str, request: Request, limit: int = 200,
                     caller: Caller = Depends(get_caller)) -> dict:
    """The link's usage ledger (spec §7.1).

    Read from this service's own rows rather than from the audit log, so an
    ordinary creator can see who used their link without holding an AUDIT_READ
    scope. The full forensic trail stays in `audit_service` for anyone who does.
    """
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        _owned_link(conn, link_uid, caller, cfg)
        return {"redemptions": links.redemptions(conn, link_uid, limit=min(limit, 500))}
    finally:
        conn.close()


@router.post("/links/{link_uid}/recipients", status_code=status.HTTP_201_CREATED)
def add_recipient(link_uid: str, body: AddRecipientRequest, request: Request,
                  caller: Caller = Depends(get_caller)) -> dict:
    """Extend the allowlist after the fact. An outside caller never can (spec
    §6.9); this is audited as a permission change because it widens who can
    reach the resource."""
    cfg = _config(request)
    _require_enabled(cfg)
    email = links.normalize_email(body.email)
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "email required")

    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        # No `cfg` here, deliberately: an admin must not widen someone else's
        # link. Console powers stop at revocation (spec §10.3) - adding an
        # address is a grant of access, the direction oversight is meant to
        # close, not open.
        link = _owned_link(conn, link_uid, caller)
        # A dead link can never work again, so this would grant nothing — but it
        # would still write a `permission` audit event saying access was widened
        # and put the address on a roster the creator reads as "these people can
        # reach this file". Both would be false, and the audit chain is the only
        # custodian of the fact that an access was external (spec §11), so a
        # phantom grant there is the expensive kind. Refuse.
        #
        # Measured in production 2026-09-09: an address was added 28 seconds
        # AFTER the link was revoked, and the call returned 201.
        if link.is_dead:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {"error": "link_not_live", "status": link.status(),
                 "message": f"this link is {link.status()} — it cannot be "
                            "widened; create a new one instead"})
        # An open link has no recipient list (MEDIA_SHARE.md §5 rule 3); an
        # address on it would read as a restriction that does not exist.
        if link.access_mode == ACCESS_OPEN:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "an open link has no recipient list")
        if links.count_recipients(conn, link_uid) >= cfg.max_recipients:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"at most {cfg.max_recipients} recipients")
        links.add_recipient(conn, link_uid, email, caller.user)
    finally:
        conn.close()

    try:
        get_emitter(cfg).emit_or_raise(
            action="share_link_recipient_add", outcome="ok", category="permission",
            actor=caller.user, tenant=caller.tenant, source_addr=caller.source_addr,
            request_id=link_uid, detail={"link_uid": link_uid, "email": email})
    except AuditUnavailable:
        links.remove_recipient(conn := db.connect_for_tenant(cfg, caller.tenant),
                               link_uid, email, "system:audit-unavailable")
        conn.close()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "recipient not added: the audit record could not be written")
    return {"link_uid": link_uid, "email": email}


@router.delete("/links/{link_uid}/recipients/{email}")
def remove_recipient(link_uid: str, email: str, request: Request,
                     caller: Caller = Depends(get_caller)) -> dict:
    """Partial revoke — cheaper than revoking and re-issuing, which would
    invalidate the URL for everyone who already has it (spec §10.2)."""
    cfg = _config(request)
    normalized = links.normalize_email(email)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        _owned_link(conn, link_uid, caller, cfg)
        changed = links.remove_recipient(conn, link_uid, normalized, caller.user)
    finally:
        conn.close()

    if changed:
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_recipient_remove", outcome="ok",
                category="permission", actor=caller.user, tenant=caller.tenant,
                source_addr=caller.source_addr, request_id=link_uid,
                detail={"link_uid": link_uid, "email": normalized})
        except AuditUnavailable:
            log.error("share_link_recipient_remove NOT audited for %s/%s",
                      link_uid, normalized)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "recipient removed, but the audit record could not "
                                "be written — report this")
    return {"link_uid": link_uid, "email": normalized, "removed": True, "changed": changed}


# --- the audience (MEDIA_SHARE.md §7.2, §8) ---------------------------------

def _media_link_owned(conn, link_uid: str, caller: Caller) -> links.Link:
    """The creator's own media link. NOT widened to tenant admins: the roster is
    personal data about people the creator chose to send to."""
    link = _owned_link(conn, link_uid, caller)
    if link.kind != KIND_MEDIA:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return link


@router.get("/links/{link_uid}/audience")
def link_audience(link_uid: str, request: Request,
                  caller: Caller = Depends(get_caller)) -> dict:
    """Who watched this link, and how much (§7.2). `verified` is the column a
    reader must branch on: a claimed address was typed, never checked."""
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link = _media_link_owned(conn, link_uid, caller)
        roster = audience.rows(conn, link.resource_uid, link_uid)
        from .playback import retention_curve
        curve = retention_curve(conn, link_uid) if cfg.playback_tracking else []
    finally:
        conn.close()
    totals = {"viewers": len(roster),
              "completed": sum(1 for r in roster if r["completed"]),
              "bytes_served": sum(int(r["bytes_served"] or 0) for r in roster),
              "referers": sorted({r["referer_host"] for r in roster if r["referer_host"]}),
              "retention": curve}
    return {"link_uid": link_uid, "mode": link.access_mode,
            "tracking": bool(cfg.playback_tracking),
            "unverified_note": ("These people typed an address to watch. We did not check "
                                "it, so any of them may be inaccurate or invented.")
            if link.access_mode == "claimed" else None,
            # An open link has no addresses: the aggregate is the roster.
            "audience": [] if link.access_mode == "open" else roster,
            "totals": totals}


@router.get("/links/{link_uid}/audience.csv")
def link_audience_csv(link_uid: str, request: Request,
                      caller: Caller = Depends(get_caller)):
    """The same data as the sidecar, as a download (§7.2)."""
    from fastapi.responses import Response
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link = _media_link_owned(conn, link_uid, caller)
        body = audience.render(audience.rows(conn, link.resource_uid, link_uid))
    finally:
        conn.close()
    get_emitter(cfg).emit(action="share_audience_exported", outcome="ok", category="access",
                          actor=caller.user, tenant=caller.tenant, target_uid=link.resource_uid,
                          source_addr=caller.source_addr, request_id=link_uid,
                          detail={"link_uid": link_uid, "via": "export"})
    return Response(body, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{audience.per_link_name(link_uid)}"',
                             "Cache-Control": "no-store"})


@router.post("/links/{link_uid}/audience/flush")
def flush_audience(link_uid: str, request: Request,
                   caller: Caller = Depends(get_caller)) -> dict:
    """Regenerate the sidecar now rather than at the next debounce (§8.2)."""
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link = _media_link_owned(conn, link_uid, caller)
        audience.mark_dirty(conn, link.resource_uid, force=True)
    finally:
        conn.close()
    return audience.project(cfg, caller.tenant, link.resource_uid)


class EraseAddressRequest(BaseModel):
    email: str


@router.post("/admin/audience/erase")
def erase_audience_address(body: EraseAddressRequest, request: Request,
                           caller: Caller = Depends(get_caller)) -> dict:
    """An erasure request naming an address (§8.4) — a tenant administrator's
    action. Clears the address's audience and playback rows in this tenant and
    regenerates every sidecar that held it."""
    cfg = _config(request)
    _require_admin(cfg, caller)
    email = links.normalize_email(body.email)
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "email required")
    get_emitter(cfg).emit_or_raise(
        action="share_audience_erased", outcome="ok", category="admin", actor=caller.user,
        tenant=caller.tenant, source_addr=caller.source_addr, request_id=email,
        detail={"email": email})
    return audience.erase_address(cfg, caller.tenant, email)
