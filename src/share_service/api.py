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

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from . import core_client, db, links, preflight, snapshot as snapshot_mod
from .audit import AuditUnavailable, get_emitter
from .auth import Caller, get_caller
from .config import Config
from .ldap_roles import LdapUnavailable, UnknownUser, in_share_group
from .schema import KIND_FILE_DOWNLOAD, KIND_FOLDER_DOWNLOAD, KIND_UPLOAD, KINDS

log = logging.getLogger("share_service.api")

router = APIRouter(prefix="/share/v1", dependencies=[Depends(get_caller)])


# --- request / response models -------------------------------------------

class CreateLinkRequest(BaseModel):
    """Note there is no `resource_uid`: the target comes from the path, and for
    every later call from the stored row. Nor a `send_invite`: v1 sends no
    invite mail — the creator composes their own (spec §13-R9)."""
    kind: int = Field(..., description="0 file download, 1 upload, 2 folder download")
    recipients: List[str] = Field(..., min_length=1)
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
        # Never the secret. It existed once, in the creation response.
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


def _owned_link(conn, link_uid: str, caller: Caller) -> links.Link:
    """Fetch a link the caller may act on, or 404.

    404 rather than 403 for someone else's link: whether a link exists is not
    something an unrelated user should be able to probe.
    """
    try:
        link = links.get(conn, link_uid)
    except links.LinkNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    if link.created_by != caller.user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return link


def _public_url(cfg: Config, request: Request, link_uid: str, secret: str) -> str:
    base = cfg.public_base_url or str(request.base_url).rstrip("/")
    return f"{base.rstrip('/')}/s/{link_uid}.{secret}"


# --- routes ---------------------------------------------------------------

@router.post("/nodes/{resource_uid}/links", status_code=status.HTTP_201_CREATED)
def create_link(resource_uid: str, body: CreateLinkRequest, request: Request,
                caller: Caller = Depends(get_caller)) -> dict:
    """Mint a link. The response carries the only copy of the secret."""
    cfg = _config(request)
    _require_enabled(cfg)

    if body.kind not in KINDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown kind {body.kind}")

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

    # --- recipients + expiry ----------------------------------------------
    emails: list[str] = []
    for raw in body.recipients:
        e = links.normalize_email(raw)
        if e and e not in emails:
            emails.append(e)
    if not emails:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "at least one recipient is required")
    if len(emails) > cfg.max_recipients:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"at most {cfg.max_recipients} recipients")
    try:
        expires_at = links.clamp_expiry(cfg, body.expires_at, body.ttl_days)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    if cfg.max_uses_cap and (body.max_uses == 0 or body.max_uses > cfg.max_uses_cap):
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
    try:
        with core_client.for_creator(cfg, created_by=caller.user, roles=result.roles or [],
                                     tenant=caller.tenant,
                                     source_addr=caller.source_addr) as core:
            is_dir = core.is_dir(resource_uid)
            if not links.kind_matches_resource(body.kind, is_dir):
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    "kind does not match the resource type "
                                    "(file for kind 0, folder for kinds 1 and 2)")
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

    # --- mint --------------------------------------------------------------
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        link, secret = links.create(
            conn, kind=body.kind, resource_uid=resource_uid, created_by=caller.user,
            expires_at=expires_at, recipients=emails,
            max_uses=body.max_uses, max_uses_per_recipient=body.max_uses_per_recipient,
            max_bytes=body.max_bytes, max_file_bytes=body.max_file_bytes,
            max_files=body.max_files or (cfg.upload_max_files if body.kind == KIND_UPLOAD else 0),
            pinned_version=pinned_version,
            follow_folder=body.follow_folder, include_subdirs=body.include_subdirs,
            landing_prefix=body.landing_prefix, ext_allowlist=body.ext_allowlist,
            archive_bytes=file_bytes, note=body.note)

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
                        "max_uses": link.max_uses})
        except AuditUnavailable:
            links.revoke(conn, link.link_uid, revoked_by="system:audit-unavailable")
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "link not created: the audit record could not be written")
    finally:
        conn.close()

    payload = _link_json(link)
    payload["url"] = _public_url(cfg, request, link.link_uid, secret)
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
def list_my_links(request: Request, live: bool = True,
                  caller: Caller = Depends(get_caller)) -> dict:
    cfg = _config(request)
    conn = db.connect_for_tenant(cfg, caller.tenant, provision=True)
    try:
        found = links.list_for_creator(conn, caller.user, live_only=live)
    finally:
        conn.close()
    return {"links": [_link_json(l) for l in found]}


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
        link = _owned_link(conn, link_uid, caller)
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
        link = _owned_link(conn, link_uid, caller)
        changed = links.revoke(conn, link_uid, caller.user)
    finally:
        conn.close()

    if changed:
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_revoke", outcome="ok", category="permission",
                actor=caller.user, tenant=caller.tenant, target_uid=link.resource_uid,
                source_addr=caller.source_addr, request_id=link_uid,
                detail={"link_uid": link_uid})
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
        _owned_link(conn, link_uid, caller)
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
        _owned_link(conn, link_uid, caller)
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
        _owned_link(conn, link_uid, caller)
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
        _owned_link(conn, link_uid, caller)
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
