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

"""The public door — unauthenticated (spec §7.2). **The review gate.**

This is the only surface in the platform reachable without an account, so a few
rules hold here that hold nowhere else. They are listed together because each
one is individually easy to erode:

1. **This router is mounted separately, with its own dependencies.** It does not
   read a bearer token and never falls back to session auth, so a redemption can
   never be misattributed to a passing authenticated browser. The owner-side
   router requires a caller by construction; nothing is allowlisted in either
   direction. That structural split is the whole reason `share_service` is a
   service rather than routes bolted onto the bridge (spec §7).

2. **Every failure is the same failure.** Unknown link, bad secret, expired,
   revoked, exhausted, locked, resource deleted, creator lost access, address
   not on the allowlist — all return `404 {"error":"not_found"}` (spec §8.5).
   Anything else turns this into an oracle: "this link exists but is exhausted"
   tells an attacker they hold a valid uid, and a distinct answer for an
   unlisted address enumerates the recipient list.

3. **Uniformity holds all the way through verification, then relaxes.** The
   code-entry screen is reachable by anyone with the URL, so its countdown and
   attempt feedback must read identically for a listed and an unlisted address
   (spec §10.4). Only once a recipient token exists — proof of control of a
   listed address — may this door say plainly that a session expired.

4. **The response headers are set once, for the whole router, before dispatch.**
   `Content-Disposition: attachment` + `nosniff` + `CSP: sandbox` are the
   anti-XSS boundary (spec §8.3): a shared `.html` fetched on the SPA's origin
   would otherwise run script there and read the bearer token out of
   `localStorage`. A new route inherits them or does not ship.

5. **The target uid comes only from the link record.** The core will stream
   anything the creator can read, so nothing behind this service constrains
   which uid is asked for (spec §4.3).
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from . import archive, db, links, otp_client, preflight, sessions
from . import snapshot as snapshot_mod
from .audit import AuditUnavailable, get_emitter
from .auth import client_addr
from .config import Config
from .core_client import READ, WRITE, VersionGone, for_creator
from .ldap_roles import LdapUnavailable, UnknownUser, resolve_share_roles
from .schema import KIND_FILE_DOWNLOAD, KIND_FOLDER_DOWNLOAD, KIND_UPLOAD

log = logging.getLogger("share_service.public")

router = APIRouter(prefix="/share/v1/public")

# The one response an outside caller ever gets when anything is wrong.
_NOT_FOUND = {"error": "not_found"}

# Set on every response from this router, including errors (spec §8.3).
_HARDENING = {
    "Content-Disposition": "attachment",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
    "Content-Security-Policy": "sandbox",
    "Referrer-Policy": "no-referrer",
}


def install_hardening(app) -> None:
    """Apply the header set to everything under the public prefix.

    Deliberately middleware rather than per-route: point 4 above only holds if
    forgetting is impossible, and a per-route decorator is exactly the kind of
    thing that gets forgotten on the sixth route.
    """
    @app.middleware("http")
    async def _harden(request: Request, call_next):  # noqa: ANN202
        response = await call_next(request)
        if request.url.path.startswith(router.prefix):
            for k, v in _HARDENING.items():
                response.headers[k] = v
        return response


def _json(payload: dict, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    """JSONResponse with FastAPI's encoder applied.

    A bare JSONResponse skips `jsonable_encoder` -- which the owner-side routes
    get for free by returning dicts -- so a datetime in the payload raises at
    render time, after the handler has already succeeded.
    """
    return JSONResponse(jsonable_encoder(payload), status_code=status_code)


def _deny() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, _NOT_FOUND)


def _cfg(request: Request) -> Config:
    return request.app.state.config


def _audit_denied(cfg: Config, *, link_uid: str, reason: str, tenant: str,
                  addr: str, email: str = "") -> None:
    """The real reason lives here and nowhere else (spec §8.5).

    Not fail-closed: a denial that cannot be audited is still a denial, and
    refusing to deny would be the wrong direction.
    """
    get_emitter(cfg).emit(action="share_link_denied", outcome="denied",
                          category="access", actor=f"share:{link_uid}",
                          tenant=tenant, source_addr=addr, request_id=link_uid,
                          detail={"link_uid": link_uid, "reason": reason,
                                  **({"email": email} if email else {})})


# --------------------------------------------------------------------------
# request models
# --------------------------------------------------------------------------

class IdentifyIn(BaseModel):
    email: str


class VerifyIn(BaseModel):
    email: str
    code: str


class SessionIn(BaseModel):
    email: str


# --------------------------------------------------------------------------
# link resolution
# --------------------------------------------------------------------------

def _resolve(request: Request, link_uid: str, secret: Optional[str]):
    """(config, tenant, connection, link) for a live link whose secret matches.

    Raises the uniform 404 for every failure mode. The secret is compared in
    constant time against the stored hash; the plaintext is never logged.
    """
    cfg = _cfg(request)
    if not cfg.enabled or not get_emitter(cfg).available:
        # Auditing off means sharing off (spec §4.3). Same 404 as everything
        # else: an outside caller learns nothing about why.
        raise _deny()

    tenant = request.headers.get("x-tenant") or cfg.default_tenant
    if not secret:
        raise _deny()

    conn = db.connect_for_tenant(cfg, tenant, provision=True)
    try:
        link = links.get(conn, link_uid)
    except links.LinkNotFound:
        conn.close()
        _audit_denied(cfg, link_uid=link_uid, reason="unknown_link", tenant=tenant,
                      addr=client_addr(request))
        raise _deny()
    except Exception:
        conn.close()
        raise _deny()

    if not links.secret_matches(secret, _secret_hash(conn, link_uid)):
        conn.close()
        _audit_denied(cfg, link_uid=link_uid, reason="bad_secret", tenant=tenant,
                      addr=client_addr(request))
        raise _deny()

    if link.status() != "active":
        conn.close()
        _audit_denied(cfg, link_uid=link_uid, reason=link.status(), tenant=tenant,
                      addr=client_addr(request))
        raise _deny()

    return cfg, tenant, conn, link


def _secret_hash(conn, link_uid: str) -> bytes:
    with conn.cursor() as cur:
        cur.execute("SELECT secret_hash FROM share_links WHERE link_uid = %s",
                    (link_uid,))
        row = cur.fetchone()
    return bytes(row[0]) if row else b""


def _live_creator_roles(cfg: Config, link) -> list:
    """The creator's current, admin-stripped roles — or a denial.

    LDAP unreachable denies rather than proceeding with an empty list: empty is
    a legitimate answer that silently strips access inside a gated section, so
    the two must not be confusable (spec §6.3).
    """
    try:
        return resolve_share_roles(cfg, link.created_by)
    except (LdapUnavailable, UnknownUser):
        raise _deny()


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@router.get("/{link_uid}")
def peek(link_uid: str, request: Request, k: Optional[str] = None,
         x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """Metadata only. Consumes nothing, and states that a code will be required.

    Requires the secret: without it a 128-bit uid from a proxy log would leak a
    filename and size.
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    try:
        payload = {
            "kind": link.kind,
            "expires_at": link.expires_at,
            "uses_remaining": (None if link.max_uses == 0
                               else max(0, link.max_uses - link.uses_consumed)),
            "verification_required": True,
            "note": link.note,
        }
        if link.kind == KIND_FOLDER_DOWNLOAD:
            members = snapshot_mod.load(conn, link_uid)
            payload["member_count"] = sum(1 for m in members if not m.is_dir)
            payload["archive_bytes"] = link.archive_bytes
        elif link.kind == KIND_UPLOAD:
            payload["files_remaining"] = (None if link.max_files == 0
                                          else max(0, link.max_files - link.files_consumed))
            payload["bytes_remaining"] = (None if link.max_bytes == 0
                                          else max(0, link.max_bytes - link.bytes_consumed))
        else:
            payload["size_bytes"] = None
        # Deliberately absent: the resource uid, the creator's identity, the
        # recipient list, and how many recipients there are (spec §6.6).
        return _json(payload)
    finally:
        conn.close()


@router.post("/{link_uid}/identify")
def identify(link_uid: str, body: IdentifyIn, request: Request,
             k: Optional[str] = None,
             x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """Mail a code, **iff** the address is on the link's allowlist.

    The response is identical either way — this is the endpoint that would
    otherwise enumerate the recipient list. Re-posting is also the **resend**
    path: there is no separate route, so a recipient whose code expired or never
    arrived submits the same address again (spec §6.9).
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    email = links.normalize_email(body.email)
    addr = client_addr(request)
    try:
        listed = email in {r["email"] for r in links.recipients(conn, link_uid)}
    finally:
        conn.close()

    if listed:
        try:
            result = otp_client.send_code(cfg, link_uid=link_uid, email=email,
                                          tenant=tenant, sender=link.created_by)
        except otp_client.OtpUnavailable:
            _audit_denied(cfg, link_uid=link_uid, reason="otp_unavailable",
                          tenant=tenant, addr=addr, email=email)
            raise _deny()
        if result.send_failed:
            # The creator has to find out: a mail misconfiguration otherwise
            # looks exactly like a mistyped address (spec §6.9). The recipient's
            # response stays uniform regardless.
            log.error("share OTP delivery failed for link %s: %s",
                      link_uid, result.error)
            _audit_denied(cfg, link_uid=link_uid, reason="otp_send_failed",
                          tenant=tenant, addr=addr, email=email)
    else:
        _audit_denied(cfg, link_uid=link_uid, reason="unlisted_address",
                      tenant=tenant, addr=addr, email=email)

    # One response, always. "If that address is authorized, we've sent a code."
    return _json({"status": "sent_if_authorized",
                  "expires_in_seconds": cfg.otp_ttl_seconds})


@router.post("/{link_uid}/verify")
def verify(link_uid: str, body: VerifyIn, request: Request,
           k: Optional[str] = None,
           x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """Exchange a code for a recipient token. Consumes no use.

    An unlisted address is passed to the identity service anyway, so its attempt
    budget and lockout apply identically — otherwise the *shape* of the failure
    would reveal whether the address is on the list (spec §10.4).
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    conn.close()
    email = links.normalize_email(body.email)

    try:
        result = otp_client.verify_code(cfg, link_uid=link_uid, email=email,
                                        tenant=tenant, code=body.code)
    except otp_client.OtpUnavailable:
        raise _deny()

    if not result.ok:
        _audit_denied(cfg, link_uid=link_uid,
                      reason="locked_out" if result.locked else "wrong_code",
                      tenant=tenant, addr=client_addr(request), email=email)
        # Identical body for a wrong code and an unlisted address. `locked` is
        # reported because a recipient must be able to tell "wait" from "this
        # link is broken" -- and it is reported for unlisted addresses too,
        # since their attempts feed the same bucket.
        return _json({"ok": False, "locked": result.locked},
                     status_code=status.HTTP_401_UNAUTHORIZED)

    return _json({"ok": True, "recipient_token": result.recipient_token,
                  "expires_in": result.expires_in})


@router.post("/{link_uid}/session")
def open_session(link_uid: str, body: SessionIn, request: Request,
                 k: Optional[str] = None,
                 x_share_secret: Optional[str] = Header(default=None),
                 x_recipient_token: Optional[str] = Header(default=None)) -> Response:
    """Open a redemption session. **This is where a use is consumed** (§6.4).

    Everything before this point is free: peek, identify, verify. The use is
    spent once a verified recipient has actually asked for the payload, so a
    failed or abandoned challenge never costs the creator anything.
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    email = links.normalize_email(body.email)
    addr = client_addr(request)
    try:
        try:
            if not otp_client.check_token(cfg, link_uid=link_uid, email=email,
                                          token=x_recipient_token or ""):
                _audit_denied(cfg, link_uid=link_uid, reason="no_recipient_token",
                              tenant=tenant, addr=addr, email=email)
                raise _deny()
        except otp_client.OtpUnavailable:
            raise _deny()

        # The authority re-check, as the creator, before any budget moves.
        roles = _live_creator_roles(cfg, link)
        permission = WRITE if link.kind == KIND_UPLOAD else READ
        result = preflight.check(cfg, created_by=link.created_by, tenant=tenant,
                                 resource_uid=link.resource_uid,
                                 permission=permission,
                                 pinned_version=link.pinned_version or "",
                                 source_addr=addr)
        if not result:
            _audit_denied(cfg, link_uid=link_uid, reason=result.reason,
                          tenant=tenant, addr=addr, email=email)
            raise _deny()

        try:
            session = sessions.open_session(
                conn, cfg, link_uid=link_uid, verified_email=email, tenant=tenant,
                roles=roles, source_addr=addr,
                user_agent=request.headers.get("user-agent", "")[:200])
        except sessions.SessionRefused as e:
            _audit_denied(cfg, link_uid=link_uid, reason=e.reason, tenant=tenant,
                          addr=addr, email=email)
            raise _deny()

        # Fail-closed, overriding the category default: the audit chain is the
        # only record anywhere that this access was external (spec §4.3).
        try:
            get_emitter(cfg).emit_or_raise(
                action="share_link_redeem", outcome="ok",
                category="mutate" if link.kind == KIND_UPLOAD else "access",
                actor=f"share:{link_uid}|{email}", tenant=tenant,
                target_uid=link.resource_uid, source_addr=addr,
                request_id=session.redemption_uid,
                detail={"link_uid": link_uid, "created_by": link.created_by,
                        "verified_email": email,
                        "redemption_uid": session.redemption_uid,
                        "members_served": session.members_served,
                        "members_omitted": session.members_omitted})
        except AuditUnavailable:
            log.error("share_link_redeem NOT durable for %s — refusing", link_uid)
            raise _deny()

        payload = {"redemption_uid": session.redemption_uid,
                   "expires_at": session.expires_at,
                   "kind": link.kind}
        if link.kind == KIND_FOLDER_DOWNLOAD:
            payload["archive_bytes"] = session.archive_bytes
            payload["members_served"] = session.members_served
            payload["members_omitted"] = session.members_omitted
        return _json(payload)
    finally:
        conn.close()


@router.get("/{link_uid}/manifest")
def manifest(link_uid: str, request: Request, k: Optional[str] = None,
             x_share_secret: Optional[str] = Header(default=None),
             x_redemption_uid: Optional[str] = Header(default=None)) -> Response:
    """The member list for a folder link — what the archive will contain.

    Hiding it would be theatre: the archive contains it. Requires an open
    session, so it is not readable before a recipient has verified.
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    try:
        session = _require_session(conn, link_uid, x_redemption_uid)
        if link.kind != KIND_FOLDER_DOWNLOAD:
            raise _deny()
        members = snapshot_mod.load(conn, link_uid)
        frozen = set(session["frozen_members"] or [])
        return _json({"members": [
            {"path": m.entry_name(), "size_bytes": m.size_bytes}
            for m in members if m.is_dir or m.member_uid in frozen]})
    finally:
        conn.close()


def _require_session(conn, link_uid: str, redemption_uid: Optional[str]) -> dict:
    """A live session on THIS link, or the uniform 404."""
    if not redemption_uid:
        raise _deny()
    with conn.cursor() as cur:
        cur.execute(
            """SELECT redemption_uid, verified_email, frozen_members, archive_bytes
                 FROM share_redemptions
                WHERE redemption_uid = %s AND link_uid = %s
                  AND expires_at > now() AND completed_at IS NULL""",
            (redemption_uid, link_uid))
        row = cur.fetchone()
    if not row:
        raise _deny()
    # str() every uid: psycopg returns a UUID[] column as uuid.UUID objects,
    # while member_uid is carried as a string everywhere else. Comparing the two
    # silently matches nothing -- which produces an EMPTY archive served under a
    # correct Content-Length, i.e. a corrupt download that looks fine from here.
    return {"redemption_uid": str(row[0]), "verified_email": row[1],
            "frozen_members": [str(u) for u in (row[2] or [])],
            "archive_bytes": row[3]}


@router.get("/{link_uid}/content")
def content(link_uid: str, request: Request, k: Optional[str] = None,
            x_share_secret: Optional[str] = Header(default=None),
            x_redemption_uid: Optional[str] = Header(default=None)):
    """Stream the payload. Requires an open session; consumes nothing further.

    A folder link serves the zip assembled from the member list **frozen at
    session open**, with the exact `Content-Length` computed then — which is why
    the per-member re-check cannot be deferred to here: discovering an omitted
    member after the header is on the wire produces a corrupt download.
    """
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    closed = False
    try:
        session = _require_session(conn, link_uid, x_redemption_uid)
        if link.kind == KIND_UPLOAD:
            raise _deny()

        roles = _live_creator_roles(cfg, link)
        core_ctx = for_creator(cfg, created_by=link.created_by, roles=roles,
                               tenant=tenant, source_addr=client_addr(request),
                               redemption_uid=session["redemption_uid"])

        if link.kind == KIND_FOLDER_DOWNLOAD:
            frozen = set(session["frozen_members"] or [])
            members = [m for m in snapshot_mod.load(conn, link_uid)
                       if m.is_dir or m.member_uid in frozen]
            declared = session["archive_bytes"] or archive.archive_length(members)

            def stream_zip():
                with core_ctx as core:
                    def open_member(m):
                        # (member_uid, version_name) -- the entity and the exact
                        # revision the snapshot recorded, not whatever the file
                        # has become since (spec §6.5).
                        yield core.get_pinned(m.member_uid, m.version_name)
                    try:
                        yield from archive.stream(members, open_member)
                    except VersionGone:
                        # A pinned member was culled mid-stream. The declared
                        # length is already committed, so this is the same
                        # situation as a size mismatch: abort rather than serve
                        # a short body (spec §6.5).
                        log.error("pinned member version gone on %s — aborting",
                                  link_uid)
                        raise
                    except archive.ArchiveLengthMismatch:
                        # The declared length is already on the wire. Abort
                        # rather than send a short body: a truncated archive
                        # under a declared length is silently corrupt, and a
                        # broken transfer is at least visibly broken (§6.5).
                        log.error("archive length mismatch on %s — aborting", link_uid)
                        raise

            conn.close()
            closed = True
            return StreamingResponse(
                stream_zip(), media_type="application/zip",
                headers={"Content-Length": str(declared),
                         "Accept-Ranges": "none",
                         "Content-Disposition": 'attachment; filename="download.zip"'})

        # kind 0 — the single file, at the version the link recorded.
        with core_ctx as core:
            try:
                raw = core.get_pinned(link.resource_uid, link.pinned_version or "")
            except VersionGone:
                # The pinned version was culled: the link is dead, uniformly
                # (spec §6.2). Never fall back to the current version -- that
                # is the silent substitution pinning exists to prevent.
                _audit_denied(cfg, link_uid=link_uid, reason="version_gone",
                              tenant=tenant, addr=client_addr(request),
                              email=session["verified_email"])
                raise _deny()
        return Response(content=raw, media_type="application/octet-stream",
                        headers={"Content-Length": str(len(raw))})
    finally:
        if not closed:
            conn.close()
