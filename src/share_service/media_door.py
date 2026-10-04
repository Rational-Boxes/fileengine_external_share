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

"""The media door — unauthenticated, on its own origin (MEDIA_SHARE.md §6.3-6.9). **The review gate.**

Everything the outside-share door's rules say holds here too, plus what playing
a video adds. Stated together, because each is individually easy to erode:

1. **Its own router and its own origin** (``<tenant>-media.<base>``). No bearer,
   no cookie, no SPA. It is the one place in the platform that answers with a
   real media type, which is why it cannot share an origin with anything that
   holds a credential (§6.5).
2. **A fixed MIME allowlist, enforced on the way out.** Anything else is a bug
   and becomes a 500, never a served body (§13.1).
3. **The header set is applied by middleware to every response under the
   prefix, errors included** (§13.2) — inline, nosniff, a CSP of
   ``default-src 'none'; media-src 'self'; frame-ancestors <the link's list>``,
   never ``Access-Control-Allow-Origin: *``.
4. **Uniform failure** for every refusal, as on the outside-share door — with
   one scoped exception: a PARKED **open** link says why (§6.9 rung 3), because
   "this video is popular" is not a secret and a bare 404 sends a marketing
   page's visitors to support. A gated link never gets that exception.
5. **The rendition is resolved from the link record**: the source uid stored on
   the row, its newest published set, and ``q`` as an ENUM. No uid or rendition
   name from the caller ever reaches the core (§13.4).
6. **Authorize, then serve.** The creator's authority is re-checked at session
   open and at most ``media_recheck_seconds`` later on any request, sooner when
   the core announces an ACL or role change (§6.7). No byte is fetched for a
   caller who cannot open a session (§13.11).
7. **Bytes are counted as they leave**, not from Content-Length, and the
   durable budget is checked before each response: the one in flight finishes,
   the next is refused (§6.4, §13.7).
8. **Audit the decision, not the request** (§12.1): one event per session
   opened and one when it ends — never one per range request.

The byte cache §6.6 describes is deliberately ABSENT (§14-Q10): ranges are read
from the core by authenticated seek on storage v2, so there is no fill path and
no cache-miss amplification surface to bound.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse

from . import audience, db, links, notify, otp_client, playback, preflight, public
from .audit import AuditUnavailable, get_emitter
from .auth import client_addr
from .config import Config
from .core_client import READ, for_creator
from .media_meter import get_meter
from .notify import get_publisher
from .schema import ACCESS_CLAIMED, ACCESS_OPEN, ACCESS_VERIFIED, KIND_MEDIA, MEDIA_READY
from .urls import tenant_origin

log = logging.getLogger("share_service.media_door")

router = APIRouter(prefix="/media/v1")

_NOT_FOUND = {"error": "not_found"}

#: Every Content-Type this origin may EVER emit (§6.5). JSON for the control
#: routes, the rendition types, the poster stills.
MIME_ALLOWLIST = frozenset({
    "application/json", "video/webm", "audio/webm", "audio/mpeg",
    "image/gif", "image/webp", "image/png", "image/jpeg",
})

#: q -> the published fmt it names. An enum: the caller never names a rendition.
QUALITIES = {"hd": "media", "sd": "media_sd", "opus": "audio_opus", "mp3": "audio"}
_FMT_MIME = {("media", "webm"): "video/webm", ("media_sd", "webm"): "video/webm",
             ("audio_opus", "webm"): "audio/webm", ("audio", "mp3"): "audio/mpeg"}
_POSTER_MIME = {"gif": "image/gif", "webp": "image/webp", "png": "image/png",
                "jpg": "image/jpeg", "jpeg": "image/jpeg"}
_LABELS = {"hd": "720p", "sd": "480p", "opus": "Opus", "mp3": "MP3"}

_EMAIL_RE = re.compile(r"^[^@\s,;<>\"'`=+\x00-\x1f]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")

_DEFAULT_CSP = "default-src 'none'; media-src 'self'; frame-ancestors 'none'"

_HARDENING = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex",
}


# ── metrics (§6.9) — process-local counters, rendered by the collector ─────────

_stats_lock = threading.Lock()
_stats: Dict[Tuple[str, ...], float] = {}


def _count(name: str, *labels: str, n: float = 1) -> None:
    with _stats_lock:
        _stats[(name, *labels)] = _stats.get((name, *labels), 0) + n


def collect_media(m) -> None:
    """The ``fileengine_media_*`` series (§6.9), for metrics.install."""
    with _stats_lock:
        snap = dict(_stats)
    for key, value in sorted(snap.items()):
        name, *labels = key
        if name == "bytes":
            m.counter("fileengine_media_bytes_served_total", "Media bytes written to sockets",
                      value, {"tenant": labels[0]})
        elif name == "requests":
            m.counter("fileengine_media_requests_total", "Media door requests by outcome",
                      value, {"tenant": labels[0], "outcome": labels[1]})
        elif name == "sessions":
            m.counter("fileengine_media_sessions_total", "Viewing sessions opened",
                      value, {"tenant": labels[0], "mode": labels[1]})
        elif name == "active":
            m.gauge("fileengine_media_active_streams", "Streams in flight on this instance",
                    value, {"tenant": labels[0]})
    meter = _meter_or_none()
    m.gauge("fileengine_media_meter_degraded",
            "1 when the shared rolling windows are unavailable", 1 if meter and meter.degraded else 0)


def _meter_or_none():
    from . import media_meter
    return media_meter._meter


# ── hardening (§6.5, §13.1-2) ────────────────────────────────────────────────

def install_hardening(app) -> None:
    """Set once for the prefix, errors included; refuse any non-allowlisted MIME.

    A route may set a stricter or link-specific value (frame-ancestors, a
    private cache lifetime on bytes); it may never weaken one."""
    @app.middleware("http")
    async def _harden(request: Request, call_next):  # noqa: ANN202
        response = await call_next(request)
        if not request.url.path.startswith(router.prefix):
            return response
        ctype = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype not in MIME_ALLOWLIST:
            log.error("media door refused to emit %r on %s", ctype, request.url.path)
            response = JSONResponse({"error": "internal"}, status_code=500)
        for k, v in _HARDENING.items():
            response.headers[k] = v
        response.headers["Content-Disposition"] = "inline"
        if "content-security-policy" not in response.headers:
            response.headers["Content-Security-Policy"] = _DEFAULT_CSP
        cc = response.headers.get("cache-control", "")
        if not (ctype.startswith(("video/", "audio/", "image/")) and cc.startswith("private")):
            response.headers["Cache-Control"] = "no-store"
        if response.headers.get("access-control-allow-origin") == "*":
            del response.headers["access-control-allow-origin"]
        return response


def _json(payload: dict, status_code: int = 200, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(jsonable_encoder(payload), status_code=status_code, headers=headers)


def _deny() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, _NOT_FOUND)


def _cfg(request: Request) -> Config:
    return request.app.state.config


async def _body(request: Request) -> dict:
    """JSON from any content type. Embeds post text/plain so a cross-origin call
    is a CORS 'simple request' — no preflight, and so no OPTIONS route that
    would have to answer about a link before its secret is seen."""
    raw = await request.body()
    if not raw:
        return {}
    try:
        got = json.loads(raw)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, {"error": "bad_request"})
    return got if isinstance(got, dict) else {}


# ── link resolution ───────────────────────────────────────────────────────────

def _resolve(request: Request, link_uid: str, secret: Optional[str]):
    """public._resolve (secret, status, tenant state, audit available) plus: a
    media link, on a deployment with media links on. Uniform 404 otherwise."""
    cfg = _cfg(request)
    if not cfg.media_enabled:
        raise _deny()
    cfg_, tenant, conn, link = public._resolve(request, link_uid, secret)
    if link.kind != KIND_MEDIA:
        conn.close()
        raise _deny()
    return cfg, tenant, conn, link


def _parked(link) -> bool:
    return bool(link.parked_until and link.parked_until > datetime.now(timezone.utc))


def _park_response(link) -> Response:
    """Rung 3. An OPEN link says why; a gated one fails uniformly (§6.9, §13.14)."""
    if link.access_mode != ACCESS_OPEN:
        raise _deny()
    retry = 3600
    if link.parked_until:
        retry = max(60, int((link.parked_until - datetime.now(timezone.utc)).total_seconds()))
    return _json({"error": "temporarily_unavailable",
                  "message": "This video is temporarily unavailable because it has been "
                             "very popular. Please try again later."},
                 status_code=503, headers={"Retry-After": str(retry)})


def _cors(cfg: Config, request: Request, tenant: str, link) -> dict:
    """Echo the Origin iff the link allows it, or it is the tenant's own landing
    page. Never '*' (§6.5)."""
    origin = request.headers.get("origin") or ""
    if not origin:
        return {}
    allowed = set(link.allowed_embed_origins or [])
    try:
        allowed.add(tenant_origin(cfg, request, tenant).rstrip("/"))
    except Exception:  # noqa: BLE001
        pass
    if origin.rstrip("/") in allowed:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {"Vary": "Origin"}


def _frame_csp(link) -> str:
    anc = " ".join(link.allowed_embed_origins or []) or "'none'"
    return f"default-src 'none'; media-src 'self'; frame-ancestors {anc}"


# ── authority (§6.7) ───────────────────────────────────────────────────────────

@dataclass
class _Authority:
    roles: List[str]
    checked: float


_authority: Dict[Tuple[str, str], _Authority] = {}
_authority_lock = threading.Lock()


def _authorize(cfg: Config, tenant: str, link, *, force: bool = False) -> Optional[List[str]]:
    """The creator's current, admin-stripped roles if they still hold READ on an
    existing resource; None otherwise. Cached per (tenant, link) for at most
    ``media_recheck_seconds``, and invalidated sooner by the tenant's ACL epoch
    (bumped from acl.changed / role.* on the events stream)."""
    key = (tenant, link.link_uid)
    now = time.time()
    epoch = get_meter(cfg).acl_epoch(tenant)
    with _authority_lock:
        got = _authority.get(key)
    if (not force and got and now - got.checked < cfg.media_recheck_seconds
            and got.checked >= epoch):
        return got.roles
    verdict = preflight.check(cfg, created_by=link.created_by, tenant=tenant,
                              resource_uid=link.resource_uid, permission=READ)
    if not verdict:
        with _authority_lock:
            _authority.pop(key, None)
        return None
    with _authority_lock:
        _authority[key] = _Authority(list(verdict.roles or []), now)
    return list(verdict.roles or [])


def forget_authority(tenant: str = "") -> None:
    with _authority_lock:
        for k in [k for k in _authority if not tenant or k[0] == tenant]:
            _authority.pop(k, None)


# ── the published set (§6.2 rule 3) ──────────────────────────────────────────────

_set_cache: Dict[Tuple[str, str], Tuple[float, str, dict]] = {}
_SET_TTL = 30


def _published_set(cfg: Config, tenant: str, link, roles: List[str]) -> Tuple[str, dict]:
    """(version, {fmt: entry}) of the NEWEST version whose primary rendition
    exists — the set a link plays. Listed as the creator, from the link's own
    resource uid; cached briefly, since every range of a viewing would
    otherwise list the file's children again."""
    key = (tenant, link.resource_uid)
    hit = _set_cache.get(key)
    if hit and time.time() - hit[0] < _SET_TTL:
        return hit[1], hit[2]
    by_version: Dict[str, dict] = {}
    with for_creator(cfg, created_by=link.created_by, roles=roles, tenant=tenant) as core:
        for e in core.client.dir(link.resource_uid) or []:
            name = str(getattr(e, "name", "") or "")
            stem, dot, ext = name.rpartition(".")
            version, dash, fmt = stem.rpartition("-")
            if not dot or not dash or fmt not in QUALITIES.values():
                continue
            by_version.setdefault(version, {})[fmt] = {
                "uid": str(e.uid), "size": int(getattr(e, "size", 0) or 0), "ext": ext.lower()}
    playable = [v for v, fm in by_version.items() if "media" in fm or "audio" in fm]
    if not playable:
        result = ("", {})
    else:
        v = max(playable)
        result = (v, by_version[v])
    _set_cache[key] = (time.time(), *result)
    return result


def forget_published(tenant: str, resource_uid: str) -> None:
    _set_cache.pop((tenant, resource_uid), None)


def _sources(link_uid: str, fmts: dict) -> List[dict]:
    """Assembled here, in preference order; the player takes the first it can play."""
    order = ["hd", "sd"] if "media" in fmts else ["opus", "mp3"]
    out = []
    for q in order:
        f = fmts.get(QUALITIES[q])
        if not f:
            continue
        mime = _FMT_MIME.get((QUALITIES[q], f["ext"]))
        if not mime:
            continue
        out.append({"label": _LABELS[q], "quality": q, "default": not out, "mime": mime,
                    "bytes": f["size"], "url": f"{router.prefix}/{link_uid}/content?q={q}"})
    return out


# ── routes ─────────────────────────────────────────────────────────────────────

@router.get("/{link_uid}")
def peek(link_uid: str, request: Request, k: Optional[str] = None,
         x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """What the player needs before asking for bytes (§6.8). Consumes nothing."""
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    conn.close()
    cors = _cors(cfg, request, tenant, link)
    if _parked(link):
        r = _park_response(link)
        r.headers.update(cors)
        return r
    requires = {ACCESS_OPEN: "none", ACCESS_CLAIMED: "email",
                ACCESS_VERIFIED: "code"}[link.access_mode]
    sources: List[dict] = []
    state = "preparing"
    if link.media_state == MEDIA_READY:
        roles = _authorize(cfg, tenant, link)
        if roles is None:
            raise _deny()
        _v, fmts = _published_set(cfg, tenant, link, roles)
        sources = _sources(link_uid, fmts)
        state = "ready" if sources else "preparing"
    payload = {
        "kind": "video" if any(s["quality"] in ("hd", "sd") for s in sources) or not sources
        else "audio",
        "mode": link.access_mode, "title": link.display_name, "duration_ms": link.duration_ms,
        "poster": f"{router.prefix}/{link_uid}/poster" if link.poster_uid else None,
        "state": state, "progress_pct": None, "requires": requires,
        "allow_download": False, "sources": sources,
        # The player sends no beacon when this is false, and the page says so.
        "tracking": bool(cfg.playback_tracking),
    }
    return _json(payload, headers=cors)


@router.post("/{link_uid}/identify")
async def identify(link_uid: str, request: Request, k: Optional[str] = None,
                   x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """The verified path's code request — the outside-share door's own logic."""
    body = await _body(request)
    return await run_in_threadpool(public.identify, link_uid,
                                   public.IdentifyIn(email=str(body.get("email") or "")),
                                   request, k, x_share_secret)


@router.post("/{link_uid}/verify")
async def verify(link_uid: str, request: Request, k: Optional[str] = None,
                 x_share_secret: Optional[str] = Header(default=None)) -> Response:
    body = await _body(request)
    return await run_in_threadpool(public.verify, link_uid,
                                   public.VerifyIn(email=str(body.get("email") or ""),
                                                   code=str(body.get("code") or "")),
                                   request, k, x_share_secret)


@router.post("/{link_uid}/claim")
async def claim(link_uid: str, request: Request, k: Optional[str] = None,
                x_share_secret: Optional[str] = Header(default=None)) -> Response:
    """``claimed`` mode: an address, no code, and a session (§6.3, §7.3)."""
    body = await _body(request)
    return await run_in_threadpool(_claim, link_uid, request, x_share_secret or k, body)


@router.post("/{link_uid}/session")
async def session(link_uid: str, request: Request, k: Optional[str] = None,
                  x_share_secret: Optional[str] = Header(default=None),
                  x_recipient_token: Optional[str] = Header(default=None)) -> Response:
    """``verified`` (with the recipient token from /verify) or ``open``."""
    body = await _body(request)
    return await run_in_threadpool(_session, link_uid, request, x_share_secret or k,
                                   x_recipient_token or "", body)


def _claim(link_uid: str, request: Request, secret: Optional[str], body: dict) -> Response:
    cfg, tenant, conn, link = _resolve(request, link_uid, secret)
    try:
        if link.access_mode != ACCESS_CLAIMED:
            raise _deny()
        raw = str(body.get("email") or "")
        email = links.normalize_email(raw)
        addr = client_addr(request)
        # Syntax only (§7.3): no probing a mailbox, nothing but an address, and
        # nothing that could be a spreadsheet formula when the roster is exported.
        if len(raw) > 320 or not _EMAIL_RE.match(email):
            return _json({"error": "invalid_email"}, status_code=400,
                         headers=_cors(cfg, request, tenant, link))
        if not body.get("consent"):
            return _json({"error": "consent_required"}, status_code=400,
                         headers=_cors(cfg, request, tenant, link))
        # 10 / hour / IP / link (§7.3): the table is otherwise a free write
        # endpoint for anyone holding the URL.
        ip_key = "claim:" + hashlib.sha256(addr.encode()).hexdigest()[:16]
        n = get_meter(cfg).count_in_window(tenant, link_uid, ip_key)
        if n is not None and n > cfg.claim_rate_per_hour:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, {"error": "slow_down"},
                                headers={"Retry-After": "600"})
        listed = email in {r["email"] for r in links.recipients(conn, link_uid)}
        return _open(cfg, request, tenant, conn, link, mode=ACCESS_CLAIMED, email=email,
                     verified=False, on_allowlist=listed,
                     consent=str(body.get("consent_text_id") or "v1")[:40])
    finally:
        conn.close()


def _session(link_uid: str, request: Request, secret: Optional[str], token: str,
             body: dict) -> Response:
    cfg, tenant, conn, link = _resolve(request, link_uid, secret)
    try:
        if link.access_mode == ACCESS_OPEN:
            return _open(cfg, request, tenant, conn, link, mode=ACCESS_OPEN)
        if link.access_mode != ACCESS_VERIFIED:
            raise _deny()
        email = links.normalize_email(str(body.get("email") or ""))
        try:
            if not otp_client.check_token(cfg, link_uid=link_uid, email=email, token=token):
                public._audit_denied(cfg, link_uid=link_uid, reason="no_recipient_token",
                                     tenant=tenant, addr=client_addr(request), email=email)
                raise _deny()
        except otp_client.OtpUnavailable:
            raise _deny()
        return _open(cfg, request, tenant, conn, link, mode=ACCESS_VERIFIED, email=email,
                     verified=True, on_allowlist=True)
    finally:
        conn.close()


def _open(cfg: Config, request: Request, tenant: str, conn, link, *, mode: str,
          email: Optional[str] = None, verified: bool = False, on_allowlist: bool = False,
          consent: Optional[str] = None) -> Response:
    """The one place a media session opens, whatever the mode (§6.3)."""
    addr = client_addr(request)
    cors = _cors(cfg, request, tenant, link)
    if _parked(link):
        r = _park_response(link)
        r.headers.update(cors)
        return r
    if link.media_state != MEDIA_READY:
        return _json({"state": "preparing"}, status_code=202, headers=cors)
    roles = _authorize(cfg, tenant, link, force=True)
    if roles is None:
        public._audit_denied(cfg, link_uid=link.link_uid, reason="creator_lost_access",
                             tenant=tenant, addr=addr, email=email or "")
        raise _deny()
    if link.max_bytes and link.bytes_consumed >= link.max_bytes:
        return _park(cfg, request, tenant, link, "link_budget")

    referer = urllib.parse.urlsplit(request.headers.get("referer") or "").hostname or None
    ua = (request.headers.get("user-agent") or "")[:200]
    token = secrets.token_urlsafe(32)
    session_uid = str(uuid.uuid4())
    expires = datetime.now(timezone.utc) + timedelta(seconds=cfg.media_session_ttl_seconds)
    with conn.cursor() as cur:
        # Serialise the viewer count on the link row: two first views racing
        # must not both slip under max_viewers.
        cur.execute("SELECT max_viewers FROM share_links WHERE link_uid = %s FOR UPDATE",
                    (link.link_uid,))
        audience_uid, fresh = _audience(cur, link, email=email, verified=verified,
                                        on_allowlist=on_allowlist, addr=addr, ua=ua,
                                        referer=referer, consent=consent)
        if fresh and link.max_viewers:
            cur.execute("SELECT count(*) FROM share_link_audience WHERE link_uid = %s",
                        (link.link_uid,))
            if int(cur.fetchone()[0]) > link.max_viewers:
                conn.rollback()
                public._audit_denied(cfg, link_uid=link.link_uid, reason="max_viewers",
                                     tenant=tenant, addr=addr, email=email or "")
                raise _deny()
        cur.execute(
            """INSERT INTO share_media_sessions
                 (session_uid, link_uid, audience_uid, mode, token_hash, expires_at,
                  source_addr, user_agent, referer_host)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (session_uid, link.link_uid, audience_uid, mode,
             hashlib.sha256(token.encode()).digest(), expires, addr, ua, referer))
    conn.commit()

    # Fail-closed, as the outside-share door's redeem is: the chain is the only
    # record that an outside party watched this. Actor prefixes keep claimed and
    # anonymous viewers from ever reading as verified (§12.2).
    action, actor = {
        ACCESS_VERIFIED: ("share_media_session", f"share:{link.link_uid}|{email}"),
        ACCESS_CLAIMED: ("share_media_claim", f"share:{link.link_uid}|claimed:{email}"),
        ACCESS_OPEN: ("share_media_open_view", f"share:{link.link_uid}|anon:{session_uid}"),
    }[mode]
    try:
        get_emitter(cfg).emit_or_raise(
            action=action, outcome="ok", category="access", actor=actor, tenant=tenant,
            target_uid=link.resource_uid, source_addr=addr, request_id=session_uid,
            detail={"link_uid": link.link_uid, "created_by": link.created_by, "mode": mode,
                    "session_uid": session_uid, "referer_host": referer,
                    **({"consent_text_id": consent} if consent else {})})
    except AuditUnavailable:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM share_media_sessions WHERE session_uid = %s", (session_uid,))
        conn.commit()
        log.error("%s NOT durable for %s — refusing", action, link.link_uid)
        raise _deny()

    _count("sessions", tenant, mode)
    _v, fmts = _published_set(cfg, tenant, link, roles)
    sources = [{**s, "url": s["url"] + f"&t={token}"} for s in _sources(link.link_uid, fmts)]
    audience.mark_dirty(conn, link.resource_uid)
    return _json({"session": token, "expires_at": expires, "title": link.display_name,
                  "duration_ms": link.duration_ms, "sources": sources,
                  "tracking": bool(cfg.playback_tracking),
                  **({"beacon": f"{router.prefix}/{link.link_uid}/playback?t={token}"}
                     if cfg.playback_tracking else {})},
                 headers=cors)


def _audience(cur, link, *, email, verified, on_allowlist, addr, ua, referer, consent):
    """(audience_uid, newly_seen). A returning address is an UPDATE of its row,
    so 'how many people watched' stays a row count (§7.1). An open viewer has no
    address: each session is a viewer."""
    if email:
        cur.execute(
            """INSERT INTO share_link_audience
                 (audience_uid, link_uid, email, email_norm, verified, on_allowlist,
                  sessions, source_addr, user_agent, referer_host, consent_text_id)
               VALUES (%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
               ON CONFLICT (link_uid, email_norm) DO UPDATE
                  SET last_seen_at = now(), sessions = share_link_audience.sessions + 1,
                      verified = share_link_audience.verified OR EXCLUDED.verified
            RETURNING audience_uid, (xmax = 0)""",
            (str(uuid.uuid4()), link.link_uid, email, email, verified, on_allowlist,
             addr, ua, referer, consent))
    else:
        cur.execute(
            """INSERT INTO share_link_audience
                 (audience_uid, link_uid, sessions, source_addr, user_agent, referer_host)
               VALUES (%s,%s,1,%s,%s,%s) RETURNING audience_uid, true""",
            (str(uuid.uuid4()), link.link_uid, addr, ua, referer))
    row = cur.fetchone()
    return str(row[0]), bool(row[1])


def _park(cfg: Config, request: Request, tenant: str, link, reason: str) -> Response:
    """Rung 3: park the link (never revoke), record it, tell the creator."""
    conn = db.connect_for_tenant(cfg, tenant)
    try:
        with conn.cursor() as cur:
            cur.execute("""UPDATE share_links
                              SET parked_until = now() + make_interval(mins => %s)
                            WHERE link_uid = %s
                              AND (parked_until IS NULL OR parked_until < now())
                        RETURNING parked_until""",
                        (cfg.media_park_minutes, link.link_uid))
            row = cur.fetchone()
        conn.commit()
    finally:
        conn.close()
    if row:
        link.parked_until = row[0]
        get_emitter(cfg).emit(action="share_media_parked", outcome="denied",
                              category="access", actor=f"share:{link.link_uid}", tenant=tenant,
                              source_addr=client_addr(request), request_id=link.link_uid,
                              detail={"link_uid": link.link_uid, "reason": reason,
                                      "parked_minutes": cfg.media_park_minutes,
                                      "bytes_consumed": link.bytes_consumed})
        get_publisher(cfg).publish(
            notify.MEDIA_PARKED, tenant=tenant, creator=link.created_by,
            link_uid=link.link_uid, file_uid=link.resource_uid,
            detail=_publish_elsewhere(link, parked=True))
    else:
        link.parked_until = link.parked_until or datetime.now(timezone.utc) + timedelta(
            minutes=cfg.media_park_minutes)
    _count("requests", tenant, "parked")
    r = _park_response(link)
    r.headers.update(_cors(cfg, request, tenant, link))
    return r


def _publish_elsewhere(link, *, parked: bool) -> str:
    """The numbers are the argument (§6.9)."""
    name = link.display_name or "Your video"
    gb = (link.bytes_consumed or 0) / 1e9
    state = "has been paused for a while" if parked else "is approaching its limits"
    return (f"“{name}” {state}: it has served {gb:.1f} GB. FileEngine publishes "
            "media for clients and prospects — it is not a CDN. For a large audience, "
            "upload it to PeerTube, YouTube or Vimeo and share that link instead. "
            "(Your file and this share link are unaffected.)")


# ── bytes ──────────────────────────────────────────────────────────────────────

_RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


def _plan(range_header: Optional[str], total: int):
    """(status, start, length, content_range). Multi-range is answered with the
    whole body (legal, and no player needs it); unsatisfiable is 416."""
    if not range_header or "," in range_header:
        return 200, 0, total, None
    m = _RANGE_RE.match(range_header.strip())
    if not m or (not m.group(1) and not m.group(2)):
        return 200, 0, total, None
    if m.group(1):
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else total - 1
    else:                                   # suffix: the last N bytes
        n = int(m.group(2))
        start, end = max(0, total - n), total - 1
    if start >= total or total == 0:
        return 416, 0, 0, f"bytes */{total}"
    end = min(end, total - 1)
    if end < start:
        return 416, 0, 0, f"bytes */{total}"
    return 206, start, end - start + 1, f"bytes {start}-{end}/{total}"


@router.get("/{link_uid}/content")
def content(link_uid: str, request: Request, q: str = "hd", t: Optional[str] = None):
    """Bytes for a viewing session. ``t`` is the session; ``q`` an enum."""
    cfg = _cfg(request)
    if not cfg.enabled or not cfg.media_enabled or not get_emitter(cfg).available:
        raise _deny()
    if not t or q not in QUALITIES:
        raise _deny()
    tenant = _tenant_for(cfg, link_uid)
    conn = db.connect_for_tenant(cfg, tenant, provision=True)
    try:
        try:
            link = links.get(conn, link_uid)
        except links.LinkNotFound:
            raise _deny()
        with conn.cursor() as cur:
            cur.execute("""SELECT session_uid, audience_uid FROM share_media_sessions
                            WHERE token_hash = %s AND link_uid = %s
                              AND ended_at IS NULL AND expires_at > now()""",
                        (hashlib.sha256(t.encode()).digest(), link_uid))
            row = cur.fetchone()
        if not row or link.kind != KIND_MEDIA or link.status() != "active":
            raise _deny()
        session_uid, audience_uid = str(row[0]), (str(row[1]) if row[1] else None)
        if not public._tenant_admits(cfg, tenant):
            raise _deny()
        cors = _cors(cfg, request, tenant, link)
        if _parked(link):
            r = _park_response(link)
            r.headers.update(cors)
            return r
        # The durable budget: the response in flight when it was crossed has
        # finished; this one is refused (§6.4).
        if link.max_bytes and link.bytes_consumed >= link.max_bytes:
            return _park(cfg, request, tenant, link, "link_budget")
        roles = _authorize(cfg, tenant, link)
        if roles is None:
            _end_session(conn, cfg, tenant, link, session_uid, "revoked")
            raise _deny()
        _v, fmts = _published_set(cfg, tenant, link, roles)
        entry = fmts.get(QUALITIES[q])
        mime = _FMT_MIME.get((QUALITIES[q], entry["ext"])) if entry else None
        if not entry or not mime:
            raise _deny()
    finally:
        conn.close()

    meter = get_meter(cfg)
    decision = meter.admit(tenant, link_uid, session_uid)
    if not decision.ok:
        _count("requests", tenant, "throttled")
        if decision.park and decision.reason != "client_concurrency":
            return _park(cfg, request, tenant, link, decision.reason)
        if meter.first_in_window(tenant, link_uid, f"throttled:{decision.reason}"):
            get_emitter(cfg).emit(action="share_media_throttled", outcome="denied",
                                  category="access", actor=f"share:{link_uid}", tenant=tenant,
                                  request_id=link_uid,
                                  detail={"link_uid": link_uid, "window": decision.reason})
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, {"error": "slow_down"},
                            headers={"Retry-After": str(decision.retry_after or 5), **cors})
    meter.throttle_cleared(tenant, link_uid)
    if decision.advise and meter.first_in_window(tenant, link_uid, "advise"):
        get_publisher(cfg).publish(
            notify.MEDIA_POPULAR, tenant=tenant, creator=link.created_by, link_uid=link_uid,
            file_uid=link.resource_uid, detail=_publish_elsewhere(link, parked=False))

    total = int(entry["size"])
    code, start, length, crange = _plan(request.headers.get("range"), total)
    headers = {"Accept-Ranges": "bytes", "Cache-Control": f"private, max-age={cfg.media_bytes_max_age}",
               "Content-Security-Policy": _frame_csp(link), **cors}
    if code == 416:
        meter.release(decision.ticket)
        return Response(status_code=416, media_type="application/json",
                        headers={**headers, "Content-Range": crange})
    headers["Content-Length"] = str(length)
    if crange:
        headers["Content-Range"] = crange
    _count("requests", tenant, "ok")
    gen = _stream(cfg, tenant, link, roles, entry["uid"], start, length, session_uid,
                  audience_uid, decision.ticket, total=total)
    return StreamingResponse(gen, status_code=code, media_type=mime, headers=headers)


def _tenant_for(cfg: Config, link_uid: str) -> str:
    directory = db.connect_for_tenant(cfg, cfg.default_tenant, provision=True)
    try:
        return links.tenant_for_link(directory, link_uid) or cfg.default_tenant
    except Exception:  # noqa: BLE001
        raise _deny()
    finally:
        directory.close()


class _Flusher:
    """Bytes leave in chunks; accounting is written in flushes (§6.9): every
    ``media_meter_flush_bytes`` or ``media_meter_flush_seconds``, and always at
    the end. A crash loses at most one interval — bounded, and stated."""

    def __init__(self, cfg: Config, tenant: str, link_uid: str, session_uid: str,
                 audience_uid: Optional[str]):
        self.cfg, self.tenant, self.link_uid = cfg, tenant, link_uid
        self.session_uid, self.audience_uid = session_uid, audience_uid
        self.pending = 0
        self.last = time.monotonic()

    def add(self, n: int) -> None:
        self.pending += n
        if (self.pending >= self.cfg.media_meter_flush_bytes
                or time.monotonic() - self.last >= self.cfg.media_meter_flush_seconds):
            self.flush()

    def flush(self) -> None:
        n, self.pending, self.last = self.pending, 0, time.monotonic()
        if n <= 0:
            return
        _count("bytes", self.tenant, n=n)
        get_meter(self.cfg).add_bytes(self.tenant, self.link_uid, n)
        try:
            conn = db.connect_for_tenant(self.cfg, self.tenant)
            try:
                with conn.cursor() as cur:
                    cur.execute("UPDATE share_links SET bytes_consumed = bytes_consumed + %s "
                                "WHERE link_uid = %s", (n, self.link_uid))
                    cur.execute("UPDATE share_media_sessions SET bytes_served = bytes_served + %s, "
                                "last_seen_at = now() WHERE session_uid = %s",
                                (n, self.session_uid))
                    if self.audience_uid:
                        cur.execute("UPDATE share_link_audience SET bytes_served = bytes_served + %s, "
                                    "last_seen_at = now() WHERE audience_uid = %s",
                                    (n, self.audience_uid))
                conn.commit()
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - never break a response mid-body over accounting
            log.exception("media byte accounting flush failed (%d bytes) for %s", n, self.link_uid)


def _stream(cfg: Config, tenant: str, link, roles: List[str], rendition_uid: str,
            start: int, length: int, session_uid: str, audience_uid: Optional[str], ticket,
            total: int = 0):
    meter = get_meter(cfg)
    flusher = _Flusher(cfg, tenant, link.link_uid, session_uid, audience_uid)
    began = time.monotonic()
    sent = 0
    _count("active", tenant, n=1)
    try:
        if length <= 0:
            return
        with for_creator(cfg, created_by=link.created_by, roles=roles, tenant=tenant,
                         redemption_uid=session_uid) as core:
            for chunk in core.client.get_stream(rendition_uid, offset=start, length=length):
                remaining = length - sent
                if remaining <= 0:
                    break
                chunk = chunk[:remaining]
                yield chunk
                # Counted AFTER the yield returns — i.e. once the server has taken
                # it for the socket — so a viewer who closes the tab is charged
                # for what left, not for the Content-Length (§6.4).
                sent += len(chunk)
                flusher.add(len(chunk))
                elapsed = time.monotonic() - began
                if (elapsed > cfg.media_throughput_grace_seconds
                        and sent / elapsed < cfg.media_min_throughput_bps):
                    log.info("dropping a stalled media stream on %s (%d B in %.0fs)",
                             link.link_uid, sent, elapsed)
                    return
    finally:
        flusher.flush()
        meter.release(ticket)
        _count("active", tenant, n=-1)
        if sent:
            _after_bytes(cfg, tenant, link, session_uid, audience_uid, total)


def _after_bytes(cfg: Config, tenant: str, link, session_uid: str,
                 audience_uid: Optional[str], total: int) -> None:
    """The audience changed (bytes served): the sidecar is due."""
    try:
        conn = db.connect_for_tenant(cfg, tenant)
        try:
            audience.mark_dirty(conn, link.resource_uid)
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - never fail a response over a rollup
        log.exception("post-stream audience update failed for %s", link.link_uid)


def _session_over(cfg: Config, conn, tenant: str, link_uid: str, session_uid: str) -> None:
    """When a session ENDS with no beacon ever having arrived — blocked, or an old
    player — enough bytes delivered make 'probably watched' (bytes-floor).

    Only at the end: a browser fetches a short clip whole as soon as it loads,
    before anyone presses play, so judging at the end of a stream would call
    every loaded-but-unwatched clip watched."""
    if not cfg.playback_tracking:
        return
    try:
        link = links.get(conn, link_uid)
        with conn.cursor() as cur:
            cur.execute("SELECT audience_uid FROM share_media_sessions WHERE session_uid = %s",
                        (session_uid,))
            row = cur.fetchone()
        audience_uid = str(row[0]) if row and row[0] else None
        if playback.bytes_floor(conn, cfg, session_uid=session_uid, audience_uid=audience_uid,
                                rendition_size=int(link.output_bytes or 0)):
            _completed(cfg, conn, tenant, link, session_uid, "bytes-floor")
        audience.mark_dirty(conn, link.resource_uid)
    except Exception:  # noqa: BLE001
        log.exception("end-of-session evaluation failed for %s", session_uid)


def _completed(cfg: Config, conn, tenant: str, link, session_uid: str, basis: str) -> None:
    """share_media_completed, and — for a GATED link — the attention item the
    feature is judged on ("Priya finished your video"). Off for open links,
    where it would be noise."""
    with conn.cursor() as cur:
        cur.execute("""SELECT s.mode, a.email_norm FROM share_media_sessions s
                         LEFT JOIN share_link_audience a ON a.audience_uid = s.audience_uid
                        WHERE s.session_uid = %s""", (session_uid,))
        mode, email = cur.fetchone() or ("open", None)
    actor = {"verified": f"share:{link.link_uid}|{email}",
             "claimed": f"share:{link.link_uid}|claimed:{email}"}.get(
        mode, f"share:{link.link_uid}|anon:{session_uid}")
    get_emitter(cfg).emit(action="share_media_completed", outcome="ok", category="access",
                          actor=actor, tenant=tenant, target_uid=link.resource_uid,
                          request_id=session_uid,
                          detail={"link_uid": link.link_uid, "session_uid": session_uid,
                                  "completion_basis": basis, "mode": mode})
    if mode != ACCESS_OPEN and email:
        what = "probably finished" if basis == "bytes-floor" else "finished"
        get_publisher(cfg).publish(
            notify.MEDIA_COMPLETED, tenant=tenant, creator=link.created_by,
            link_uid=link.link_uid, file_uid=link.resource_uid, actor=actor,
            detail=f"{email} {what} \u201c{link.display_name or 'your video'}\u201d"
                   + (" (unverified address)" if mode == ACCESS_CLAIMED else ""))


def _end_session(conn, cfg: Config, tenant: str, link, session_uid: str, reason: str) -> None:
    with conn.cursor() as cur:
        cur.execute("""UPDATE share_media_sessions SET ended_at = now(), end_reason = %s
                        WHERE session_uid = %s AND ended_at IS NULL
                    RETURNING bytes_served, opened_at, mode""", (reason, session_uid))
        row = cur.fetchone()
    conn.commit()
    if row:
        _audit_end(cfg, tenant, link.link_uid, link.resource_uid, session_uid, reason,
                   int(row[0] or 0), row[1], row[2])
        _session_over(cfg, conn, tenant, link.link_uid, session_uid)


def _audit_end(cfg, tenant, link_uid, resource_uid, session_uid, reason, nbytes, opened_at, mode):
    """share_media_session_end — what the session DID (§12.2): bytes, duration,
    how it ended. One per session."""
    secs = int((datetime.now(timezone.utc) - opened_at).total_seconds()) if opened_at else None
    get_emitter(cfg).emit(action="share_media_session_end", outcome="ok", category="access",
                          actor=f"share:{link_uid}", tenant=tenant, target_uid=resource_uid,
                          request_id=session_uid,
                          detail={"link_uid": link_uid, "session_uid": session_uid,
                                  "mode": mode, "bytes": nbytes, "duration_s": secs,
                                  "ended": reason})


def media_tenants(cfg: Config) -> List[str]:
    """Tenants whose schema has media sessions. Schema names are
    ``tenant_<id>`` and tenant ids are lowercase alphanumerics and underscores,
    so the id is the remainder."""
    conn = db.connect_for_tenant(cfg, cfg.default_tenant, provision=True)
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT table_schema FROM information_schema.tables
                            WHERE table_name = 'share_media_sessions'
                              AND table_schema LIKE 'tenant\\_%'""")
            return [r[0][len("tenant_"):] for r in cur.fetchall()]
    finally:
        conn.close()


def end_expired_sessions(cfg: Config, tenants) -> int:
    """Close sessions past their expiry, each with its session_end record."""
    n = 0
    for tenant in tenants:
        try:
            conn = db.connect_for_tenant(cfg, tenant)
        except Exception:  # noqa: BLE001
            continue
        try:
            with conn.cursor() as cur:
                cur.execute("""UPDATE share_media_sessions s
                                  SET ended_at = now(), end_reason = 'expired'
                                 FROM share_links l
                                WHERE l.link_uid = s.link_uid AND s.ended_at IS NULL
                                  AND s.expires_at <= now()
                            RETURNING s.session_uid, s.link_uid, l.resource_uid,
                                      s.bytes_served, s.opened_at, s.mode""")
                rows = cur.fetchall()
            conn.commit()
        except Exception:  # noqa: BLE001 - a tenant without the table yet
            conn.rollback()
            rows = []
        finally:
            conn.close()
        if rows:
            conn = db.connect_for_tenant(cfg, tenant)
            try:
                for r in rows:
                    _audit_end(cfg, tenant, str(r[1]), str(r[2]), str(r[0]), "expired",
                               int(r[3] or 0), r[4], r[5])
                    _session_over(cfg, conn, tenant, str(r[1]), str(r[0]))
                    n += 1
            finally:
                conn.close()
    return n


# ── the playback beacon (§7.4) ─────────────────────────────────────────────────

@router.post("/{link_uid}/playback")
async def beacon(link_uid: str, request: Request, t: Optional[str] = None) -> Response:
    """The session's CUMULATIVE playback state. ``t`` authorizes it, and it is
    merged into that session alone. sendBeacon posts text/plain, which is fine."""
    cfg = _cfg(request)
    if not cfg.playback_tracking:
        raise _deny()                       # no route, not an empty one
    raw = await request.body()
    if len(raw) > playback.MAX_BEACON_BYTES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, {"error": "too_large"})
    body = await _body(request)
    return await run_in_threadpool(_beacon, link_uid, request, t, body)


def _beacon(link_uid: str, request: Request, t: Optional[str], body: dict) -> Response:
    cfg = _cfg(request)
    if not cfg.enabled or not cfg.media_enabled or not t:
        raise _deny()
    tenant = _tenant_for(cfg, link_uid)
    conn = db.connect_for_tenant(cfg, tenant, provision=True)
    try:
        try:
            link = links.get(conn, link_uid)
        except links.LinkNotFound:
            raise _deny()
        with conn.cursor() as cur:
            cur.execute("""SELECT session_uid, audience_uid FROM share_media_sessions
                            WHERE token_hash = %s AND link_uid = %s
                              AND ended_at IS NULL AND expires_at > now()""",
                        (hashlib.sha256(t.encode()).digest(), link_uid))
            row = cur.fetchone()
        if not row or link.kind != KIND_MEDIA or link.status() != "active":
            raise _deny()
        session_uid, audience_uid = str(row[0]), (str(row[1]) if row[1] else None)
        # Another session's state is refused, never merged (§13.15).
        if body.get("session") is not None and body.get("session") != t:
            return _json({"error": "session_mismatch"}, status_code=403)
        try:
            b = playback.parse(body, cfg)
        except playback.BadBeacon as e:
            return _json({"error": "bad_beacon", "message": str(e)}, status_code=400)
        size = None
        roles = _authorize(cfg, tenant, link)
        if roles is None:
            raise _deny()
        if b.quality:
            _v, fmts = _published_set(cfg, tenant, link, roles)
            entry = fmts.get(QUALITIES[b.quality])
            size = int(entry["size"]) if entry else None
        basis = playback.record(conn, cfg, session_uid=session_uid, link=link,
                                audience_uid=audience_uid, beacon=b,
                                user_agent=request.headers.get("user-agent", ""),
                                rendition_size=size)
        if basis:
            _completed(cfg, conn, tenant, link, session_uid, basis)
        audience.mark_dirty(conn, link.resource_uid)
        return _json({"ok": True}, headers=_cors(cfg, request, tenant, link))
    finally:
        conn.close()


# ── the poster ─────────────────────────────────────────────────────────────────

@router.get("/{link_uid}/poster")
def poster(link_uid: str, request: Request, k: Optional[str] = None,
           x_share_secret: Optional[str] = Header(default=None)):
    """The still. Metered, NOT audited (§12.1): mail-privacy proxies fetch every
    image, so an entry per fetch would describe something that is not a view."""
    cfg, tenant, conn, link = _resolve(request, link_uid, x_share_secret or k)
    conn.close()
    if not link.poster_uid:
        raise _deny()
    roles = _authorize(cfg, tenant, link)
    if roles is None:
        raise _deny()
    with for_creator(cfg, created_by=link.created_by, roles=roles, tenant=tenant) as core:
        info = core.stat(link.poster_uid)
        # The poster must still be a child of THIS link's source — a stored uid
        # is trusted no further than the tree says.
        if str(getattr(info, "parent_uid", "") or "") != link.resource_uid:
            raise _deny()
        ext = str(getattr(info, "name", "") or "").rpartition(".")[2].lower()
        size = int(getattr(info, "size", 0) or 0)
    mime = _POSTER_MIME.get(ext)
    if not mime:
        raise _deny()
    poster_uid = link.poster_uid

    def gen():
        sent = 0
        try:
            with for_creator(cfg, created_by=link.created_by, roles=roles, tenant=tenant) as core:
                for chunk in core.client.get_stream(poster_uid):
                    yield chunk
                    sent += len(chunk)
        finally:
            get_meter(cfg).add_bytes(tenant, link_uid, sent)
            _count("bytes", tenant, n=sent)

    return StreamingResponse(gen(), media_type=mime,
                             headers={"Content-Length": str(size),
                                      "Cache-Control": "private, max-age=3600",
                                      "Content-Security-Policy": _frame_csp(link),
                                      **_cors(cfg, request, tenant, link)})
