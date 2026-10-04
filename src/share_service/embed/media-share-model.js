// SPDX-License-Identifier: MIT
// FileEngine embedding kit — media-share model (MEDIA_SHARE.md §9). (c) 2026 James Hickman.
//
// The pure half of <fe-media-share>: everything that decides something lives
// here so it can be tested without a DOM. Imports nothing.

/**
 * Parse a media share URL into the door's origin, the link and its secret.
 * Accepts the media-origin URL the Share tab hands out
 * (`https://<tenant>-media.<base>/media/v1/<uid>?k=<secret>`) and the
 * `/s/<uid>.<secret>` form. Returns null for anything else.
 */
export function parseShareSrc(src) {
  let u
  try { u = new URL(String(src)) } catch { return null }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && /^(localhost|127\.0\.0\.1)$/.test(u.hostname))) return null
  let m = u.pathname.match(/^\/media\/v1\/([0-9a-fA-F-]{36})\/?$/)
  if (m && u.searchParams.get("k")) return { origin: u.origin, linkUid: m[1], secret: u.searchParams.get("k") }
  m = u.pathname.match(/^\/s\/([0-9a-fA-F-]{36})\.([A-Za-z0-9_-]+)$/)
  if (m) return { origin: u.origin, linkUid: m[1], secret: m[2] }
  return null
}

/**
 * Which shape to render — decided by the DOOR's answer, never by an attribute
 * (§9.2): a gated link is framed whatever the host would prefer, because a form
 * in the host's DOM is one the host can read and forge. Anything not plainly
 * open is framed (the safe direction).
 */
export function renderingFor(peek) {
  return peek && peek.requires === "none" ? "inline" : "iframe"
}

export const peekUrl = (p) => `${p.origin}/media/v1/${p.linkUid}?k=${encodeURIComponent(p.secret)}`
export const sessionUrl = (p) => `${p.origin}/media/v1/${p.linkUid}/session?k=${encodeURIComponent(p.secret)}`
export const posterUrl = (p, peek) => (peek && peek.poster ? `${p.origin}${peek.poster}?k=${encodeURIComponent(p.secret)}` : "")

/** The framed player. `parent` names the host origin the frame may talk to. */
export function playerUrl(p, { parent = "", autoplay = false } = {}) {
  const q = new URLSearchParams({ k: p.secret })
  if (parent) q.set("parent", parent)
  if (autoplay) q.set("autoplay", "true")
  return `${p.origin}/media/v1/player/${p.linkUid}?${q.toString()}`
}

/** A message from the frame is believed only from the door's origin, and only
 *  if it is one of ours. */
const EVENTS = new Set(["fe:media-ready", "fe:media-play", "fe:media-ended", "fe:media-gate",
                        "fe:media-identified", "fe:media-error"])
export function acceptFrameMessage(event, doorOrigin) {
  return !!event && event.origin === doorOrigin && !!event.data && EVENTS.has(event.data.type)
}

/** What a host may learn from a frame event. Never an address. */
export function eventDetail(data) {
  const out = {}
  if (data && typeof data.requires === "string") out.requires = data.requires
  if (data && typeof data.state === "string") out.state = data.state
  return out
}

/** The first source this browser can play, in the server's order. */
export function pickSource(sources, canPlay) {
  const list = Array.isArray(sources) ? sources : []
  return list.find((s) => !s.mime || canPlay(s.mime)) || list[0] || null
}

/** Absolute URLs for the door's relative ones. */
export function absolutise(p, sources) {
  return (sources || []).map((s) => ({ ...s, url: s.url.startsWith("http") ? s.url : `${p.origin}${s.url}` }))
}

/** CSS size for the box from width/height/aspect attributes. */
export function boxStyle({ width, height, aspect }) {
  const w = /^\d+$/.test(width || "") ? `${width}px` : "100%"
  if (/^\d+$/.test(height || "")) return { width: w, height: `${height}px` }
  const a = /^(\d+)[:/](\d+)$/.exec(aspect || "16:9") || [0, 16, 9]
  return { width: w, aspectRatio: `${a[1]} / ${a[2]}` }
}

// ── playback telemetry, the in-page path (§7.4) ─────────────────────────────
export function quantise(played, durationS) {
  const n = Math.max(1, Math.min(1000, Math.round(durationS)))
  const w = durationS / n
  let bits = ""
  for (let b = 0; b < n; b++) {
    let c = 0
    for (const [s, e] of played) c += Math.max(0, Math.min(e, (b + 1) * w) - Math.max(s, b * w))
    bits += c >= w / 2 ? "1" : "0"
  }
  return bits
}

export function bitsToBase64(bits) {
  const a = new Uint8Array(Math.ceil(bits.length / 8))
  for (let i = 0; i < bits.length; i++) if (bits[i] === "1") a[i >> 3] |= 0x80 >> (i & 7)
  let s = ""
  for (const x of a) s += String.fromCharCode(x)
  return btoa(s)
}
