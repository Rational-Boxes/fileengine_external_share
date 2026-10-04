// SPDX-License-Identifier: MIT
// FileEngine embedding kit — <fe-media-share> (MEDIA_SHARE.md §9). (c) 2026 James Hickman.
//
// The first component in the kit that does NOT use <fe-session>, and must not
// require one: it takes a share URL and nothing else.
//
//   <script type="module" src="https://acme-media.example.com/media/v1/embed/fe-media-share.js"></script>
//   <fe-media-share src="https://acme-media.example.com/media/v1/<link>?k=<secret>"></fe-media-share>
//
// It asks the door what the link requires BEFORE rendering anything, and takes
// one of two shapes (§9.2):
//   * gated (claimed / verified) -> a cross-origin <iframe> to the media origin's
//     player page. The gate lives there, where the host page cannot read what is
//     typed or forge it. There is no attribute to opt out of this.
//   * open -> an in-page <video> in a CLOSED shadow root. The viewer session
//     token (it rides in the media URLs) lives in this closure only — never in
//     localStorage, an attribute or a dataset field the host can read.
//
// Attributes: src (required), poster ("auto"|"none"), autoplay, muted, loop,
// width, height, aspect, theme (light|dark|auto), lang.
// Events: fe:media-ready, fe:media-play, fe:media-ended, fe:media-gate,
// fe:media-identified (never carries the address), fe:media-error.
// Methods: play(), pause().

import {
  parseShareSrc, renderingFor, peekUrl, sessionUrl, posterUrl, playerUrl,
  acceptFrameMessage, eventDetail, pickSource, absolutise, boxStyle, quantise, bitsToBase64,
} from "./media-share-model.js"

const Base = (typeof HTMLElement !== "undefined") ? HTMLElement : class {}

export class FeMediaShare extends Base {
  static get observedAttributes() { return ["src"] }

  // All private. Nothing here is reachable from the host page.
  #root = null
  #parsed = null
  #shape = null
  #frame = null
  #media = null
  #onMessage = null
  #fetch = (typeof fetch !== "undefined") ? fetch.bind(globalThis) : null

  /** Test seam: the fetch implementation. */
  set fetchImpl(f) { this.#fetch = f }

  connectedCallback() { void this.#start() }
  attributeChangedCallback(_n, a, b) { if (this.isConnected && a !== null && a !== b) void this.#start() }
  disconnectedCallback() {
    if (this.#onMessage && typeof window !== "undefined") window.removeEventListener("message", this.#onMessage)
  }

  /** The rendering in use: "iframe" | "inline" | null (introspection for tests/hosts). */
  get rendering() { return this.#shape }

  play() {
    if (this.#media) return this.#media.play()
    if (this.#frame && this.#parsed) this.#frame.contentWindow?.postMessage({ type: "fe:media-command", command: "play" }, this.#parsed.origin)
  }
  pause() {
    if (this.#media) return this.#media.pause()
    if (this.#frame && this.#parsed) this.#frame.contentWindow?.postMessage({ type: "fe:media-command", command: "pause" }, this.#parsed.origin)
  }

  #emit(type, detail = {}) {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }))
  }

  #shadow() {
    if (!this.#root) this.#root = this.attachShadow ? this.attachShadow({ mode: "closed" }) : this
    return this.#root
  }

  async #start() {
    this.#parsed = parseShareSrc(this.getAttribute("src"))
    if (!this.#parsed || !this.#fetch) return this.#emit("fe:media-error", { reason: "bad-src" })
    let peek = null
    try {
      const r = await this.#fetch(peekUrl(this.#parsed), { credentials: "omit" })
      if (r.status === 503) return this.#unavailable((await r.json().catch(() => ({}))).message)
      if (!r.ok) return this.#unavailable()
      peek = await r.json()
    } catch {
      return this.#unavailable()
    }
    // The door decides. Only now is anything rendered.
    this.#shape = renderingFor(peek)
    if (this.#shape === "iframe") this.#renderFrame()
    else this.#renderInline(peek)
  }

  #unavailable(message) {
    this.#shadow().innerHTML = `<p part="message" style="font:14px system-ui">${escapeText(message || "This video isn't available.")}</p>`
    this.#emit("fe:media-error", { reason: "unavailable" })
  }

  #box() {
    const s = boxStyle({ width: this.getAttribute("width"), height: this.getAttribute("height"),
                        aspect: this.getAttribute("aspect") })
    return Object.entries(s).map(([k, v]) => `${k.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())}:${v}`).join(";")
  }

  #renderFrame() {
    const host = (typeof location !== "undefined") ? location.origin : ""
    const src = playerUrl(this.#parsed, { parent: host, autoplay: this.getAttribute("autoplay") === "true" })
    const root = this.#shadow()
    root.innerHTML = `<style>:host{display:block}iframe{border:0;display:block;${this.#box()}}</style>`
      + `<iframe allow="autoplay; fullscreen; picture-in-picture" referrerpolicy="origin" title="Video"></iframe>`
    this.#frame = root.querySelector("iframe")
    this.#frame.src = src
    const door = this.#parsed.origin
    this.#onMessage = (e) => {
      if (e.source !== this.#frame.contentWindow || !acceptFrameMessage(e, door)) return
      this.#emit(e.data.type, eventDetail(e.data))
    }
    window.addEventListener("message", this.#onMessage)
  }

  #renderInline(peek) {
    const root = this.#shadow()
    const poster = this.getAttribute("poster") === "none" ? "" : posterUrl(this.#parsed, peek)
    root.innerHTML = `<style>:host{display:block}.b{position:relative;${this.#box()};background:#000}`
      + `video,audio,img{width:100%;height:100%;object-fit:contain;display:block}`
      + `button{position:absolute;inset:0;margin:auto;width:64px;height:64px;border-radius:50%;border:0;`
      + `background:rgba(0,0,0,.6);color:#fff;font-size:24px;cursor:pointer}</style>`
      + `<div class="b" part="player">${poster ? '<img alt="" part="poster">' : ""}`
      + `<button part="play" aria-label="Play">▶</button></div>`
    if (poster) root.querySelector("img").src = poster
    this.#emit("fe:media-ready", { requires: "none", state: peek.state })
    const start = async () => {
      const btn = root.querySelector("button")
      if (btn) btn.disabled = true
      // The session token lives in THIS closure only.
      let s
      try {
        const r = await this.#fetch(sessionUrl(this.#parsed), { method: "POST", credentials: "omit",
          headers: { "Content-Type": "text/plain" }, body: "{}" })
        if (!r.ok) return this.#unavailable(r.status === 503 ? (await r.json().catch(() => ({}))).message : "")
        s = await r.json()
      } catch {
        return this.#unavailable()
      }
      const kind = peek.kind === "audio" ? "audio" : "video"
      const probe = document.createElement(kind)
      const src = pickSource(absolutise(this.#parsed, s.sources), (m) => probe.canPlayType(m) !== "")
      const media = document.createElement(kind)
      media.controls = true
      media.setAttribute("playsinline", "")
      media.muted = this.getAttribute("muted") === "true"
      media.loop = this.getAttribute("loop") === "true"
      media.src = src ? src.url : ""
      if (poster && kind === "video") media.poster = poster
      root.querySelector(".b").replaceChildren(media)
      this.#media = media
      media.addEventListener("play", () => this.#emit("fe:media-play"))
      media.addEventListener("ended", () => this.#emit("fe:media-ended"))
      if (s.beacon) this.#track(media, `${this.#parsed.origin}${s.beacon}`, src && src.quality)
      void media.play().catch(() => {})
    }
    root.querySelector("button").addEventListener("click", start)
    if (this.getAttribute("autoplay") === "true") void start()
  }

  #track(v, url, quality) {
    let plays = 0, ended = false, since = 0, last = 0
    const send = (beacon) => {
      if (!Number.isFinite(v.duration) || !v.duration) return
      const played = []
      for (let i = 0; i < v.played.length; i++) played.push([v.played.start(i), v.played.end(i)])
      const bits = quantise(played, v.duration)
      const body = JSON.stringify({ buckets: bits.length, coverage: bitsToBase64(bits),
        duration_ms: Math.round(v.duration * 1000),
        furthest_ms: Math.round(Math.max(0, ...played.map((p) => p[1])) * 1000),
        watch_ms: Math.round(played.reduce((m, p) => m + p[1] - p[0], 0) * 1000), plays, ended, quality })
      since = 0
      if (beacon && navigator.sendBeacon) navigator.sendBeacon(url, new Blob([body], { type: "text/plain" }))
      else fetch(url, { method: "POST", body, credentials: "omit", keepalive: true, headers: { "Content-Type": "text/plain" } }).catch(() => {})
    }
    v.addEventListener("play", () => { plays++; if (plays === 1) send() })
    v.addEventListener("timeupdate", () => { const d = v.currentTime - last; last = v.currentTime; if (d > 0 && d < 2) since += d; if (since >= 30) send() })
    v.addEventListener("pause", () => send())
    v.addEventListener("ended", () => { ended = true; send() })
    window.addEventListener("pagehide", () => send(true))
  }
}

function escapeText(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

export function defineFeMediaShare(registry =
    (typeof customElements !== "undefined" ? customElements : null)) {
  if (registry && !registry.get("fe-media-share")) registry.define("fe-media-share", FeMediaShare)
  return FeMediaShare
}

// Served as a plain <script type="module"> from the media origin, so it defines
// itself on load — the host adds one tag and one element.
defineFeMediaShare()
