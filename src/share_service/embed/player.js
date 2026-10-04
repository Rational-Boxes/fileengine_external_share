// The media origin's player page (MEDIA_SHARE.md §9.2) — vanilla, no build.
//
// Same-origin calls only (CSP connect-src 'self'). The gate is here, never in
// the host page. Messages to the embedding page go ONLY to the origin the host
// named in ?parent=, and only if that origin is on the link's embed allowlist
// (or the link is embeddable anywhere); messages FROM the host are accepted only
// from that same origin. No '*' target in either direction.

const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.getAttribute('content') || ''
const LINK = meta('fe-link')
const ALLOWED = (() => { try { return JSON.parse(meta('fe-embed-origins') || '[]') } catch { return [] } })()
const q = new URLSearchParams(location.search)
const K = q.get('k') || ''
const PARENT = (() => {
  try { const o = new URL(q.get('parent') || '').origin; return (ALLOWED.includes('*') || ALLOWED.includes(o)) ? o : '' }
  catch { return '' }
})()
const AUTOPLAY = q.get('autoplay') === 'true'
const BASE = `/media/v1/${LINK}`
const CONSENT_ID = 'media-v1'
const app = document.getElementById('app')

function tell(type, detail = {}) {
  // Never the address: fe:media-identified says THAT someone identified.
  if (PARENT && window.parent !== window) window.parent.postMessage({ type, ...detail }, PARENT)
}

window.addEventListener('message', (e) => {
  if (!PARENT || e.origin !== PARENT || !e.data || e.data.type !== 'fe:media-command') return
  const v = document.querySelector('video, audio')
  if (!v) return
  if (e.data.command === 'play') v.play().catch(() => {})
  if (e.data.command === 'pause') v.pause()
})

const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) n.addEventListener(k.slice(2), v)
    else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v)
  }
  for (const c of kids) n.append(c)
  return n
}

async function api(path, body, headers = {}) {
  const r = await fetch(`${BASE}${path}${path.includes('?') ? '&' : '?'}k=${encodeURIComponent(K)}`,
    body === undefined ? { credentials: 'omit' }
      : { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'text/plain', ...headers },
          body: JSON.stringify(body) })
  const data = await r.json().catch(() => ({}))
  return { status: r.status, data }
}

function show(...nodes) { app.replaceChildren(...nodes) }
function gone() { show(el('h1', {}, "This link isn't available"),
  el('p', { class: 'fp-small' }, 'It may have expired or been withdrawn.')); tell('fe:media-error') }

// ── the beacon (§7.4): cumulative coverage from the element's own `played` ──
function quantise(v) {
  const d = v.duration, n = Math.max(1, Math.min(1000, Math.round(d))), w = d / n
  let bits = ''
  for (let b = 0; b < n; b++) {
    let c = 0
    for (let i = 0; i < v.played.length; i++) c += Math.max(0, Math.min(v.played.end(i), (b + 1) * w) - Math.max(v.played.start(i), b * w))
    bits += c >= w / 2 ? '1' : '0'
  }
  return bits
}
function b64(bits) {
  const a = new Uint8Array(Math.ceil(bits.length / 8))
  for (let i = 0; i < bits.length; i++) if (bits[i] === '1') a[i >> 3] |= 0x80 >> (i & 7)
  return btoa(String.fromCharCode(...a))
}
function track(v, url, quality) {
  let plays = 0, ended = false, since = 0, last = 0, rate = 1
  const send = (beacon) => {
    if (!Number.isFinite(v.duration) || !v.duration) return
    const bits = quantise(v)
    let furthest = 0, watched = 0
    for (let i = 0; i < v.played.length; i++) { furthest = Math.max(furthest, v.played.end(i)); watched += v.played.end(i) - v.played.start(i) }
    const body = JSON.stringify({ buckets: bits.length, coverage: b64(bits), duration_ms: Math.round(v.duration * 1000),
      furthest_ms: Math.round(furthest * 1000), watch_ms: Math.round(watched * 1000), plays, rate_max: rate, ended, quality })
    since = 0
    if (beacon && navigator.sendBeacon) navigator.sendBeacon(url, new Blob([body], { type: 'text/plain' }))
    else fetch(url, { method: 'POST', body, credentials: 'omit', keepalive: true, headers: { 'Content-Type': 'text/plain' } }).catch(() => {})
  }
  v.addEventListener('play', () => { plays++; if (plays === 1) send(); tell('fe:media-play') })
  v.addEventListener('timeupdate', () => { const d = v.currentTime - last; last = v.currentTime; if (d > 0 && d < 2) since += d; if (since >= 30) send() })
  v.addEventListener('ratechange', () => { rate = Math.max(rate, v.playbackRate) })
  v.addEventListener('pause', () => send())
  v.addEventListener('ended', () => { ended = true; send(); tell('fe:media-ended') })
  addEventListener('pagehide', () => send(true))
}

function play(peek, s) {
  const probe = document.createElement(peek.kind === 'audio' ? 'audio' : 'video')
  const src = s.sources.find((x) => !x.mime || probe.canPlayType(x.mime) !== '') || s.sources[0]
  const v = el(peek.kind === 'audio' ? 'audio' : 'video', { controls: true, playsinline: true, src: src.url,
    poster: peek.poster ? `${peek.poster}?k=${encodeURIComponent(K)}` : false, autoplay: true })
  if (s.beacon) track(v, s.beacon, src.quality)
  show(el('h1', {}, peek.title || 'Shared video'), v)
}

async function session(peek, path, body, headers) {
  const r = await api(path, body, headers)
  if (r.status === 200) { if (peek.requires !== 'none') tell('fe:media-identified'); play(peek, r.data); return true }
  if (r.status === 202) { show(el('p', {}, 'Still being prepared — try again in a minute.')); return false }
  if (r.status === 400 || r.status === 429) return false
  gone(); return false
}

async function main() {
  const r = await api('')
  if (r.status === 503) { show(el('p', {}, r.data?.message || 'Temporarily unavailable.')); tell('fe:media-error'); return }
  if (r.status !== 200) return gone()
  const peek = r.data
  tell('fe:media-ready', { requires: peek.requires, state: peek.state })
  const note = el('p', { class: 'fp-small' }, peek.tracking
    ? `The sender can see whether and how much of this you ${peek.kind === 'audio' ? 'listen to' : 'watch'}.`
    : 'The sender does not see how much of this you watch.')
  const title = el('h1', {}, peek.title || 'Shared video')
  if (peek.state !== 'ready') { show(title, el('p', {}, 'This video is still being prepared — usually a minute or two.')); setTimeout(main, 5000); return }

  if (peek.requires === 'none') {
    const start = () => session(peek, '/session', {})
    if (AUTOPLAY) return start()
    const btn = el('button', { onclick: start, 'aria-label': 'Play' }, '▶')
    return show(title, peek.poster ? el('div', { class: 'fp-poster' },
      el('img', { src: `${peek.poster}?k=${encodeURIComponent(K)}`, alt: '' }), btn) : btn, note)
  }
  tell('fe:media-gate', { requires: peek.requires })
  const email = el('input', { type: 'email', required: true, autocomplete: 'email' })
  const err = el('p', { class: 'fp-err' })
  if (peek.requires === 'email') {
    const consent = el('input', { type: 'checkbox', required: true })
    const form = el('form', { onsubmit: async (e) => { e.preventDefault(); err.textContent = ''
      const ok = await session(peek, '/claim', { email: email.value.trim().toLowerCase(), consent: consent.checked, consent_text_id: CONSENT_ID })
      if (!ok) err.textContent = 'Please check the address and try again.' } },
      el('label', {}, 'Your email address', email), el('label', { class: 'chk' }, consent, note.textContent), err,
      el('button', { type: 'submit' }, 'Watch'))
    return show(title, form)
  }
  // verified: an emailed code
  const code = el('input', { inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', required: true })
  const step2 = el('form', { onsubmit: async (e) => { e.preventDefault(); err.textContent = ''
    const v = await api('/verify', { email: email.value.trim().toLowerCase(), code: code.value.trim() })
    if (v.status !== 200 || !v.data.ok) { err.textContent = v.data?.locked ? 'Too many attempts — try later.' : 'That code was not right.'; return }
    await session(peek, '/session', { email: email.value.trim().toLowerCase() }, { 'X-Recipient-Token': v.data.recipient_token }) } },
    el('p', {}, 'If that address is on this link, a code is on its way.'), el('label', {}, 'Six-digit code', code), err,
    el('button', { type: 'submit' }, 'Continue'))
  const step1 = el('form', { onsubmit: async (e) => { e.preventDefault()
    await api('/identify', { email: email.value.trim().toLowerCase() }); show(title, step2) } },
    el('p', {}, "We'll email you a one-time code — that's how we check it's you."),
    el('label', {}, 'Your email address', email), el('button', { type: 'submit' }, 'Email me a code'))
  show(title, step1, note)
}

main().catch(() => gone())
