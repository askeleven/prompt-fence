/**
 * Enough of RFC 5322, 2045-2047 and 2231 to read a raw email the way a triage agent
 * sees it: headers, every text part, attached emails, and attachment names.
 */

/**
 * @typedef {object} MimePart
 * @property {string} type Lowercase, such as text/html.
 * @property {string} text Decoded text for text parts, "" otherwise.
 * @property {string | null} filename
 * @property {number} size Decoded bytes.
 * @property {string} path Where the part sits, such as "1.2".
 *
 * @typedef {object} ParsedEmail
 * @property {Record<string, string>} headers Lowercase names, decoded, first value wins.
 * @property {MimePart[]} parts Leaf parts in order, attached emails flattened in.
 * @property {ParsedEmail[]} attached Emails attached as message/rfc822.
 */

const MAX_DEPTH = 8

/**
 * @param {string} raw
 * @returns {ParsedEmail}
 */
export function parseEmail(raw) {
  return parseEntity(raw.replace(/\r\n?/g, '\n'), '', 0)
}

/**
 * Whether text starts like an email: header lines and at least two of the headers every
 * email has.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeEmail(text) {
  const head = text.replace(/\r\n?/g, '\n').split('\n\n', 1)[0]
  if (!/^[A-Za-z][A-Za-z0-9-]*:[ \t]/.test(head)) return false
  const names = new Set(
    [...head.matchAll(/^([A-Za-z][A-Za-z0-9-]*):/gm)].map((m) => m[1].toLowerCase()),
  )
  const core = ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type', 'received']
  return core.filter((n) => names.has(n)).length >= 2
}

/**
 * @param {string} raw
 * @param {string} path
 * @param {number} depth
 * @returns {ParsedEmail}
 */
function parseEntity(raw, path, depth) {
  const split = raw.indexOf('\n\n')
  const headText = split === -1 ? raw : raw.slice(0, split)
  const body = split === -1 ? '' : raw.slice(split + 2)
  const headers = parseHeaders(headText)

  /** @type {ParsedEmail} */
  const email = { headers, parts: [], attached: [] }
  walk(headers, body, path || '1', depth, email)
  return email
}

/**
 * @param {Record<string, string>} headers
 * @param {string} body
 * @param {string} path
 * @param {number} depth
 * @param {ParsedEmail} into
 */
function walk(headers, body, path, depth, into) {
  const contentType = parseParams(headers['content-type'] ?? 'text/plain')
  const type = contentType.value.toLowerCase() || 'text/plain'
  const disposition = parseParams(headers['content-disposition'] ?? '')
  const filename = disposition.params.filename ?? contentType.params.name ?? null

  if (type.startsWith('multipart/') && contentType.params.boundary && depth < MAX_DEPTH) {
    const pieces = splitMultipart(body, contentType.params.boundary)
    pieces.forEach((piece, n) => {
      const split = piece.indexOf('\n\n')
      const partHeaders = parseHeaders(split === -1 ? piece : piece.slice(0, split))
      const partBody = split === -1 ? '' : piece.slice(split + 2)
      walk(partHeaders, partBody, `${path}.${n + 1}`, depth + 1, into)
    })
    return
  }

  const encoding = (headers['content-transfer-encoding'] ?? '').toLowerCase().trim()
  const encoded = encoding === 'base64' || encoding === 'quoted-printable'
  const bytes = encoded ? decodeTransfer(body, encoding) : Buffer.from(body, 'utf8')
  // 7bit, 8bit and binary bodies are already characters by the time they are a string.
  const asText = (/** @type {string} */ charset) => (encoded ? bytesToString(bytes, charset) : body)

  if (type === 'message/rfc822' && depth < MAX_DEPTH) {
    const inner = parseEntity(asText('utf-8').replace(/\r\n?/g, '\n'), path, depth + 1)
    into.attached.push(inner)
    into.parts.push({ type, text: '', filename, size: bytes.length, path })
    into.parts.push(...inner.parts)
    return
  }

  const isText = type.startsWith('text/') || type === 'application/json' || type === 'application/xml'
  const text = isText ? asText(contentType.params.charset ?? 'utf-8') : ''
  into.parts.push({ type, text, filename, size: bytes.length, path })
}

/**
 * @param {string} body
 * @param {string} boundary
 * @returns {string[]}
 */
function splitMultipart(body, boundary) {
  const lines = body.split('\n')
  /** @type {string[]} */
  const pieces = []
  /** @type {string[] | null} */
  let current = null
  const open = `--${boundary}`
  const close = `--${boundary}--`
  for (const line of lines) {
    const trimmed = line.trimEnd()
    if (trimmed === close) {
      if (current) pieces.push(current.join('\n'))
      current = null
      break
    }
    if (trimmed === open) {
      if (current) pieces.push(current.join('\n'))
      current = []
      continue
    }
    if (current) current.push(line)
  }
  if (current) pieces.push(current.join('\n'))
  return pieces
}

/**
 * @param {string} text
 * @returns {Record<string, string>}
 */
function parseHeaders(text) {
  /** @type {Record<string, string>} */
  const headers = {}
  const unfolded = text.replace(/\n[ \t]+/g, ' ')
  for (const line of unfolded.split('\n')) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    const name = line.slice(0, colon).trim().toLowerCase()
    if (!/^[a-z0-9-]+$/.test(name) || name in headers) continue
    headers[name] = decodeWords(line.slice(colon + 1).trim())
  }
  return headers
}

/**
 * @param {string} header
 * @returns {{ value: string, params: Record<string, string> }}
 */
function parseParams(header) {
  const [value, ...rest] = splitOutsideQuotes(header, ';')
  /** @type {Record<string, string>} */
  const params = {}
  /** @type {Record<string, string[]>} */
  const continued = {}
  for (const piece of rest) {
    const eq = piece.indexOf('=')
    if (eq === -1) continue
    let key = piece.slice(0, eq).trim().toLowerCase()
    let val = piece.slice(eq + 1).trim()
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1).replace(/\\(.)/g, '$1')
    // RFC 2231: name*=charset'lang'percent-encoded, possibly split as name*0*, name*1*.
    const extended = /^(.+?)(\*\d+)?(\*)?$/.exec(key)
    if (extended && (extended[2] || extended[3])) {
      key = extended[1]
      if (extended[3]) val = decode2231(val, !!extended[2] && !extended[2].endsWith('*0'))
      ;(continued[key] ??= []).push(val)
      continue
    }
    params[key] = decodeWords(val)
  }
  for (const [key, vals] of Object.entries(continued)) params[key] = vals.join('')
  return { value: value.trim(), params }
}

/**
 * @param {string} value
 * @param {boolean} isContinuation Later pieces have no charset prefix.
 * @returns {string}
 */
function decode2231(value, isContinuation) {
  let charset = 'utf-8'
  let encoded = value
  if (!isContinuation) {
    const m = /^([^']*)'[^']*'(.*)$/.exec(value)
    if (m) {
      charset = m[1] || 'utf-8'
      encoded = m[2]
    }
  }
  const bytes = []
  for (let i = 0; i < encoded.length; i++) {
    if (encoded[i] === '%' && /^[0-9a-f]{2}$/i.test(encoded.slice(i + 1, i + 3))) {
      bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16))
      i += 2
    } else bytes.push(encoded.charCodeAt(i) & 0xff)
  }
  return bytesToString(Uint8Array.from(bytes), charset)
}

/**
 * @param {string} text
 * @param {string} separator
 * @returns {string[]}
 */
function splitOutsideQuotes(text, separator) {
  /** @type {string[]} */
  const out = []
  let current = ''
  let quoted = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (ch === '"' && text[i - 1] !== '\\') quoted = !quoted
    if (ch === separator && !quoted) {
      out.push(current)
      current = ''
    } else current += ch
  }
  out.push(current)
  return out
}

/**
 * RFC 2047 encoded words, such as =?utf-8?B?SGk=?=.
 *
 * @param {string} text
 * @returns {string}
 */
export function decodeWords(text) {
  return text
    .replace(/(=\?[^?]+\?[bq]\?[^?]*\?=)\s+(?==\?[^?]+\?[bq]\?)/gi, '$1')
    .replace(/=\?([^?*]+)(?:\*[^?]*)?\?([bq])\?([^?]*)\?=/gi, (whole, charset, enc, data) => {
      try {
        const bytes =
          enc.toLowerCase() === 'b'
            ? Buffer.from(data, 'base64')
            : Buffer.from(
                data.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (/** @type {string} */ _m, /** @type {string} */ h) => String.fromCharCode(parseInt(h, 16))),
                'latin1',
              )
        return bytesToString(bytes, charset)
      } catch {
        return whole
      }
    })
}

/**
 * @param {string} body
 * @param {'base64' | 'quoted-printable'} encoding
 * @returns {Uint8Array}
 */
function decodeTransfer(body, encoding) {
  if (encoding === 'base64') return Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64')
  const utf8 = Buffer.from(body.replace(/=[ \t]*\n/g, ''), 'utf8')
  /** @type {number[]} */
  const bytes = []
  for (let i = 0; i < utf8.length; i++) {
    if (utf8[i] === 0x3d && i + 2 < utf8.length) {
      const hex = String.fromCharCode(utf8[i + 1], utf8[i + 2])
      if (/^[0-9a-f]{2}$/i.test(hex)) {
        bytes.push(parseInt(hex, 16))
        i += 2
        continue
      }
    }
    bytes.push(utf8[i])
  }
  return Uint8Array.from(bytes)
}

/**
 * @param {Uint8Array} bytes
 * @param {string} charset
 * @returns {string}
 */
function bytesToString(bytes, charset) {
  const label = charset.trim().toLowerCase().replace(/^"|"$/g, '')
  try {
    return new TextDecoder(label === 'us-ascii' || label === 'ascii' ? 'utf-8' : label).decode(bytes)
  } catch {
    return new TextDecoder('utf-8').decode(bytes)
  }
}
