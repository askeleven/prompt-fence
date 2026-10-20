import { isReadable } from './unicode.js'

/**
 * Finds stretches of text in an encoding a model can read but a filter would not:
 * base64, hex, percent-encoding and escape sequences. Only decodings that come out as
 * readable words are returned, so tracking tokens and IDs drop out.
 */

/**
 * @typedef {object} Encoded
 * @property {number} start
 * @property {number} end
 * @property {'base64'|'hex'|'percent'|'escapes'} scheme
 * @property {string} decoded
 */

const BASE64_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])/g
const HEX_RE = /(?<![0-9a-f])(?:[0-9a-f]{2}[ :]?){16,}(?![0-9a-f])/gi
// Whole runs of escapes, or words with escaped spaces between them, as encodeURIComponent writes.
const PERCENT_RE = /(?:%[0-9a-f]{2}){8,}|(?:[A-Za-z0-9._~'!*()-]+%[0-9a-f]{2}){4,}[A-Za-z0-9._~'!*()-]*/gi
const ESCAPES_RE = /(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){8,}/gi

/**
 * @param {string} text
 * @returns {Encoded[]}
 */
export function findEncoded(text) {
  /** @type {Encoded[]} */
  const found = []
  /**
   * @param {RegExp} re
   * @param {Encoded['scheme']} scheme
   * @param {(s: string) => string | null} decode
   */
  const scan = (re, scheme, decode) => {
    for (const m of text.matchAll(re)) {
      const start = /** @type {number} */ (m.index)
      if (found.some((f) => start < f.end && f.start < start + m[0].length)) continue
      const decoded = decode(m[0])
      if (decoded !== null && isReadable(decoded)) found.push({ start, end: start + m[0].length, scheme, decoded })
    }
  }
  scan(HEX_RE, 'hex', (s) => utf8(Buffer.from(s.replace(/[ :]/g, ''), 'hex')))
  scan(PERCENT_RE, 'percent', (s) => {
    try {
      return decodeURIComponent(s)
    } catch {
      return null
    }
  })
  scan(ESCAPES_RE, 'escapes', (s) =>
    s.replace(/\\u([0-9a-f]{4})|\\x([0-9a-f]{2})/gi, (_m, u, x) => String.fromCharCode(parseInt(u ?? x, 16))),
  )
  scan(BASE64_RE, 'base64', (s) => {
    // A run of one letter case with no digits is a long word or an identifier.
    if (!/[0-9+/_-]/.test(s) && !(/[a-z]/.test(s) && /[A-Z]/.test(s))) return null
    return utf8(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
  })
  return found.sort((a, b) => a.start - b.start)
}

/**
 * @param {Uint8Array} bytes
 * @returns {string | null}
 */
function utf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
}

/**
 * @param {string} text
 * @returns {string}
 */
export function rot13(text) {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
  })
}
