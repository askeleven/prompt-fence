/**
 * Characters that change what a model reads without changing what a person sees, and a
 * normalized view of text for matching, with a map back to the original offsets.
 */

/** Zero-width and other characters with no visible glyph. */
const ZERO_WIDTH = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0x180e, 0x034f,
  0x115f, 0x1160, 0x3164, 0xffa0, 0x00ad, 0x17b4, 0x17b5,
])

/** Bidirectional controls. LRM and RLM have honest uses in right-to-left text. */
const BIDI_OVERRIDE = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069])
const BIDI_MARK = new Set([0x200e, 0x200f, 0x061c])

/** @param {number} cp */
export const isTag = (cp) => cp >= 0xe0000 && cp <= 0xe007f
/** @param {number} cp */
export const isVariationSelector = (cp) =>
  (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)

/**
 * @param {number} cp
 * @returns {boolean}
 */
export function isInvisible(cp) {
  return (
    ZERO_WIDTH.has(cp) || BIDI_OVERRIDE.has(cp) || BIDI_MARK.has(cp) || isTag(cp) || isVariationSelector(cp)
  )
}

/** @param {number} cp */
export const isBidiOverride = (cp) => BIDI_OVERRIDE.has(cp)
/** @param {number} cp */
export const isZeroWidth = (cp) => ZERO_WIDTH.has(cp)

/**
 * Letters from other scripts that look like Latin ones, after lowercasing. Not the full
 * Unicode confusables table: the ones that turn up in real attacks on English text.
 *
 * @type {Record<string, string>}
 */
const CONFUSABLES = {
  // Cyrillic
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't',
  у: 'y', х: 'x', ѕ: 's', і: 'i', ї: 'i', ј: 'j', ԁ: 'd', һ: 'h', ԛ: 'q', ԝ: 'w', ӏ: 'l',
  ɡ: 'g', ո: 'n', ս: 'u', // Latin small script g, Armenian
  // Greek
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u',
  χ: 'x', γ: 'y', ω: 'w', ϲ: 'c', ϳ: 'j',
  // Punctuation people type and models read the same way
  '‘': "'", '’': "'", '‚': "'", '‛': "'", '′': "'",
  '“': '"', '”': '"', '„': '"', '‟': '"', '″': '"',
  '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-', '―': '-',
  '−': '-', '‹': '<', '›': '>', '＜': '<', '＞': '>',
}

const NEWLINES = new Set(['\n', '\r', ' ', ' ', '\u0085', '\v', '\f'])
const SPACE_RE = /\s/u

/**
 * @typedef {object} Normalized
 * @property {string} text Lowercased, invisible characters dropped, look-alikes folded
 *   to ASCII, runs of spaces collapsed to one space and runs with a line break to one
 *   line break.
 * @property {number[]} start Where each character of text starts in the original.
 * @property {number[]} end Where each character of text ends in the original.
 */

/**
 * @param {string} original
 * @returns {Normalized}
 */
export function normalize(original) {
  // Built as an array: indexing a string grown with += makes V8 flatten it each time.
  /** @type {string[]} */
  const chars = []
  /** @type {number[]} */
  const start = []
  /** @type {number[]} */
  const end = []

  for (let i = 0; i < original.length; ) {
    const cp = /** @type {number} */ (original.codePointAt(i))
    const ch = String.fromCodePoint(cp)
    const next = i + ch.length

    if (cp < 0x80 && cp > 0x20) {
      chars.push(cp >= 0x41 && cp <= 0x5a ? String.fromCharCode(cp + 32) : ch)
      start.push(i)
      end.push(next)
      i = next
      continue
    }

    if (isInvisible(cp)) {
      i = next
      continue
    }

    if (SPACE_RE.test(ch)) {
      const kind = NEWLINES.has(ch) ? '\n' : ' '
      const last = chars[chars.length - 1]
      if (last === ' ' || last === '\n') {
        if (kind === '\n') chars[chars.length - 1] = '\n'
        end[end.length - 1] = next
      } else {
        chars.push(kind)
        start.push(i)
        end.push(next)
      }
      i = next
      continue
    }

    for (const out of fold(ch)) {
      chars.push(out)
      start.push(i)
      end.push(next)
    }
    i = next
  }
  return { text: chars.join(''), start, end }
}

/** @type {Map<string, string>} */
const FOLD_CACHE = new Map()

/**
 * @param {string} ch One code point.
 * @returns {string}
 */
function fold(ch) {
  if (ch.length === 1 && ch.charCodeAt(0) < 0x80) return ch.toLowerCase()
  const cached = FOLD_CACHE.get(ch)
  if (cached !== undefined) return cached
  let out = ''
  for (const c of ch.normalize('NFKC').toLowerCase()) out += CONFUSABLES[c] ?? c
  FOLD_CACHE.set(ch, out)
  return out
}

/**
 * Whether a stretch of original text only reads as the normalized words because of
 * invisible characters or look-alike letters: someone dressed it up to slip past a filter.
 *
 * @param {string} slice
 * @returns {boolean}
 */
export function isObfuscated(slice) {
  for (const ch of slice) {
    const cp = /** @type {number} */ (ch.codePointAt(0))
    if (cp < 0x80) continue
    if (isInvisible(cp)) return true
    const folded = fold(ch)
    if (/^[a-z0-9]+$/.test(folded)) return true
  }
  return false
}

/**
 * Text hidden in Unicode tag characters (U+E0020 to U+E007E mirror printable ASCII), the
 * "ASCII smuggling" trick: invisible on screen, read by many models. The one honest use,
 * subdivision flags such as England's, starts with U+1F3F4 and is left alone.
 *
 * @param {string} text
 * @returns {{ start: number, end: number, decoded: string }[]}
 */
export function findTagRuns(text) {
  /** @type {{ start: number, end: number, decoded: string }[]} */
  const runs = []
  let i = 0
  while (i < text.length) {
    const cp = /** @type {number} */ (text.codePointAt(i))
    if (!isTag(cp)) {
      i += cp > 0xffff ? 2 : 1
      continue
    }
    const runStart = i
    let decoded = ''
    while (i < text.length) {
      const c = /** @type {number} */ (text.codePointAt(i))
      if (!isTag(c)) break
      if (c >= 0xe0020 && c <= 0xe007e) decoded += String.fromCharCode(c - 0xe0000)
      i += 2
    }
    const before = text.codePointAt(runStart - 2)
    const isFlag = before === 0x1f3f4 && i - runStart <= 16 && /^[a-z0-9]{2,7}$/.test(decoded)
    if (!isFlag) runs.push({ start: runStart, end: i, decoded })
  }
  return runs
}

/**
 * Bytes hidden in variation selectors after a visible character ("emoji smuggling"):
 * VS1 to VS16 carry 0 to 15 and VS17 to VS256 carry 16 to 255. One or two selectors
 * after an emoji are normal; a long run is a payload.
 *
 * @param {string} text
 * @param {number} [minRun]
 * @returns {{ start: number, end: number, decoded: string }[]}
 */
export function findVariationRuns(text, minRun = 8) {
  /** @type {{ start: number, end: number, decoded: string }[]} */
  const runs = []
  let i = 0
  while (i < text.length) {
    const cp = /** @type {number} */ (text.codePointAt(i))
    if (!isVariationSelector(cp)) {
      i += cp > 0xffff ? 2 : 1
      continue
    }
    const runStart = i
    /** @type {number[]} */
    const bytes = []
    while (i < text.length) {
      const c = /** @type {number} */ (text.codePointAt(i))
      if (!isVariationSelector(c)) break
      bytes.push(c <= 0xfe0f ? c - 0xfe00 : c - 0xe0100 + 16)
      i += c > 0xffff ? 2 : 1
    }
    if (bytes.length >= minRun) {
      runs.push({ start: runStart, end: i, decoded: new TextDecoder().decode(Uint8Array.from(bytes)) })
    }
  }
  return runs
}

const ZW_BITS = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff])

/**
 * Text written in binary with two zero-width characters, the oldest invisible-ink
 * scheme. Both ways round are tried; only a decoding that comes out as readable text
 * counts.
 *
 * @param {string} text
 * @returns {{ start: number, end: number, decoded: string }[]}
 */
export function findZeroWidthBinary(text) {
  /** @type {{ start: number, end: number, decoded: string }[]} */
  const runs = []
  const re = /[​‌‍⁠﻿]{16,}/g
  for (const m of text.matchAll(re)) {
    const chars = [...m[0]].map((c) => /** @type {number} */ (c.codePointAt(0)))
    const kinds = [...new Set(chars)].filter((c) => ZW_BITS.has(c))
    if (kinds.length !== 2) continue
    for (const one of kinds) {
      const bits = chars.map((c) => (c === one ? '1' : '0')).join('')
      let decoded = ''
      for (let b = 0; b + 8 <= bits.length; b += 8) decoded += String.fromCharCode(parseInt(bits.slice(b, b + 8), 2))
      if (isReadable(decoded)) {
        runs.push({ start: /** @type {number} */ (m.index), end: /** @type {number} */ (m.index) + m[0].length, decoded })
        break
      }
    }
  }
  return runs
}

/**
 * Mostly printable characters, some letters and at least one space: decoded words rather
 * than decoded noise.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function isReadable(text) {
  if (text.length < 8) return false
  let printable = 0
  let letters = 0
  for (const ch of text) {
    const cp = /** @type {number} */ (ch.codePointAt(0))
    if ((cp >= 0x20 && cp < 0x7f) || cp === 0x0a || cp === 0x0d || cp === 0x09 || (cp >= 0xa0 && cp !== 0xfffd)) printable++
    if (/\p{L}/u.test(ch)) letters++
  }
  const length = [...text].length
  return printable / length >= 0.9 && letters / length >= 0.5 && /\s/.test(text)
}

/**
 * Removes every invisible character, keeping subdivision flag tag sequences and single
 * emoji variation selectors.
 *
 * @param {string} text
 * @returns {{ text: string, removed: number }}
 */
export function stripInvisible(text) {
  const keep = new Set()
  for (let i = 0; i < text.length; ) {
    const cp = /** @type {number} */ (text.codePointAt(i))
    if (cp === 0x1f3f4) {
      let j = i + 2
      while (j < text.length && isTag(/** @type {number} */ (text.codePointAt(j)))) j += 2
      if (j - (i + 2) <= 16) for (let k = i + 2; k < j; k += 2) keep.add(k)
      i = j
      continue
    }
    if (cp === 0xfe0f || cp === 0xfe0e) {
      const prev = codePointBefore(text, i)
      const nextCp = text.codePointAt(i + 1)
      if (prev !== undefined && !isVariationSelector(prev) && (nextCp === undefined || !isVariationSelector(nextCp))) {
        keep.add(i)
      }
    }
    // A zero-width joiner between two emoji builds one emoji, such as a family.
    if (cp === 0x200d) {
      const prev = codePointBefore(text, i)
      const nextCp = text.codePointAt(i + 1)
      if (prev !== undefined && nextCp !== undefined && (isEmoji(prev) || prev === 0xfe0f) && isEmoji(nextCp)) {
        keep.add(i)
      }
    }
    i += cp > 0xffff ? 2 : 1
  }

  let out = ''
  let removed = 0
  for (let i = 0; i < text.length; ) {
    const cp = /** @type {number} */ (text.codePointAt(i))
    const ch = String.fromCodePoint(cp)
    if (isInvisible(cp) && !keep.has(i)) removed++
    else out += ch
    i += ch.length
  }
  return { text: out, removed }
}

/**
 * @param {string} text
 * @param {number} i
 * @returns {number | undefined}
 */
function codePointBefore(text, i) {
  if (i <= 0) return undefined
  const low = text.charCodeAt(i - 1)
  if (low >= 0xdc00 && low <= 0xdfff && i >= 2) return text.codePointAt(i - 2)
  return low
}

/** @param {number} cp */
const isEmoji = (cp) => /\p{Extended_Pictographic}|\p{Emoji_Modifier}/u.test(String.fromCodePoint(cp))
