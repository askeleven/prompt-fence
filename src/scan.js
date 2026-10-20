import { RULES, HIDDEN_RULES, POINTS, CODES } from './rules.js'
import {
  normalize,
  isObfuscated,
  findTagRuns,
  findVariationRuns,
  findZeroWidthBinary,
  isBidiOverride,
} from './unicode.js'
import { findEncoded, rot13 } from './decode.js'
import { extract } from './extract.js'

/**
 * @typedef {import('./rules.js').Code} Code
 * @typedef {import('./rules.js').Severity} Severity
 * @typedef {import('./rules.js').Rule} Rule
 * @typedef {import('./extract.js').Segment} Segment
 * @typedef {import('./extract.js').ContentType} ContentType
 * @typedef {import('./extract.js').Entities} Entities
 * @typedef {import('./extract.js').EmailMeta} EmailMeta
 *
 * @typedef {'allow'|'review'|'block'} Verdict
 *
 * @typedef {object} Finding
 * @property {Code} code
 * @property {string} rule Which rule matched, such as ignore_all_instructions.
 * @property {Severity} severity
 * @property {number} points What it added to the score. Repeats of a rule count for less.
 * @property {string} where Which part of the content, such as "subject" or "body, hidden".
 * @property {string} text The words as written, up to 200 characters.
 * @property {number} start Offset in that part's text, in UTF-16 units.
 * @property {number} end
 * @property {number} line 1-based, within that part.
 * @property {number} column 1-based.
 * @property {boolean} hidden A person reading the message would not see it.
 * @property {string} why Why it is hidden, or "".
 * @property {boolean} obfuscated It only reads this way once look-alike letters or
 *   invisible characters are undone.
 * @property {string | null} decoded For text found inside an encoding or invisible
 *   characters, what it decodes to.
 * @property {string} detail Plain English.
 *
 * @typedef {object} Reason
 * @property {Code} code Stable, safe to match on.
 * @property {Severity} severity The worst finding with this code.
 * @property {number} count
 * @property {string} detail
 *
 * @typedef {object} ScanResult
 * @property {Verdict} verdict block on any high finding or a score at blockAt;
 *   review at reviewAt; otherwise allow.
 * @property {number} score 0 to 100. How much the content reads as an attempt to
 *   instruct an AI that reads it.
 * @property {string} summary One line for a person.
 * @property {Reason[]} reasons Worst first.
 * @property {Finding[]} findings Worst first, then in order.
 * @property {ContentType} type What the content was read as.
 * @property {Entities} entities Addresses, links, domains and phone numbers in the
 *   content, hidden parts included: the places an injected instruction could point a
 *   tool call.
 * @property {string[]} senders For an email, its From, Reply-To and Sender addresses.
 * @property {EmailMeta | null} email
 * @property {{ segments: number, hiddenSegments: number, characters: number }} facts
 * @property {string[]} notes
 *
 * @typedef {object} ScanOptions
 * @property {ContentType | 'auto'} [type] Default auto: an email if it starts with email
 *   headers, HTML if it has tags, text otherwise.
 * @property {number} [reviewAt] Default 25.
 * @property {number} [blockAt] Default 50: two medium findings, such as an instruction
 *   addressed to an AI and a request to delete mail.
 * @property {string[]} [ignore] Codes or rule ids to skip.
 */

export const DEFAULT_REVIEW_AT = 25
export const DEFAULT_BLOCK_AT = 50

const SEVERITY_ORDER = { high: 2, medium: 1, low: 0 }
const MAX_DEPTH = 2
const EXCERPT = 200

export class FenceError extends Error {
  /**
   * @param {'invalid_option'|'invalid_input'} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message)
    this.name = 'FenceError'
    this.code = code
  }
}

const RULE_IDS = new Set(RULES.map((r) => r.id))
const EXTRA_RULE_IDS = new Set([
  'instructions_in_hidden_text', 'disguised_instructions', 'tag_characters', 'variation_selectors',
  'zero_width_binary', 'zero_width_in_words', 'bidi_controls', 'base64', 'hex', 'percent', 'escapes', 'rot13',
  'leetspeak', 'letter_spacing', 'reversed_text',
])

/**
 * Reads content an agent is about to see (an email, a web page, a chat message) and
 * reports what in it reads as instructions for the agent rather than information for
 * a person.
 *
 * @param {string} input
 * @param {ScanOptions} [options]
 * @returns {ScanResult}
 */
export function scan(input, options = {}) {
  return analyze(input, options).result
}

/**
 * The scan, and the extracted document it was run on, for callers that need both.
 *
 * @param {string} input
 * @param {ScanOptions} [options]
 * @returns {{ result: ScanResult, doc: import('./extract.js').Extracted }}
 */
export function analyze(input, options = {}) {
  if (typeof input !== 'string') throw new FenceError('invalid_input', 'Content must be a string.')
  const { reviewAt, blockAt, ignore } = checkOptions(options)
  const doc = extract(input, options.type ?? 'auto')

  /** @type {Finding[]} */
  let findings = []
  for (const segment of doc.segments) findings.push(...scanSegment(segment, 0))
  findings = findings.filter((f) => !ignore.has(f.code) && !ignore.has(f.rule))
  score(findings)

  const total = Math.min(100, Math.round(findings.reduce((sum, f) => sum + f.points, 0)))
  const hasHigh = findings.some((f) => f.severity === 'high')
  /** @type {Verdict} */
  const verdict = hasHigh || total >= blockAt ? 'block' : total >= reviewAt ? 'review' : 'allow'
  const reasons = reasonsFor(findings)

  const result = {
    verdict,
    score: total,
    summary: summarize(verdict, total, reasons, findings),
    reasons,
    findings,
    type: doc.type,
    entities: doc.entities,
    senders: doc.senders,
    email: doc.email,
    facts: {
      segments: doc.segments.length,
      hiddenSegments: doc.segments.filter((s) => s.hidden).length,
      characters: input.length,
    },
    notes: [
      'Pattern matching catches the known ways of writing an injection, not every way. ' +
        'Fence untrusted content and gate risky tool calls whatever the verdict.',
    ],
  }
  return { result, doc }
}

/**
 * Scans a bare string as visible text: for checking a decoded payload, or for callers
 * that already have plain text.
 *
 * @param {string} text
 * @param {number} depth
 * @returns {Finding[]}
 */
function scanText(text, depth) {
  return scanSegment({ where: 'decoded', text, hidden: false, why: '' }, depth)
}

/**
 * @param {Segment} segment
 * @param {number} depth
 * @returns {Finding[]}
 */
function scanSegment(segment, depth) {
  const { text } = segment
  /** @type {Finding[]} */
  const findings = [...matchRules(segment, segment.hidden ? [...RULES, ...HIDDEN_RULES] : RULES)]

  if (segment.counterpart !== undefined) markShadowed(findings, segment)

  findings.push(...unicodeFindings(segment, depth))

  if (depth < MAX_DEPTH) {
    for (const enc of findEncoded(text)) {
      const inner = scanText(enc.decoded, depth + 1).filter((f) => f.severity !== 'low')
      if (!inner.length) continue
      findings.push(
        make(segment, enc.start, enc.end, {
          code: 'encoded_payload',
          rule: enc.scheme,
          severity: worst(inner),
          decoded: enc.decoded,
          detail: `${enc.scheme} that decodes to ${describe(inner)}: "${clip(enc.decoded, 120)}"`,
        }),
      )
    }
    if (depth === 0) findings.push(...viewFindings(segment, findings))
  }

  escalate(findings, segment)
  return dedupe(findings)
}

const VIEW_RULES = RULES.filter((r) => r.severity !== 'low' && !r.raw)

/**
 * The same text read another way: ROT13, leetspeak, letters spaced out, and text a
 * right-to-left override shows backwards. Each view keeps a map to the original, so a
 * finding points at the words as written.
 *
 * @param {Segment} segment
 * @param {Finding[]} found What the plain reading already found, so it is not repeated.
 * @returns {Finding[]}
 */
function viewFindings(segment, found) {
  /** @type {Finding[]} */
  const out = []
  for (const view of altViews(segment.text)) {
    for (const f of matchRules({ ...segment, text: view.text }, VIEW_RULES)) {
      const start = view.map[f.start]
      const end = view.map[f.end - 1] + 1
      const [from, to] = start <= end ? [start, end] : [end - 1, start + 1]
      if ([...found, ...out].some((b) => b.rule === f.rule && from < b.end && b.start < to)) continue
      const decoded = f.text
      const finding = make(segment, from, to, {
        code: view.name === 'rot13' ? 'encoded_payload' : 'obfuscated',
        rule: view.name,
        severity: view.name === 'rot13' ? f.severity : 'high',
        obfuscated: true,
        decoded,
        detail: `${VIEW_NAMES[view.name]} that reads as ${describe([f])}: "${clip(decoded, 120)}"`,
      })
      out.push(finding)
    }
  }
  return out
}

const VIEW_NAMES = {
  rot13: 'ROT13',
  leetspeak: 'Leetspeak',
  letter_spacing: 'Letters spaced out',
  reversed_text: 'Text shown backwards by a right-to-left override',
}

/**
 * @param {string} text
 * @returns {{ name: keyof typeof VIEW_NAMES, text: string, map: number[] }[]}
 */
function altViews(text) {
  /** @type {{ name: keyof typeof VIEW_NAMES, text: string, map: number[] }[]} */
  const views = []
  const identity = () => Array.from({ length: text.length }, (_, i) => i)
  if (/[a-z]{4}/i.test(text)) views.push({ name: 'rot13', text: rot13(text), map: identity() })

  if (/[a-z][0-9@$]|[0-9@$][a-z]/i.test(text)) {
    const leet = text.replace(/[a-z0-9@$]*[a-z][a-z0-9@$]*/gi, (word) =>
      /[0-9@$]/.test(word) ? word.replace(/[013457@$]/g, (c) => LEET[c]) : word,
    )
    if (leet !== text) views.push({ name: 'leetspeak', text: leet, map: identity() })
  }

  const spaced = /(?:[a-z][ \t]{1,3}){5,}[a-z]\b/gi
  if (/(?:[a-z][ \t]{1,3}){5,}[a-z]\b/i.test(text)) {
    let out = ''
    /** @type {number[]} */
    const map = []
    let last = 0
    for (const m of text.matchAll(spaced)) {
      const at = /** @type {number} */ (m.index)
      for (let i = last; i < at; i++) {
        out += text[i]
        map.push(i)
      }
      for (let i = at; i < at + m[0].length; ) {
        if (/[ \t]/.test(text[i])) {
          let j = i
          while (j < at + m[0].length && /[ \t]/.test(text[j])) j++
          if (j - i >= 2) {
            out += ' '
            map.push(i)
          }
          i = j
        } else {
          out += text[i]
          map.push(i)
          i++
        }
      }
      last = at + m[0].length
    }
    for (let i = last; i < text.length; i++) {
      out += text[i]
      map.push(i)
    }
    views.push({ name: 'letter_spacing', text: out, map })
  }

  if (text.includes('\u202e')) {
    const map = identity()
    const chars = [...text.split('')]
    for (const m of text.matchAll(/\u202e([^\u202c\n]*)/g)) {
      const from = /** @type {number} */ (m.index) + 1
      const to = from + m[1].length
      const reversed = map.slice(from, to).reverse()
      for (let k = 0; k < reversed.length; k++) {
        map[from + k] = reversed[k]
        chars[from + k] = text[reversed[k]]
      }
    }
    views.push({ name: 'reversed_text', text: chars.join(''), map })
  }
  return views
}

/** @type {Record<string, string>} */
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', $: 's' }

/**
 * An attack quoted as an example, as in a security notice: 'emails that say "ignore
 * previous instructions"'. Counted for less, not dropped, since quoting is also cheap
 * for an attacker.
 *
 * @param {string} text
 * @param {number} start
 * @param {number} end
 * @returns {boolean}
 */
function isQuotedMention(text, start, end) {
  const before = text.slice(Math.max(0, start - 60), start)
  const after = text.slice(end, end + 200).split('\n', 1)[0]
  return QUOTE_INTRO.test(before) && /["'\u201d\u2019`]/.test(after)
}

const QUOTE_INTRO = /(?:\bsays?|\bsaying|\bsaid|\blike|\bsuch\s+as|\be\.g\.|\bphrases?|\bwording|\btext|\blines?|\breads?|\bcontaining|\bcontains?|\binclud(?:e|es|ing)|\bwrote|\bwritten|\btyped|\btold|\bas\s+in|\bclassic)\s*[:,]?\s*["'\u201c\u2018`]\s*$/i

const DOWNGRADE = /** @type {const} */ ({ high: 'medium', medium: 'low', low: 'low' })

/**
 * @param {Segment} segment
 * @param {Rule[]} rules
 * @returns {Finding[]}
 */
function matchRules(segment, rules) {
  const { text } = segment
  const norm = normalize(text)
  const lower = text.toLowerCase()
  const lowerUsable = lower.length === text.length

  /** @type {Finding[]} */
  const out = []
  for (const r of rules) {
    const target = r.raw ? (lowerUsable ? lower : null) : norm.text
    if (target === null) continue
    r.re.lastIndex = 0
    for (const m of target.matchAll(r.re)) {
      if (!m[0].length) continue
      const at = /** @type {number} */ (m.index)
      let start = r.raw ? at : norm.start[at]
      const end = r.raw ? at + m[0].length : norm.end[at + m[0].length - 1]
      while (start < end && /\s/.test(text[start])) start++
      const obfuscated = !r.raw && isObfuscated(text.slice(start, end))
      const quoted = isQuotedMention(text, start, end)
      out.push(
        make(segment, start, end, {
          code: r.code,
          rule: r.id,
          severity: quoted ? DOWNGRADE[r.severity] : r.severity,
          obfuscated,
          detail: quoted ? `${CODES[r.code]} Quoted as an example, so it counts for less.` : CODES[r.code],
        }),
      )
    }
  }
  return out
}

/**
 * A text/plain part sent alongside HTML is what many agents read, while people see
 * the HTML. Instructions in the plain part that the HTML does not show are hidden.
 *
 * @param {Finding[]} findings
 * @param {Segment} segment
 */
function markShadowed(findings, segment) {
  const shown = normalize(segment.counterpart ?? '').text
  for (const f of findings) {
    const words = normalize(segment.text.slice(f.start, f.end)).text.trim()
    if (words && !shown.includes(words)) {
      f.hidden = true
      f.why = 'only in the text/plain part; the HTML part people see does not say it'
    }
  }
}

/**
 * @param {Segment} segment
 * @param {number} depth
 * @returns {Finding[]}
 */
function unicodeFindings(segment, depth) {
  const { text } = segment
  /** @type {Finding[]} */
  const out = []

  /**
   * @param {{ start: number, end: number, decoded: string }} run
   * @param {string} rule
   * @param {string} what
   * @param {boolean} alwaysHigh
   */
  const smuggled = (run, rule, what, alwaysHigh) => {
    const inner = depth < MAX_DEPTH ? scanText(run.decoded, depth + 1).filter((f) => f.severity !== 'low') : []
    /** @type {Severity} */
    const severity = alwaysHigh || inner.length ? 'high' : 'medium'
    const finding = make(segment, run.start, run.end, {
      code: 'smuggled_text',
      rule,
      severity,
      decoded: run.decoded,
      obfuscated: true,
      detail: `${what} spell out${inner.length ? ` ${describe(inner)}` : ' hidden text'}: "${clip(run.decoded, 120)}"`,
    })
    // The characters themselves print as nothing, so say what is there instead.
    finding.text = `[${[...text.slice(run.start, run.end)].length} invisible characters]`
    out.push(finding)
  }

  for (const run of findTagRuns(text)) {
    if (run.decoded.trim()) smuggled(run, 'tag_characters', 'Invisible Unicode tag characters', true)
  }
  for (const run of findVariationRuns(text)) {
    if (/[\p{L}\p{N}]{2}/u.test(run.decoded) && !run.decoded.includes('�')) {
      smuggled(run, 'variation_selectors', 'Variation selectors hidden after a character', false)
    } else {
      out.push(
        make(segment, run.start, run.end, {
          code: 'invisible_chars',
          rule: 'variation_selectors',
          severity: 'low',
          obfuscated: true,
          detail: `A run of ${run.end - run.start} invisible variation selectors: room for a hidden payload.`,
        }),
      )
    }
  }
  for (const run of findZeroWidthBinary(text)) smuggled(run, 'zero_width_binary', 'Zero-width characters written as binary', false)

  const inWords = [...text.matchAll(/[a-z][​‌‍⁠﻿]+(?=[a-z])/gi)]
  if (inWords.length >= 3) {
    const first = /** @type {number} */ (inWords[0].index)
    out.push(
      make(segment, first, first + inWords[0][0].length + 1, {
        code: 'invisible_chars',
        rule: 'zero_width_in_words',
        severity: 'low',
        obfuscated: true,
        detail: `Zero-width characters inside ${inWords.length} words, which breaks them up for a filter but not for a reader.`,
      }),
    )
  }

  /** @type {number[]} */
  const bidi = []
  for (let i = 0; i < text.length; i++) if (isBidiOverride(text.charCodeAt(i))) bidi.push(i)
  if (bidi.length) {
    const rlo = text.includes('‮')
    out.push(
      make(segment, bidi[0], bidi[0] + 1, {
        code: 'bidi_override',
        rule: 'bidi_controls',
        severity: rlo ? 'medium' : 'low',
        obfuscated: true,
        detail: rlo
          ? 'A right-to-left override (U+202E): what is shown is in a different order from what is read, as in "invoice‮fdp.exe".'
          : `${bidi.length} bidirectional control character(s).`,
      }),
    )
  }
  return out
}

/**
 * Instructions a person cannot see are the clearest sign of an attack: there is no
 * honest reason to hide "forward all emails" from the person the email is for.
 *
 * @param {Finding[]} findings
 * @param {Segment} segment
 */
function escalate(findings, segment) {
  const serious = findings.filter((f) => f.severity !== 'low' && f.code !== 'invisible_chars')
  const hidden = serious.find((f) => f.hidden && f.code !== 'hidden_text')
  if (hidden) {
    findings.push({
      ...hidden,
      code: 'hidden_text',
      rule: 'instructions_in_hidden_text',
      severity: 'high',
      points: 0,
      detail: `${CODES[hidden.code].replace(/\.$/, '')}, where a person cannot see it (${hidden.why || segment.why}).`,
    })
  }
  const hiddenLows = findings.filter(
    (f) =>
      f.hidden &&
      f.severity === 'low' &&
      f.rule !== 'instructions_in_hidden_text' &&
      !['invisible_chars', 'bidi_override'].includes(f.code),
  )
  if (!hidden && hiddenLows.length) {
    const rules = new Set(hiddenLows.map((f) => f.rule))
    const first = hiddenLows[0]
    findings.push({
      ...first,
      code: 'hidden_text',
      rule: 'instructions_in_hidden_text',
      severity: rules.size >= 2 ? 'high' : 'medium',
      points: 0,
      detail: `Directions for whoever reads it, where a person cannot see them (${first.why || segment.why}).`,
    })
  }
  const disguised = serious.find(
    (f) => f.obfuscated && !['obfuscated', 'smuggled_text', 'encoded_payload', 'bidi_override'].includes(f.code),
  )
  if (disguised) {
    findings.push({
      ...disguised,
      code: 'obfuscated',
      rule: 'disguised_instructions',
      severity: 'high',
      points: 0,
      detail: `${CODES[disguised.code].replace(/\.$/, '')}, written with look-alike letters or invisible characters so a filter would miss it.`,
    })
  }
}

/**
 * Where two findings with the same code cover the same words, keeps the worse one.
 *
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
function dedupe(findings) {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.start - b.start,
  )
  /** @type {Finding[]} */
  const kept = []
  for (const f of sorted) {
    const overlaps = kept.some(
      (k) => k.code === f.code && k.where === f.where && f.start < k.end && k.start < f.end,
    )
    if (!overlaps) kept.push(f)
  }
  return kept
}

/**
 * Points per finding: the first of a rule counts in full, each repeat for half the one
 * before, so a newsletter that says "click the link" ten times is not an attack.
 *
 * @param {Finding[]} findings
 */
function score(findings) {
  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.where.localeCompare(b.where) ||
      a.start - b.start,
  )
  /** @type {Map<string, number>} */
  const seen = new Map()
  for (const f of findings) {
    const n = seen.get(f.rule) ?? 0
    seen.set(f.rule, n + 1)
    f.points = Math.round((POINTS[f.severity] / 2 ** n) * 10) / 10
  }
}

/**
 * @param {Finding[]} findings
 * @returns {Reason[]}
 */
function reasonsFor(findings) {
  /** @type {Map<Code, Reason>} */
  const byCode = new Map()
  for (const f of findings) {
    const r = byCode.get(f.code)
    if (!r) byCode.set(f.code, { code: f.code, severity: f.severity, count: 1, detail: CODES[f.code] })
    else {
      r.count++
      if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[r.severity]) r.severity = f.severity
    }
  }
  return [...byCode.values()].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.count - a.count)
}

/**
 * @param {Verdict} verdict
 * @param {number} total
 * @param {Reason[]} reasons
 * @param {Finding[]} findings
 * @returns {string}
 */
function summarize(verdict, total, reasons, findings) {
  if (!findings.length) return 'Nothing in this reads as instructions for an AI.'
  const top = findings[0]
  const lead = {
    block: 'Do not let an agent act on this.',
    review: 'Have a person look before an agent acts on this.',
    allow: 'Probably fine.',
  }[verdict]
  const where = top.hidden && top.code !== 'hidden_text' ? ` (hidden: ${top.why})` : ''
  const more = reasons.length > 1 ? ` ${reasons.length - 1} other kind${reasons.length > 2 ? 's' : ''} of finding.` : ''
  const words = top.decoded === null ? `: "${clip(top.text, 80)}"` : ''
  return `${lead} ${top.detail.replace(/\.$/, '')}${where}${words}. Score ${total}.${more}`
}

/**
 * @param {Segment} segment
 * @param {number} start
 * @param {number} end
 * @param {{ code: Code, rule: string, severity: Severity, detail: string, obfuscated?: boolean, decoded?: string }} fields
 * @returns {Finding}
 */
function make(segment, start, end, fields) {
  const before = segment.text.slice(0, start)
  const line = (before.match(/\n/g)?.length ?? 0) + 1
  const column = start - (before.lastIndexOf('\n') + 1) + 1
  return {
    code: fields.code,
    rule: fields.rule,
    severity: fields.severity,
    points: 0,
    where: segment.where,
    text: clip(segment.text.slice(start, end), EXCERPT),
    start,
    end,
    line,
    column,
    hidden: segment.hidden,
    why: segment.why,
    obfuscated: fields.obfuscated ?? false,
    decoded: fields.decoded ?? null,
    detail: fields.detail,
  }
}

/**
 * @param {Finding[]} findings
 * @returns {Severity}
 */
function worst(findings) {
  return findings.some((f) => f.severity === 'high') ? 'high' : 'medium'
}

/**
 * @param {Finding[]} inner
 * @returns {string}
 */
function describe(inner) {
  const codes = [...new Set(inner.map((f) => f.code))]
  return `instructions (${codes.join(', ')})`
}

/**
 * @param {string} text
 * @param {number} max
 * @returns {string}
 */
export function clip(text, max) {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`
}

/**
 * @param {ScanOptions} options
 * @returns {{ reviewAt: number, blockAt: number, ignore: Set<string> }}
 */
function checkOptions(options) {
  const reviewAt = options.reviewAt ?? DEFAULT_REVIEW_AT
  const blockAt = options.blockAt ?? DEFAULT_BLOCK_AT
  for (const [name, value] of /** @type {const} */ ([['reviewAt', reviewAt], ['blockAt', blockAt]])) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
      throw new FenceError('invalid_option', `${name} must be a number from 0 to 100.`)
    }
  }
  if (reviewAt > blockAt) throw new FenceError('invalid_option', 'reviewAt must not be above blockAt.')
  if (options.type !== undefined && !['auto', 'email', 'html', 'text'].includes(options.type)) {
    throw new FenceError('invalid_option', `type must be auto, email, html or text, got ${options.type}.`)
  }
  const ignore = new Set(options.ignore ?? [])
  for (const id of ignore) {
    if (!(id in CODES) && !RULE_IDS.has(id) && !EXTRA_RULE_IDS.has(id)) {
      throw new FenceError('invalid_option', `Unknown code or rule in ignore: ${id}.`)
    }
  }
  return { reviewAt, blockAt, ignore }
}
