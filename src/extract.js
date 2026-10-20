import { parseEmail, looksLikeEmail } from './mime.js'
import { htmlToText } from './html.js'

/**
 * Turns an email, a web page or a chat message into segments: each stretch of text a
 * model might read, where it came from, and whether a person would see it.
 */

/**
 * @typedef {'email'|'html'|'text'} ContentType
 *
 * @typedef {object} Segment
 * @property {string} where Such as "subject", "body", "attachment name".
 * @property {string} text
 * @property {boolean} hidden A person reading the message would not see this.
 * @property {string} why Why it is hidden, or "".
 * @property {string} [counterpart] For a text/plain part sent alongside HTML: the
 *   text the HTML shows, so words only in the plain part count as hidden.
 *
 * @typedef {object} Entities
 * @property {string[]} emails Lowercase.
 * @property {string[]} urls
 * @property {string[]} domains Lowercase, from the emails, URLs and bare domains.
 * @property {string[]} phones Digits only, with a leading + kept.
 *
 * @typedef {object} EmailMeta
 * @property {string} from
 * @property {string} to
 * @property {string} subject
 * @property {string} date
 * @property {{ filename: string, type: string, size: number }[]} attachments
 *
 * @typedef {object} Extracted
 * @property {ContentType} type
 * @property {Segment[]} segments
 * @property {Entities} entities Everything in the content a tool call could be pointed at.
 * @property {string[]} senders For an email, the From, Reply-To and Sender addresses.
 * @property {string} visible The text a person sees, in reading order.
 * @property {EmailMeta | null} email
 */

/**
 * @param {string} input
 * @param {ContentType | 'auto'} [type]
 * @returns {Extracted}
 */
export function extract(input, type = 'auto') {
  const resolved = type === 'auto' ? detectType(input) : type
  if (resolved === 'email') return fromEmail(input)
  if (resolved === 'html') return fromHtml(input)
  return fromText(input)
}

/**
 * @param {string} input
 * @returns {ContentType}
 */
export function detectType(input) {
  if (looksLikeEmail(input)) return 'email'
  const tags = input.match(/<(?:!doctype|html|head|body|div|p|span|table|td|tr|br|a\s|img|style|meta|font|center|ul|li|h[1-6])[\s>/]/gi)
  if (tags && (tags.length >= 3 || /<(?:!doctype|html|body)[\s>]/i.test(input))) return 'html'
  return 'text'
}

/**
 * @param {string} raw
 * @returns {Extracted}
 */
function fromEmail(raw) {
  const email = parseEmail(raw)
  const h = email.headers
  /** @type {Segment[]} */
  const segments = []
  /** @type {string[]} */
  const links = []
  /** @type {string[]} */
  const visible = []

  if (h.subject) {
    segments.push({ where: 'subject', text: h.subject, hidden: false, why: '' })
    visible.push(`Subject: ${h.subject}`)
  }
  const fromName = displayName(h.from ?? '')
  if (fromName) segments.push({ where: 'sender name', text: fromName, hidden: false, why: '' })

  for (const attached of email.attached) {
    if (attached.headers.subject) {
      segments.push({ where: 'attached email subject', text: attached.headers.subject, hidden: false, why: '' })
    }
  }

  const htmlParts = email.parts.filter((p) => p.type === 'text/html')
  const htmlVisible = htmlParts.map((p) => htmlToText(p.text).visible).join('\n\n')

  for (const part of email.parts) {
    const label = email.parts.length > 1 ? ` (part ${part.path}, ${part.type})` : ''
    if (part.type === 'text/html') {
      const html = htmlToText(part.text)
      links.push(...html.links)
      if (html.visible) {
        segments.push({ where: `body${label}`, text: html.visible, hidden: false, why: '' })
        visible.push(html.visible)
      }
      for (const hidden of html.hidden) {
        segments.push({ where: `body${label}, hidden`, text: hidden.text, hidden: true, why: hidden.why })
      }
    } else if (part.type === 'text/plain' && !part.filename) {
      /** @type {Segment} */
      const segment = { where: `body${label}`, text: part.text, hidden: false, why: '' }
      if (htmlParts.length) segment.counterpart = htmlVisible
      else visible.push(part.text)
      segments.push(segment)
    } else if (part.text) {
      segments.push({ where: part.filename ? `attachment ${part.filename}` : `part ${part.path} (${part.type})`, text: part.text, hidden: false, why: '' })
    }
    if (part.filename) segments.push({ where: 'attachment name', text: part.filename, hidden: false, why: '' })
  }

  const senders = unique(
    ['from', 'reply-to', 'sender'].flatMap((name) => findEmails(h[name] ?? '')),
  )
  const attachments = email.parts
    .filter((p) => p.filename)
    .map((p) => ({ filename: /** @type {string} */ (p.filename), type: p.type, size: p.size }))

  return {
    type: 'email',
    segments,
    entities: entitiesOf(segments, links),
    senders,
    visible: visible.join('\n\n'),
    email: {
      from: h.from ?? '',
      to: h.to ?? '',
      subject: h.subject ?? '',
      date: h.date ?? '',
      attachments,
    },
  }
}

/**
 * @param {string} input
 * @returns {Extracted}
 */
function fromHtml(input) {
  const html = htmlToText(input)
  /** @type {Segment[]} */
  const segments = []
  if (html.title) segments.push({ where: 'title', text: html.title, hidden: false, why: '' })
  if (html.visible) segments.push({ where: 'body', text: html.visible, hidden: false, why: '' })
  for (const hidden of html.hidden) segments.push({ where: 'body, hidden', text: hidden.text, hidden: true, why: hidden.why })
  return {
    type: 'html',
    segments,
    entities: entitiesOf(segments, html.links),
    senders: [],
    visible: [html.title, html.visible].filter(Boolean).join('\n\n'),
    email: null,
  }
}

/**
 * Plain text and chat (Slack, Discord, SMS, Markdown). The parts a chat client or
 * Markdown renderer hides, HTML comments and reference-style comments, are hidden
 * segments; the rest is one visible segment.
 *
 * @param {string} input
 * @returns {Extracted}
 */
function fromText(input) {
  /** @type {Segment[]} */
  const segments = []
  const comment = /<!--([\s\S]*?)(?:-->|$)|^\s*\[(?:\/\/|comment|#)\]:\s*(?:#|<>)?\s*[("'](.*)[)"']\s*$/gim
  for (const m of input.matchAll(comment)) {
    const text = (m[1] ?? m[2] ?? '').trim()
    if (text) segments.push({ where: 'message, hidden', text, hidden: true, why: m[1] !== undefined ? 'HTML comment' : 'Markdown comment' })
  }
  // Blanked to the same length, so offsets in the visible segment are offsets in the input.
  const visible = input.replace(comment, (m) => m.replace(/[^\n]/g, ' '))
  segments.unshift({ where: 'message', text: visible, hidden: false, why: '' })

  /** @type {string[]} */
  const links = []
  // Slack: <https://example.com|label>, <mailto:a@b.c|a@b.c>
  for (const m of input.matchAll(/<((?:https?|mailto):[^|>\s]+)(?:\|[^>]*)?>/g)) links.push(m[1].replace(/^mailto:/, ''))
  // Markdown: [label](url) and ![alt](url)
  for (const m of input.matchAll(/\]\(\s*<?(https?:\/\/[^\s)>]+)>?/g)) links.push(m[1])

  return {
    type: 'text',
    segments,
    entities: entitiesOf(segments, links),
    senders: [],
    visible: visible.trim(),
    email: null,
  }
}

// Bounded, and anchored to the start of a run, so a long run with no @ stays linear.
const EMAIL_RE = /(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,8}\.[a-z]{2,24}\b/gi
const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]|]+/gi
const DOMAIN_RE = /(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ai|app|dev|xyz|info|biz|me|us|uk|de|ru|cn|top|site|online|link|click|live|cloud|tech|sh|gg|ly|to|cc|tk|ml|ga|cf|gq|pw|zip|mov|page|run|so|ws|eu|ca|au|in|fr|nl|br|jp|es|it)\b(?!\.[a-z])/gi
const PHONE_RE = /(?<![\w.])\+?\d[\d ().-]{7,18}\d(?![\w.])/g

/**
 * @param {string} text
 * @returns {string[]}
 */
export function findEmails(text) {
  return [...text.matchAll(EMAIL_RE)].map((m) => m[0].toLowerCase())
}

/**
 * @param {string} text
 * @returns {string[]}
 */
export function findUrls(text) {
  return [...text.matchAll(URL_RE)].map((m) => m[0].replace(/[.,;:!?]+$/, ''))
}

/**
 * @param {string} url
 * @returns {string | null}
 */
export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '')
  } catch {
    return null
  }
}

/**
 * @param {string} text
 * @returns {string[]}
 */
export function findPhones(text) {
  /** @type {string[]} */
  const out = []
  for (const m of text.matchAll(PHONE_RE)) {
    const digits = normalizePhone(m[0])
    if (digits.replace('+', '').length >= 10) out.push(digits)
  }
  return out
}

/**
 * @param {string} value
 * @returns {string}
 */
export function normalizePhone(value) {
  const plus = value.trim().startsWith('+') ? '+' : ''
  return plus + value.replace(/\D/g, '')
}

/**
 * @param {Segment[]} segments
 * @param {string[]} links
 * @returns {Entities}
 */
function entitiesOf(segments, links) {
  const all = [...segments.map((s) => s.text), ...links].join('\n')
  const emails = unique([...findEmails(all), ...links.filter((l) => !/^https?:/i.test(l)).flatMap(findEmails)])
  const urls = unique([...findUrls(all), ...links.filter((l) => /^https?:/i.test(l))])
  const domains = unique([
    ...emails.map((e) => e.split('@')[1]),
    ...urls.map(hostOf).filter((d) => d !== null),
    ...[...all.matchAll(DOMAIN_RE)].map((m) => m[0].toLowerCase().replace(/^www\./, '')),
  ])
  return { emails, urls, domains, phones: unique(findPhones(all)) }
}

/**
 * @param {string} header
 * @returns {string}
 */
function displayName(header) {
  const m = /^\s*"?([^"<]*?)"?\s*<[^>]+>/.exec(header)
  return m ? m[1].trim() : ''
}

/**
 * @template T
 * @param {T[]} items
 * @returns {T[]}
 */
function unique(items) {
  return [...new Set(items)]
}
