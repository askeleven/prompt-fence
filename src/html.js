/**
 * HTML to text, split into what a person sees and what only a model reads: elements
 * hidden by CSS or attributes, comments, and alt or title text. Not a full HTML5 parser;
 * a tolerant tokenizer that is enough for email bodies and fetched pages, with no
 * dependencies.
 */

/**
 * @typedef {object} HtmlChunk
 * @property {string} text
 * @property {boolean} hidden
 * @property {string} why Why it is hidden, such as "display:none", or "" when visible.
 *
 * @typedef {object} HtmlText
 * @property {string} visible What a person sees, as text.
 * @property {{ text: string, why: string }[]} hidden Each stretch only a model reads.
 * @property {string[]} links Every href and src.
 * @property {string} title
 */

const VOID = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr',
])
const RAW_TEXT = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes'])
const SKIP_CONTENT = new Set(['script', 'style'])
const HIDDEN_ELEMENTS = new Set(['template', 'noscript', 'head'])
const BLOCK = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'dd', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure',
  'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre',
  'section', 'table', 'tr', 'td', 'th', 'ul', 'tbody', 'thead', 'center',
])
const MAX_NESTING = 512
const TEXT_ATTRIBUTES = ['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'data-content']

/** @type {Record<string, string>} */
const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', zwnj: '‌', zwj: '‍',
  shy: '­', copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—',
  ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•',
  middot: '·', euro: '€', pound: '£', yen: '¥', cent: '¢', laquo: '«',
  raquo: '»', times: '×', divide: '÷', deg: '°', ensp: ' ', emsp: ' ',
  thinsp: ' ', lrm: '‎', rlm: '‏', sect: '§', para: '¶', iexcl: '¡',
  iquest: '¿', eacute: 'é', egrave: 'è', aacute: 'á', agrave: 'à',
  oacute: 'ó', uacute: 'ú', iacute: 'í', ntilde: 'ñ', ccedil: 'ç',
  uuml: 'ü', ouml: 'ö', auml: 'ä', szlig: 'ß', Eacute: 'É',
}

/**
 * @param {string} text
 * @returns {string}
 */
export function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);?/gi, (whole, body) => {
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10)
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : whole
    }
    return ENTITIES[body] ?? ENTITIES[body.toLowerCase()] ?? whole
  })
}

/**
 * @typedef {object} Frame
 * @property {string} name
 * @property {boolean} hidden
 * @property {string} why
 * @property {string | null} color
 * @property {string | null} background
 */

/**
 * @param {string} html
 * @returns {HtmlText}
 */
export function htmlToText(html) {
  /** @type {HtmlChunk[]} */
  const chunks = []
  /** @type {string[]} */
  const links = []
  let title = ''
  /** @type {Frame[]} */
  const stack = [{ name: '#root', hidden: false, why: '', color: null, background: null }]
  const top = () => stack[stack.length - 1]

  /**
   * @param {string} text
   * @param {boolean} [forceHidden]
   * @param {string} [why]
   */
  const emit = (text, forceHidden = false, why = '') => {
    if (!text) return
    const frame = top()
    const hidden = forceHidden || frame.hidden
    chunks.push({ text, hidden, why: forceHidden ? why : frame.why })
  }

  let i = 0
  while (i < html.length) {
    const lt = html.indexOf('<', i)
    if (lt === -1) {
      emit(decodeEntities(html.slice(i)))
      break
    }
    if (lt > i) emit(decodeEntities(html.slice(i, lt)))

    if (html.startsWith('<!--', lt)) {
      const close = html.indexOf('-->', lt + 4)
      const body = html.slice(lt + 4, close === -1 ? html.length : close)
      i = close === -1 ? html.length : close + 3
      // Outlook conditional comments hold markup, not words.
      if (/^\s*\[(if|endif)/i.test(body) || /^\s*<!\[endif\]/i.test(body)) continue
      if (body.trim()) emit(` ${body.trim()} `, true, 'HTML comment')
      continue
    }
    if (html.startsWith('<![CDATA[', lt)) {
      const close = html.indexOf(']]>', lt)
      emit(html.slice(lt + 9, close === -1 ? html.length : close))
      i = close === -1 ? html.length : close + 3
      continue
    }
    if (html[lt + 1] === '!' || html[lt + 1] === '?') {
      const close = html.indexOf('>', lt)
      i = close === -1 ? html.length : close + 1
      continue
    }

    const tag = readTag(html, lt)
    if (!tag) {
      emit('<')
      i = lt + 1
      continue
    }
    i = tag.end

    if (tag.closing) {
      const at = findOpen(stack, tag.name)
      if (at > 0) stack.length = at
      if (BLOCK.has(tag.name)) emit('\n')
      continue
    }

    const frame = enter(top(), tag.name, tag.attributes)
    for (const name of ['href', 'src']) {
      const value = tag.attributes[name]
      if (value && !/^(#|cid:|data:)/i.test(value)) links.push(decodeEntities(value).trim())
    }
    for (const name of TEXT_ATTRIBUTES) {
      const value = tag.attributes[name]
      if (value && value.trim()) emit(` ${decodeEntities(value).trim()} `, true, `${name} attribute`)
    }
    if (tag.name === 'meta') {
      const name = (tag.attributes.name ?? tag.attributes.property ?? '').toLowerCase()
      if (/description|title|keywords|summary/.test(name) && tag.attributes.content) {
        emit(` ${decodeEntities(tag.attributes.content)} `, true, `meta ${name}`)
      }
    }

    if (BLOCK.has(tag.name)) emit('\n')

    if (RAW_TEXT.has(tag.name) && !tag.selfClosing) {
      const closeRe = new RegExp(`</${tag.name}\\s*>`, 'ig')
      closeRe.lastIndex = i
      const m = closeRe.exec(html)
      const body = html.slice(i, m ? m.index : html.length)
      i = m ? m.index + m[0].length : html.length
      if (tag.name === 'title') title = decodeEntities(body).trim()
      else if (tag.name === 'textarea') {
        stack.push(frame)
        emit(decodeEntities(body))
        stack.pop()
      } else if (!SKIP_CONTENT.has(tag.name) && body.trim()) {
        emit(` ${decodeEntities(body.replace(/<[^>]*>/g, ' ')).trim()} `, true, `<${tag.name}>`)
      }
      continue
    }

    // Browsers stop nesting at a depth like this too; it keeps close tags cheap to match.
    if (!VOID.has(tag.name) && !tag.selfClosing && stack.length < MAX_NESTING) stack.push(frame)
  }

  return { ...join(chunks), links, title }
}

/**
 * @param {Frame[]} stack
 * @param {string} name
 * @returns {number}
 */
function findOpen(stack, name) {
  for (let k = stack.length - 1; k > 0; k--) if (stack[k].name === name) return k
  return -1
}

/**
 * @param {HtmlChunk[]} chunks
 * @returns {{ visible: string, hidden: { text: string, why: string }[] }}
 */
function join(chunks) {
  let visible = ''
  /** @type {{ text: string, why: string }[]} */
  const hidden = []
  let previousHidden = false
  for (const chunk of chunks) {
    if (!chunk.hidden) {
      visible += chunk.text
      if (chunk.text.trim()) previousHidden = false
      continue
    }
    const last = hidden[hidden.length - 1]
    if (previousHidden && last && last.why === chunk.why) last.text += chunk.text
    else hidden.push({ text: chunk.text, why: chunk.why })
    previousHidden = true
  }
  return {
    visible: tidy(visible),
    hidden: hidden.map((h) => ({ text: tidy(h.text), why: h.why })).filter((h) => h.text),
  }
}

/**
 * @param {string} text
 * @returns {string}
 */
function tidy(text) {
  return text
    .replace(/[ \t ]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

/**
 * @typedef {object} Tag
 * @property {string} name
 * @property {boolean} closing
 * @property {boolean} selfClosing
 * @property {Record<string, string>} attributes
 * @property {number} end
 */

/**
 * @param {string} html
 * @param {number} at Index of "<".
 * @returns {Tag | null}
 */
function readTag(html, at) {
  let i = at + 1
  const closing = html[i] === '/'
  if (closing) i++
  const nameMatch = /^[a-zA-Z][a-zA-Z0-9:-]*/.exec(html.slice(i, i + 64))
  if (!nameMatch) return null
  const name = nameMatch[0].toLowerCase()
  i += nameMatch[0].length

  /** @type {Record<string, string>} */
  const attributes = {}
  let selfClosing = false
  while (i < html.length) {
    while (i < html.length && /\s/.test(html[i])) i++
    if (html[i] === '>') {
      i++
      break
    }
    if (html[i] === '/' && html[i + 1] === '>') {
      selfClosing = true
      i += 2
      break
    }
    if (html[i] === '/') {
      i++
      continue
    }
    const attrMatch = /^[^\s/>=]+/.exec(html.slice(i, i + 256))
    if (!attrMatch) {
      i++
      continue
    }
    const attrName = attrMatch[0].toLowerCase()
    i += attrMatch[0].length
    while (i < html.length && /\s/.test(html[i])) i++
    let value = ''
    if (html[i] === '=') {
      i++
      while (i < html.length && /\s/.test(html[i])) i++
      const quote = html[i]
      if (quote === '"' || quote === "'") {
        const close = html.indexOf(quote, i + 1)
        value = html.slice(i + 1, close === -1 ? html.length : close)
        i = close === -1 ? html.length : close + 1
      } else {
        const m = /^[^\s>]*/.exec(html.slice(i))
        value = m ? m[0] : ''
        i += value.length
      }
    }
    if (!(attrName in attributes)) attributes[attrName] = value
  }
  return { name, closing, selfClosing, attributes, end: i }
}

/**
 * @param {Frame} parent
 * @param {string} name
 * @param {Record<string, string>} attributes
 * @returns {Frame}
 */
function enter(parent, name, attributes) {
  const style = parseStyle(decodeEntities(attributes.style ?? ''))
  const color = style.color ?? attributes.color ?? parent.color
  const background = style['background-color'] ?? backgroundFrom(style.background) ?? attributes.bgcolor ?? parent.background

  /** @type {Frame} */
  const frame = { name, hidden: parent.hidden, why: parent.why, color, background }
  if (parent.hidden) return frame

  const why = hiddenBy(name, attributes, style, color, background)
  if (why) {
    frame.hidden = true
    frame.why = why
  }
  return frame
}

/**
 * @param {string} name
 * @param {Record<string, string>} attributes
 * @param {Record<string, string>} style
 * @param {string | null} color
 * @param {string | null} background
 * @returns {string}
 */
function hiddenBy(name, attributes, style, color, background) {
  if (HIDDEN_ELEMENTS.has(name)) return `<${name}>`
  if ('hidden' in attributes) return 'hidden attribute'
  if (name === 'input' && (attributes.type ?? '').toLowerCase() === 'hidden') return 'hidden input'

  const display = style.display
  if (display && /^none\b/.test(display)) return 'display:none'
  const visibility = style.visibility
  if (visibility && /^(hidden|collapse)\b/.test(visibility)) return `visibility:${visibility}`
  if (style['mso-hide'] && /^all\b/.test(style['mso-hide'])) return 'mso-hide:all'

  const opacity = style.opacity !== undefined ? Number.parseFloat(style.opacity) : NaN
  if (Number.isFinite(opacity) && opacity <= 0.05) return `opacity:${style.opacity}`

  const fontSize = lengthPx(style['font-size'])
  if (fontSize !== null && fontSize <= 2) return `font-size:${style['font-size']}`
  const lineHeight = lengthPx(style['line-height'])
  const overflowHidden = /hidden|clip/.test(style.overflow ?? '') || /hidden|clip/.test(style['overflow-y'] ?? '')
  for (const prop of ['max-height', 'height', 'max-width', 'width']) {
    const px = lengthPx(style[prop])
    if (px !== null && px <= 1 && overflowHidden) return `${prop}:${style[prop]} with overflow hidden`
  }
  if (lineHeight !== null && lineHeight <= 1 && overflowHidden) return 'line-height:0 with overflow hidden'

  const position = style.position ?? ''
  if (/absolute|fixed/.test(position)) {
    for (const prop of ['left', 'top', 'right']) {
      const px = lengthPx(style[prop])
      if (px !== null && px <= -500) return `positioned off screen (${prop}:${style[prop]})`
    }
  }
  const indent = lengthPx(style['text-indent'])
  if (indent !== null && indent <= -500) return `text-indent:${style['text-indent']}`
  if (/rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)/.test(style.clip ?? '')) return 'clip:rect(0 0 0 0)'
  if (/inset\(\s*(50%|100%)/.test(style['clip-path'] ?? '')) return 'clip-path'
  if (/scale\(\s*0(\.0*)?\s*\)/.test(style.transform ?? '')) return 'transform:scale(0)'

  const setsColour =
    style.color !== undefined ||
    attributes.color !== undefined ||
    style['background-color'] !== undefined ||
    style.background !== undefined ||
    attributes.bgcolor !== undefined
  if (color && setsColour) {
    if (isTransparent(color)) return 'transparent text'
    const fg = parseColor(color)
    const bg = parseColor(background ?? '#ffffff')
    if (fg && bg && contrast(fg, bg) < 1.15) return `text colour matches background (${color} on ${background ?? 'white'})`
  }
  return ''
}

/**
 * @param {string} style
 * @returns {Record<string, string>}
 */
function parseStyle(style) {
  /** @type {Record<string, string>} */
  const out = {}
  for (const decl of style.replace(/\/\*[\s\S]*?\*\//g, '').split(';')) {
    const colon = decl.indexOf(':')
    if (colon === -1) continue
    const prop = decl.slice(0, colon).trim().toLowerCase()
    const value = decl.slice(colon + 1).replace(/!important/i, '').trim().toLowerCase()
    if (prop && value) out[prop] = value
  }
  return out
}

/**
 * @param {string | undefined} background
 * @returns {string | undefined}
 */
function backgroundFrom(background) {
  if (!background) return undefined
  const m = /(#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|\b(white|black|transparent)\b)/.exec(background)
  return m ? m[0] : undefined
}

/**
 * @param {string | undefined} value
 * @returns {number | null}
 */
function lengthPx(value) {
  if (!value) return null
  const m = /^(-?\d*\.?\d+)\s*(px|pt|em|rem|%|)?\b/.exec(value.trim())
  if (!m) return null
  const n = Number.parseFloat(m[1])
  switch (m[2]) {
    case 'pt': return n * (4 / 3)
    case 'em':
    case 'rem': return n * 16
    case '%': return null
    default: return n
  }
}

/** @param {string} color */
function isTransparent(color) {
  return color === 'transparent' || /^rgba\([^)]*,\s*0(\.0+)?\s*\)$/.test(color) || /^#[0-9a-f]{6}00$/.test(color)
}

/** @type {Record<string, [number, number, number]>} */
const NAMED_COLOURS = {
  white: [255, 255, 255], black: [0, 0, 0], snow: [255, 250, 250], ivory: [255, 255, 240],
  whitesmoke: [245, 245, 245], ghostwhite: [248, 248, 255], red: [255, 0, 0], blue: [0, 0, 255],
  gray: [128, 128, 128], grey: [128, 128, 128], silver: [192, 192, 192], green: [0, 128, 0],
}

/**
 * @param {string} color
 * @returns {[number, number, number] | null}
 */
function parseColor(color) {
  const c = color.trim().toLowerCase()
  if (NAMED_COLOURS[c]) return NAMED_COLOURS[c]
  let m = /^#([0-9a-f]{3})$/.exec(c)
  if (m) return /** @type {[number, number, number]} */ ([...m[1]].map((h) => parseInt(h + h, 16)))
  m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/.exec(c)
  if (m) return [parseInt(m[1].slice(0, 2), 16), parseInt(m[1].slice(2, 4), 16), parseInt(m[1].slice(4, 6), 16)]
  m = /^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/.exec(c)
  if (m) return [Number(m[1]), Number(m[2]), Number(m[3])]
  return null
}

/**
 * WCAG contrast ratio, 1 (none) to 21.
 *
 * @param {[number, number, number]} a
 * @param {[number, number, number]} b
 * @returns {number}
 */
function contrast(a, b) {
  const lum = (/** @type {[number, number, number]} */ rgb) => {
    const [r, g, bl] = rgb.map((v) => {
      const s = v / 255
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
    })
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl
  }
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}
