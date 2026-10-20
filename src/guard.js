import { fence, fenceInstructions, newNonce } from './fence.js'
import { extract, findEmails, findUrls, findPhones, hostOf, normalizePhone } from './extract.js'

/**
 * The part that holds when detection misses: a guard for one agent conversation. It
 * fences each piece of untrusted content as it comes in, remembers what came in, and
 * checks each tool call the model then makes. A call that sends, deletes, pays, grants
 * access or runs code after untrusted content was read needs a person's yes, and a call
 * pointed at an address or link that only the untrusted content mentioned is held.
 */

/**
 * @typedef {import('./scan.js').Verdict} Verdict
 * @typedef {import('./scan.js').ScanOptions} ScanOptions
 * @typedef {import('./fence.js').FenceMode} FenceMode
 * @typedef {import('./fence.js').Fenced} Fenced
 *
 * @typedef {'read'|'organize'|'write'|'draft'|'send'|'browse'|'destructive'|'financial'|'access'|'execute'|'unknown'} Category
 * @typedef {'allow'|'confirm'|'block'} Decision
 *
 * @typedef {object} Trusted
 * @property {string[]} [emails]
 * @property {string[]} [domains] Your own domains; subdomains count.
 * @property {string[]} [phones]
 *
 * @typedef {object} Policy
 * @property {Record<string, Category>} [tools] Category for each tool name, over the
 *   guess from the name.
 * @property {Trusted} [trusted] Addresses and domains that are yours, never treated as
 *   coming from untrusted content.
 * @property {Partial<Record<Category, Decision>>} [afterUntrusted] What each category
 *   gets once untrusted content is in the conversation.
 * @property {Partial<Record<Category, Decision>>} [always] The least each category
 *   gets, untrusted content or not.
 * @property {boolean} [allowReplyToSender] A send whose every recipient is the sender
 *   of the untrusted content, when that content scanned clean, is allowed. Default true.
 * @property {string[]} [targetKeys] Argument names that say where a call goes, compared
 *   lowercase without - or _. Default to, cc, bcc, recipient, url, webhook and others.
 * @property {FenceMode} [mode] Default tags.
 * @property {ScanOptions} [scan]
 *
 * @typedef {object} IngestOptions
 * @property {string} [source] Such as "email from dana@example.com".
 * @property {string} [id] Default a counter.
 * @property {import('./extract.js').ContentType | 'auto'} [type]
 *
 * @typedef {object} Ingested
 * @property {string} id
 * @property {string} source
 * @property {Verdict} verdict
 * @property {import('./extract.js').Entities} entities
 * @property {string[]} senders
 *
 * @typedef {object} ToolCall
 * @property {string} [tool]
 * @property {string} [name] The same as tool, as MCP and most SDKs name it.
 * @property {unknown} [args]
 * @property {unknown} [arguments]
 * @property {unknown} [input]
 * @property {Category} [category] Over the policy and the guess from the name.
 *
 * @typedef {'trusted'|'sender'|'untrusted'|'unknown'} Origin
 *
 * @typedef {object} Target
 * @property {string} value
 * @property {'email'|'url'|'domain'|'phone'} kind
 * @property {Origin} origin
 * @property {string | null} from The id of the untrusted content it came from, if any.
 *
 * @typedef {object} GateReason
 * @property {'no_untrusted'|'untrusted_in_context'|'injection_in_context'|'target_from_untrusted'|'reply_to_sender'|'data_in_url'|'policy'} code
 * @property {Decision} decision What this reason alone would make of the call.
 * @property {string} detail
 *
 * @typedef {object} Check
 * @property {Decision} decision
 * @property {string} tool
 * @property {Category} category
 * @property {GateReason[]} reasons
 * @property {Target[]} targets
 * @property {string} summary
 */

/** @type {Record<Category, Decision>} */
export const DEFAULT_AFTER_UNTRUSTED = {
  read: 'allow',
  organize: 'allow',
  write: 'allow',
  draft: 'allow',
  browse: 'allow',
  send: 'confirm',
  destructive: 'confirm',
  financial: 'confirm',
  access: 'confirm',
  execute: 'confirm',
  unknown: 'confirm',
}

/** Categories a block verdict on content in the conversation turns into a block. */
const HARD = new Set(['send', 'destructive', 'financial', 'access', 'execute', 'unknown'])

const DEFAULT_TARGET_KEYS = [
  'to', 'cc', 'bcc', 'recipient', 'recipients', 'email', 'emails', 'emailaddress', 'address', 'addresses',
  'phone', 'phones', 'phonenumber', 'number', 'tonumber', 'url', 'urls', 'uri', 'href', 'link', 'endpoint',
  'webhook', 'webhookurl', 'callback', 'callbackurl', 'destination', 'target', 'forwardto', 'sharewith',
  'invitee', 'invitees', 'attendee', 'attendees', 'member', 'members', 'user', 'users', 'grantee', 'payee',
  'account', 'domain', 'host', 'channel', 'replyto',
]

const RANK = { allow: 0, confirm: 1, block: 2 }

/**
 * @param {Policy} [policy]
 */
export function createGuard(policy = {}) {
  const nonce = newNonce()
  const mode = policy.mode ?? 'tags'
  const after = { ...DEFAULT_AFTER_UNTRUSTED, ...(policy.afterUntrusted ?? {}) }
  const always = policy.always ?? {}
  const allowReply = policy.allowReplyToSender ?? true
  const targetKeys = new Set((policy.targetKeys ?? DEFAULT_TARGET_KEYS).map(keyOf))
  const trusted = {
    emails: new Set((policy.trusted?.emails ?? []).map((e) => e.toLowerCase())),
    domains: new Set((policy.trusted?.domains ?? []).map((d) => d.toLowerCase().replace(/^\.|^www\./, ''))),
    phones: new Set((policy.trusted?.phones ?? []).map(phoneKey)),
  }
  /** @type {Map<string, Ingested>} */
  const ingested = new Map()
  let counter = 0

  return {
    nonce,
    /** Put this in the system prompt once; it covers every fence from this guard. */
    instructions: fenceInstructions({ nonce, mode }),

    /**
     * Fences untrusted content and remembers it, so later tool calls are checked
     * against it. Put the returned text in the prompt in place of the content.
     *
     * @param {string} content
     * @param {IngestOptions} [options]
     * @returns {Fenced & { id: string }}
     */
    ingest(content, options = {}) {
      const id = options.id ?? `c${++counter}`
      const fenced = fence(content, {
        source: options.source,
        mode,
        nonce,
        scan: { ...(policy.scan ?? {}), ...(options.type ? { type: options.type } : {}) },
      })
      ingested.set(id, {
        id,
        source: options.source ?? fenced.text.match(/source="([^"]*)"/)?.[1] ?? 'content',
        verdict: fenced.scan.verdict,
        entities: fenced.scan.entities,
        senders: fenced.scan.senders,
      })
      return { ...fenced, id }
    },

    /**
     * Marks addresses, domains and numbers as the user's own words: what the user typed,
     * or your own systems said. Targets found here are never held for coming from
     * untrusted content.
     *
     * @param {string} text
     */
    trust(text) {
      const { entities } = extract(text, 'text')
      for (const e of entities.emails) trusted.emails.add(e)
      for (const p of entities.phones) trusted.phones.add(phoneKey(p))
      for (const u of entities.urls) {
        const host = hostOf(u)
        if (host) trusted.domains.add(host)
      }
    },

    /**
     * Checks a tool call the model wants to make.
     *
     * @param {ToolCall} call
     * @returns {Check}
     */
    check(call) {
      const tool = String(call.tool ?? call.name ?? '')
      const args = call.args ?? call.arguments ?? call.input ?? {}
      const category = call.category ?? policy.tools?.[tool] ?? categorize(tool)
      const untrusted = [...ingested.values()]
      const worstVerdict = untrusted.reduce(
        (w, c) => (VERDICT_RANK[c.verdict] > VERDICT_RANK[w] ? c.verdict : w),
        /** @type {Verdict} */ ('allow'),
      )

      /** @type {GateReason[]} */
      const reasons = []
      const targets = findTargets(args, targetKeys, category).map((t) => classify(t, untrusted, trusted))

      if (!untrusted.length) {
        reasons.push({ code: 'no_untrusted', decision: 'allow', detail: 'No untrusted content has been read in this conversation.' })
      } else {
        const names = untrusted.map((c) => c.source).join(', ')
        let base = after[category]
        const allYours = targets.length > 0 && targets.every((t) => t.origin === 'trusted')
        if (worstVerdict === 'block' && HARD.has(category)) base = allYours ? 'confirm' : 'block'
        if (worstVerdict !== 'allow' && category === 'browse' && base === 'allow') base = 'confirm'
        reasons.push(
          worstVerdict === 'allow'
            ? { code: 'untrusted_in_context', decision: base, detail: `${an(category)} call after reading untrusted content (${names}).` }
            : {
                code: 'injection_in_context',
                decision: base,
                detail: `${an(category)} call after reading content that looks like a prompt injection (${untrusted
                  .filter((c) => c.verdict !== 'allow')
                  .map((c) => `${c.source}: ${c.verdict}`)
                  .join(', ')}).`,
              },
        )

        for (const t of targets.filter((x) => x.origin === 'untrusted')) {
          const from = /** @type {Ingested} */ (ingested.get(/** @type {string} */ (t.from)))
          /** @type {Decision} */
          let decision = from.verdict === 'allow' ? 'confirm' : 'block'
          if (category === 'browse' && from.verdict === 'allow') decision = 'allow'
          if (category === 'read' || category === 'organize' || category === 'draft' || category === 'write') {
            decision = from.verdict === 'allow' ? 'allow' : 'confirm'
          }
          reasons.push({
            code: 'target_from_untrusted',
            decision,
            detail: `${t.value} appears in ${from.source}, not anywhere the user or your policy put it.`,
          })
        }

        for (const t of targets.filter((x) => x.kind === 'url' && x.origin === 'unknown')) {
          const query = (() => {
            try {
              return new URL(t.value).search.length > 1
            } catch {
              return false
            }
          })()
          if (query) {
            reasons.push({
              code: 'data_in_url',
              decision: 'confirm',
              detail: `${clip(t.value)} is a link no one gave the model, with data in it: the way an injection carries things out.`,
            })
          }
        }

        if (
          category === 'send' &&
          allowReply &&
          worstVerdict === 'allow' &&
          targets.length > 0 &&
          targets.every((t) => t.origin === 'sender' || t.origin === 'trusted')
        ) {
          reasons.push({
            code: 'reply_to_sender',
            decision: 'allow',
            detail: 'Every recipient is the sender of the content, or yours, and the content scanned clean.',
          })
          reasons[0].decision = 'allow'
        }
      }

      const floor = always[category]
      if (floor) reasons.push({ code: 'policy', decision: floor, detail: `Your policy gives ${category} calls at least ${floor}.` })

      const decision = reasons.reduce(
        (d, r) => (RANK[r.decision] > RANK[d] ? r.decision : d),
        /** @type {Decision} */ ('allow'),
      )
      return { decision, tool, category, reasons, targets, summary: summarize(decision, tool, category, reasons) }
    },

    /** What has been read, for logs. */
    get ingested() {
      return [...ingested.values()]
    },

    /**
     * Forgets one piece of content, once it has left the model's context.
     *
     * @param {string} id
     * @returns {boolean}
     */
    forget(id) {
      return ingested.delete(id)
    },

    /** Forgets everything read; for a new conversation. Trusted entries stay. */
    reset() {
      ingested.clear()
    },
  }
}

const VERDICT_RANK = { allow: 0, review: 1, block: 2 }

/** @type {[Category, string[]][]} */
const VERBS = [
  ['draft', ['draft', 'drafts', 'compose']],
  ['read', ['get', 'list', 'search', 'read', 'find', 'lookup', 'query', 'count', 'describe', 'view', 'show', 'check', 'retrieve', 'summarize', 'summarise', 'peek', 'inspect', 'stat']],
  ['browse', ['fetch', 'browse', 'navigate', 'open', 'visit', 'download', 'crawl', 'scrape', 'http', 'request', 'curl', 'goto', 'web']],
  ['organize', ['label', 'unlabel', 'tag', 'untag', 'archive', 'unarchive', 'mark', 'move', 'star', 'unstar', 'flag', 'unflag', 'snooze', 'categorize', 'categorise', 'pin', 'unpin', 'sort']],
  ['execute', ['exec', 'execute', 'shell', 'bash', 'terminal', 'command', 'eval', 'python', 'script', 'run', 'sh', 'powershell', 'cmd', 'code', 'sql']],
  ['financial', ['pay', 'payment', 'payments', 'transfer', 'wire', 'refund', 'charge', 'purchase', 'buy', 'order', 'checkout', 'payout', 'invoice', 'billing', 'withdraw', 'deposit']],
  ['access', ['share', 'unshare', 'permission', 'permissions', 'grant', 'role', 'roles', 'password', 'credential', 'credentials', 'token', 'apikey', 'oauth', 'delegate', 'admin', 'forwarding', 'filter', 'filters', 'rule', 'rules', 'acl', 'collaborator', 'sharing', 'authorize', 'authorise']],
  ['destructive', ['delete', 'remove', 'trash', 'purge', 'wipe', 'destroy', 'drop', 'erase', 'revoke', 'cancel', 'unsubscribe', 'block', 'ban', 'kick', 'close', 'clear', 'truncate', 'reset']],
  ['send', ['send', 'reply', 'forward', 'post', 'publish', 'tweet', 'comment', 'notify', 'dm', 'respond', 'broadcast', 'invite', 'call', 'sms', 'text', 'message', 'email', 'mail', 'schedule', 'book', 'submit', 'upload']],
  ['write', ['create', 'update', 'set', 'edit', 'modify', 'add', 'save', 'write', 'put', 'patch', 'insert', 'upsert', 'rename', 'assign', 'log', 'note']],
]
/** @type {Map<string, Category>} */
const WORD_CATEGORY = new Map()
for (const [category, words] of VERBS) for (const w of words) if (!WORD_CATEGORY.has(w)) WORD_CATEGORY.set(w, category)

/** Nouns that name a send when no verb says otherwise, such as create_event. */
const SENDING_NOUNS = new Set(['event', 'events', 'meeting', 'invitation', 'invite', 'reply', 'message', 'email', 'sms'])

/**
 * Guesses what a tool does from its name: the first word that says, so send_draft is a
 * send and create_draft is a draft. "create", "update" and the like only decide when
 * nothing later in the name does.
 *
 * @param {string} name
 * @returns {Category}
 */
export function categorize(name) {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
  /** @type {Category | null} */
  let weak = null
  for (const w of words) {
    const c = WORD_CATEGORY.get(w)
    if (!c) continue
    if (c === 'write') {
      weak ??= 'write'
      continue
    }
    return c
  }
  if (weak && words.some((w) => SENDING_NOUNS.has(w))) return 'send'
  return weak ?? 'unknown'
}

/**
 * @typedef {{ value: string, kind: Target['kind'] }} RawTarget
 */

/**
 * Where a call is pointed: values under recipient-like argument names, and for calls
 * that fetch or send, any link anywhere in the arguments.
 *
 * @param {unknown} args
 * @param {Set<string>} keys
 * @param {Category} category
 * @returns {RawTarget[]}
 */
function findTargets(args, keys, category) {
  /** @type {RawTarget[]} */
  const out = []
  const seen = new Set()
  /** @param {RawTarget} t */
  const add = (t) => {
    const k = `${t.kind}:${t.value}`
    if (!seen.has(k)) {
      seen.add(k)
      out.push(t)
    }
  }
  const anyUrl = category === 'browse' || category === 'unknown' || category === 'execute'

  /**
   * @param {unknown} value
   * @param {boolean} under A recipient-like key is above this value.
   * @param {number} depth
   */
  const walk = (value, under, depth) => {
    if (depth > 8 || value === null || value === undefined) return
    if (typeof value === 'string') {
      if (!under && !anyUrl) return
      const emails = findEmails(value)
      const urls = findUrls(value)
      for (const e of emails) add({ value: e, kind: 'email' })
      for (const u of urls) add({ value: u, kind: 'url' })
      if (!under) return
      if (!emails.length && !urls.length) {
        const phones = findPhones(value)
        for (const p of phones) add({ value: p, kind: 'phone' })
        const bare = value.trim().toLowerCase()
        if (!phones.length && /^(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/\S*)?$/.test(bare)) add({ value: bare, kind: 'domain' })
      }
      return
    }
    if (Array.isArray(value)) {
      for (const v of value) walk(v, under, depth + 1)
      return
    }
    if (typeof value === 'object') {
      for (const [k, v] of Object.entries(/** @type {Record<string, unknown>} */ (value))) {
        walk(v, under || keys.has(keyOf(k)), depth + 1)
      }
    }
  }
  walk(args, false, 0)
  return out
}

/**
 * @param {RawTarget} t
 * @param {Ingested[]} untrusted
 * @param {{ emails: Set<string>, domains: Set<string>, phones: Set<string> }} trusted
 * @returns {Target}
 */
function classify(t, untrusted, trusted) {
  const domain =
    t.kind === 'email' ? t.value.split('@')[1] : t.kind === 'url' ? hostOf(t.value) : t.kind === 'domain' ? t.value.split('/')[0] : null
  const inTrustedDomain = domain !== null && [...trusted.domains].some((d) => domain === d || domain.endsWith(`.${d}`))
  if (
    inTrustedDomain ||
    (t.kind === 'email' && trusted.emails.has(t.value)) ||
    (t.kind === 'phone' && trusted.phones.has(phoneKey(t.value)))
  ) {
    return { ...t, origin: 'trusted', from: null }
  }
  for (const c of untrusted) {
    if (t.kind === 'email' && c.senders.includes(t.value)) return { ...t, origin: 'sender', from: c.id }
  }
  for (const c of untrusted) {
    const e = c.entities
    const hit =
      (t.kind === 'email' && (e.emails.includes(t.value) || (domain !== null && e.domains.includes(domain) && !c.senders.some((s) => s.endsWith(`@${domain}`))))) ||
      (t.kind === 'url' && (e.urls.includes(t.value) || (domain !== null && e.domains.includes(domain)))) ||
      (t.kind === 'domain' && domain !== null && e.domains.includes(domain)) ||
      (t.kind === 'phone' && e.phones.some((p) => phoneKey(p) === phoneKey(t.value)))
    if (hit) return { ...t, origin: 'untrusted', from: c.id }
  }
  return { ...t, origin: 'unknown', from: null }
}

/**
 * The last ten digits, so +1 305 555 0142 and (305) 555-0142 match.
 *
 * @param {string} phone
 * @returns {string}
 */
function phoneKey(phone) {
  return normalizePhone(phone).replace('+', '').slice(-10)
}

/**
 * @param {string} key
 * @returns {string}
 */
function keyOf(key) {
  return key.toLowerCase().replace(/[-_\s]/g, '')
}

/**
 * @param {string} word
 * @returns {string}
 */
function an(word) {
  return `${/^[aeiou]/.test(word) ? 'An' : 'A'} ${word}`
}

/**
 * @param {string} value
 * @returns {string}
 */
function clip(value) {
  return value.length > 100 ? `${value.slice(0, 99)}…` : value
}

/**
 * @param {Decision} decision
 * @param {string} tool
 * @param {Category} category
 * @param {GateReason[]} reasons
 * @returns {string}
 */
function summarize(decision, tool, category, reasons) {
  const deciding = reasons.filter((r) => r.decision === decision)
  const why = (deciding[deciding.length - 1] ?? reasons[0]).detail
  const lead = { allow: 'Allow', confirm: 'Ask the user first', block: 'Block' }[decision]
  return `${lead}: ${tool || 'tool'} (${category}). ${why}`
}
