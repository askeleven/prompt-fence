#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { readFile } from 'node:fs/promises'
import { existsSync, statSync } from 'node:fs'
import { scan, fence, createGuard, FenceError, DEFAULT_REVIEW_AT, DEFAULT_BLOCK_AT } from '../src/index.js'
import { formatScan, formatCheck } from '../src/report.js'
import { serve } from '../src/mcp.js'
import { VERSION } from '../src/version.js'
import { starHint } from './star-hint.js'

const USAGE = `
prompt-fence <message.eml | page.html | "text" | ->
prompt-fence fence <file | -> [--source <label>] [--mode tags|datamark|base64]
prompt-fence check --call <call.json | json> <content files...>
prompt-fence mcp [--policy policy.json]

  Finds text written to instruct an AI that reads an email, a web page or a
  chat message: "ignore previous instructions", fake system markers, orders
  hidden in invisible HTML or Unicode, base64 payloads, requests to forward
  mail or send credentials. Fences untrusted content for a prompt, and checks
  the tool calls an agent makes after reading it. Runs locally, no network.

Commands
  (none)                Scan. Prints a verdict (allow, review, block), a 0-100
                        score and every finding.
  fence                 Print the content fenced for a prompt, and the system
                        prompt text that goes with it on standard error.
  check                 Read the content files as untrusted, then check one
                        tool call: {"tool": "send_email", "args": {...}}.
  mcp                   MCP server over stdio, for agents.

Options
  --type <t>            auto (default), email, html or text.
  --fail-on <v>         Exit 1 at this verdict or worse: review (default) or block.
  --ignore <list>       Codes or rule ids to skip, comma-separated.
  --review-at <n>       Review at this score or above. Default ${DEFAULT_REVIEW_AT}.
  --block-at <n>        Block at this score or above. Default ${DEFAULT_BLOCK_AT}.
  --source <label>      fence: what the content is, such as "email from Dana".
  --mode <m>            fence: tags (default), datamark or base64.
  --keep-hidden         fence: keep hidden text, marked, instead of removing it.
  --call <json|file>    check: the tool call.
  --policy <file>       check, mcp: a JSON policy (see the README).
  --json                Machine-readable output.
  --no-colour           Plain text.
  --version, --help

Exit codes
  0  allow
  1  scan: at --fail-on or worse; check: confirm or block
  2  could not run

Examples
  npx @askeleven/prompt-fence message.eml
  npx @askeleven/prompt-fence page.html --json
  npx @askeleven/prompt-fence fence message.eml --mode datamark
  npx @askeleven/prompt-fence check --call '{"tool":"send_email","args":{"to":"x@evil.com"}}' message.eml
`

/**
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
async function main(argv) {
  const command = ['fence', 'check', 'mcp', 'scan'].includes(argv[0]) ? argv[0] : 'scan'
  const rest = command === 'scan' && argv[0] !== 'scan' ? argv : argv.slice(1)

  let parsed
  try {
    parsed = parseArgs({
      args: rest,
      allowPositionals: true,
      options: {
        type: { type: 'string' },
        'fail-on': { type: 'string' },
        ignore: { type: 'string' },
        'review-at': { type: 'string' },
        'block-at': { type: 'string' },
        source: { type: 'string' },
        mode: { type: 'string' },
        'keep-hidden': { type: 'boolean', default: false },
        call: { type: 'string' },
        policy: { type: 'string' },
        json: { type: 'boolean', default: false },
        // parseArgs has no --no-x negation, so both spellings are declared explicitly.
        'no-colour': { type: 'boolean', default: false },
        'no-color': { type: 'boolean', default: false },
        version: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
    })
  } catch (error) {
    process.stderr.write(`${/** @type {Error} */ (error).message}\n${USAGE}`)
    return 2
  }
  const { values, positionals } = parsed

  if (values.help) {
    process.stdout.write(USAGE)
    return 0
  }
  if (values.version) {
    process.stdout.write(`${VERSION}\n`)
    return 0
  }

  try {
    const policy = values.policy ? JSON.parse(await readFile(values.policy, 'utf8')) : undefined
    if (command === 'mcp') {
      await serve({ policy })
      return 0
    }

    const type = /** @type {any} */ (values.type)
    if (type !== undefined && !['auto', 'email', 'html', 'text'].includes(type)) {
      throw new FenceError('invalid_option', `--type must be auto, email, html or text, got ${type}`)
    }
    const scanOptions = {
      type,
      reviewAt: number(values['review-at'], 'review-at'),
      blockAt: number(values['block-at'], 'block-at'),
      ignore: values.ignore ? values.ignore.split(',').map((s) => s.trim()).filter(Boolean) : [],
    }
    const colour = useColour(values)

    if (command === 'check') {
      if (!values.call) throw new FenceError('invalid_option', '--call is required: the tool call as JSON or a JSON file.')
      const callText = existsSync(values.call) && statSync(values.call).isFile() ? await readFile(values.call, 'utf8') : values.call
      const call = JSON.parse(callText)
      const guard = createGuard({ ...(policy ?? {}), scan: scanOptions })
      for (const file of positionals) guard.ingest(await readFile(file, 'utf8'), { source: file })
      const check = guard.check(call)
      process.stdout.write(values.json ? `${JSON.stringify(check, null, 2)}\n` : formatCheck(check, { colour }))
      return check.decision === 'allow' ? 0 : 1
    }

    const content = await readInput(positionals)

    if (command === 'fence') {
      const mode = /** @type {any} */ (values.mode ?? 'tags')
      const fenced = fence(content, { source: values.source, mode, keepHidden: values['keep-hidden'], scan: scanOptions })
      if (values.json) process.stdout.write(`${JSON.stringify(fenced, null, 2)}\n`)
      else {
        process.stdout.write(`${fenced.text}\n`)
        process.stderr.write(`\n${fenced.instructions}\n\n${fenced.scan.summary}\n`)
      }
      return 0
    }

    const failOn = values['fail-on'] ?? 'review'
    if (failOn !== 'review' && failOn !== 'block') throw new FenceError('invalid_option', `--fail-on must be review or block, got ${failOn}`)
    const result = scan(content, scanOptions)
    process.stdout.write(values.json ? `${JSON.stringify(result, null, 2)}\n` : formatScan(result, { colour }))
    if (result.verdict === 'block') return 1
    return result.verdict === 'review' && failOn === 'review' ? 1 : 0
  } catch (error) {
    if (error instanceof FenceError || error instanceof SyntaxError || error instanceof TypeError || isFsError(error)) {
      process.stderr.write(`${/** @type {Error} */ (error).message}\n`)
      return 2
    }
    throw error
  }
}

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isFsError(error) {
  return error instanceof Error && typeof (/** @type {any} */ (error).code) === 'string' && /^E[A-Z]+$/.test(/** @type {any} */ (error).code)
}

/**
 * @param {string | undefined} value
 * @param {string} name
 * @returns {number | undefined}
 */
function number(value, name) {
  if (value === undefined) return undefined
  const n = Number(value)
  if (value.trim() === '' || !Number.isFinite(n)) throw new FenceError('invalid_option', `--${name} must be a number from 0 to 100, got ${value}`)
  return n
}

/**
 * One positional that names a file is read from it; "-", or nothing with input piped
 * in, reads standard input; anything else is the content itself, words joined by
 * single spaces the way the shell split them.
 *
 * @param {string[]} positionals
 * @returns {Promise<string>}
 */
async function readInput(positionals) {
  if (positionals.length === 0 || (positionals.length === 1 && positionals[0] === '-')) {
    if (process.stdin.isTTY) throw new FenceError('invalid_option', `Give a file, the text, or pipe it in.\n${USAGE}`)
    return readStdin()
  }
  if (positionals.length === 1 && existsSync(positionals[0]) && statSync(positionals[0]).isFile()) {
    return readFile(positionals[0], 'utf8')
  }
  return positionals.join(' ')
}

/** @returns {Promise<string>} */
async function readStdin() {
  /** @type {Buffer[]} */
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Honours --no-colour, --no-color, NO_COLOR, and a non-TTY stdout.
 *
 * @param {Record<string, unknown>} values
 * @returns {boolean}
 */
function useColour(values) {
  if (values['no-colour'] || values['no-color']) return false
  if (process.env.NO_COLOR) return false
  return process.stdout.isTTY === true
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
    starHint('prompt-fence', code, process.argv.slice(2))
  },
  (error) => {
    process.stderr.write(`${error?.stack ?? error}\n`)
    process.exitCode = 2
  },
)
