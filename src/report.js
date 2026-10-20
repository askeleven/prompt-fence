/**
 * Plain-text reports for the CLI.
 */

/**
 * @typedef {import('./scan.js').ScanResult} ScanResult
 * @typedef {import('./guard.js').Check} Check
 */

const PAINT = {
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  reset: '\u001b[0m',
}

/**
 * @param {boolean} on
 * @returns {(colour: keyof typeof PAINT, text: string) => string}
 */
function painter(on) {
  return (colour, text) => (on ? `${PAINT[colour]}${text}${PAINT.reset}` : text)
}

/**
 * @param {ScanResult} result
 * @param {{ colour?: boolean }} [options]
 * @returns {string}
 */
export function formatScan(result, options = {}) {
  const paint = painter(options.colour ?? false)
  const verdictColour = { block: 'red', review: 'yellow', allow: 'green' }[result.verdict]
  const what = result.email
    ? `email${result.email.from ? ` from ${result.email.from}` : ''}${result.email.subject ? `: "${result.email.subject}"` : ''}`
    : result.type === 'html'
      ? 'web page'
      : 'message'
  const lines = [
    `${paint(/** @type {keyof typeof PAINT} */ (verdictColour), result.verdict.toUpperCase().padEnd(7))}score ${result.score}  ${what}`,
    '',
  ]
  if (!result.findings.length) {
    lines.push('Nothing in this reads as instructions for an AI.', '')
    return lines.join('\n')
  }
  for (const f of result.findings) {
    const sev = f.severity.toUpperCase().padEnd(8)
    const sevColour = f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'yellow' : 'dim'
    const place = `${f.where}${f.line > 1 ? `, line ${f.line}` : ''}`
    lines.push(`${paint(/** @type {keyof typeof PAINT} */ (sevColour), sev)}${f.code.padEnd(17)}${paint('dim', place)}`)
    lines.push(`        ${f.detail}`)
    lines.push(`        ${paint('dim', `"${f.text}"`)}`)
    if (f.decoded !== null && !f.detail.includes(f.decoded.slice(0, 40))) {
      lines.push(`        ${paint('dim', `decodes to: "${f.decoded.slice(0, 160)}"`)}`)
    }
    lines.push('')
  }
  lines.push(paint('dim', result.notes.join(' ')), '')
  return lines.join('\n')
}

/**
 * @param {Check} check
 * @param {{ colour?: boolean }} [options]
 * @returns {string}
 */
export function formatCheck(check, options = {}) {
  const paint = painter(options.colour ?? false)
  const colour = { block: 'red', confirm: 'yellow', allow: 'green' }[check.decision]
  const lines = [`${paint(/** @type {keyof typeof PAINT} */ (colour), check.decision.toUpperCase().padEnd(8))}${check.tool} (${check.category})`, '']
  for (const r of check.reasons) lines.push(`${r.decision.padEnd(8)}${r.code.padEnd(23)}${r.detail}`)
  if (check.targets.length) {
    lines.push('', 'Targets')
    for (const t of check.targets) lines.push(`  ${t.origin.padEnd(10)}${t.kind.padEnd(7)}${t.value}`)
  }
  lines.push('')
  return lines.join('\n')
}
