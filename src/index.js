export { scan, analyze, FenceError, DEFAULT_REVIEW_AT, DEFAULT_BLOCK_AT } from './scan.js'
export { fence, fenceInstructions, newNonce, DATAMARK } from './fence.js'
export { createGuard, categorize, DEFAULT_AFTER_UNTRUSTED } from './guard.js'
export { extract, detectType } from './extract.js'
export { CODES, RULES } from './rules.js'

/**
 * @typedef {import('./scan.js').ScanResult} ScanResult
 * @typedef {import('./scan.js').ScanOptions} ScanOptions
 * @typedef {import('./scan.js').Finding} Finding
 * @typedef {import('./scan.js').Reason} Reason
 * @typedef {import('./scan.js').Verdict} Verdict
 * @typedef {import('./rules.js').Code} Code
 * @typedef {import('./rules.js').Severity} Severity
 * @typedef {import('./fence.js').Fenced} Fenced
 * @typedef {import('./fence.js').FenceOptions} FenceOptions
 * @typedef {import('./fence.js').FenceMode} FenceMode
 * @typedef {import('./guard.js').Policy} Policy
 * @typedef {import('./guard.js').ToolCall} ToolCall
 * @typedef {import('./guard.js').Check} Check
 * @typedef {import('./guard.js').Category} Category
 * @typedef {import('./guard.js').Decision} Decision
 * @typedef {import('./guard.js').Target} Target
 * @typedef {ReturnType<typeof import('./guard.js').createGuard>} Guard
 */
