/**
 * Test Fixture: GT-001
 * CVE-2026-35020 pattern — env var injected into shell exec
 * The engine MUST detect this chain.
 */
import { execa } from 'execa'

// SOURCE: process.env.TERMINAL is attacker-controlled
const command = process.env.TERMINAL

// PASSTHROUGH: template literal preserves taint
const shellCmd = `which ${command}`

// SINK: shell: true means semicolons, $() execute
// EXPECTED: engine flags this as Critical, env-injection-to-shell pattern
execa(shellCmd, { shell: true })

// ---- SAFE VARIANT (engine must NOT flag this) ----
const safeCommand = process.env.TERMINAL
execa('which', [safeCommand ?? ''])   // args array, no shell expansion
