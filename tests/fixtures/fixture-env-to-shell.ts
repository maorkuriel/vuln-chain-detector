/**
 * Test Fixture: GT-001
 * DG-2024-001 pattern — env var injected into shell exec
 * The engine MUST detect this chain.
 */
import { execSync } from 'child_process'

// SOURCE: process.env.DG_REGISTRY is attacker-controlled
const registry = process.env.DG_REGISTRY ?? 'https://registry.npmjs.org'
const packageName = 'lodash'

// PASSTHROUGH: template literal preserves taint
const cmd = `curl -s "${registry}/${packageName}/latest"`

// SINK: no shell:false — string form uses system shell
// EXPECTED: engine flags as Critical, env-injection-to-shell pattern
execSync(cmd)

// ---- SAFE VARIANT (engine must NOT flag this) ----
import { execa } from 'execa'
const safeRegistry = process.env.DG_REGISTRY ?? 'https://registry.npmjs.org'
const safeUrl = new URL(`/${packageName}/latest`, safeRegistry)
execa('curl', ['-s', safeUrl.toString()])  // args array, no shell expansion
