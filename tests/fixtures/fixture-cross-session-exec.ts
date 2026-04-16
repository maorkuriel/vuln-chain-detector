/**
 * Test Fixture: GT-003, Session B
 * Simulates DG-2024-003 — config written in Session A is loaded and
 * preScanHook is executed at the start of the next scan.
 * Engine must detect: LOAD from registered STORE path → SINK (cross-session STORED_FLOW)
 */
import * as fs from 'fs'
import * as path from 'path'
import { execSync, execFileSync } from 'child_process'
import * as os from 'os'

const CONFIG_PATH = path.join(os.homedir(), '.depguard', 'config.json')

interface DepguardConfig {
  registry?: string
  preScanHook?: string
}

export function loadAndRunHooks(): void {
  if (!fs.existsSync(CONFIG_PATH)) return

  // LOAD: reads from path registered as STORE in Session A
  // Engine must link this to the STORE node via STORED_FLOW edge
  const config: DepguardConfig = JSON.parse(
    fs.readFileSync(CONFIG_PATH, 'utf8')
  )

  // PASSTHROUGH: preScanHook field inherits taint from STORED_FLOW
  if (config.preScanHook) {
    // SINK: executes preScanHook before scan begins — no output, no warning
    // EXPECTED: engine flags as Critical, config-write-to-exec pattern
    // EXPECTED: session_crossing = true (STORE in Session A, SINK here in Session B)
    execSync(config.preScanHook, { stdio: 'inherit' })
  }
}

// ---- SAFE VARIANT (engine must NOT flag this) ----
export function loadAndRunHooksSafe(): void {
  if (!fs.existsSync(CONFIG_PATH)) return

  const config: DepguardConfig = JSON.parse(
    fs.readFileSync(CONFIG_PATH, 'utf8')
  )

  if (config.preScanHook) {
    // Validate: only absolute paths to executables — no shell strings
    const SAFE_HOOK_RE = /^\/[a-zA-Z0-9_\-\/\.]+$/
    if (!SAFE_HOOK_RE.test(config.preScanHook)) {
      throw new Error(`preScanHook value is not a valid executable path — rejecting`)
    }
    execFileSync(config.preScanHook, [], { stdio: 'inherit' })
  }
}
