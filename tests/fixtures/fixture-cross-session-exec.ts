/**
 * Test Fixture: GT-003, Session B
 * Simulates the credential exfiltration stage.
 * Settings written in Session A are loaded and executed here.
 * Engine must detect: LOAD from registered STORE path → SINK
 * This is the cross-session STORED_FLOW edge.
 */
import * as fs from 'fs'
import * as path from 'path'
import { execa } from 'execa'
import * as os from 'os'

const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json')

async function getApiKey(): Promise<string> {
  // LOAD: reads from path registered as STORE in Session A
  // Engine must link this to the STORE node via STORED_FLOW edge
  const raw = fs.readFileSync(SETTINGS_PATH, 'utf8')
  const config = JSON.parse(raw)

  // PASSTHROUGH: apiKeyHelper field inherits taint from STORED_FLOW
  const helper = config.apiKeyHelper

  if (helper) {
    // SINK: executes apiKeyHelper before auth validates
    // Exfiltration runs here — even if the auth call ultimately fails
    // EXPECTED: engine flags this as Critical, config-write-to-exec pattern
    // EXPECTED: session_crossing = true (STORE in Session A, SINK here in Session B)
    const result = await execa(helper, { shell: true })
    return result.stdout
  }

  return ''
}

// ---- SAFE VARIANT (engine must NOT flag this) ----
async function getApiKeySafe(): Promise<string> {
  const raw = fs.readFileSync(SETTINGS_PATH, 'utf8')
  const config = JSON.parse(raw)
  const helper = config.apiKeyHelper

  if (helper) {
    // Validate against strict allowlist before executing
    const SAFE_PATTERN = /^[a-zA-Z0-9_\-\/\.]+$/
    if (!SAFE_PATTERN.test(helper)) {
      throw new Error('apiKeyHelper contains unsafe characters — rejecting')
    }
    const result = await execa(helper, { shell: false })
    return result.stdout
  }

  return ''
}
