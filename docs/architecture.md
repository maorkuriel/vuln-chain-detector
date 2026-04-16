# Engine Architecture

## Overview

The engine performs **interprocedural taint analysis with cross-session flow tracking**, represented as a directed graph where nodes are code locations and edges are data flows.

```
┌─────────────┐    ┌──────────────────┐    ┌───────────────┐
│   AST Parse │───▶│  Taint Graph      │───▶│ Chain Finder  │
│  (per file) │    │  Builder          │    │ (BFS/DFS)     │
└─────────────┘    └──────────────────┘    └───────┬───────┘
                          ▲                        │
                   ┌──────┴──────┐         ┌───────▼───────┐
                   │  Pattern    │         │    Scorer     │
                   │  Library    │         └───────┬───────┘
                   └─────────────┘                │
                                          ┌───────▼───────┐
                                          │  Output       │
                                          │  (SARIF/CLI)  │
                                          └───────────────┘
```

---

## Node Types

Every location in the taint graph is one of:

| Node Type | Description | Example |
|---|---|---|
| `SOURCE` | Untrusted data enters here | `process.env.TERMINAL` |
| `SANITIZE` | Data is validated/escaped — breaks taint chain | `shellEscape(input)` |
| `PASSTHROUGH` | Transform that preserves taint | Template literal, string concat |
| `SINK` | Dangerous execution point | `execa({shell:true})` |
| `STORE` | Writes tainted data to persistent storage | `fs.writeFile('~/.config/...')` |
| `LOAD` | Reads from persistent storage | `fs.readFileSync('~/.config/...')` |

`STORE → LOAD` pairs are **cross-session edges**. This is what enables chain detection across session boundaries.

---

## Edge Types

| Edge Type | Description |
|---|---|
| `DIRECT_FLOW` | Value passed directly, same execution context |
| `TRANSFORM_FLOW` | Value modified but taint preserved (concat, template) |
| `STORED_FLOW` | Written to file/DB/config; read later (cross-session capable) |
| `ENV_FLOW` | Set as environment variable; read in different process context |
| `RETURN_FLOW` | Tainted value returned from function |
| `CALL_FLOW` | Tainted value passed as argument to another function |

---

## Phase 1: AST Parsing

Parse each file into an AST. Identify:

1. All function calls matching sink patterns
2. All property accesses matching source patterns  
3. All variable assignments (for data flow tracking)
4. All `require/import` statements (for cross-file flow)

**Supported parsers:**
- TypeScript/JavaScript: Babel or ts-morph
- Python: ast module or tree-sitter-python
- Go: go/ast
- Generic: tree-sitter (multi-language fallback)

---

## Phase 2: Taint Graph Construction

For each source node found:

```
1. Create SOURCE node
2. Follow all assignments, function calls, and returns
3. At each step:
   a. If SANITIZE pattern matched → stop (taint broken)
   b. If STORE pattern matched → create STORE node + STORED_FLOW edge
      → register path as cross-session candidate
   c. If SINK pattern matched → create SINK node + record chain
   d. Otherwise → create PASSTHROUGH node + continue
```

Cross-file flows require resolving imports and tracking function definitions across files.

---

## Phase 3: Cross-Session Flow Resolution

After per-file analysis, resolve `STORE → LOAD` pairs:

```
For each STORE node writing to path P:
  Find all LOAD nodes reading from path P
  Create STORED_FLOW edge: STORE → LOAD
  Mark chain as session-crossing = true
```

Known cross-session paths to track:
- `~/.depguard/config.json`
- `~/.ssh/config`
- `~/.aws/credentials`
- `~/.gitconfig`
- `package.json` scripts
- `.env` files
- CI/CD variable stores

---

## Phase 4: Chain Discovery

Run BFS/DFS from each SOURCE node through the taint graph:

```
chain_find(node, visited, current_chain):
  if node is SANITIZE: return  # taint broken
  if node is SINK:
    score_and_record(current_chain)
    return
  for each edge from node:
    if edge.target not in visited:
      chain_find(edge.target, visited + [node], current_chain + [node])
```

A valid chain must:
- Start at a SOURCE
- End at a SINK
- Have no SANITIZE node in the path
- Have at least one PASSTHROUGH or STORE node (single-hop is an individual vuln, not a chain)

---

## Phase 5: Scoring

See [chain-scoring.md](chain-scoring.md) for full scoring logic.

Base CVSS is calculated per chain, not per individual node. Key multipliers:
- Session-crossing chain → +1.5x
- No user interaction required → +1.3x
- CI/CD environment detected → +1.2x
- Exfiltration sink at terminal node → +1.4x

---

## Phase 6: Output

Emit one finding per chain (not per node). Include:
- Chain ID (hash of node sequence)
- Severity + score
- Full step-by-step path with file:line references
- Fix recommendation (per sink type)
- SARIF-compatible JSON for tooling integration

---

## Key Design Constraints

1. **No false-positive tradeoff skew** — prefer false negatives over noisy false positives for chain detection (individual vuln scanners cover the low-hanging fruit)
2. **SANITIZE nodes must be conservative** — only mark as sanitizing if the function demonstrably removes shell metacharacters, SQL tokens, etc. for the relevant sink type
3. **Cross-session flows are highest priority** — a STORED_FLOW edge that crosses a session boundary and ends at an exec sink is automatically Critical
4. **Pattern library is the knowledge layer** — the engine is generic; CVE-specific knowledge lives in YAML patterns, not hardcoded logic
