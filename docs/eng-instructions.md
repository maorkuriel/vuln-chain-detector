# Engineering Instructions: Building the Vulnerability Chain Detector

## Build Order

Build in this sequence. Each phase has a clear done-signal before moving to the next.

---

## Phase 1: Sink + Source Enumeration (Week 1)

**Goal:** Catalog every dangerous function call and every untrusted input in a target codebase.

### Tasks

1. **Choose your AST parser**
   - TypeScript/JS: use `@babel/parser` + `@babel/traverse`, or `ts-morph`
   - Multi-language: use `tree-sitter` with language grammars

2. **Implement `SinkScanner`**
   - Input: a parsed AST
   - Output: list of `SinkNode { type, file, line, functionName, args }`
   - Start with these patterns:
     ```
     execa(*, { shell: true })
     execSync(string_literal_or_template)
     exec(string_with_variable)
     spawn('sh' | 'bash', ['-c', *])
     eval(*)
     new Function(*)
     ```
   - Each pattern is a tree-sitter query or AST visitor rule — store in `/src/sinks/patterns/`

3. **Implement `SourceScanner`**
   - Input: a parsed AST
   - Output: list of `SourceNode { type, file, line, identifier }`
   - Start with:
     ```
     process.env.*
     process.argv[*]
     fs.readFileSync(variable_path)
     req.body.* / req.query.* / req.params.*
     ```

4. **Done signal:** Run both scanners on the `/tests/fixtures/` code samples. They must detect all sources and sinks in `cve-chain-example.yaml`.

---

## Phase 2: Single-File Taint Tracking (Week 2)

**Goal:** For each source in a file, trace all data flows to sinks within the same file.

### Tasks

1. **Implement `TaintTracker` (intra-file)**
   - Input: AST + list of SourceNodes
   - Algorithm:
     ```
     For each SourceNode:
       Mark its identifier as tainted
       Walk all assignments, function calls, returns
       At each step:
         If identifier is used in a SANITIZE pattern → unmark
         If identifier is used in a SINK → record chain
         If identifier is assigned to new variable → mark new variable
         If used in template literal or concat → mark result as tainted
     ```
   - Output: list of `Chain { source, hops[], sink }`

2. **Handle template literals explicitly**
   - `` `command: ${tainted}` `` → result is tainted
   - Nested template literals → taint propagates

3. **Done signal:** The tracker finds the single-file chain in `fixture-single-file.ts`:
   ```typescript
   const input = process.env.TARGET      // SOURCE
   const cmd = `ping ${input}`           // PASSTHROUGH
   execSync(cmd)                         // SINK
   ```

---

## Phase 3: Cross-File + Interprocedural (Week 3)

**Goal:** Track taint across function calls and file imports.

### Tasks

1. **Build the call graph**
   - For each `import` / `require`, record the symbol and its origin file
   - For each function definition, record its parameters and return values
   - For each function call, resolve it to its definition

2. **Extend `TaintTracker` to be interprocedural**
   - When a tainted value is passed as an argument to a function:
     → Mark the corresponding parameter as tainted in the callee
   - When a function returns a tainted value:
     → Mark the return value as tainted at all call sites

3. **Done signal:** Tracker finds the cross-file chain in `fixture-cross-file/`:
   ```typescript
   // file-a.ts
   export function getInput() { return process.env.CMD }  // SOURCE in file-a

   // file-b.ts
   import { getInput } from './file-a'
   const val = getInput()                 // taint flows here
   execa(val, { shell: true })            // SINK in file-b
   ```

---

## Phase 4: Cross-Session Flow Detection (Week 4)

**Goal:** Detect STORE → LOAD pairs that cross session boundaries. This is what enables chain detection across process restarts.

### Tasks

1. **Build `SensitivePathRegistry`**
   - Hardcoded sensitive paths: `~/.claude/`, `~/.ssh/`, `~/.aws/`, `.env`, `package.json`
   - Dynamic detection: any path string containing `config`, `credentials`, `token`, `secret`, `settings`

2. **Implement `StoreNodeDetector`**
   - Detect: `fs.writeFile(sensitivePath, taintedData)`
   - Register: `{ path, taintOrigin, file, line }`

3. **Implement `LoadNodeDetector`**
   - Detect: `fs.readFile(path)` / `JSON.parse(fs.readFileSync(path))`
   - If path matches any registered StoreNode path:
     → Create `STORED_FLOW` edge
     → Mark all properties of the loaded object as tainted

4. **Done signal:** Detects the 2-session chain in `fixture-cross-session/`:
   ```
   Session A: process.env.DG_REGISTRY → fs.writeFileSync('~/.depguard/config.json', payload)
   Session B: JSON.parse(readFileSync('~/.depguard/config.json')) → execSync(preScanHook)
   ```
   Both files in the fixture — the engine must link them via STORED_FLOW.

---

## Phase 5: Pattern Library + Zero-Day Detection (Week 5)

**Goal:** Match discovered chains against known CVE patterns. Flag unmatched chains as zero-day candidates.

### Tasks

1. **Load YAML patterns** from `/patterns/`
   - Each pattern defines: source type, sink type, optional STORE path, chain length
   - Match chains against patterns using structural comparison

2. **Implement `ZeroDayFlagger`**
   - If a chain scores ≥ 7.0 AND has no pattern match AND has session-crossing flow:
     → Tag as `zero_day_candidate: true`
     → Add to separate output section with manual review note

3. **Done signal:** Engine correctly classifies:
   - DG-2024-001 chain → matched pattern `env-injection-to-shell`
   - Modified variant (different env var name, same structure) → `zero_day_candidate: true`

---

## Phase 6: Scoring + Output (Week 6)

**Goal:** Score all chains per `chain-scoring.md`. Emit SARIF-compatible output.

### Tasks

1. **Implement `ChainScorer`** per the scoring formula in `chain-scoring.md`

2. **Implement SARIF emitter**
   - SARIF 2.1.0 format
   - One `result` per chain
   - Include full chain path as `codeFlows` array
   - `ruleId` = pattern name or `CHAIN-ZERO-DAY`

3. **Implement CLI output**
   - Human-readable per-chain summary (see README example output)
   - `--format sarif` flag for SARIF
   - `--min-severity` flag to filter output

4. **Done signal:** Running `npm run scan -- --target ./tests/fixtures/ --format sarif` produces valid SARIF that GitHub Code Scanning accepts without schema errors.

---

## Testing Strategy

### Unit Tests (per phase)
- Fixture files in `/tests/fixtures/` — small, focused TypeScript snippets
- One fixture per chain type
- All 3 CVE chains must have fixtures and must be detected

### Integration Tests
- Run the engine against a known-vulnerable open source project
- Verify no crashes, reasonable runtime, no duplicate findings

### False Positive Budget
- Aim for < 10% false positive rate on chains
- Individual node detection (not chained) can have higher FP rate — that is expected
- Track FP rate per pattern in CI

---

## Performance Targets

| Codebase Size | Max Scan Time |
|---|---|
| < 10k files | < 60 seconds |
| < 50k files | < 5 minutes |
| < 200k files | < 20 minutes |

Use incremental analysis (cache unchanged files) for repeat scans.

---

## Definition of Done (Full Engine)

- [ ] Detects all 3 CVEs in Claude Code fixture
- [ ] Detects cross-session STORED_FLOW chains
- [ ] Flags zero-day candidates (unmatched high-severity chains)
- [ ] Emits valid SARIF 2.1.0
- [ ] False positive rate < 10% on chain findings
- [ ] CLI scan of 10k file project completes in < 60 seconds
- [ ] Pattern library has ≥ 10 patterns covering OWASP Top 10 chain variants
