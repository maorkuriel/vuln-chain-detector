# Taint Analysis Deep Dive

## What Is Taint Analysis

Taint analysis marks data as "tainted" when it comes from an untrusted source and tracks that mark through all operations. If tainted data reaches a dangerous sink without being sanitized, it is a potential vulnerability.

Single-hop taint: `source → sink`  
Chain taint: `source → sink₁ → store → load → sink₂ → store → load → sink₃`

---

## Source Definitions

### Environment Variables
```typescript
// Tainted: any process.env access where the key is controlled or variable
process.env.TERMINAL          // tainted: attacker-controlled via .env or CI
process.env.EDITOR            // tainted
process.env[variable]         // tainted: dynamic key lookup

// Not tainted (typically safe, but context-dependent)
process.env.NODE_ENV          // low-risk, but flag if reaches shell
```

### File Reads from Untrusted Paths
```typescript
fs.readFileSync(userPath)          // tainted if userPath is attacker-controlled
fs.readFile(configPath, callback)  // tainted if configPath outside project root
JSON.parse(fs.readFileSync(...))   // tainted: JSON fields inherit taint
```

### CLI Arguments
```typescript
process.argv[2]         // tainted
yargs.argv.target       // tainted
commander.opts().file   // tainted
```

### HTTP/External Input
```typescript
req.body.command        // tainted
req.query.path          // tainted
req.headers['x-input']  // tainted
```

### Config Files (Cross-Session Source)
```typescript
// If written by attacker-controlled process in prior session:
JSON.parse(fs.readFileSync('~/.claude/settings.json'))
// Every field of the resulting object is tainted
```

---

## Sink Definitions

### OS Command Injection Sinks

```typescript
// Critical sinks — shell: true means shell metacharacters execute
execa(command, { shell: true })
execa(taintedString)                    // even without shell:true, string form is dangerous
execSync(taintedString)
exec(taintedString, callback)
spawn('sh', ['-c', taintedString])      // explicit shell invocation
spawnSync('bash', ['-c', taintedString])

// Python equivalents
subprocess.call(tainted, shell=True)
subprocess.run(tainted, shell=True)
os.system(tainted)
os.popen(tainted)
```

### Eval / Code Execution Sinks
```typescript
eval(taintedString)
new Function(taintedString)
vm.runInNewContext(taintedString)
require(taintedPath)                    // path traversal + code exec
```

### Exfiltration Sinks
```typescript
// Network exfiltration
fetch(url, { body: taintedData })
axios.post(externalUrl, taintedData)
http.request({ host: attacker, ... })

// File exfiltration (world-readable paths)
fs.writeFile('/tmp/' + taintedName, sensitiveData)
fs.writeFile(taintedPath, process.env)
```

### Persistence Sinks (STORE nodes)
```typescript
// Writing to user config paths — creates cross-session STORED_FLOW
fs.writeFileSync('~/.claude/settings.json', taintedContent)
fs.writeFileSync('~/.ssh/config', taintedContent)
fs.writeFileSync('.env', taintedContent)
```

---

## PASSTHROUGH Patterns (Taint Preserved)

```typescript
// String operations — taint propagates through all of these
`command: ${tainted}`                   // template literal
tainted + ' --flag'                     // concatenation
tainted.replace('x', 'y')              // replace (doesn't sanitize shell chars)
tainted.trim()                          // trim
tainted.toLowerCase()                   // case change
JSON.stringify({ key: tainted })        // JSON encode (does NOT sanitize shell chars)
Buffer.from(tainted).toString()         // encoding change
path.join('/tmp', tainted)             // path join (taint preserved)

// Assignment
const x = tainted                       // taint transfers to x
let { key } = taintedObject            // destructuring preserves taint
return tainted                          // return propagates taint
```

---

## SANITIZE Patterns (Taint Broken)

These patterns **break** the taint chain — only include if the function demonstrably removes dangerous characters for the target sink type:

```typescript
// Shell sanitization (breaks taint for shell sinks)
shellEscape(input)                      // shell-escape package
shellescape([input])
input.replace(/[^a-zA-Z0-9_\-\.]/g, '') // strict allowlist

// SQL sanitization (breaks taint for SQL sinks only)
db.escape(input)
parameterized query: db.query('SELECT ? ', [input])

// HTML sanitization (breaks taint for HTML sinks only, NOT shell sinks)
DOMPurify.sanitize(input)               // does NOT sanitize for shell — common mistake
escapeHTML(input)                       // does NOT sanitize for shell
```

**Important:** HTML encoding does NOT sanitize for shell sinks. A node that only HTML-escapes input is still PASSTHROUGH for shell injection purposes.

---

## Cross-Session Flow Detection

The hardest part. Algorithm:

```
1. Build a registry of "sensitive write paths":
   - Absolute: ~/.claude/, ~/.ssh/, ~/.aws/, ~/.gitconfig
   - Relative: .env, package.json, *.config.js, settings.json
   - Dynamic: any path containing 'config', 'settings', 'credentials', 'token'

2. For each fs.writeFile / fs.writeFileSync call:
   - Resolve the target path
   - If path matches sensitive write paths AND data is tainted:
     → Create STORE node
     → Register (path, taint_origin, file:line) in cross-session registry

3. For each fs.readFile / fs.readFileSync / require call:
   - Resolve the source path
   - If path matches any registered STORE path:
     → Create LOAD node
     → Create STORED_FLOW edge: STORE → LOAD
     → All data read from this path is tainted (inherits from STORE origin)

4. Continue taint propagation from LOAD node normally
```

---

## Interprocedural Analysis

Taint must follow function calls across file boundaries:

```typescript
// file-a.ts
function getTerminal() {
  return process.env.TERMINAL  // SOURCE
}

// file-b.ts
import { getTerminal } from './file-a'
const terminal = getTerminal()           // taint flows here
execa(`which ${terminal}`, {shell:true}) // SINK
```

To handle this:
1. Build a call graph across all files in the project
2. For each function that returns a tainted value, mark its call sites as tainted
3. For each function that receives a tainted argument, propagate taint to uses within the function body

This is O(n²) in the worst case — scope it to direct callers first, then expand.
