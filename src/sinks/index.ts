/**
 * Sink node definitions.
 * A SINK is a dangerous execution point where tainted data causes harm.
 */

export enum SinkType {
  SHELL_EXEC = 'SHELL_EXEC',           // OS command injection
  CODE_EVAL = 'CODE_EVAL',             // eval / new Function
  FILE_WRITE_SENSITIVE = 'FILE_WRITE_SENSITIVE',  // write to sensitive path (STORE)
  NETWORK_EXFIL = 'NETWORK_EXFIL',     // HTTP POST to external host
  DYNAMIC_REQUIRE = 'DYNAMIC_REQUIRE', // require(variable)
}

export interface SinkNode {
  type: SinkType
  file: string
  line: number
  column: number
  call: string                         // original call expression
  shellExpansion: boolean              // true if shell: true or equivalent
  isSensitivePath?: boolean            // for FILE_WRITE sinks
  isExternal?: boolean                 // for NETWORK_EXFIL sinks
}

/**
 * Sink patterns — mapped to SinkType.
 * shell: true variants are automatically Critical; others depend on context.
 */
export const SINK_PATTERNS: Record<SinkType, SinkPattern[]> = {
  [SinkType.SHELL_EXEC]: [
    { pattern: 'execa(string, { shell: true })',      critical: true },
    { pattern: 'execa(templateLiteral)',               critical: true },
    { pattern: 'execSync(string)',                     critical: true },
    { pattern: 'exec(string, callback)',               critical: true },
    { pattern: "spawn('sh', ['-c', string])",         critical: true },
    { pattern: "spawn('bash', ['-c', string])",       critical: true },
    { pattern: "spawnSync('sh', ['-c', string])",     critical: true },
  ],
  [SinkType.CODE_EVAL]: [
    { pattern: 'eval(string)',                         critical: true },
    { pattern: 'new Function(string)',                 critical: true },
    { pattern: 'vm.runInNewContext(string)',            critical: true },
    { pattern: 'vm.runInThisContext(string)',           critical: true },
  ],
  [SinkType.FILE_WRITE_SENSITIVE]: [
    { pattern: 'fs.writeFileSync(sensitivePath, *)',   critical: false }, // STORE node
    { pattern: 'fs.writeFile(sensitivePath, *)',       critical: false },
  ],
  [SinkType.NETWORK_EXFIL]: [
    { pattern: 'fetch(externalUrl, { body: tainted })', critical: false },
    { pattern: 'axios.post(externalUrl, tainted)',      critical: false },
    { pattern: 'http.request({ host: external })',      critical: false },
  ],
  [SinkType.DYNAMIC_REQUIRE]: [
    { pattern: 'require(variable)',                    critical: true },
    { pattern: 'import(variable)',                     critical: true },
  ],
}

interface SinkPattern {
  pattern: string
  critical: boolean
}

/**
 * Sensitive paths for FILE_WRITE_SENSITIVE detection.
 * Writes to these paths create STORE nodes for cross-session tracking.
 */
export const SENSITIVE_WRITE_PATHS = [
  /\~\/\.claude\//,
  /\~\/\.ssh\//,
  /\~\/\.aws\//,
  /\~\/\.gitconfig/,
  /\.env$/,
  /package\.json$/,
  /settings\.json$/,
  /\.config\.(js|ts|json)$/,
  /credentials$/,
]
