/**
 * Source node definitions.
 * A SOURCE is where untrusted data enters the program.
 * All data from these locations is marked as tainted.
 */

export enum SourceType {
  ENV_VAR = 'ENV_VAR',
  CLI_ARG = 'CLI_ARG',
  FILE_READ = 'FILE_READ',
  CONFIG_LOAD = 'CONFIG_LOAD',   // loaded from a registered STORE path
  HTTP_INPUT = 'HTTP_INPUT',
  FILE_PATH = 'FILE_PATH',       // filename supplied by attacker
}

export interface SourceNode {
  type: SourceType
  file: string
  line: number
  column: number
  identifier: string             // variable name or expression that holds tainted data
  raw: string                    // original source code expression
}

/**
 * AST patterns that identify source nodes.
 * Each entry maps to a tree-sitter query or Babel AST visitor pattern.
 */
export const SOURCE_PATTERNS: Record<SourceType, string[]> = {
  [SourceType.ENV_VAR]: [
    'process.env.*',
    'process.env[*]',
  ],
  [SourceType.CLI_ARG]: [
    'process.argv[*]',
    'yargs.argv.*',
    'commander.opts().*',
    'program.opts().*',
  ],
  [SourceType.FILE_READ]: [
    'fs.readFileSync(*)',
    'fs.readFile(*)',
    'await fs.promises.readFile(*)',
  ],
  [SourceType.CONFIG_LOAD]: [
    // Dynamically populated by StoreNodeDetector at scan time
    // Any path matching a registered STORE path becomes a CONFIG_LOAD source
  ],
  [SourceType.HTTP_INPUT]: [
    'req.body.*',
    'req.query.*',
    'req.params.*',
    'req.headers[*]',
    'ctx.request.body.*',
  ],
  [SourceType.FILE_PATH]: [
    // File paths passed as CLI args or function arguments
    // where the path string itself could contain shell metacharacters
  ],
}
