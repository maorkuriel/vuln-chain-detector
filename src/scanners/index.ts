/**
 * Scanner Type Adapter Interface
 * Each scanner type implements this interface.
 * The TaintGraph merges nodes from all adapters before chain discovery.
 */

import { SourceNode } from '../sources/index.js'
import { SinkNode } from '../sinks/index.js'

export enum ScannerType {
  SAST = 'sast',
  SCA = 'sca',
  DAST = 'dast',
  IAST = 'iast',
  SECRETS = 'secrets',
  CONTAINER = 'container',
}

export interface StorePath {
  path: string
  file: string
  line: number
  taintOrigin?: string
}

export interface ScanTarget {
  rootDir: string
  files?: string[]
  httpEndpoints?: string[]  // for DAST
  dockerfiles?: string[]    // for Container
  manifestFiles?: string[]  // for IaC
}

export interface ScannerAdapter {
  type: ScannerType

  /**
   * Find all source nodes (untrusted data entry points) for this scanner type.
   */
  findSources(target: ScanTarget): Promise<SourceNode[]>

  /**
   * Find all sink nodes (dangerous execution points) for this scanner type.
   */
  findSinks(target: ScanTarget): Promise<SinkNode[]>

  /**
   * Find all paths where tainted data is written to persistent storage.
   * These become STORE nodes in the taint graph.
   */
  findStorePaths(target: ScanTarget): Promise<StorePath[]>
}

/**
 * Registry of all scanner adapters.
 * Add new adapters here as new scanner types are implemented.
 */
export const SCANNER_REGISTRY: Record<ScannerType, string> = {
  [ScannerType.SAST]:      'src/scanners/sast-adapter.ts',
  [ScannerType.SCA]:       'src/scanners/sca-adapter.ts',
  [ScannerType.DAST]:      'src/scanners/dast-adapter.ts',
  [ScannerType.IAST]:      'src/scanners/iast-adapter.ts',
  [ScannerType.SECRETS]:   'src/scanners/secrets-adapter.ts',
  [ScannerType.CONTAINER]: 'src/scanners/container-adapter.ts',
}

/**
 * Cross-scanner edge types.
 * These connect findings from different scanner types in the chain graph.
 */
export const CROSS_SCANNER_EDGES = [
  {
    from: ScannerType.SCA,
    to: ScannerType.SAST,
    description: 'Vulnerable dependency output reaches application code sink',
  },
  {
    from: ScannerType.DAST,
    to: ScannerType.SAST,
    description: 'HTTP input flows through application logic to OS exec',
  },
  {
    from: ScannerType.CONTAINER,
    to: ScannerType.SAST,
    description: 'Container ENV variable flows into application code source',
  },
  {
    from: ScannerType.SECRETS,
    to: ScannerType.SAST,
    description: 'Hardcoded secret flows from config into network exfil sink',
  },
]
