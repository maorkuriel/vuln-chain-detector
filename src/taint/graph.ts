/**
 * Taint Graph
 * Represents data flow from sources through transforms to sinks.
 * Cross-session flows are tracked via STORED_FLOW edges.
 */

import { SourceNode, SourceType } from '../sources/index.js'
import { SinkNode, SinkType } from '../sinks/index.js'

export enum NodeType {
  SOURCE = 'SOURCE',
  SANITIZE = 'SANITIZE',
  PASSTHROUGH = 'PASSTHROUGH',
  SINK = 'SINK',
  STORE = 'STORE',   // writes tainted data to persistent storage
  LOAD = 'LOAD',     // reads from a path registered as STORE
}

export enum EdgeType {
  DIRECT_FLOW = 'DIRECT_FLOW',         // value passed directly
  TRANSFORM_FLOW = 'TRANSFORM_FLOW',   // modified but taint preserved
  STORED_FLOW = 'STORED_FLOW',         // written to storage; read later (cross-session)
  ENV_FLOW = 'ENV_FLOW',               // set as env var; read in different process
  RETURN_FLOW = 'RETURN_FLOW',         // returned from function
  CALL_FLOW = 'CALL_FLOW',             // passed as function argument
}

export interface TaintNode {
  id: string                           // unique: file:line:col
  type: NodeType
  file: string
  line: number
  column: number
  expression: string                   // original code expression
  session?: 'A' | 'B'                 // for cross-session nodes
  storePath?: string                   // for STORE/LOAD nodes: the file path
  source?: SourceNode
  sink?: SinkNode
}

export interface TaintEdge {
  from: string                         // node id
  to: string                           // node id
  type: EdgeType
  crossSession: boolean                // true for STORED_FLOW across session boundary
}

export class TaintGraph {
  private nodes: Map<string, TaintNode> = new Map()
  private edges: TaintEdge[] = []
  private storeRegistry: Map<string, TaintNode> = new Map() // path → STORE node

  addNode(node: TaintNode): void {
    this.nodes.set(node.id, node)

    if (node.type === NodeType.STORE && node.storePath) {
      this.storeRegistry.set(node.storePath, node)
    }
  }

  addEdge(edge: TaintEdge): void {
    this.edges.push(edge)
  }

  /**
   * When a LOAD node is added, check if its path matches any registered STORE.
   * If yes, create a STORED_FLOW edge connecting them.
   */
  resolveStoredFlows(): void {
    for (const [nodeId, node] of this.nodes) {
      if (node.type === NodeType.LOAD && node.storePath) {
        const storeNode = this.storeRegistry.get(node.storePath)
        if (storeNode) {
          this.addEdge({
            from: storeNode.id,
            to: node.id,
            type: EdgeType.STORED_FLOW,
            crossSession: true,
          })
        }
      }
    }
  }

  /**
   * Find all chains from SOURCE nodes to SINK nodes.
   * A valid chain has no SANITIZE node in the path.
   */
  findChains(): Chain[] {
    const chains: Chain[] = []

    for (const [nodeId, node] of this.nodes) {
      if (node.type === NodeType.SOURCE) {
        this.dfs(node, [], new Set(), chains)
      }
    }

    return this.deduplicateChains(chains)
  }

  private dfs(
    current: TaintNode,
    path: TaintNode[],
    visited: Set<string>,
    chains: Chain[]
  ): void {
    if (visited.has(current.id)) return
    visited.add(current.id)

    const newPath = [...path, current]

    if (current.type === NodeType.SANITIZE) {
      return // taint broken — do not continue
    }

    if (current.type === NodeType.SINK && newPath.length > 1) {
      // Valid chain found (must have at least source + sink)
      chains.push(this.buildChain(newPath))
      return
    }

    const outEdges = this.edges.filter(e => e.from === current.id)
    for (const edge of outEdges) {
      const nextNode = this.nodes.get(edge.to)
      if (nextNode) {
        this.dfs(nextNode, newPath, new Set(visited), chains)
      }
    }
  }

  private buildChain(path: TaintNode[]): Chain {
    const source = path[0]
    const sink = path[path.length - 1]

    const sessionCrossing = this.edges.some(
      e => e.type === EdgeType.STORED_FLOW && e.crossSession &&
        path.some(n => n.id === e.from) &&
        path.some(n => n.id === e.to)
    )

    return {
      id: this.hashChain(path),
      source,
      sink,
      hops: path,
      sessionCrossing,
      hopCount: path.length,
    }
  }

  private hashChain(path: TaintNode[]): string {
    const key = path.map(n => n.id).join('→')
    return Buffer.from(key).toString('base64').slice(0, 12)
  }

  private deduplicateChains(chains: Chain[]): Chain[] {
    // Two chains are the same if they share source and terminal sink
    const seen = new Map<string, Chain>()
    for (const chain of chains) {
      const key = `${chain.source.id}→${chain.sink.id}`
      if (!seen.has(key)) {
        seen.set(key, chain)
      }
    }
    return Array.from(seen.values())
  }
}

export interface Chain {
  id: string
  source: TaintNode
  sink: TaintNode
  hops: TaintNode[]
  sessionCrossing: boolean
  hopCount: number
}
