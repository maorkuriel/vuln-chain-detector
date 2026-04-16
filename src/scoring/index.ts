/**
 * Chain Scorer
 * Scores a discovered chain as a unit — not individual nodes.
 * See docs/chain-scoring.md for full methodology.
 */

import { Chain } from '../taint/graph.js'
import { SinkType } from '../sinks/index.js'
import { NodeType } from '../taint/graph.js'

export enum Severity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
}

export interface ScoredChain {
  chain: Chain
  score: number
  severity: Severity
  confidence: number
  isZeroDayCandidate: boolean
  matchedPattern?: string
  breakdown: ScoreBreakdown
}

export interface ScoreBreakdown {
  baseSinkScore: number
  multipliers: Record<string, number>
  hopAdjustment: number
  final: number
}

const SINK_BASE_SCORES: Record<SinkType, number> = {
  [SinkType.SHELL_EXEC]: 8.0,
  [SinkType.NETWORK_EXFIL]: 7.0,
  [SinkType.FILE_WRITE_SENSITIVE]: 7.5,
  [SinkType.CODE_EVAL]: 8.0,
  [SinkType.DYNAMIC_REQUIRE]: 8.0,
}

export function scoreChain(
  chain: Chain,
  context: ScanContext,
  matchedPattern?: string
): ScoredChain {
  const terminalSink = chain.sink.sink
  const baseSinkScore = terminalSink
    ? SINK_BASE_SCORES[terminalSink.type] ?? 6.0
    : 6.0

  const multipliers: Record<string, number> = {}

  if (chain.sessionCrossing) {
    multipliers['session_crossing'] = 1.5
  }

  if (!context.userInteractionRequired) {
    multipliers['no_user_interaction'] = 1.3
  }

  if (context.isCiCd) {
    multipliers['ci_cd_context'] = 1.2
  }

  if (terminalSink?.type === SinkType.NETWORK_EXFIL ||
      context.hasExfiltrationSink) {
    multipliers['exfiltration_terminal'] = 1.4
  }

  if (context.sandboxFailOpen) {
    multipliers['sandbox_fail_open'] = 1.25
  }

  const multiplierProduct = Object.values(multipliers).reduce((a, b) => a * b, 1.0)

  const hopAdjustment = getHopAdjustment(chain.hopCount)

  const rawScore = baseSinkScore * multiplierProduct + hopAdjustment
  const finalScore = Math.min(10.0, rawScore)

  const severity = getSeverityTier(finalScore)
  const confidence = calculateConfidence(chain, matchedPattern)
  const isZeroDayCandidate = !matchedPattern &&
    finalScore >= 7.0 &&
    chain.sessionCrossing &&
    confidence >= 40

  return {
    chain,
    score: Math.round(finalScore * 10) / 10,
    severity,
    confidence,
    isZeroDayCandidate,
    matchedPattern,
    breakdown: {
      baseSinkScore,
      multipliers,
      hopAdjustment,
      final: finalScore,
    },
  }
}

function getHopAdjustment(hopCount: number): number {
  if (hopCount <= 2) return -0.5
  if (hopCount === 3) return 0
  if (hopCount === 4) return 0.3
  return 0.5  // 5+
}

function getSeverityTier(score: number): Severity {
  if (score >= 9.0) return Severity.Critical
  if (score >= 7.0) return Severity.High
  if (score >= 4.0) return Severity.Medium
  return Severity.Low
}

function calculateConfidence(chain: Chain, matchedPattern?: string): number {
  let confidence = 50  // baseline

  if (matchedPattern) confidence += 40
  if (chain.sessionCrossing) confidence += 10   // well-understood mechanism

  // Penalize for dynamic/unresolved nodes
  const hasDynamicAccess = chain.hops.some(n =>
    n.expression.includes('[variable]') || n.expression.includes('*')
  )
  if (hasDynamicAccess) confidence -= 20

  return Math.max(0, Math.min(100, confidence))
}

export interface ScanContext {
  userInteractionRequired: boolean
  isCiCd: boolean
  sandboxFailOpen: boolean
  hasExfiltrationSink: boolean
}

export function detectScanContext(projectRoot: string): ScanContext {
  const fs = require('fs')
  const path = require('path')

  const isCiCd = [
    '.github',
    '.gitlab-ci.yml',
    'Jenkinsfile',
    '.circleci',
    'Dockerfile',
    '.travis.yml',
    'azure-pipelines.yml',
  ].some(f => fs.existsSync(path.join(projectRoot, f)))

  return {
    userInteractionRequired: false, // default: no user interaction (worst case)
    isCiCd,
    sandboxFailOpen: true,          // default: assume fail-open (conservative)
    hasExfiltrationSink: false,     // updated after chain analysis
  }
}
