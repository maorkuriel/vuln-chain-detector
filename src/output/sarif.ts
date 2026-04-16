/**
 * SARIF 2.1.0 Output Emitter
 * Produces GitHub Code Scanning-compatible output.
 * One result per chain. Full chain path in codeFlows.
 */

import { ScoredChain, Severity } from '../scoring/index.js'

export function emitSarif(findings: ScoredChain[], toolVersion: string): object {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'vuln-chain-detector',
            version: toolVersion,
            informationUri: 'https://github.com/your-org/vuln-chain-detector',
            rules: buildRules(findings),
          },
        },
        results: findings.map(buildResult),
      },
    ],
  }
}

function buildRules(findings: ScoredChain[]): object[] {
  const seen = new Set<string>()
  return findings
    .map(f => f.matchedPattern ?? 'CHAIN-ZERO-DAY')
    .filter(id => {
      if (seen.has(id)) return false
      seen.add(id)
      return true
    })
    .map(id => ({
      id,
      name: id,
      shortDescription: { text: `Chained vulnerability: ${id}` },
      helpUri: `https://github.com/your-org/vuln-chain-detector/blob/main/patterns/${id}.yaml`,
      properties: {
        tags: ['security', 'chain-vulnerability'],
      },
    }))
}

function buildResult(finding: ScoredChain): object {
  const { chain, score, severity, isZeroDayCandidate, matchedPattern } = finding

  return {
    ruleId: matchedPattern ?? 'CHAIN-ZERO-DAY',
    level: severityToSarifLevel(severity),
    message: {
      text: buildMessage(finding),
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: chain.source.file },
          region: { startLine: chain.source.line, startColumn: chain.source.column },
        },
        logicalLocations: [{ name: 'source' }],
      },
    ],
    codeFlows: [
      {
        threadFlows: [
          {
            locations: chain.hops.map((hop, i) => ({
              location: {
                physicalLocation: {
                  artifactLocation: { uri: hop.file },
                  region: { startLine: hop.line, startColumn: hop.column },
                },
                message: { text: `Step ${i + 1}: ${hop.type} — ${hop.expression}` },
              },
            })),
          },
        ],
      },
    ],
    properties: {
      chainScore: score,
      sessionCrossing: chain.sessionCrossing,
      hopCount: chain.hopCount,
      isZeroDayCandidate,
      confidence: finding.confidence,
    },
  }
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case Severity.Critical: return 'error'
    case Severity.High: return 'error'
    case Severity.Medium: return 'warning'
    case Severity.Low: return 'note'
  }
}

function buildMessage(finding: ScoredChain): string {
  const { chain, score, severity, isZeroDayCandidate, matchedPattern } = finding
  const label = isZeroDayCandidate ? 'ZERO-DAY CANDIDATE' : `Pattern: ${matchedPattern}`

  return [
    `[${severity} ${score}] Chained vulnerability — ${label}`,
    `Hops: ${chain.hopCount} | Session-crossing: ${chain.sessionCrossing}`,
    `Chain: ${chain.hops.map(h => h.type).join(' → ')}`,
    `Source: ${chain.source.file}:${chain.source.line}`,
    `Sink: ${chain.sink.file}:${chain.sink.line}`,
  ].join('\n')
}
