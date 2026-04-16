# Chain Scoring

## Philosophy

Score the chain as a unit, not the individual nodes. A single unsanitized env var may be CVSS 4.0 alone. A 3-hop chain ending at credential exfiltration with no user interaction is Critical 9.4.

Scoring is modeled on CVSS 3.1 but extended for chain-specific properties.

---

## Base Score Calculation

### Step 1: Sink Severity (terminal node)

| Terminal Sink Type | Base Score |
|---|---|
| OS command execution | 8.0 |
| Credential / secret exfiltration | 8.5 |
| Arbitrary file write to sensitive path | 7.5 |
| Code eval / dynamic require | 8.0 |
| Network exfiltration | 7.0 |
| Persistence mechanism only | 6.0 |

### Step 2: Chain Multipliers

Apply all that match:

| Property | Multiplier | Condition |
|---|---|---|
| Session-crossing flow | ×1.5 | Chain contains at least one STORED_FLOW edge |
| No user interaction | ×1.3 | No manual trigger required at any hop |
| CI/CD context | ×1.2 | Project has `.github/`, `.gitlab-ci.yml`, Dockerfile, etc. |
| Exfiltration at terminal node | ×1.4 | Last node is network POST or file write with secrets |
| Sandbox bypassed | ×1.25 | Project has allowUnsandboxedCommands or equivalent fail-open |
| Privilege escalation | ×1.3 | Chain crosses privilege boundary (user → root, user → service account) |

**Formula:** `chain_score = base_score × PRODUCT(applicable_multipliers)`  
Cap at 10.0.

### Step 3: Hop Penalty / Bonus

| Chain Length | Adjustment |
|---|---|
| 2 hops | −0.5 (simpler chain) |
| 3 hops | ±0 (baseline) |
| 4 hops | +0.3 |
| 5+ hops | +0.5 |

More hops = harder to detect and more sophisticated = higher severity for zero-day candidates.

---

## Severity Tiers

| Score | Tier | Action |
|---|---|---|
| 9.0–10.0 | Critical | Block merge, immediate triage, auto-create P0 Jira |
| 7.0–8.9 | High | Flag in PR review, create P1 Jira |
| 4.0–6.9 | Medium | Add to backlog, document in findings |
| 1.0–3.9 | Low | Log only |

---

## Example Scoring: CVE-2026-35020/22 Chain

```
Terminal sink: Credential exfiltration        → base 8.5
Session-crossing STORED_FLOW                  → ×1.5
No user interaction required                  → ×1.3
CI/CD context present (.github/)              → ×1.2
Exfiltration at terminal node                 → ×1.4
Sandbox fail-open (allowUnsandboxedCommands)  → ×1.25

chain_score = 8.5 × 1.5 × 1.3 × 1.2 × 1.4 × 1.25
            = 8.5 × 4.095
            = 34.8 → capped at 10.0

Tier: Critical
```

---

## Zero-Day Signal Properties

A chain is flagged as a **zero-day candidate** (no matching CVE) if:

1. Score ≥ 7.0
2. Chain length ≥ 3
3. No matching pattern in the pattern library
4. Session-crossing flow present
5. No SANITIZE node anywhere in the path

These are the chains that represent novel attack paths — structurally similar to known CVEs but in new code or new combinations.

---

## Deduplication

Two chains are the same if they share:
- Same SOURCE node (file:line)
- Same terminal SINK node (file:line)
- Same STORE paths (if cross-session)

Different intermediate paths between the same source and sink are reported as one finding with a note that multiple paths exist (increases confidence, not severity).

---

## Confidence Score

Separate from severity. Tracks how certain the engine is about the finding.

| Factor | Confidence Boost |
|---|---|
| Exact pattern library match | +40 |
| All edges are DIRECT_FLOW (no dynamic) | +20 |
| Chain confirmed by unit test fixture | +30 |
| Dynamic property access in chain | −20 |
| Unresolved import in call graph | −15 |
| Pattern is structural match only (no CVE ref) | −10 |

Findings below confidence 40 are "Low Confidence" — useful for zero-day candidates but require manual review before escalation.
