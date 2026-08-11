# Artifact Contracts

## Contents

1. Artifact sequence
2. Authority model
3. Dynamic runner handoff

## Artifact sequence

| File | Purpose |
|---|---|
| `00-scan-manifest.json` | Input hashes, scope, rule/model configuration |
| `01-workflow-ir.json` | Normalized nodes, edges, variables, capabilities and coverage gaps |
| `02-security-facts.json` | Immutable deterministic evidence |
| `03-semantic-inventory.json` | Business purpose, assets, boundaries and invariants |
| `04-rule-candidates.json` | Rule candidates linked to facts |
| `05-test-cluster.json` | Positive, negative, boundary and attack cases |
| `06-llm-adjudication.json` | Semantic applicability, counter-evidence and assumptions |
| `07-verification.json` | Reference validation and model decision policy |
| `08-findings.json` | Authoritative merged findings |
| `09-attack-surface.json` | Entry points, assets, capabilities and attack paths |
| `10-dynamic-test-plan.json` | Inert handoff for a future sandbox executor |
| `11-quality-gate.json` | CI decision, blocker/review IDs and waiver audit |
| `12-artifact-index.json` | SHA-256 and size for each emitted report artifact |
| `report.json`, `report.md` | Machine and human views |

Every JSON artifact includes `schema_version`, `scan_id`, `producer`, `producer_version`, `workflow_hash`, and `created_at`.

## Authority model

- The parser owns node, edge, variable and DSL-location facts.
- The rule engine owns deterministic facts, severity and `CONFIRMED` status.
- The model may add semantic context, assumptions, counter-evidence and candidates.
- The verifier rejects unknown node, rule, fact, finding or candidate references.
- The quality gate blocks only configured status/severity pairs and never deletes waived findings.
- Waivers require an approver, justification and unexpired timestamp; optional workflow hashes prevent reuse across changed DSL files.
- `report.json` is authoritative; Markdown must not introduce new findings.

## Dynamic runner handoff

`10-dynamic-test-plan.json` sets `execution_authorized` to false. A future runner must require explicit authorization and enforce a deny-by-default network, synthetic credentials, read-only fixtures, blocked real side effects, human approval for high-impact operations, and CPU/memory/time/token/iteration limits.
