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
| `03-semantic-inventory.json` | Deterministically derived purpose, assets, boundaries and invariants |
| `04-rule-candidates.json` | Root candidates plus every pre-aggregation raw rule match |
| `05-test-cluster.json` | Seed-derived positive, negative, boundary, metamorphic and rule-targeted cases with lineage |
| `06-model-advisory.json` | Whether the optional non-authoritative model advisor was enabled and its allowed uses |
| `07-verification.json` | Deterministic reference, aggregation, input-cluster and model-boundary validation |
| `08-findings.json` | Authoritative node/control-domain risk items with rule and path evidence instances |
| `09-attack-surface.json` | Entry points, assets, capabilities and attack paths |
| `attack-surface.md` | Human-readable tables for entry points, assets, trust boundaries, capabilities and attack chains |
| `10-dynamic-test-plan.json` | Inert handoff for a future sandbox executor |
| `11-quality-gate.json` | CI decision, blocker/review IDs and waiver audit |
| `12-artifact-index.json` | SHA-256 and size for each emitted report artifact |
| `report.json`, `report.md` | Machine report and primary human-facing security report |

Every JSON artifact includes `schema_version`, `scan_id`, `producer`, `producer_version`, `workflow_hash`, and `created_at`.

## Authority model

- The parser owns node, edge, variable and DSL-location facts.
- The rule engine owns deterministic facts, severity and `CONFIRMED` status.
- The deterministic cluster builder owns the user-seed copy, minimum positive/negative/boundary coverage and lineage.
- The optional model advisor may add inert test proposals and non-authoritative wording only.
- Unexecuted test cases cannot alter Finding status, severity or the quality gate.
- Assessment seed files use `confirmed_by_user: true` for the user's seed/oracle confirmation and `confirmed_dsl_sha256` as scanner-managed integrity metadata. Users do not confirm the hash; a mismatch still stops the scan before rule execution.
- Finding applicability, status, confidence, severity and the quality gate are determined without model voting.
- The verifier rejects unknown deterministic node, rule, fact or Finding references and invalid model-proposed test references.
- Root-cause aggregation must preserve every raw matched rule ID as either a primary or `related_rule_ids` mapping.
- The user-facing risk identity is `(anchor_node_id, control_domain, evidence_class)`. `instance_summaries` and `path_variants` preserve the underlying rule/path evidence without increasing the risk-item count.
- Different control domains on the same node remain separate because they require different owners, controls or verification. Attack paths remain a non-additive view.
- The quality gate blocks only configured status/severity pairs and never deletes waived findings.
- Waivers require an approver, justification and unexpired timestamp; optional workflow hashes prevent reuse across changed DSL files.
- `report.json` is authoritative; `report.md` and `attack-surface.md` must not introduce new findings or attack paths.

## Dynamic runner handoff

`10-dynamic-test-plan.json` sets `execution_authorized` to false. A future runner must require explicit test authorization and enforce a deny-by-default network, synthetic credentials, read-only fixtures, mocked or blocked real side effects, and CPU/memory/time/token/iteration limits. Human confirmation is required only when the test specifically evaluates a business consent step; it is not a universal substitute for deterministic authorization.
