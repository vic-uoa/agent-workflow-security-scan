# Rule Catalog

## Contents

1. Matching model
2. Evidence states
3. Rule families
4. Runtime boundaries
5. Adding a rule

## Matching model

Rules are not keyword findings. A rule may use keywords only to classify a candidate capability. A finding is produced from one or more of:

- an exact DSL field/configuration predicate;
- a variable binding from a producer to a consumer;
- a taint path from an untrusted or sensitive source to a sink;
- a graph path that bypasses mandatory validation or approval;
- a registered tool capability and parameter controllability;
- a schema-constrained semantic assertion with evidence references.

Security findings use a four-part applicability gate: relevant capability, reachable data/control path, missing matching deterministic control, and plausible business impact. A missing hardening option without those conditions is either omitted or recorded as a coverage limitation, not promoted to a vulnerability.

In particular:

- an external read-only tool is a content source, not automatically a dangerous sink;
- fixed sandbox code receiving variables as function data is not command injection;
- a high-consequence action needs a mandatory action gate, but that gate may be deterministic authorization, object-level policy, parameter constraints, or business-required human confirmation;
- ordinary text LLM, static single-dataset RAG, and human-readable output do not inherit controls meant for autonomous, privileged, regulated, or machine-consumed paths.

Every rule has an ID, base severity, detectability class, standard mappings, evidence, remediation, and optional dynamic test type. The executable metadata is in `rules/core-rules.yml`; evaluators are in `scripts/agent_workflow_scan/engine.py`.

## Evidence states

- `CONFIRMED`: deterministic DSL/config/path evidence exists.
- `OBSERVED`: a deterministic DSL property exists, but exploitability or business impact has not been demonstrated.
- `PROBABLE`: the path is proven but semantic or runtime assumptions remain.
- `CANDIDATE`: semantic hypothesis requiring validation.
- `COVERAGE_GAP`: the required fact is absent from DSL.
- `MITIGATED`: an effective mandatory control blocks the path.

An LLM cannot create `CONFIRMED`, overwrite facts, or cite an unknown ID.

The catalog assigns every rule to exactly one remediation-oriented `control_domain`. The scanner first correlates aliases, then forms one user-facing risk item per responsible node, control domain and evidence class. Preserve underlying rules, messages and path variants in the evidence layer; do not count them as separate vulnerabilities.

Do not collapse unlike controls merely because they share a node. Authorization, code/query execution safety, egress, data protection, structured contracts, resilience, supply chain and Agent governance can require different owners and acceptance tests.

## Rule families

- `FLOW-001..013`: graph integrity, taint paths, injection/exfiltration chains, cross-agent trust, cascading failures, rogue-agent containment.
- `IN-001..009`: types, bounds, file constraints, normalization, sensitive input, persistence, direct injection.
- `LLM-001..011`: instruction hierarchy, context trust, tool control, schema, authorization, budgets, fallback, prompt leakage.
- `TOOL-001..017`: capability, parameter control, SSRF, command/SQL/path injection, authorization, exfiltration, approval, secrets, schemas, timeouts, supply chain.
- `OUT-001..010`: output schema, disclosure, rich text, links, web exfiltration, human trust, citations, fallback.
- `KB-001..012`: dataset scope, tenant filters, retrieval thresholds, indirect injection, exfiltration, memory poisoning, provenance, runtime gaps.

Primary mappings include OWASP AISVS C2/C7/C8/C9/C10/C12, OWASP Agentic Top 10, OWASP LLMSVS, MITRE ATLAS, and NIST AI 100-2.

Tencent AI-Infra-Guard 的对照、静态化映射和归属信息见 [upstream-research.md](upstream-research.md)。
逐规则适用条件、攻击簇和排除条件见 [node-rule-matrix.md](node-rule-matrix.md)。

## Runtime boundaries

DSL-only scanning does not prove actual IAM, knowledge ACLs, plugin implementation, network egress, model behavior, or sandbox isolation. Represent these as missing context and dynamic test tasks instead of confirmed vulnerabilities.

## Adding a rule

1. Add metadata to `rules/core-rules.yml`.
2. Assign the rule to exactly one `control_domains` entry. Catalog loading fails on missing, duplicate or unknown assignments.
3. Add a deterministic or hybrid evaluator to `engine.py`.
4. Emit a Fact before a Finding and preserve DSL pointers.
5. Add positive, negative, mitigated, and coverage-gap fixtures.
6. Map a safe dynamic test type when runtime confirmation is needed.
