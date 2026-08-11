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

Every rule has an ID, base severity, detectability class, standard mappings, evidence, remediation, and optional dynamic test type. The executable metadata is in `rules/core-rules.yml`; evaluators are in `scripts/agent_workflow_scan/engine.py`.

## Evidence states

- `CONFIRMED`: deterministic DSL/config/path evidence exists.
- `PROBABLE`: the path is proven but semantic or runtime assumptions remain.
- `CANDIDATE`: semantic hypothesis requiring validation.
- `COVERAGE_GAP`: the required fact is absent from DSL.
- `MITIGATED`: an effective mandatory control blocks the path.

An LLM cannot create `CONFIRMED`, overwrite facts, or cite an unknown ID.

## Rule families

- `FLOW-001..013`: graph integrity, taint paths, injection/exfiltration chains, cross-agent trust, cascading failures, rogue-agent containment.
- `IN-001..009`: types, bounds, file constraints, normalization, sensitive input, persistence, direct injection.
- `LLM-001..011`: instruction hierarchy, context trust, tool control, schema, authorization, budgets, fallback, prompt leakage.
- `TOOL-001..017`: capability, parameter control, SSRF, command/SQL/path injection, authorization, exfiltration, approval, secrets, schemas, timeouts, supply chain.
- `OUT-001..010`: output schema, disclosure, rich text, links, web exfiltration, human trust, citations, fallback.
- `KB-001..012`: dataset scope, tenant filters, retrieval thresholds, indirect injection, exfiltration, memory poisoning, provenance, runtime gaps.

Primary mappings include OWASP AISVS C2/C7/C8/C9/C10/C12, OWASP Agentic Top 10, OWASP LLMSVS, MITRE ATLAS, and NIST AI 100-2.

Tencent AI-Infra-Guard 的对照、静态化映射和归属信息见 [upstream-research.md](upstream-research.md)。

## Runtime boundaries

DSL-only scanning does not prove actual IAM, knowledge ACLs, plugin implementation, network egress, model behavior, or sandbox isolation. Represent these as missing context and dynamic test tasks instead of confirmed vulnerabilities.

## Adding a rule

1. Add metadata to `rules/core-rules.yml`.
2. Add a deterministic or hybrid evaluator to `engine.py`.
3. Emit a Fact before a Finding and preserve DSL pointers.
4. Add positive, negative, mitigated, and coverage-gap fixtures.
5. Map a safe dynamic test type when runtime confirmation is needed.
