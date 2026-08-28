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

Sensitive-data rules use typed evidence rather than a boolean keyword flag:

- `credential_literal`: a credential-shaped literal outside examples, placeholders and security documentation;
- `sensitive_field_name`: a field or schema name only; this is not a live asset;
- `runtime_user_data` / `environment_value`: a runtime value with explicit type or data-classification evidence;
- `retrieved_business_data`: knowledge data with explicit classification, or lower-confidence inference from asset metadata;
- `example_content`, `placeholder`, `security_instruction`: inert contexts excluded from high-severity egress chains.

Sink capability is also typed. `NETWORK_WRITE` and `MESSAGE_SEND` cross an external boundary. Dify `end` is an `API_RESPONSE` to the workflow caller and `answer` is `HUMAN_OUTPUT` to the current user; neither is attacker-observable unless the DSL explicitly declares public, anonymous or untrusted audience. Unknown output audience is a coverage gap, not confirmed exfiltration.

Composite rules such as `FLOW-009` are proof obligations, not unions of weak matches. Every required fact must be satisfied and status is bounded by the weakest asset/precondition evidence. Field-name and contextual-credential candidates remain reviewable evidence but cannot form `FLOW-009`. Only a verified mandatory redaction/DLP control that intercepts every typed data path yields `MITIGATED`; a generic flag or unverified self-declaration does not suppress the active risk.

Negative contexts use an evidence ladder rather than absolute exclusion: placeholders and generic assignments in explicitly labelled examples are inert; provider-specific token shapes, unlabelled code blocks and concrete values adjacent to security instructions are `CANDIDATE`; literals outside those contexts and Dify-native `secret/password/credential/token` value types are typed assets. Prompt-boundary impact is raised when model output enters conditions, machine consumption or automated decisions even when no tool node exists.

Machine consumption includes more than tools. `LLM → JSON/regex parser code → End/condition/tool` is a typed integrity path when the code interprets model text rather than merely carrying it as an opaque string. Fixed code is not automatically a validation control: it must enforce a strict schema or allowlist, reject duplicate/unknown values and fail closed. Producer and consumer types are compared when both sides declare a contract; an incompatible declared pair is confirmed evidence, while an unknown type on either side is not a mismatch.

Control flow also includes derived control data. `untrusted text → parser output → condition` is eligible for routing-integrity analysis when variable references prove the data path. A branch-selected LLM directly entering another branch-selected LLM is only a structural candidate until intentional multi-stage review is excluded; node titles are explanatory context, not proof. Model endpoints, caller authentication and downstream automation that are absent from an exported DSL remain deployment coverage gaps and never prove external disclosure by themselves.

Every rule has an ID, base severity, detectability class, standard mappings, evidence, remediation, and optional dynamic test type. The executable metadata is in `rules/core-rules.yml`; evaluators are in `scripts/agent_workflow_scan/engine.py`.

`rules/dify-dsl-bindings.yml` additionally binds every catalog rule, exactly once, to native Dify node types and exported DSL fields. It also lists facts that live only in deployment configuration, plugin registries or runtime policy. Catalog loading fails if a rule is missing, duplicated or unknown in this binding file. Candidate artifacts carry this binding so reviewers can distinguish native DSL evidence from missing runtime context.

## Evidence states

- `CONFIRMED`: deterministic DSL/config/path evidence exists.
- `OBSERVED`: a deterministic DSL property exists, but exploitability or business impact has not been demonstrated.
- `PROBABLE`: the path is proven but semantic or runtime assumptions remain.
- `CANDIDATE`: semantic hypothesis requiring validation.
- `COVERAGE_GAP`: the required fact is absent from DSL.
- `MITIGATED`: an effective mandatory control blocks the path.

Potential impact, evidence status and release-gate effect are calculated separately. By default LOW/INFO observations remain advisory; REVIEW requires MEDIUM-or-higher confirmed/probable/observed/candidate/coverage evidence, while FAIL requires a confirmed HIGH/CRITICAL item.

An LLM cannot create `CONFIRMED`, overwrite facts, or cite an unknown ID.

The catalog assigns every rule to exactly one remediation-oriented `control_domain`. The scanner first correlates aliases, then forms one user-facing risk item per responsible node, control domain and evidence class. Preserve underlying rules, messages and path variants in the evidence layer; do not count them as separate vulnerabilities.

Do not collapse unlike controls merely because they share a node. Authorization, code/query execution safety, egress, data protection, structured contracts, resilience, supply chain and Agent governance can require different owners and acceptance tests.

## Rule families

- `FLOW-001..016`: graph integrity, taint paths, injection/exfiltration chains, cross-agent trust, cascading failures, type contracts and derived routing integrity.
- `IN-001..009`: types, bounds, file constraints, normalization, sensitive input, persistence, direct injection.
- `LLM-001..012`: instruction hierarchy, context trust, tool/code parser control, schema, authorization, budgets, fallback, prompt leakage and provider-boundary coverage.
- `TOOL-001..017`: capability, parameter control, SSRF, command/SQL/path injection, authorization, exfiltration, approval, secrets, schemas, timeouts, supply chain.
- `OUT-001..011`: output schema, disclosure, rich text, links, web exfiltration, human trust, citations, fallback and downstream-consumer coverage.
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
4. Add or update the rule's unique entry in `rules/dify-dsl-bindings.yml`.
5. Emit a Fact before a Finding and preserve DSL pointers.
6. Add positive, negative, mitigated, coverage-gap, and official-Dify-contract fixtures.
7. Map a safe dynamic test type when runtime confirmation is needed.
