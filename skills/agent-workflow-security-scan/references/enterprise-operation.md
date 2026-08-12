# Enterprise Operation Contract

## Contents

1. Intended assurance
2. Evidence requirements
3. Internal DSL control annotations
4. CI quality gate
5. Waiver governance
6. Validation matrix

## Intended assurance

Use this scanner as a pre-release static architecture and data-flow gate for company-internal Dify workflows. It can prove DSL facts, unsafe parameter bindings, unguarded graph paths and missing declared controls. It cannot certify runtime model behavior, tool implementation, IAM enforcement, network policy, knowledge ACLs or sandbox isolation. A `PASS` means no unwaived blocking static finding under the selected baseline; it does not mean the workflow is vulnerability-free.

## Evidence requirements

- `CONFIRMED` requires a concrete field predicate, strict-schema failure, parameter binding, action route or graph path.
- `OBSERVED` records a deterministic DSL property when exploitability or business impact still requires runtime evidence.
- `PROBABLE` requires a proven structural path plus a clearly listed semantic/runtime precondition.
- `COVERAGE_GAP` identifies evidence that the DSL cannot supply.
- Keywords may classify a capability candidate but cannot establish an approval, validation or authorization control.
- A model may add context or downgrade a candidate; it cannot create deterministic facts or promote a finding to `CONFIRMED`.
- A generated input is a test hypothesis, not execution evidence. Do not use it to establish applicability, exploitability or mitigation.
- False-positive reduction must be lossless at rule-coverage level: retain raw matches, merge only aliases sharing the same root family and source/sink, and fail if a matched rule ID disappears from primary/related mappings.

## Internal DSL control annotations

When a control exists in the company platform but is otherwise invisible in exported Dify DSL, emit a machine-readable annotation during export instead of relying on a node title:

```yaml
security_control:
  type: validation       # validation | policy | guardrail | authorization | approval
  mandatory: true
  control_id: input-policy-v3
```

Use strict object schemas at tool, model and output boundaries:

```yaml
input_schema:
  type: object
  properties:
    resource_id: {type: string}
  required: [resource_id]
  additionalProperties: false
```

For high-impact tools, declare an execution-side authorization policy such as `authorization_policy`, `ownership_check`, `subject_binding`, `resource_binding`, `tenant_enforced`, `rbac` or `abac`. Authentication headers alone do not satisfy object-level authorization.

For Human Input nodes, retain action IDs in edge `sourceHandle` values. The scanner verifies that reject, cancel and unknown actions cannot reach high-impact tools.

## CI quality gate

The default gate is:

- `FAIL`: unwaived `CONFIRMED` finding with `CRITICAL` or `HIGH` severity.
- `REVIEW`: no blocker, but an `OBSERVED`, `PROBABLE` or `COVERAGE_GAP` remains.
- `PASS`: neither blocker nor review item remains.

Count node/control-domain remediation items, not rule aliases or path permutations. Store rule mappings in `related_rule_ids`, raw instances in `instance_summaries`, and alternate routes in `path_variants`. Coverage gaps and attack-chain counts are separate and never added to risk items.

Use `11-quality-gate.json` as the CI decision and `12-artifact-index.json` to verify report-package hashes. Do not derive CI status from the total finding count.

## Waiver governance

A waiver must include `waiver_id`, `workflow_hash`, `approver`, `justification` and a future `expires_at`. Scope it to a risk-item `finding_id`. A rule-level waiver is accepted only when the item contains that rule alone; it is rejected as ambiguous when other rules were aggregated into the same node/control-domain item. Waivers never delete findings. They only remove matching items from the gate and remain visible in JSON and Markdown.

## Validation matrix

| Fixture | Expected result | Security property |
|---|---|---|
| `safe-workflow.yml` | PASS / 0 findings | Baseline false-positive check |
| `approval-protected-workflow.yml` | PASS / 0 findings | Human approval dominates destructive action |
| `approval-bypass-workflow.yml` | FAIL / FLOW-006 | Reject branch reaches destructive action |
| `keyword-spoofed-control.yml` | FAIL / FLOW-003 + TOOL-008 | Security words do not create a control |
| `parameter-precision-workflow.yml` | PASS / no TOOL-003 or TOOL-017 | Dynamic body is not misclassified as dynamic URL |
| `review-only-workflow.yml` | REVIEW / LLM-009 + LLM-010 | Non-blocking runtime resilience gaps require human review |
| `non-strict-schema-workflow.yml` | FAIL / LLM-006 + TOOL-011 | Schema presence without closed properties is insufficient |
| `document-indirect-injection-workflow.yml` | FAIL / FLOW-005 + FLOW-010 | Uploaded document text is an untrusted content source |
| `tencent-inspired-workflow.yml` | FAIL | Composite injection, exfiltration, memory, agent and code-execution paths |
