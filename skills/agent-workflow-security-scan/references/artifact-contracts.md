# Artifact Contracts

## Contents

1. Artifact sequence
2. Authority model
3. Dynamic runner handoff

## Artifact sequence

Workflow IR、事实、规则候选、输入簇、Finding、攻击面、沙盒计划、门禁和引用校验均是扫描进程内的瞬态对象。它们必须完成既有确定性校验后才可用于构建页面，但不得作为文件落盘。

唯一持久化产物为：

| 文件 | 用途 |
|---|---|
| `<workflow>/<workflow>-安全扫描报告.html` | 自包含的人工安全报告；包含结论、风险详情、完整 Workflow 图及高亮的逻辑链图 |

报告目录以输入 DSL 的文件名（不含扩展名）命名；HTML 内嵌 SVG 和全部样式/筛选逻辑，不依赖网络或额外资源。

## Authority model

- The parser owns node, edge, variable and DSL-location facts.
- The rule engine owns deterministic facts, severity and `CONFIRMED` status.
- The deterministic cluster builder owns the user-seed copy, minimum positive/negative/boundary coverage and lineage.
- The optional model advisor may add inert test proposals and non-authoritative wording only.
- Unexecuted test cases cannot alter Finding status, severity or the quality gate.
- Planned coverage means a case exists; route-satisfiable coverage means its graph path and statically solvable predicates are satisfied; executed coverage requires sandbox evidence. Never collapse these metrics.
- A test-to-path mapping requires an exact Finding ID, target node and matching route variant. A shared rule ID is not sufficient.
- Assessment seed files use `confirmed_by_user: true` for the user's seed/oracle confirmation and `confirmed_dsl_sha256` as scanner-managed integrity metadata. Users do not confirm the hash; a mismatch still stops the scan before rule execution.
- Finding applicability, status, confidence, severity and the quality gate are determined without model voting.
- The verifier rejects unknown deterministic node, rule, fact or Finding references and invalid model-proposed test references.
- Root-cause aggregation must preserve every raw matched rule ID as either a primary or `related_rule_ids` mapping.
- The user-facing risk identity is `(anchor_node_id, control_domain, evidence_class)`. `instance_summaries` and `path_variants` preserve the underlying rule/path evidence without increasing the risk-item count.
- Different control domains on the same node remain separate because they require different owners, controls or verification. Attack paths remain a non-additive view.
- The quality gate blocks only configured status/severity pairs and never deletes waived findings.
- Waivers require an approver, justification and unexpired timestamp; optional workflow hashes prevent reuse across changed DSL files.
- HTML 报告只能呈现内存中已完成确定性校验的 Finding 与攻击路径，不得引入新风险项或新路径。

## Dynamic runner handoff

`10-dynamic-test-plan.json` sets `execution_authorized` to false. A future runner must require explicit test authorization and enforce a deny-by-default network, synthetic credentials, read-only fixtures, mocked or blocked real side effects, and CPU/memory/time/token/iteration limits. Human confirmation is required only when the test specifically evaluates a business consent step; it is not a universal substitute for deterministic authorization.
