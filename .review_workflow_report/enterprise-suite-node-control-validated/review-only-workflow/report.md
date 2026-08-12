# Workflow 静态安全扫描报告：review-only-llm

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`4d1f3d367ae97e7d28f6037990bc8defe24432b046f71c4875ffae58b3369f03`
- 节点/边：3 / 2
- 节点风险项：1
- 规则/路径证据实例：1（不重复计为风险项）
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：MEDIUM=1
- 证据状态：PROBABLE=1、COVERAGE_GAP=1
- 发布门禁：`REVIEW`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：1
- 类型分布：negative=1
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

未形成可展示的跨节点攻击链。

## 节点风险项

### 节点 `llm` · Bounded summarizer

节点类型：`LLM`；风险项：1；最高等级：`MEDIUM`

#### [MEDIUM] resilience_budget · Bounded summarizer：失败处理与资源预算不足

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 当前证据等级：`MEDIUM`；最大潜在等级：`MEDIUM`
- 代表路径：`llm`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-009
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-91101ff7dec6`
- 风险项指纹：`RISK-3830078f85df`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

## 覆盖缺口

- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
