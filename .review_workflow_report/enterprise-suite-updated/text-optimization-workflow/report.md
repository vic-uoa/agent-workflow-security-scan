# Workflow 静态安全扫描报告：普通文本优化工作流

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`5f6bfdd6d6a8a6c22eac9d79218c6028b6f7ae7d4e10184a4b1e4bda22356beb`
- 节点/边：3 / 2
- Finding 数：2
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：MEDIUM=2
- 证据状态：CONFIRMED=1、OBSERVED=1、COVERAGE_GAP=1
- 发布门禁：`REVIEW`

## 关键攻击链

### MEDIUM · LLM-001, IN-007, IN-009, LLM-002

攻击族：general_workflow_security

- 路径：`start → llm`
- 状态：`OBSERVED`
- 动态用例：TC-c6881422fe4f

## Findings

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 inputStr 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-a3b727da46b4`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [MEDIUM] LLM-001 · 不可信输入进入高权限 Prompt

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`OBSERVED`；置信度：0.90
- 节点：`start → llm`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`
- 证据：`FACT-a5f0d2be15e6`, `FACT-d095317c7327`, `FACT-11309d7a66f1`, `FACT-334bb61249e3`
- 根因指纹：`ROOT-29320d7aa50c`
- 关联规则（不重复计数）：IN-007, IN-009, LLM-002
- 建议动态测试：`direct_or_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

### [LOW] IN-004 · 未声明输入规范化

DSL 未声明输入解码和 Unicode 规范化控制。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-d4a60448cde7`
- 缺失上下文：输入规范化可能由平台统一实现，DSL 无法验证。
- 建议动态测试：`encoding_unicode_smuggling`（本次未执行）
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

## 覆盖缺口

- `IN-004`：DSL 未声明输入解码和 Unicode 规范化控制。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
