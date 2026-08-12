# Workflow 静态安全扫描报告：document-indirect-injection

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`1bb0ace2209edaa159d1946c33cdb1c0dd22d162c105a929bd4f49b8f800f8bd`
- 节点/边：5 / 4
- Finding 数：11
- 覆盖缺口数：2（不计入 Finding）
- 严重等级：CRITICAL=2、HIGH=8、MEDIUM=1
- 证据状态：CONFIRMED=7、PROBABLE=4、COVERAGE_GAP=2
- 发布门禁：`FAIL`

## 关键攻击链

### CRITICAL · FLOW-010, FLOW-003, FLOW-005, LLM-003

攻击族：unexpected_code_execution, general_workflow_security

- 路径：`extract → llm → code`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-184aba591794, TC-ce28491db959, TC-373d7df36657, TC-3e66094f03cb

### CRITICAL · TOOL-004, TOOL-014

攻击族：general_workflow_security

- 路径：`code`
- 状态：`CONFIRMED, COVERAGE_GAP`
- 动态用例：TC-773182cd7b7b

### HIGH · FLOW-003, TOOL-008

攻击族：general_workflow_security

- 路径：`start → extract → llm → code`
- 状态：`CONFIRMED`
- 动态用例：TC-ce28491db959, TC-373d7df36657, TC-94ca80f76b03

### HIGH · LLM-001, LLM-002

攻击族：general_workflow_security

- 路径：`extract → llm`
- 状态：`PROBABLE`
- 动态用例：TC-2dc7904932bf

### HIGH · LLM-005, LLM-006, OUT-006, LLM-008, TOOL-002

攻击族：general_workflow_security

- 路径：`llm → code`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-a1c03c7b8334, TC-966222522187, TC-e03dd7db65d1

## Findings

### [CRITICAL] FLOW-010 · 外部不可信内容经模型到代码执行

外部或检索内容可经模型输出进入代码/命令执行节点。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`extract → llm → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-42ae491c2207`
- 建议动态测试：`external_content_to_code_execution`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] TOOL-004 · 命令或代码注入风险

动态变量可到达命令、代码或脚本执行能力。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-e24a1cdc6ec9`
- 建议动态测试：`command_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → extract → llm → code`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-5b0ea4b71887`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`extract → llm → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-b21d3eac38ed`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-005 · 间接 Prompt Injection 工具链

上传文档或提取内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`extract → llm → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-d2850d089b18`, `FACT-eba884be669b`
- 根因指纹：`ROOT-dc76187ddda0`
- 关联规则（不重复计数）：LLM-003
- 建议动态测试：`rag_to_tool_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] LLM-001 · 不可信输入进入高权限 Prompt

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`extract → llm`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-43985ba8c52b`, `FACT-b907ad0fc2fb`
- 根因指纹：`ROOT-d7fbada66d67`
- 关联规则（不重复计数）：LLM-002
- 建议动态测试：`direct_or_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → code`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-6f86df1426e2`, `FACT-8bf0bfbf5771`, `FACT-35ca64adbbab`
- 根因指纹：`ROOT-f1c6fd71f83c`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-008 · 高影响决策无确定性复核

LLM 输出可触发高影响操作，路径中缺少确定性复核证据。

- 状态：`PROBABLE`；置信度：0.88
- 节点：`llm → code`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-31989e78bdb0`
- 建议动态测试：`high_impact_model_decision`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] TOOL-002 · 高危工具参数由模型控制

高影响工具的安全敏感参数由模型或上游变量控制。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → code`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-23c595965581`
- 建议动态测试：`model_controlled_tool_argument`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-008 · 高影响操作缺少必经审批

高影响工具存在不经过审批节点的可达路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → extract → llm → code`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-f57033d43c21`
- 建议动态测试：`high_impact_action_approval`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-014 · 工具供应链或描述投毒风险

DSL 无法证明工具来源、版本完整性或定义变更审批。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-ad5e359aba8b`
- 缺失上下文：工具供应链与插件代码不在 DSL 中。
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-009 · 工具能力超出业务目的

高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-1694754d95ab`
- 缺失上下文：tool_business_purpose；allowed_operations
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-3cde63f04996`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

## 覆盖缺口

- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
