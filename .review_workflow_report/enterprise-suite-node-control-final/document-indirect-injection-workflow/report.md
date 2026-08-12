# Workflow 静态安全扫描报告：document-indirect-injection

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`1bb0ace2209edaa159d1946c33cdb1c0dd22d162c105a929bd4f49b8f800f8bd`
- 节点/边：5 / 4
- 节点风险项：5
- 规则/路径证据实例：11（不重复计为风险项）
- 覆盖缺口数：2（不计入 Finding）
- 严重等级：CRITICAL=1、HIGH=4
- 证据状态：CONFIRMED=3、PROBABLE=2、COVERAGE_GAP=2
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：11
- 类型分布：negative=11
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### CRITICAL · FLOW-010, FLOW-005, LLM-003, FLOW-003

攻击族：general_workflow_security

- 路径：`extract → llm → code`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-f9a5d04ecfdc, TC-f59a4a22bce9, TC-1afdb606ab5a, TC-68bf63ab9853, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40

### CRITICAL · TOOL-004, TOOL-011, TOOL-014

攻击族：general_workflow_security

- 路径：`code`
- 状态：`CONFIRMED, PROBABLE, COVERAGE_GAP`
- 建议测试用例（未执行）：TC-f9a5d04ecfdc, TC-f59a4a22bce9, TC-4e247f684615

### HIGH · TOOL-008

攻击族：general_workflow_security

- 路径：`start → extract → llm → code`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40

### HIGH · LLM-001, LLM-002

攻击族：general_workflow_security

- 路径：`extract → llm`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-c583114b0456, TC-62360fa03f25

### HIGH · LLM-005, LLM-006, OUT-006, TOOL-002

攻击族：general_workflow_security

- 路径：`llm → code`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-4e247f684615, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40

## 节点风险项

### 节点 `code` · 执行动作脚本

节点类型：`CODE`；风险项：3；最高等级：`CRITICAL`

#### [CRITICAL] execution_boundary · 执行动作脚本：代码、命令或查询执行边界不足

责任节点“执行动作脚本”在“代码、命令或查询执行边界不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`code`；路径变体：2
- 合并证据实例：2
- 规则映射：TOOL-004, FLOW-010
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-e24a1cdc6ec9`, `FACT-42ae491c2207`
- 风险项指纹：`RISK-f37959ca21e1`
- 建议动态测试：`command_injection`, `external_content_to_code_execution`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] structured_data_contract · 执行动作脚本：结构化数据契约不足

责任节点“执行动作脚本”在“结构化数据契约不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm → code`；路径变体：2
- 合并证据实例：2
- 规则映射：LLM-005, TOOL-011, LLM-006, OUT-006
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/2`
- 证据：`FACT-3cde63f04996`, `FACT-6f86df1426e2`, `FACT-8bf0bfbf5771`, `FACT-35ca64adbbab`
- 风险项指纹：`RISK-c776462c48ad`
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

#### [HIGH] action_authorization · 执行动作脚本：高影响动作授权控制不足

责任节点“执行动作脚本”在“高影响动作授权控制不足”方面存在 5 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm → code`；路径变体：3
- 合并证据实例：5
- 规则映射：TOOL-002, TOOL-008, FLOW-003, LLM-008
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`
- 证据：`FACT-23c595965581`, `FACT-f57033d43c21`, `FACT-5b0ea4b71887`, `FACT-b21d3eac38ed`, `FACT-31989e78bdb0`
- 风险项指纹：`RISK-72beb5f3940c`
- 建议动态测试：`model_controlled_tool_argument`, `high_impact_action_approval`, `source_to_high_impact_sink`, `high_impact_model_decision`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `llm` · 文档处理 Agent

节点类型：`LLM`；风险项：2；最高等级：`HIGH`

#### [HIGH] untrusted_content_boundary · 文档处理 Agent：外部内容信任边界不足

上传文档或提取内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 代表路径：`extract → llm → code`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-005, LLM-003
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-d2850d089b18`, `FACT-eba884be669b`
- 风险项指纹：`RISK-318279210f4f`
- 建议动态测试：`rag_to_tool_injection`, `indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] instruction_boundary · 文档处理 Agent：模型指令与数据边界不足

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.90
- 代表路径：`extract → llm`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-001, LLM-002
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-43985ba8c52b`, `FACT-b907ad0fc2fb`
- 风险项指纹：`RISK-59724d4c5b14`
- 建议动态测试：`direct_or_indirect_prompt_injection`, `instruction_data_boundary`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

## 覆盖缺口

- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
