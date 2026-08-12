# Workflow 静态安全扫描报告：tencent-inspired-risk-chain

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`b01ee8c4c8fd5f2b2451863af5da83de2a25473ec076b2c1a4ff70d2dd414997`
- 节点/边：10 / 11
- 节点风险项：33
- 规则/路径证据实例：74（不重复计为风险项）
- 覆盖缺口数：11（不计入 Finding）
- 严重等级：CRITICAL=3、HIGH=21、MEDIUM=9
- 证据状态：CONFIRMED=17、PROBABLE=16、COVERAGE_GAP=11
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：1
- 派生用例：54
- 类型分布：positive=1、boundary=1、metamorphic=1、negative=51
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### CRITICAL · TOOL-017, FLOW-005, KB-005, LLM-003

攻击族：web_exfiltration, general_workflow_security

- 路径：`kb → llm1 → llm2 → exfil`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-44a551d3ab04, TC-039fd8e43876, TC-a7e36782e2c4, TC-5cd80b69dc20, TC-71d25d8b3831, TC-ac2743a6eaad, TC-b931217e902a, TC-ef7d7f87e805, TC-9353ae97ab5e, TC-bd5cb3b31583

### CRITICAL · FLOW-010, FLOW-012

攻击族：general_workflow_security, cascading_failure

- 路径：`web → llm1 → llm2 → code`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-f9a5d04ecfdc, TC-f59a4a22bce9, TC-7eb63d893cbd, TC-b703da746ef3, TC-f99407e3734f, TC-2167fac66d7d, TC-c7507e538caa, TC-d07ff0763fe5, TC-10248fe71806, TC-d58137094ba6

### CRITICAL · FLOW-010, FLOW-003, FLOW-005, KB-005, LLM-003

攻击族：general_workflow_security

- 路径：`kb → llm1 → llm2 → code`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-f9a5d04ecfdc, TC-f59a4a22bce9, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40, TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-7e7ed9daaecd, TC-0b6955400112, TC-1729fbb8834d, TC-6318be2b6daa, TC-9c2ae64ea125, TC-024eaf41d95e, TC-0dbe056b06b5, TC-ac2743a6eaad, TC-b931217e902a, TC-ef7d7f87e805, TC-9353ae97ab5e, TC-bd5cb3b31583

### CRITICAL · TOOL-004, TOOL-013, TOOL-011, TOOL-014

攻击族：general_workflow_security, cascading_failure

- 路径：`code`
- 状态：`CONFIRMED, PROBABLE, COVERAGE_GAP`
- 建议测试用例（未执行）：TC-f9a5d04ecfdc, TC-f59a4a22bce9, TC-7eb63d893cbd, TC-b703da746ef3, TC-f99407e3734f, TC-2167fac66d7d, TC-c7507e538caa, TC-d07ff0763fe5, TC-10248fe71806, TC-d58137094ba6, TC-4e247f684615, TC-04000e9957cc

### CRITICAL · FLOW-009, KB-006, OUT-007

攻击族：web_exfiltration, general_workflow_security

- 路径：`kb → llm1 → llm2 → answer`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-5cd80b69dc20, TC-71d25d8b3831, TC-44a551d3ab04, TC-039fd8e43876, TC-c61e46135fae, TC-92e52f9b0792, TC-b9f471927f36, TC-29753e023629

### HIGH · TOOL-013, TOOL-015, TOOL-014

攻击族：cascading_failure, general_workflow_security

- 路径：`admin_tool`
- 状态：`PROBABLE, COVERAGE_GAP`
- 建议测试用例（未执行）：TC-f99407e3734f, TC-2167fac66d7d, TC-7eb63d893cbd, TC-b703da746ef3, TC-c7507e538caa, TC-d07ff0763fe5, TC-10248fe71806, TC-d58137094ba6, TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-7e7ed9daaecd, TC-0b6955400112, TC-1729fbb8834d, TC-6318be2b6daa, TC-9c2ae64ea125, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40, TC-024eaf41d95e, TC-0dbe056b06b5

### HIGH · FLOW-012

攻击族：cascading_failure

- 路径：`admin_tool → exfil`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-c7507e538caa, TC-d07ff0763fe5, TC-7eb63d893cbd, TC-b703da746ef3, TC-f99407e3734f, TC-2167fac66d7d, TC-10248fe71806, TC-d58137094ba6

### HIGH · FLOW-012

攻击族：cascading_failure

- 路径：`web → llm1 → llm2 → admin_tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-f99407e3734f, TC-2167fac66d7d, TC-7eb63d893cbd, TC-b703da746ef3, TC-c7507e538caa, TC-d07ff0763fe5, TC-10248fe71806, TC-d58137094ba6

### HIGH · OUT-009

攻击族：web_exfiltration

- 路径：`answer`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-5cd80b69dc20, TC-71d25d8b3831, TC-44a551d3ab04, TC-039fd8e43876

### HIGH · LLM-002, TOOL-012

攻击族：general_workflow_security

- 路径：`memory → llm2`
- 状态：`PROBABLE, CONFIRMED`
- 建议测试用例（未执行）：TC-0f3e3a19d35c, TC-c8a319682f87, TC-2d1cfadb15ea, TC-f558fb781e8e, TC-2bf0f6428d90, TC-bd5cb3b31583, TC-ac2743a6eaad, TC-b931217e902a, TC-ef7d7f87e805, TC-9353ae97ab5e

### HIGH · FLOW-003, FLOW-005, KB-005, LLM-003

攻击族：general_workflow_security

- 路径：`kb → llm1 → llm2 → admin_tool`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-7e7ed9daaecd, TC-0b6955400112, TC-1729fbb8834d, TC-6318be2b6daa, TC-9c2ae64ea125, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40, TC-024eaf41d95e, TC-0dbe056b06b5, TC-ac2743a6eaad, TC-b931217e902a, TC-ef7d7f87e805, TC-9353ae97ab5e, TC-bd5cb3b31583

### HIGH · TOOL-012

攻击族：general_workflow_security

- 路径：`web → llm1`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-ac2743a6eaad, TC-b931217e902a, TC-ef7d7f87e805, TC-9353ae97ab5e, TC-bd5cb3b31583

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → web`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-0dbe056b06b5, TC-024eaf41d95e, TC-7e7ed9daaecd, TC-0b6955400112, TC-1729fbb8834d, TC-6318be2b6daa, TC-9c2ae64ea125, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40

### HIGH · TOOL-003, TOOL-013, TOOL-011

攻击族：web_exfiltration, cascading_failure, general_workflow_security

- 路径：`exfil`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-44a551d3ab04, TC-039fd8e43876, TC-a7e36782e2c4, TC-5cd80b69dc20, TC-71d25d8b3831, TC-c7507e538caa, TC-d07ff0763fe5, TC-7eb63d893cbd, TC-b703da746ef3, TC-f99407e3734f, TC-2167fac66d7d, TC-10248fe71806, TC-d58137094ba6, TC-04000e9957cc, TC-4e247f684615

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → kb → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-024eaf41d95e, TC-0dbe056b06b5, TC-7e7ed9daaecd, TC-0b6955400112, TC-1729fbb8834d, TC-6318be2b6daa, TC-9c2ae64ea125, TC-475699625927, TC-d7e93005f5fd, TC-c3356616ca34, TC-70c9f7055d40

### HIGH · LLM-005, LLM-006, OUT-006

攻击族：general_workflow_security

- 路径：`llm2 → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-04000e9957cc, TC-4e247f684615

### HIGH · LLM-005, LLM-006, OUT-006

攻击族：general_workflow_security

- 路径：`llm1 → llm2 → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-04000e9957cc, TC-4e247f684615

### HIGH · IN-009

攻击族：general_workflow_security

- 路径：`start → llm1`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-c8a319682f87, TC-2d1cfadb15ea, TC-f558fb781e8e, TC-2bf0f6428d90, TC-0f3e3a19d35c

### HIGH · FLOW-013

攻击族：rogue_agent

- 路径：`start → llm1 → llm2 → admin_tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-3863a17b94fb

### HIGH · TOOL-003

攻击族：general_workflow_security

- 路径：`web`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-a7e36782e2c4, TC-44a551d3ab04, TC-039fd8e43876

## 节点风险项

### 节点 `answer` · 安全验证结果

节点类型：`OUTPUT`；风险项：3；最高等级：`CRITICAL`

#### [CRITICAL] egress_control · 安全验证结果：网络与输出外发控制不足

责任节点“安全验证结果”在“网络与输出外发控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`kb → llm1 → llm2 → answer`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-009, OUT-009
- DSL 位置：`/workflow/graph/nodes/9`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-b7bf9a442b48`, `FACT-0cbfb4cb25d7`
- 风险项指纹：`RISK-35591c45d098`
- 建议动态测试：`markdown_url_exfiltration`, `web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] data_protection · 安全验证结果：敏感数据保护控制不足

责任节点“安全验证结果”在“敏感数据保护控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.78
- 代表路径：`kb → llm1 → llm2 → answer`；路径变体：1
- 合并证据实例：2
- 规则映射：KB-006, FLOW-004
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/9`
- 证据：`FACT-28374567e86b`, `FACT-78537ae3650d`
- 风险项指纹：`RISK-2fd8eaa085bc`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [MEDIUM] output_safety · 安全验证结果：用户输出安全控制不足

责任节点“安全验证结果”在“用户输出安全控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`kb → llm1 → llm2 → answer`；路径变体：2
- 合并证据实例：3
- 规则映射：OUT-007, OUT-004, OUT-010
- DSL 位置：`/workflow/graph/nodes/9`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-5a4a7003a8b8`, `FACT-9f6c074eef19`, `FACT-d53997d341bc`
- 风险项指纹：`RISK-1668512415bc`
- 建议动态测试：`rich_text_injection`, `human_agent_trust_exploit`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### 节点 `code` · 动态代码执行

节点类型：`CODE`；风险项：4；最高等级：`CRITICAL`

#### [CRITICAL] execution_boundary · 动态代码执行：代码、命令或查询执行边界不足

责任节点“动态代码执行”在“代码、命令或查询执行边界不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`code`；路径变体：3
- 合并证据实例：3
- 规则映射：TOOL-004, FLOW-010
- DSL 位置：`/workflow/graph/nodes/8`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/2`
- 证据：`FACT-e24a1cdc6ec9`, `FACT-59b8803d622d`, `FACT-2b10472c7144`
- 风险项指纹：`RISK-f37959ca21e1`
- 建议动态测试：`command_injection`, `external_content_to_code_execution`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] resilience_budget · 动态代码执行：失败处理与资源预算不足

责任节点“动态代码执行”在“失败处理与资源预算不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`web → llm1 → llm2 → code`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-012, TOOL-013
- DSL 位置：`/workflow/graph/nodes/8`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-220cc318c481`, `FACT-21295edac0d7`
- 风险项指纹：`RISK-37df3bd64f0b`
- 建议动态测试：`tool_timeout`, `cascading_failure`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] structured_data_contract · 动态代码执行：结构化数据契约不足

责任节点“动态代码执行”在“结构化数据契约不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm1 → llm2 → code`；路径变体：3
- 合并证据实例：3
- 规则映射：LLM-005, TOOL-011, LLM-006, OUT-006
- DSL 位置：`/workflow/graph/nodes/8`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-3cde63f04996`, `FACT-54881f611493`, `FACT-8370183c7953`, `FACT-e83017039b3c`, `FACT-e5908eb802da`, `FACT-4daddda1dcdd`, `FACT-7c0b493e125f`
- 风险项指纹：`RISK-c776462c48ad`
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

#### [HIGH] action_authorization · 动态代码执行：高影响动作授权控制不足

责任节点“动态代码执行”在“高影响动作授权控制不足”方面存在 6 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm2 → code`；路径变体：4
- 合并证据实例：6
- 规则映射：TOOL-002, TOOL-008, FLOW-003, LLM-008
- DSL 位置：`/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/1`
- 证据：`FACT-2c8d768ad681`, `FACT-a2b9706db7dd`, `FACT-ffe205cb0b31`, `FACT-77f02bcfbb78`, `FACT-5327e9ed9634`, `FACT-371a0e0108d2`
- 风险项指纹：`RISK-72beb5f3940c`
- 建议动态测试：`model_controlled_tool_argument`, `high_impact_action_approval`, `source_to_high_impact_sink`, `high_impact_model_decision`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `exfil` · 外部 HTTP 写入

节点类型：`TOOL`；风险项：5；最高等级：`CRITICAL`

#### [CRITICAL] egress_control · 外部 HTTP 写入：网络与输出外发控制不足

责任节点“外部 HTTP 写入”在“网络与输出外发控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`kb → llm1 → llm2 → exfil`；路径变体：2
- 合并证据实例：3
- 规则映射：TOOL-017, TOOL-003, FLOW-009
- DSL 位置：`/workflow/graph/nodes/7`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-20af87f21fb4`, `FACT-860ad7d07c74`, `FACT-9433c0005638`
- 风险项指纹：`RISK-3ad5158441e2`
- 建议动态测试：`ssrf`, `web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] action_authorization · 外部 HTTP 写入：高影响动作授权控制不足

责任节点“外部 HTTP 写入”在“高影响动作授权控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`start → kb → exfil`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-003
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/7`
- 证据：`FACT-e52b6f3d0fc8`, `FACT-7bb959489e1c`
- 风险项指纹：`RISK-1b0949096404`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] resilience_budget · 外部 HTTP 写入：失败处理与资源预算不足

责任节点“外部 HTTP 写入”在“失败处理与资源预算不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`web → llm1 → llm2 → exfil`；路径变体：3
- 合并证据实例：3
- 规则映射：FLOW-012, TOOL-013
- DSL 位置：`/workflow/graph/nodes/7`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-373095834ee0`, `FACT-e41aab121a54`, `FACT-ad5fb1532216`
- 风险项指纹：`RISK-cd9591da8b06`
- 建议动态测试：`tool_timeout`, `cascading_failure`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] data_protection · 外部 HTTP 写入：敏感数据保护控制不足

责任节点“外部 HTTP 写入”在“敏感数据保护控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.78
- 代表路径：`kb → exfil`；路径变体：1
- 合并证据实例：2
- 规则映射：KB-006, FLOW-004, TOOL-007
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/7`
- 证据：`FACT-8c8ffc891d29`, `FACT-a12a34377474`, `FACT-369d8d150456`
- 风险项指纹：`RISK-64f9e7a7749b`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] structured_data_contract · 外部 HTTP 写入：结构化数据契约不足

责任节点“外部 HTTP 写入”在“结构化数据契约不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm1 → llm2 → exfil`；路径变体：3
- 合并证据实例：3
- 规则映射：LLM-005, TOOL-011, LLM-006, OUT-006
- DSL 位置：`/workflow/graph/nodes/7`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-e585d17c5bc6`, `FACT-355ae6eb6385`, `FACT-a5ad265c5b7c`, `FACT-c6fa63ea1420`, `FACT-4292394bf719`, `FACT-4b308e5974f1`, `FACT-a5be077e7813`
- 风险项指纹：`RISK-fe3cc19e81c7`
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `web` · 外部网页读取

节点类型：`TOOL`；风险项：4；最高等级：`HIGH`

#### [HIGH] action_authorization · 外部网页读取：高影响动作授权控制不足

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`start → web`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-003
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-82b543f035e7`
- 风险项指纹：`RISK-1e931174d25a`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] egress_control · 外部网页读取：网络与输出外发控制不足

动态 URL/Host 缺少域名或地址 Allowlist。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`web`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-003
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-ceabf24a45ad`
- 风险项指纹：`RISK-2caaca7447f3`
- 建议动态测试：`ssrf`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

#### [MEDIUM] structured_data_contract · 外部网页读取：结构化数据契约不足

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 代表路径：`web`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-011
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-f2ea412bed87`
- 风险项指纹：`RISK-db7b24a46b27`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

#### [MEDIUM] resilience_budget · 外部网页读取：失败处理与资源预算不足

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`web`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-013
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-889fdc91680f`
- 风险项指纹：`RISK-88d460f46978`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### 节点 `llm2` · 执行 Agent

节点类型：`LLM`；风险项：4；最高等级：`HIGH`

#### [HIGH] structured_data_contract · 执行 Agent：结构化数据契约不足

上游 Agent 的自由文本被下游 Agent 信任，缺少消息 Schema、来源身份或不可信指令隔离。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm1 → llm2`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-011
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-2f7fa4ea7d74`
- 风险项指纹：`RISK-7762319f8fcc`
- 建议动态测试：`inter_agent_message_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] instruction_boundary · 执行 Agent：模型指令与数据边界不足

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.72
- 代表路径：`memory → llm2`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-002
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-ff152fafcb71`
- 风险项指纹：`RISK-7f18c0700b19`
- 建议动态测试：`instruction_data_boundary`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

#### [HIGH] untrusted_content_boundary · 执行 Agent：外部内容信任边界不足

工具输出未经严格 Schema 验证进入 LLM 上下文。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`memory → llm2`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-012
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-caa1117d6700`
- 风险项指纹：`RISK-c8e1e8d3fa73`
- 建议动态测试：`tool_output_prompt_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

#### [MEDIUM] resilience_budget · 执行 Agent：失败处理与资源预算不足

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 代表路径：`llm2`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-009
- DSL 位置：`/workflow/graph/nodes/5`
- 证据：`FACT-53d25bcbde22`
- 风险项指纹：`RISK-7bf206fa7394`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `admin_tool` · 管理员资源更新工具

节点类型：`TOOL`；风险项：4；最高等级：`HIGH`

#### [HIGH] resilience_budget · 管理员资源更新工具：失败处理与资源预算不足

责任节点“管理员资源更新工具”在“失败处理与资源预算不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`web → llm1 → llm2 → admin_tool`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-012, TOOL-013
- DSL 位置：`/workflow/graph/nodes/6`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-9035832a63aa`, `FACT-3e87d9e6b774`
- 风险项指纹：`RISK-897f560c9ff0`
- 建议动态测试：`tool_timeout`, `cascading_failure`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] agent_governance · 管理员资源更新工具：Agent 目标与停止边界不足

自主 Agent 接收不可信上下文并可影响高危能力，但 DSL 未声明目标锁定、停止条件或紧急停止控制。

- 状态：`PROBABLE`；置信度：0.82
- 代表路径：`start → llm1 → llm2 → admin_tool`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-013
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-05cb2346b895`
- 风险项指纹：`RISK-9bff6d891e05`
- 缺失上下文：运行时规划行为与停止指令服从性只能在沙盒确认。
- 建议动态测试：`rogue_agent_containment`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] action_authorization · 管理员资源更新工具：高影响动作授权控制不足

责任节点“管理员资源更新工具”在“高影响动作授权控制不足”方面存在 6 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`start → admin_tool`；路径变体：3
- 合并证据实例：6
- 规则映射：TOOL-002, TOOL-008, TOOL-015, TOOL-016, FLOW-003
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-7f6fa15c65f3`, `FACT-273d4a07533c`, `FACT-457659234e01`, `FACT-f4929fb63e04`, `FACT-517d0058f40d`, `FACT-aacd07f794eb`
- 风险项指纹：`RISK-58f60dc3a5aa`
- 缺失上下文：平台统一身份认证不等同于对象级授权；需要确认工具执行端是否重新授权。
- 建议动态测试：`model_controlled_tool_argument`, `high_impact_action_approval`, `authorization_bypass`, `cross_tenant_object_access`, `source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [MEDIUM] structured_data_contract · 管理员资源更新工具：结构化数据契约不足

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 代表路径：`admin_tool`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-011
- DSL 位置：`/workflow/graph/nodes/6`
- 证据：`FACT-daa2a662dcb1`
- 风险项指纹：`RISK-616e8270ca3e`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### 节点 `kb` · 客户身份与病例知识库

节点类型：`KNOWLEDGE`；风险项：2；最高等级：`HIGH`

#### [HIGH] knowledge_governance · 客户身份与病例知识库：知识资产治理控制不足

责任节点“客户身份与病例知识库”在“知识资产治理控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`kb`；路径变体：1
- 合并证据实例：3
- 规则映射：KB-002, KB-003, KB-008
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-55c4ecb9530d`, `FACT-4fc3be561f9a`, `FACT-dd03e9b6672c`
- 风险项指纹：`RISK-c2fba5e9f127`
- 缺失上下文：若平台在 DSL 外强制租户隔离，应在内部基线中登记。
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

#### [HIGH] untrusted_content_boundary · 客户身份与病例知识库：外部内容信任边界不足

检索内容进入模型前缺少可识别的注入筛查或隔离控制。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`kb`；路径变体：1
- 合并证据实例：1
- 规则映射：KB-009
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-640c7a7c0c1f`
- 风险项指纹：`RISK-99966d7cc527`
- 建议动态测试：`rag_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### 节点 `llm1` · 主 Agent

节点类型：`LLM`；风险项：3；最高等级：`HIGH`

#### [HIGH] instruction_boundary · 主 Agent：模型指令与数据边界不足

责任节点“主 Agent”在“模型指令与数据边界不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`kb → llm1`；路径变体：3
- 合并证据实例：3
- 规则映射：KB-004, LLM-001, LLM-002, IN-009
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-5e789ecef80b`, `FACT-c05db8c65fba`, `FACT-dbd72c86bd37`, `FACT-d86aad6daa5d`
- 风险项指纹：`RISK-979865bc0743`
- 建议动态测试：`rag_system_prompt_injection`, `direct_or_indirect_prompt_injection`, `instruction_data_boundary`, `direct_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

#### [HIGH] untrusted_content_boundary · 主 Agent：外部内容信任边界不足

责任节点“主 Agent”在“外部内容信任边界不足”方面存在 5 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`web → llm1`；路径变体：5
- 合并证据实例：5
- 规则映射：TOOL-012, FLOW-005, KB-005, LLM-003
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/6`, `/workflow/graph/nodes/7`, `/workflow/graph/nodes/8`
- 证据：`FACT-4220ca37e1f2`, `FACT-5e4c852144bd`, `FACT-933bd4ac2531`, `FACT-db828845b05b`, `FACT-03cb64251cf0`, `FACT-c04a7004147f`, `FACT-52dea32ea1ca`, `FACT-324968fc9a7c`, `FACT-854f029a08ca`, `FACT-37b8f2b4a341`, `FACT-4fdf33318628`
- 风险项指纹：`RISK-ec216158724a`
- 建议动态测试：`tool_output_prompt_injection`, `rag_to_tool_injection`, `indirect_prompt_injection`, `knowledge_controlled_tool`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [MEDIUM] resilience_budget · 主 Agent：失败处理与资源预算不足

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 代表路径：`llm1`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-009
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-62743a962286`
- 风险项指纹：`RISK-03b4ed027e74`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `memory` · shared persistent memory store

节点类型：`TOOL`；风险项：3；最高等级：`HIGH`

#### [HIGH] memory_identity_scope · shared persistent memory store：记忆身份与隔离控制不足

责任节点“shared persistent memory store”在“记忆身份与隔离控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`memory`；路径变体：3
- 合并证据实例：3
- 规则映射：KB-011, IN-008, KB-012
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-4fd0bff93817`, `FACT-9d2680d268ef`, `FACT-0e4b8c3226a8`
- 风险项指纹：`RISK-a09587b4e1de`
- 建议动态测试：`memory_poisoning`, `cross_user_memory_isolation`, `persistent_memory_poisoning`（本次未执行）
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

#### [MEDIUM] structured_data_contract · shared persistent memory store：结构化数据契约不足

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 代表路径：`memory`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-011
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-725e7f279e5f`
- 风险项指纹：`RISK-8e7151968d67`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

#### [MEDIUM] resilience_budget · shared persistent memory store：失败处理与资源预算不足

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 代表路径：`memory`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-013
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-858355960425`
- 风险项指纹：`RISK-aa8c43ce14d5`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### 节点 `start` · 用户输入

节点类型：`INPUT`；风险项：1；最高等级：`MEDIUM`

#### [MEDIUM] input_contract · 用户输入：输入契约与边界控制不足

责任节点“用户输入”在“输入契约与边界控制不足”方面存在 4 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`start`；路径变体：1
- 合并证据实例：4
- 规则映射：IN-002
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-d3980431b8ae`, `FACT-b730525caff3`, `FACT-bc21b03198b8`, `FACT-6b253618948b`
- 风险项指纹：`RISK-7a6029a46ab6`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

## 覆盖缺口

- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `OUT-008`：输出节点未显示低置信或失败回退行为。
- `TOOL-001`：责任节点“管理员资源更新工具”在“失败处理与资源预算不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。
- `TOOL-001`：工具能力无法从内部基线或 DSL 描述中确定。
- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。
- `IN-004`：DSL 未声明输入解码和 Unicode 规范化控制。
- `KB-010`：知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
