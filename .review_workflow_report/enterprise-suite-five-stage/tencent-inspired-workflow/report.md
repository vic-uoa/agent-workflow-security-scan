# Workflow 静态安全扫描报告：tencent-inspired-risk-chain

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`b01ee8c4c8fd5f2b2451863af5da83de2a25473ec076b2c1a4ff70d2dd414997`
- 节点/边：10 / 11
- Finding 数：74
- 覆盖缺口数：12（不计入 Finding）
- 严重等级：CRITICAL=6、HIGH=48、MEDIUM=20
- 证据状态：CONFIRMED=37、PROBABLE=37、COVERAGE_GAP=12
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：1
- 派生用例：63
- 类型分布：positive=1、boundary=1、metamorphic=1、negative=60
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### CRITICAL · FLOW-009, TOOL-017, FLOW-005, KB-005, LLM-003

攻击族：web_exfiltration, general_workflow_security

- 路径：`kb → llm1 → llm2 → exfil`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-bed377930035, TC-b422495e9c0e, TC-7fc9aec3fac1, TC-b0981fd71b46, TC-a439886058b6

### CRITICAL · FLOW-010, FLOW-012

攻击族：unexpected_code_execution, cascading_failure

- 路径：`web → llm1 → llm2 → code`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-f5ee7cad2b09, TC-1b5b29477714, TC-caed4f42e78d, TC-1453fdccc43f, TC-a24e0df112cb, TC-86df90667ae7

### CRITICAL · FLOW-010, FLOW-003, FLOW-005, KB-005, LLM-003

攻击族：unexpected_code_execution, general_workflow_security

- 路径：`kb → llm1 → llm2 → code`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-1b5b29477714, TC-f5ee7cad2b09, TC-412d145586a9, TC-82db08834ff5, TC-0cc9ff540c22, TC-a3ebce17ee94, TC-59e9deccc8bb, TC-ac57087d0787, TC-5a87afc0d52f, TC-b0981fd71b46, TC-a439886058b6, TC-7fc9aec3fac1

### CRITICAL · TOOL-004, TOOL-014

攻击族：general_workflow_security

- 路径：`code`
- 状态：`CONFIRMED, COVERAGE_GAP`
- 建议测试用例（未执行）：TC-773182cd7b7b

### CRITICAL · FLOW-009, FLOW-004, KB-006, OUT-007

攻击族：web_exfiltration, general_workflow_security

- 路径：`kb → llm1 → llm2 → answer`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-b422495e9c0e, TC-bed377930035, TC-9269b138e9cb, TC-b59114204e7c

### HIGH · TOOL-014, TOOL-015

攻击族：general_workflow_security, authorization_bypass

- 路径：`admin_tool`
- 状态：`COVERAGE_GAP, PROBABLE`
- 建议测试用例（未执行）：TC-deeee77726f1

### HIGH · FLOW-012

攻击族：cascading_failure

- 路径：`admin_tool → exfil`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-a24e0df112cb, TC-caed4f42e78d, TC-1453fdccc43f, TC-86df90667ae7

### HIGH · FLOW-012

攻击族：cascading_failure

- 路径：`web → llm1 → llm2 → admin_tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-1453fdccc43f, TC-caed4f42e78d, TC-a24e0df112cb, TC-86df90667ae7

### HIGH · OUT-004, OUT-009

攻击族：general_workflow_security, web_exfiltration

- 路径：`answer`
- 状态：`PROBABLE, CONFIRMED`
- 建议测试用例（未执行）：TC-b52299b0bd46, TC-2171b0552a27

### HIGH · LLM-002, TOOL-012

攻击族：general_workflow_security

- 路径：`memory → llm2`
- 状态：`PROBABLE, CONFIRMED`
- 建议测试用例（未执行）：TC-b5f3aebaa656, TC-30c7532dd775, TC-7ad33e37f436, TC-d75a64e8fb5e, TC-50b0b00d95dc

### HIGH · FLOW-003, FLOW-005, KB-005, LLM-003

攻击族：general_workflow_security

- 路径：`kb → llm1 → llm2 → admin_tool`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-ac57087d0787, TC-82db08834ff5, TC-0cc9ff540c22, TC-412d145586a9, TC-a3ebce17ee94, TC-59e9deccc8bb, TC-5a87afc0d52f, TC-a439886058b6, TC-b0981fd71b46, TC-7fc9aec3fac1

### HIGH · TOOL-012

攻击族：general_workflow_security

- 路径：`web → llm1`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-d75a64e8fb5e, TC-50b0b00d95dc, TC-7ad33e37f436

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → web`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-59e9deccc8bb, TC-82db08834ff5, TC-0cc9ff540c22, TC-412d145586a9, TC-a3ebce17ee94, TC-ac57087d0787, TC-5a87afc0d52f

### HIGH · TOOL-003

攻击族：general_workflow_security

- 路径：`exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-224f48c84b5d, TC-23eaf94ec198

### HIGH · LLM-005, LLM-006, OUT-006

攻击族：general_workflow_security

- 路径：`llm2 → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-21103979333a, TC-037787bd966d, TC-22fd12983123, TC-3e0c7892bb3d

### HIGH · LLM-005, LLM-006, OUT-006

攻击族：general_workflow_security

- 路径：`llm1 → llm2 → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-037787bd966d, TC-21103979333a, TC-22fd12983123, TC-3e0c7892bb3d

### HIGH · IN-009

攻击族：direct_prompt_injection

- 路径：`start → llm1`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-d9b18c3d283a

### HIGH · FLOW-013

攻击族：rogue_agent

- 路径：`start → llm1 → llm2 → admin_tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-b1e2037858ee

### HIGH · TOOL-003

攻击族：general_workflow_security

- 路径：`web`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-23eaf94ec198, TC-224f48c84b5d

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → admin_tool → exfil`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-0cc9ff540c22, TC-82db08834ff5, TC-412d145586a9, TC-a3ebce17ee94, TC-59e9deccc8bb, TC-ac57087d0787, TC-5a87afc0d52f

## Findings

### [CRITICAL] FLOW-009 · 敏感资产经模型到外部通道的复合外泄链

敏感资产经模型传播到外部通道；与提示注入组合后可形成完整数据外泄链。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → answer`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/9`
- 证据：`FACT-0cbfb4cb25d7`
- 建议动态测试：`web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] FLOW-009 · 敏感资产经模型到外部通道的复合外泄链

敏感资产作为网络载荷，同时模型可控制外部目标，形成完整的复合外泄链。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-9433c0005638`
- 建议动态测试：`web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] FLOW-010 · 外部不可信内容经模型到代码执行

外部或检索内容可经模型输出进入代码/命令执行节点。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`web → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-2b10472c7144`
- 建议动态测试：`external_content_to_code_execution`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] FLOW-010 · 外部不可信内容经模型到代码执行

外部或检索内容可经模型输出进入代码/命令执行节点。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-59b8803d622d`
- 建议动态测试：`external_content_to_code_execution`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] TOOL-004 · 命令或代码注入风险

动态变量可到达命令、代码或脚本执行能力。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/8`
- 证据：`FACT-e24a1cdc6ec9`
- 建议动态测试：`command_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [CRITICAL] TOOL-017 · 敏感载荷与动态网络目标形成外带通道

敏感载荷可进入具有动态目标的网络写工具，且未发现 DLP/出站载荷策略。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-860ad7d07c74`
- 建议动态测试：`web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → admin_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`
- 证据：`FACT-517d0058f40d`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → admin_tool → exfil`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`, `/workflow/graph/nodes/7`
- 证据：`FACT-63cb48341a87`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-77f02bcfbb78`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/7`
- 证据：`FACT-7bb959489e1c`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → web`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-82b543f035e7`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → admin_tool`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-aacd07f794eb`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-ffe205cb0b31`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-004 · 敏感数据可达外部边界

疑似敏感数据可达外部工具或输出边界。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`kb → llm1 → llm2 → answer`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/9`
- 证据：`FACT-78537ae3650d`
- 根因指纹：`ROOT-b06fc73f5908`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-004 · 敏感数据可达外部边界

疑似敏感数据可达外部工具或输出边界。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`kb → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/7`
- 证据：`FACT-a12a34377474`, `FACT-369d8d150456`
- 根因指纹：`ROOT-85610270a22c`
- 关联规则（不重复计数）：TOOL-007
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-005 · 间接 Prompt Injection 工具链

知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`kb → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-854f029a08ca`, `FACT-37b8f2b4a341`, `FACT-4fdf33318628`
- 根因指纹：`ROOT-18e67c0e1486`
- 关联规则（不重复计数）：KB-005, LLM-003
- 建议动态测试：`rag_to_tool_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-005 · 间接 Prompt Injection 工具链

知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`kb → llm1 → llm2 → admin_tool`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-933bd4ac2531`, `FACT-db828845b05b`, `FACT-03cb64251cf0`
- 根因指纹：`ROOT-6e33de2d44c2`
- 关联规则（不重复计数）：KB-005, LLM-003
- 建议动态测试：`rag_to_tool_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-005 · 间接 Prompt Injection 工具链

知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`kb → llm1 → llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-c04a7004147f`, `FACT-52dea32ea1ca`, `FACT-324968fc9a7c`
- 根因指纹：`ROOT-12e5c5f90f8c`
- 关联规则（不重复计数）：KB-005, LLM-003
- 建议动态测试：`rag_to_tool_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-011 · 跨 Agent 消息缺少结构与信任校验

上游 Agent 的自由文本被下游 Agent 信任，缺少消息 Schema、来源身份或不可信指令隔离。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm1 → llm2`
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-2f7fa4ea7d74`
- 建议动态测试：`inter_agent_message_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-012 · 多级副作用链缺少故障隔离

多个副作用节点串联，但路径上未发现幂等、熔断、补偿或失败关闭控制。

- 状态：`PROBABLE`；置信度：0.84
- 节点：`web → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-21295edac0d7`
- 建议动态测试：`cascading_failure`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-012 · 多级副作用链缺少故障隔离

多个副作用节点串联，但路径上未发现幂等、熔断、补偿或失败关闭控制。

- 状态：`PROBABLE`；置信度：0.84
- 节点：`web → llm1 → llm2 → admin_tool`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-3e87d9e6b774`
- 建议动态测试：`cascading_failure`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-012 · 多级副作用链缺少故障隔离

多个副作用节点串联，但路径上未发现幂等、熔断、补偿或失败关闭控制。

- 状态：`PROBABLE`；置信度：0.84
- 节点：`admin_tool → exfil`
- DSL 位置：`/workflow/graph/nodes/6`, `/workflow/graph/nodes/7`
- 证据：`FACT-ad5fb1532216`
- 建议动态测试：`cascading_failure`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-012 · 多级副作用链缺少故障隔离

多个副作用节点串联，但路径上未发现幂等、熔断、补偿或失败关闭控制。

- 状态：`PROBABLE`；置信度：0.84
- 节点：`web → llm1 → llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-e41aab121a54`
- 建议动态测试：`cascading_failure`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-013 · 自主 Agent 缺少目标锁定和紧急停止边界

自主 Agent 接收不可信上下文并可影响高危能力，但 DSL 未声明目标锁定、停止条件或紧急停止控制。

- 状态：`PROBABLE`；置信度：0.82
- 节点：`start → llm1 → llm2 → admin_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/6`
- 证据：`FACT-05cb2346b895`
- 缺失上下文：运行时规划行为与停止指令服从性只能在沙盒确认。
- 建议动态测试：`rogue_agent_containment`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] IN-008 · 未验证输入被持久化

不可信内容可能未经验证写入持久化记忆。

- 状态：`PROBABLE`；置信度：0.75
- 节点：`start → llm1 → memory`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/4`
- 证据：`FACT-4fd0bff93817`
- 建议动态测试：`memory_poisoning`（本次未执行）
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [HIGH] IN-009 · 不可信输入进入高权限 Prompt

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`start → llm1`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`
- 证据：`FACT-d86aad6daa5d`
- 根因指纹：`ROOT-457d9c325ebe`
- 建议动态测试：`direct_prompt_injection`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

### [HIGH] KB-002 · 缺少租户或业务元数据过滤

知识检索未配置可识别的租户、用户或业务元数据过滤。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-55c4ecb9530d`
- 缺失上下文：若平台在 DSL 外强制租户隔离，应在内部基线中登记。
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-004 · 知识内容进入高权限 Prompt

知识检索内容被插入 LLM 高权限 Prompt。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`
- 证据：`FACT-5e789ecef80b`
- 建议动态测试：`rag_system_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-006 · 知识敏感内容可达外部边界

敏感内容存在到达外部边界的静态路径。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`kb → llm1 → llm2 → answer`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/9`
- 证据：`FACT-28374567e86b`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-006 · 知识敏感内容可达外部边界

敏感内容存在到达外部边界的静态路径。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`kb → exfil`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/7`
- 证据：`FACT-8c8ffc891d29`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-009 · 知识内容缺少注入隔离

检索内容进入模型前缺少可识别的注入筛查或隔离控制。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-640c7a7c0c1f`
- 建议动态测试：`rag_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-011 · 持久记忆缺少用户或租户命名空间

持久记忆节点未声明用户、租户或会话命名空间。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`memory`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-9d2680d268ef`
- 建议动态测试：`cross_user_memory_isolation`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-012 · 不可信写入可被后续 Agent 读取

不可信内容可写入持久记忆并被后续 Agent 读取，形成可持续指令投毒闭环。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm1 → memory → llm2`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-0e4b8c3226a8`
- 建议动态测试：`persistent_memory_poisoning`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] LLM-001 · 不可信输入进入高权限 Prompt

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`kb → start → web → llm1`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-c05db8c65fba`, `FACT-dbd72c86bd37`
- 根因指纹：`ROOT-0d52819ff3d6`
- 关联规则（不重复计数）：LLM-002
- 建议动态测试：`direct_or_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

### [HIGH] LLM-002 · 不可信输入进入高权限 Prompt

用户输入被放入系统/开发者指令区域；静态扫描确认了边界缺陷，但是否可劫持模型及其实际影响仍需动态样例验证。

- 状态：`PROBABLE`；置信度：0.72
- 节点：`memory → llm2`
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-ff152fafcb71`
- 根因指纹：`ROOT-6906898c3d39`
- 建议动态测试：`instruction_data_boundary`（本次未执行）
- 修复建议：
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm1 → llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-355ae6eb6385`, `FACT-a5ad265c5b7c`, `FACT-c6fa63ea1420`
- 根因指纹：`ROOT-2aa2d1f23da8`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm2 → exfil`
- DSL 位置：`/workflow/graph/nodes/5`, `/workflow/graph/nodes/7`
- 证据：`FACT-4292394bf719`, `FACT-4b308e5974f1`, `FACT-a5be077e7813`
- 根因指纹：`ROOT-5a939b113932`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-54881f611493`, `FACT-8370183c7953`, `FACT-e83017039b3c`
- 根因指纹：`ROOT-eb4cd37a372f`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm2 → code`
- DSL 位置：`/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-e5908eb802da`, `FACT-4daddda1dcdd`, `FACT-7c0b493e125f`
- 根因指纹：`ROOT-35e815d12b0c`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-008 · 高影响决策无确定性复核

LLM 输出可触发高影响操作，路径中缺少确定性复核证据。

- 状态：`PROBABLE`；置信度：0.88
- 节点：`llm2 → code`
- DSL 位置：`/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-371a0e0108d2`
- 建议动态测试：`high_impact_model_decision`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-008 · 高影响决策无确定性复核

LLM 输出可触发高影响操作，路径中缺少确定性复核证据。

- 状态：`PROBABLE`；置信度：0.88
- 节点：`llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-5327e9ed9634`
- 建议动态测试：`high_impact_model_decision`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] OUT-004 · 富文本输出缺少上下文编码

动态 HTML/Markdown 输出缺少可识别的上下文编码。

- 状态：`PROBABLE`；置信度：0.82
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/9`
- 证据：`FACT-5a4a7003a8b8`
- 建议动态测试：`rich_text_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] OUT-009 · 动态 Markdown 链接或图片可形成隐蔽外带

动态 Markdown 链接或图片目标未受限，可通过客户端取链或 URL 路径编码形成隐蔽外带。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/9`
- 证据：`FACT-b7bf9a442b48`
- 建议动态测试：`markdown_url_exfiltration`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] TOOL-002 · 高危工具参数由模型控制

高影响工具的安全敏感参数由模型或上游变量控制。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm2 → code`
- DSL 位置：`/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-2c8d768ad681`
- 建议动态测试：`model_controlled_tool_argument`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-002 · 高危工具参数由模型控制

高影响工具的安全敏感参数由模型或上游变量控制。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → admin_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`
- 证据：`FACT-7f6fa15c65f3`
- 建议动态测试：`model_controlled_tool_argument`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-003 · 可控 URL 形成 SSRF 风险

动态 URL/Host 缺少域名或地址 Allowlist。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`exfil`
- DSL 位置：`/workflow/graph/nodes/7`
- 证据：`FACT-20af87f21fb4`
- 建议动态测试：`ssrf`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-003 · 可控 URL 形成 SSRF 风险

动态 URL/Host 缺少域名或地址 Allowlist。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`web`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-ceabf24a45ad`
- 建议动态测试：`ssrf`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-008 · 高影响操作缺少必经审批

高影响工具存在不经过审批节点的可达路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → admin_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`
- 证据：`FACT-273d4a07533c`
- 建议动态测试：`high_impact_action_approval`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-008 · 高影响操作缺少必经审批

高影响工具存在不经过审批节点的可达路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm1 → llm2 → code`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/8`
- 证据：`FACT-a2b9706db7dd`
- 建议动态测试：`high_impact_action_approval`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-012 · 工具输出未经验证进入模型

工具输出未经严格 Schema 验证进入 LLM 上下文。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`web → llm1`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-4220ca37e1f2`
- 建议动态测试：`tool_output_prompt_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-012 · 工具输出未经验证进入模型

工具输出未经严格 Schema 验证进入 LLM 上下文。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`web → llm1 → llm2`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`
- 证据：`FACT-5e4c852144bd`
- 建议动态测试：`tool_output_prompt_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-012 · 工具输出未经验证进入模型

工具输出未经严格 Schema 验证进入 LLM 上下文。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`memory → llm2`
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/5`
- 证据：`FACT-caa1117d6700`
- 建议动态测试：`tool_output_prompt_injection`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-015 · 高影响工具缺少对象级授权约束

高影响工具未声明 subject-object-action、所有权或租户范围的确定性授权检查。

- 状态：`PROBABLE`；置信度：0.86
- 节点：`admin_tool`
- DSL 位置：`/workflow/graph/nodes/6`
- 证据：`FACT-457659234e01`
- 缺失上下文：平台统一身份认证不等同于对象级授权；需要确认工具执行端是否重新授权。
- 建议动态测试：`authorization_bypass`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-016 · 用户可控身份或资源标识直达工具

用户输入中的身份、租户、角色或资源标识直接绑定到工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → admin_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/6`
- 证据：`FACT-f4929fb63e04`
- 建议动态测试：`cross_tenant_object_access`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 callback_url 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-6b253618948b`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 tenant_id 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-b730525caff3`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 resource_id 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-bc21b03198b8`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 query 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-d3980431b8ae`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [MEDIUM] KB-003 · 检索 Top-K 或阈值扩大暴露面

Top-K 过大或相似度阈值缺失/过低，可能扩大无关内容和投毒内容暴露面。

- 状态：`PROBABLE`；置信度：0.82
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-4fc3be561f9a`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [MEDIUM] KB-008 · 知识来源元数据不可追踪

DSL 未显示检索来源和引用元数据要求。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-dd03e9b6672c`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [MEDIUM] LLM-009 · 模型资源预算不完整

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`llm2`
- DSL 位置：`/workflow/graph/nodes/5`
- 证据：`FACT-53d25bcbde22`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [MEDIUM] LLM-009 · 模型资源预算不完整

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`llm1`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-62743a962286`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [MEDIUM] OUT-007 · RAG 引用不可追踪

知识库回答到达输出，但未发现引用元数据绑定。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm1 → llm2 → answer`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/5`, `/workflow/graph/nodes/9`
- 证据：`FACT-d53997d341bc`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [MEDIUM] OUT-010 · 面向人的高信任声明缺少来源证明

模型生成的安全验证、审批或紧急声明面向用户展示，但未绑定可验证来源。

- 状态：`PROBABLE`；置信度：0.76
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/9`
- 证据：`FACT-9f6c074eef19`
- 建议动态测试：`human_agent_trust_exploit`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/8`
- 证据：`FACT-3cde63f04996`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`memory`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-725e7f279e5f`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`admin_tool`
- DSL 位置：`/workflow/graph/nodes/6`
- 证据：`FACT-daa2a662dcb1`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`exfil`
- DSL 位置：`/workflow/graph/nodes/7`
- 证据：`FACT-e585d17c5bc6`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`web`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-f2ea412bed87`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`code`
- DSL 位置：`/workflow/graph/nodes/8`
- 证据：`FACT-220cc318c481`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`exfil`
- DSL 位置：`/workflow/graph/nodes/7`
- 证据：`FACT-373095834ee0`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`memory`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-858355960425`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`web`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-889fdc91680f`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`admin_tool`
- DSL 位置：`/workflow/graph/nodes/6`
- 证据：`FACT-9035832a63aa`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

## 覆盖缺口

- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `TOOL-014`：DSL 无法证明工具来源、版本完整性或定义变更审批。
- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `OUT-008`：输出节点未显示低置信或失败回退行为。
- `TOOL-001`：工具能力无法从内部基线或 DSL 描述中确定。
- `TOOL-001`：工具能力无法从内部基线或 DSL 描述中确定。
- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。
- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。
- `IN-004`：DSL 未声明输入解码和 Unicode 规范化控制。
- `KB-010`：知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
