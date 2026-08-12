# Workflow 静态安全扫描报告：risky-rag-tool-workflow

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`405f5cb278c616af965dbdce79e4b5b7f2874d26dac2ad342858f7a880dd4d8a`
- 节点/边：5 / 4
- Finding 数：45
- 严重等级：CRITICAL=7、HIGH=24、MEDIUM=12、LOW=1、INFO=1
- 证据状态：CONFIRMED=23、PROBABLE=18、COVERAGE_GAP=4
- 发布门禁：`FAIL`

## 关键攻击链

### CRITICAL · FLOW-009, TOOL-017, FLOW-004, LLM-005, LLM-006, OUT-002, OUT-006, TOOL-007

攻击族：web_exfiltration, general_workflow_security

- 路径：`llm → http`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-7273d0fc5cb4, TC-1e473bba6fc4, TC-71a03bd0c198, TC-0b3f6308962f, TC-abfa9f21e1eb

### CRITICAL · FLOW-008, LLM-004, LLM-011

攻击族：general_workflow_security, data_leakage

- 路径：`llm`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-40b2ad891950, TC-1bc3a3d3589c

### CRITICAL · FLOW-009, FLOW-004, OUT-002

攻击族：web_exfiltration, general_workflow_security

- 路径：`llm → answer`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-7273d0fc5cb4, TC-1e473bba6fc4, TC-71a03bd0c198, TC-0b3f6308962f

### CRITICAL · TOOL-010, TOOL-003

攻击族：general_workflow_security

- 路径：`http`
- 状态：`CONFIRMED`
- 动态用例：TC-8e4d192b7456

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → kb → http`
- 状态：`CONFIRMED`
- 动态用例：TC-c87f83394e28, TC-dc53ed1eb2ad

### HIGH · OUT-004, OUT-009

攻击族：general_workflow_security, web_exfiltration

- 路径：`answer`
- 状态：`PROBABLE, CONFIRMED`
- 动态用例：TC-b52299b0bd46, TC-2171b0552a27

### HIGH · KB-004

攻击族：general_workflow_security

- 路径：`kb → llm`
- 状态：`CONFIRMED`
- 动态用例：TC-285e8f3c951c

### HIGH · IN-009

攻击族：direct_prompt_injection

- 路径：`start → llm`
- 状态：`CONFIRMED`
- 动态用例：TC-55d9b91e1cac

### HIGH · KB-001, KB-002, KB-009

攻击族：general_workflow_security

- 路径：`kb`
- 状态：`PROBABLE`
- 动态用例：TC-5e360f0ba124

### HIGH · LLM-001, LLM-002

攻击族：general_workflow_security

- 路径：`kb → start → llm`
- 状态：`CONFIRMED, PROBABLE`
- 动态用例：TC-f10de959d667, TC-504203fc3488

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`kb → http`
- 状态：`CONFIRMED`
- 动态用例：TC-c87f83394e28, TC-dc53ed1eb2ad

### HIGH · IN-006

攻击族：general_workflow_security

- 路径：`start`
- 状态：`PROBABLE`
- 动态用例：TC-4bd7bcbfe2e0

### HIGH · FLOW-005, KB-005, LLM-003

攻击族：general_workflow_security

- 路径：`kb → llm → http`
- 状态：`PROBABLE, CONFIRMED`
- 动态用例：TC-82193ef76cb1, TC-864c1689d987, TC-b2fa267a18e5

### MEDIUM · OUT-007

攻击族：general_workflow_security

- 路径：`kb → answer`
- 状态：`CONFIRMED`
- 动态用例：待生成

## Findings

### [CRITICAL] FLOW-008 · 凭证进入模型可见上下文

DSL 中检测到疑似明文凭证；若其位于 Prompt 或节点变量中，模型可能观察到凭证。

- 状态：`CONFIRMED`；置信度：0.98
- 节点：`llm`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-c342c5c90be4`
- 动态验证：`credential_context_exposure`
- 修复建议：
  - 从 DSL 移除明文凭证，使用运行时密钥引用，并保证凭证不进入模型上下文。

### [CRITICAL] FLOW-009 · 敏感资产经模型到外部通道的复合外泄链

敏感资产经模型传播到外部通道；与提示注入组合后可形成完整数据外泄链。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → answer`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/4`
- 证据：`FACT-087ae7b3c06e`
- 动态验证：`web_exfiltration_chain`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] FLOW-009 · 敏感资产经模型到外部通道的复合外泄链

敏感资产作为网络载荷，同时模型可控制外部目标，形成完整的复合外泄链。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-0fa7fb59a544`
- 动态验证：`web_exfiltration_chain`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] FLOW-009 · 敏感资产经模型到外部通道的复合外泄链

敏感资产经模型传播到外部通道；与提示注入组合后可形成完整数据外泄链。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-153e38f7ddf9`
- 动态验证：`web_exfiltration_chain`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [CRITICAL] LLM-004 · 密钥或内部上下文暴露

LLM 节点文本中包含疑似明文凭证。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-dfb118a177f7`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [CRITICAL] TOOL-010 · 工具凭证处理不安全

工具配置中存在疑似明文凭证。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`http`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-991cfbb1fa94`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [CRITICAL] TOOL-017 · 敏感载荷与动态网络目标形成外带通道

敏感载荷可进入具有动态目标的网络写工具，且未发现 DLP/出站载荷策略。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-ebe8b001f9a1`
- 动态验证：`web_exfiltration_chain`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → http`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`
- 证据：`FACT-08e204ba0560`
- 动态验证：`source_to_high_impact_sink`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → kb → http`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/3`
- 证据：`FACT-68e32cf110bc`
- 动态验证：`source_to_high_impact_sink`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-004 · 敏感数据可达外部边界

疑似敏感数据可达外部工具或输出边界。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-c4cde0855742`
- 动态验证：`sensitive_data_exfiltration`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-004 · 敏感数据可达外部边界

疑似敏感数据可达外部工具或输出边界。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`llm → answer`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/4`
- 证据：`FACT-ce5bfbcac39c`
- 动态验证：`sensitive_data_exfiltration`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] FLOW-005 · 间接 Prompt Injection 工具链

知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`kb → llm → http`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-fc8d90f5e830`
- 动态验证：`rag_to_tool_injection`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] IN-006 · 敏感输入缺少保护

输入字段 api_key 可能包含敏感信息，需要验证下游传播和脱敏。

- 状态：`PROBABLE`；置信度：0.75
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-2ff4d43c2b2e`
- 动态验证：`sensitive_input_propagation`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [HIGH] IN-009 · 直接 Prompt Injection 可达模型

用户消息可直接到达模型，且系统指令未声明对角色覆盖、目标劫持或提示词提取的防护边界。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-11309d7a66f1`
- 动态验证：`direct_prompt_injection`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [HIGH] KB-001 · 知识检索数据集范围未限定

知识检索数据集范围未固定或无法识别。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-8fdf8b561594`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

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
- 节点：`kb → llm`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-dea702265759`
- 动态验证：`rag_system_prompt_injection`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-005 · 知识内容经模型控制工具

知识内容可经模型传播到工具。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm → http`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-50be1cb79f0b`
- 动态验证：`knowledge_controlled_tool`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] KB-009 · 知识内容缺少注入隔离

检索内容进入模型前缺少可识别的注入筛查或隔离控制。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-640c7a7c0c1f`
- 动态验证：`rag_indirect_prompt_injection`
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### [HIGH] LLM-001 · 不可信变量进入系统指令

不可信变量被插入系统或高权限指令区域。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → start → llm`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-9e43b2cb8c71`
- 动态验证：`direct_or_indirect_prompt_injection`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-003 · 间接内容可控制工具

间接外部内容进入具备工具影响能力的 LLM。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → llm → http`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-546eb56f2701`
- 动态验证：`indirect_prompt_injection`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-7f24df8e8cab`
- 动态验证：`free_text_tool_control`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-006 · 下游依赖结构化数据但无输出 Schema

下游工具依赖 LLM 输出，但节点未声明严格结构化输出。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-bbd20be44857`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-011 · 系统指令敏感内容存在泄露面

系统指令区包含敏感信息或凭证迹象，但未发现提示词防泄露/上下文 DLP 控制。

- 状态：`PROBABLE`；置信度：0.90
- 节点：`llm`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-018db969148c`
- 动态验证：`system_prompt_and_credential_leakage`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] OUT-002 · 敏感信息可达外部输出

敏感内容存在到达外部边界的静态路径。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`llm → answer`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/4`
- 证据：`FACT-6e37d1d76437`
- 动态验证：`sensitive_data_exfiltration`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] OUT-002 · 敏感信息可达外部输出

敏感内容存在到达外部边界的静态路径。

- 状态：`PROBABLE`；置信度：0.78
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-b965e9dabc9d`
- 动态验证：`sensitive_data_exfiltration`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] OUT-004 · 富文本输出缺少上下文编码

动态 HTML/Markdown 输出缺少可识别的上下文编码。

- 状态：`PROBABLE`；置信度：0.82
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-5a4a7003a8b8`
- 动态验证：`rich_text_injection`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] OUT-006 · 未验证输出进入下游执行者

未经严格结构验证的模型输出进入下游执行节点。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-227f8afcd0f4`
- 动态验证：`free_text_tool_control`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] OUT-009 · 动态 Markdown 链接或图片可形成隐蔽外带

动态 Markdown 链接或图片目标未受限，可通过客户端取链或 URL 路径编码形成隐蔽外带。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-b7bf9a442b48`
- 动态验证：`markdown_url_exfiltration`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] TOOL-003 · 可控 URL 形成 SSRF 风险

动态 URL/Host 缺少域名或地址 Allowlist。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`http`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-5dccf8f0a473`
- 动态验证：`ssrf`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-007 · 敏感数据通过工具外传

敏感数据存在经工具离开工作流信任边界的路径。

- 状态：`PROBABLE`；置信度：0.82
- 节点：`llm → http`
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-db501d2c8995`
- 动态验证：`sensitive_data_exfiltration`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] IN-002 · 输入缺少长度或数量限制

输入字段 api_key 缺少长度或数量上限。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-a428f408d1de`
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

### [MEDIUM] LLM-002 · 指令与外部数据未隔离

外部内容进入 LLM，但系统指令中未发现明确的数据/指令隔离约束。

- 状态：`PROBABLE`；置信度：0.72
- 节点：`kb → start → llm`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`
- 证据：`FACT-be9267c28068`
- 动态验证：`instruction_data_boundary`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [MEDIUM] LLM-009 · 模型资源预算不完整

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`llm`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-91101ff7dec6`
- 动态验证：`resource_budget`
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [MEDIUM] LLM-010 · 模型失败回退路径不安全

DSL 未显示模型失败、拒答或解析失败后的安全回退策略。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`llm`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-9d7a8c4fd729`
- 缺失上下文：运行时可能统一处理模型错误。
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [MEDIUM] OUT-001 · 结构化输出缺少 Schema

动态输出缺少结构化 Schema。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-a0bc2f369393`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [MEDIUM] OUT-007 · RAG 引用不可追踪

知识库回答到达输出，但未发现引用元数据绑定。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`kb → answer`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/4`
- 证据：`FACT-8ebd29c4ba03`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [MEDIUM] OUT-008 · 低置信或失败输出无回退

输出节点未显示低置信或失败回退行为。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`answer`
- DSL 位置：`/workflow/graph/nodes/4`
- 证据：`FACT-0c9b42606853`
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`http`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-0fab3ba4961d`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-013 · 工具缺少超时或调用限制

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 节点：`http`
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-ad44783ba931`
- 动态验证：`tool_timeout`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [LOW] IN-004 · 未声明输入规范化

DSL 未声明输入解码和 Unicode 规范化控制。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`start`
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-d4a60448cde7`
- 缺失上下文：输入规范化可能由平台统一实现，DSL 无法验证。
- 动态验证：`encoding_unicode_smuggling`
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

### [INFO] KB-010 · 知识库运行控制不在 DSL 中

知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`kb`
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-407027395fcd`
- 缺失上下文：knowledge_acl；document_provenance；retention；quarantine
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

## 覆盖缺口

- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `OUT-008`：输出节点未显示低置信或失败回退行为。
- `IN-004`：DSL 未声明输入解码和 Unicode 规范化控制。
- `KB-010`：知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
