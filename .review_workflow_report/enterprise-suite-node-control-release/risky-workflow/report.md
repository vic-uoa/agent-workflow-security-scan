# Workflow 静态安全扫描报告：risky-rag-tool-workflow

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`405f5cb278c616af965dbdce79e4b5b7f2874d26dac2ad342858f7a880dd4d8a`
- 节点/边：5 / 4
- 节点风险项：15
- 规则/路径证据实例：32（不重复计为风险项）
- 覆盖缺口数：4（不计入 Finding）
- 严重等级：CRITICAL=4、HIGH=7、MEDIUM=4
- 证据状态：CONFIRMED=9、PROBABLE=6、COVERAGE_GAP=4
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：1
- 派生用例：27
- 类型分布：positive=1、boundary=1、metamorphic=1、negative=24
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### CRITICAL · FLOW-009, FLOW-004, OUT-002, TOOL-007, LLM-005, LLM-006, OUT-006

攻击族：web_exfiltration, general_workflow_security

- 路径：`llm → http`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-5c91bc0ec2d6, TC-4b86d3f9614c, TC-5cd80b69dc20, TC-71d25d8b3831, TC-6a782ac186b1, TC-c61e46135fae, TC-7db8a711bb1c

### CRITICAL · FLOW-008

攻击族：general_workflow_security

- 路径：`llm`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-cccba76ee76e, TC-fa079c4f493e

### CRITICAL · FLOW-009, FLOW-004, OUT-002

攻击族：web_exfiltration, general_workflow_security

- 路径：`llm → answer`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-5cd80b69dc20, TC-71d25d8b3831, TC-5c91bc0ec2d6, TC-4b86d3f9614c, TC-c61e46135fae, TC-6a782ac186b1

### CRITICAL · TOOL-003, TOOL-010, TOOL-011

攻击族：web_exfiltration, general_workflow_security

- 路径：`http`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-5c91bc0ec2d6, TC-4b86d3f9614c, TC-5cd80b69dc20, TC-71d25d8b3831, TC-6a782ac186b1, TC-c61e46135fae, TC-7db8a711bb1c

### HIGH · OUT-009

攻击族：web_exfiltration

- 路径：`answer`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-5cd80b69dc20, TC-71d25d8b3831, TC-5c91bc0ec2d6, TC-4b86d3f9614c

### HIGH · KB-004

攻击族：general_workflow_security

- 路径：`kb → llm`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-0ae740236377, TC-c583114b0456, TC-62360fa03f25, TC-0bfb66c528f5

### HIGH · KB-001, KB-009

攻击族：general_workflow_security

- 路径：`kb`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-438c61d328ba

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`kb → http`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-2cd16751d836

### HIGH · FLOW-005, KB-005, LLM-003

攻击族：general_workflow_security

- 路径：`kb → llm → http`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-1afdb606ab5a, TC-68bf63ab9853, TC-80d632f81067

### HIGH · FLOW-003

攻击族：general_workflow_security

- 路径：`start → llm → http`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-1be424fc394b, TC-d7984eb856cb, TC-83c5e2475f5c, TC-2cd16751d836

### MEDIUM · OUT-007

攻击族：general_workflow_security

- 路径：`kb → answer`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-b9f471927f36

### MEDIUM · IN-009

攻击族：general_workflow_security

- 路径：`start → llm`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-0ae740236377, TC-c583114b0456, TC-62360fa03f25, TC-0bfb66c528f5

### MEDIUM · LLM-001, LLM-002

攻击族：general_workflow_security

- 路径：`kb → start → llm`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-0ae740236377, TC-c583114b0456, TC-62360fa03f25, TC-0bfb66c528f5

## 节点风险项

### 节点 `answer` · Markdown回答

节点类型：`OUTPUT`；风险项：3；最高等级：`CRITICAL`

#### [CRITICAL] egress_control · Markdown回答：网络与输出外发控制不足

责任节点“Markdown回答”在“网络与输出外发控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`CRITICAL`；最大潜在等级：`CRITICAL`
- 代表路径：`llm → answer`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-009, OUT-009
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/2`
- 证据：`FACT-b7bf9a442b48`, `FACT-087ae7b3c06e`
- 风险项指纹：`RISK-35591c45d098`
- 建议动态测试：`markdown_url_exfiltration`, `web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] data_protection · Markdown回答：敏感数据保护控制不足

疑似敏感数据可达外部工具或输出边界。

- 状态：`PROBABLE`；置信度：0.78
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`llm → answer`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-004, OUT-002
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/4`
- 证据：`FACT-ce5bfbcac39c`, `FACT-6e37d1d76437`
- 风险项指纹：`RISK-2fd8eaa085bc`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [MEDIUM] output_safety · Markdown回答：用户输出安全控制不足

责任节点“Markdown回答”在“用户输出安全控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`MEDIUM`；最大潜在等级：`HIGH`
- 代表路径：`kb → answer`；路径变体：2
- 合并证据实例：2
- 规则映射：OUT-007, OUT-004
- DSL 位置：`/workflow/graph/nodes/4`, `/workflow/graph/nodes/1`
- 证据：`FACT-5a4a7003a8b8`, `FACT-8ebd29c4ba03`
- 风险项指纹：`RISK-1668512415bc`
- 建议动态测试：`rich_text_injection`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### 节点 `http` · 外部HTTP写入工具

节点类型：`TOOL`；风险项：5；最高等级：`CRITICAL`

#### [CRITICAL] egress_control · 外部HTTP写入工具：网络与输出外发控制不足

责任节点“外部HTTP写入工具”在“网络与输出外发控制不足”方面存在 4 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`CRITICAL`；最大潜在等级：`CRITICAL`
- 代表路径：`llm → http`；路径变体：2
- 合并证据实例：4
- 规则映射：FLOW-009, TOOL-003, TOOL-017
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/2`
- 证据：`FACT-5dccf8f0a473`, `FACT-153e38f7ddf9`, `FACT-ebe8b001f9a1`, `FACT-0fa7fb59a544`
- 风险项指纹：`RISK-7bf48082ebdc`
- 建议动态测试：`ssrf`, `web_exfiltration_chain`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [CRITICAL] data_protection · 外部HTTP写入工具：敏感数据保护控制不足

责任节点“外部HTTP写入工具”在“敏感数据保护控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`CRITICAL`；最大潜在等级：`CRITICAL`
- 代表路径：`http`；路径变体：2
- 合并证据实例：2
- 规则映射：TOOL-010, FLOW-004, OUT-002, TOOL-007
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/2`
- 证据：`FACT-991cfbb1fa94`, `FACT-c4cde0855742`, `FACT-b965e9dabc9d`, `FACT-db501d2c8995`
- 风险项指纹：`RISK-de85063c6c79`
- 建议动态测试：`sensitive_data_exfiltration`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] action_authorization · 外部HTTP写入工具：高影响动作授权控制不足

责任节点“外部HTTP写入工具”在“高影响动作授权控制不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`start → llm → http`；路径变体：2
- 合并证据实例：2
- 规则映射：FLOW-003
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`, `/workflow/graph/nodes/1`
- 证据：`FACT-945de85a7b0c`, `FACT-08e204ba0560`
- 风险项指纹：`RISK-4bee44afe1bf`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] structured_data_contract · 外部HTTP写入工具：结构化数据契约不足

责任节点“外部HTTP写入工具”在“结构化数据契约不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`llm → http`；路径变体：2
- 合并证据实例：2
- 规则映射：LLM-005, TOOL-011, LLM-006, OUT-006
- DSL 位置：`/workflow/graph/nodes/3`, `/workflow/graph/nodes/2`
- 证据：`FACT-0fab3ba4961d`, `FACT-7f24df8e8cab`, `FACT-bbd20be44857`, `FACT-227f8afcd0f4`
- 风险项指纹：`RISK-6a5869d9e579`
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

#### [MEDIUM] resilience_budget · 外部HTTP写入工具：失败处理与资源预算不足

工具缺少可识别的超时设置。

- 状态：`PROBABLE`；置信度：0.85
- 当前证据等级：`MEDIUM`；最大潜在等级：`MEDIUM`
- 代表路径：`http`；路径变体：1
- 合并证据实例：1
- 规则映射：TOOL-013
- DSL 位置：`/workflow/graph/nodes/3`
- 证据：`FACT-ad44783ba931`
- 风险项指纹：`RISK-ff973669bdee`
- 建议动态测试：`tool_timeout`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### 节点 `llm` · 决策模型

节点类型：`LLM`；风险项：4；最高等级：`CRITICAL`

#### [CRITICAL] data_protection · 决策模型：敏感数据保护控制不足

责任节点“决策模型”在“敏感数据保护控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`CRITICAL`；最大潜在等级：`CRITICAL`
- 代表路径：`llm`；路径变体：1
- 合并证据实例：3
- 规则映射：LLM-004, FLOW-008, LLM-011
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-c342c5c90be4`, `FACT-dfb118a177f7`, `FACT-018db969148c`
- 风险项指纹：`RISK-1185ebbc88b5`
- 建议动态测试：`credential_context_exposure`, `system_prompt_and_credential_leakage`（本次未执行）
- 修复建议：
  - 从 DSL 移除明文凭证，使用运行时密钥引用，并保证凭证不进入模型上下文。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

#### [HIGH] untrusted_content_boundary · 决策模型：外部内容信任边界不足

知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。

- 状态：`PROBABLE`；置信度：0.90
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`kb → llm → http`；路径变体：1
- 合并证据实例：1
- 规则映射：FLOW-005, KB-005, LLM-003
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/3`
- 证据：`FACT-fc8d90f5e830`, `FACT-546eb56f2701`, `FACT-50be1cb79f0b`
- 风险项指纹：`RISK-318279210f4f`
- 建议动态测试：`rag_to_tool_injection`, `indirect_prompt_injection`, `knowledge_controlled_tool`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

#### [HIGH] instruction_boundary · 决策模型：模型指令与数据边界不足

责任节点“决策模型”在“模型指令与数据边界不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`kb → llm`；路径变体：3
- 合并证据实例：3
- 规则映射：KB-004, LLM-001, LLM-002, IN-009
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/0`
- 证据：`FACT-dea702265759`, `FACT-9e43b2cb8c71`, `FACT-be9267c28068`, `FACT-11309d7a66f1`
- 风险项指纹：`RISK-59724d4c5b14`
- 建议动态测试：`rag_system_prompt_injection`, `direct_or_indirect_prompt_injection`, `instruction_data_boundary`, `direct_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。
  - 将固定指令保留在 system/developer 消息中，将待处理内容放入 user 消息或明确的数据容器。
  - 使用已确认的正常、对抗和边界样例验证任务目标不会被输入内容覆盖。

#### [MEDIUM] resilience_budget · 决策模型：失败处理与资源预算不足

LLM 节点缺少可识别的 Token、重试、超时或预算限制。

- 状态：`PROBABLE`；置信度：0.80
- 当前证据等级：`MEDIUM`；最大潜在等级：`MEDIUM`
- 代表路径：`llm`；路径变体：1
- 合并证据实例：1
- 规则映射：LLM-009
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-91101ff7dec6`
- 风险项指纹：`RISK-3830078f85df`
- 建议动态测试：`resource_budget`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### 节点 `kb` · 企业敏感知识库

节点类型：`KNOWLEDGE`；风险项：2；最高等级：`HIGH`

#### [HIGH] knowledge_governance · 企业敏感知识库：知识资产治理控制不足

责任节点“企业敏感知识库”在“知识资产治理控制不足”方面存在 4 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`PROBABLE`；置信度：0.85
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`kb`；路径变体：1
- 合并证据实例：4
- 规则映射：KB-001, KB-002, KB-003, KB-008
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-8fdf8b561594`, `FACT-55c4ecb9530d`, `FACT-4fc3be561f9a`, `FACT-dd03e9b6672c`
- 风险项指纹：`RISK-c2fba5e9f127`
- 缺失上下文：若平台在 DSL 外强制租户隔离，应在内部基线中登记。
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

#### [HIGH] untrusted_content_boundary · 企业敏感知识库：外部内容信任边界不足

检索内容进入模型前缺少可识别的注入筛查或隔离控制。

- 状态：`PROBABLE`；置信度：0.85
- 当前证据等级：`HIGH`；最大潜在等级：`HIGH`
- 代表路径：`kb`；路径变体：1
- 合并证据实例：1
- 规则映射：KB-009
- DSL 位置：`/workflow/graph/nodes/1`
- 证据：`FACT-640c7a7c0c1f`
- 风险项指纹：`RISK-99966d7cc527`
- 建议动态测试：`rag_indirect_prompt_injection`（本次未执行）
- 修复建议：
  - 限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。

### 节点 `start` · 用户输入

节点类型：`INPUT`；风险项：1；最高等级：`MEDIUM`

#### [MEDIUM] input_contract · 用户输入：输入契约与边界控制不足

责任节点“用户输入”在“输入契约与边界控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 当前证据等级：`MEDIUM`；最大潜在等级：`HIGH`
- 代表路径：`start`；路径变体：1
- 合并证据实例：3
- 规则映射：IN-002, IN-006
- DSL 位置：`/workflow/graph/nodes/0`
- 证据：`FACT-d3980431b8ae`, `FACT-a428f408d1de`, `FACT-2ff4d43c2b2e`
- 风险项指纹：`RISK-7a6029a46ab6`
- 建议动态测试：`sensitive_input_propagation`（本次未执行）
- 修复建议：
  - 为输入定义严格类型、长度、枚举和额外字段策略。

## 覆盖缺口

- `LLM-010`：DSL 未显示模型失败、拒答或解析失败后的安全回退策略。
- `OUT-008`：输出节点未显示低置信或失败回退行为。
- `IN-004`：DSL 未声明输入解码和 Unicode 规范化控制。
- `KB-010`：知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
