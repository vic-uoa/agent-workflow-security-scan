# Tencent AI-Infra-Guard 对照与静态化说明

## 使用边界

本 Skill 参考了 Tencent AI-Infra-Guard 的 Agent Scan 分类、三阶段检测思路和公开测试场景，但没有复制其检测 Prompt 或实现代码。AI-Infra-Guard 的 Agent Scan 是动态黑盒检测；本项目面向公司内部 Dify 二开平台的 DSL 静态分析，检测的是攻击成立所需的结构性前置条件，并把运行时确认项输出到沙盒动态计划。

- 上游项目：[Tencent/AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)
- Agent Scan：[agent-scan](https://github.com/Tencent/AI-Infra-Guard/tree/main/agent-scan)
- 检测 Skill 目录：[prompt/skills](https://github.com/Tencent/AI-Infra-Guard/tree/main/agent-scan/agent_scan/prompt/skills)
- 上游许可证：Apache License 2.0；使用或分发上游代码时应保留其许可证和归属。本实现仅进行独立规则转译，仍在文档和规则元数据中保留来源链接。
- OWASP 基准：[Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- OWASP 工程控制：[Securing Agentic Applications Guide 1.0](https://genai.owasp.org/download/49059/?tmstv=1753666640)
- Dify DSL 实现参考：[app_dsl_service.py](https://github.com/langgenius/dify/blob/main/api/services/app_dsl_service.py)
- NIST TEVV：[AI Test, Evaluation, Validation and Verification](https://www.nist.gov/ai-test-evaluation-validation-and-verification-tevv) 与 [AI RMF Measure](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)。本 Skill 据此记录测试集、方法、适用上下文和测量限制，不把未执行用例当作测量结果。
- OWASP Prompt Injection：[LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)。提示注入需要持续渗透测试和边界验证，因此 DSL 可达性只形成静态前置条件，不能单独证明模型会服从攻击输入。
- Promptfoo：[promptfoo/promptfoo](https://github.com/promptfoo/promptfoo)。参考其测试变量、断言和红队数据集分离方式；本 Skill 进一步将用户种子、派生方式、安全不变量与禁止副作用显式写入每个用例。

## 独立校准依据

本轮规则不以“规则越多越安全”为目标，而以攻击成立所需的能力、数据路径和可验证影响为成项门槛：

- [AgentDojo](https://github.com/ethz-spylab/agentdojo) 同时测量正常任务效用和攻击任务安全结果。因此静态规则不能只计算危险词命中；必须保留正常任务可用性，测试簇也必须包含正例。
- [AgentDyn](https://arxiv.org/abs/2602.03117) 指出现有防御在真实开放任务上可能出现显著 over-defense。由此将“任意外部内容进入模型”“任意工具无审批”“任意 RAG 无引用”等宽泛条件改为能力和影响敏感条件。
- [ToolEmu](https://arxiv.org/abs/2309.15817) 通过沙盒场景和人工评估验证 Agent 风险，其自动评估识别的失败并非全部是真实失败。由此禁止模型独立创建或确认 Finding，并要求未执行输入簇保持 `NOT_EXECUTED`。
- [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant) 的示例规则关注具体轨迹组合，例如外部网页输出之后调用发送邮件工具，而非孤立地把网页读取或邮件工具本身判为漏洞。本 Skill 相应采用“源 → 模型/控制点 → 副作用汇”的路径规则。
- [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 将目标劫持、工具滥用、身份与权限滥用、供应链、代码执行、记忆投毒等区分为不同风险域；这些域在同一节点上也不能互相替代或合并。
- Dify 的[知识检索实现](https://github.com/langgenius/dify/blob/main/api/core/workflow/nodes/knowledge_retrieval/knowledge_retrieval_node.py) 会把运行上下文的 tenant/user/app 标识传给检索请求，同时元数据过滤是独立配置。因此“DSL 没有 metadata filter”不能自动推出跨租户漏洞；只有动态/多业务数据范围且缺少业务分区约束时才成项。
- Dify Code 节点使用独立的 [dify-sandbox](https://github.com/langgenius/dify-sandbox) 执行代码；Dify 的部署配置还提供代码执行连接/读写超时、结果大小和工作流步数上限。固定函数接收工作流变量是正常数据处理；只有变量进入命令/解释器字段、整个代码体被模板控制或代码使用危险执行原语时，才进入命令/代码注入攻击簇。沙盒真实隔离强度仍不由 DSL 静态扫描确认。

据此采用四个报告门槛：存在危险能力、存在可达数据/控制路径、缺少对应确定性控制、影响与业务语义匹配。任何一项不满足，都应不成项或降为观察/覆盖，而不能写成确认漏洞。

## 从动态行为到静态前置条件

| 上游检测族 | DSL 静态证据 | 本地规则 | 仍需动态沙盒确认 |
|---|---|---|---|
| Authorization bypass | 用户可控 tenant/user/resource/role 参数；高影响工具无对象级授权策略 | TOOL-015/016 | 工具端是否重新鉴权、是否能跨用户/租户读取或修改 |
| Data leakage / hardcoded secret | Prompt、工具配置、输出路径中的凭证/PII/系统信息；敏感源到外部边界 | FLOW-004/008/009、LLM-004/011、TOOL-010/017、OUT-002/003 | 模型是否实际泄露、编码或拆分敏感信息 |
| Direct injection | 用户输入到 LLM 的数据路径；系统指令无角色覆盖/目标劫持边界 | IN-009、LLM-001/002 | 模型是否服从覆盖标记或泄露系统内容 |
| Indirect injection | RAG、网页、工具返回进入 LLM，再到工具/输出/代码执行 | FLOW-005/010、LLM-003、TOOL-012、KB-004/005/009 | 模型是否执行外部内容中的指令 |
| Tool abuse / SSRF / path traversal | 动态 URL、命令、代码、SQL、文件路径；缺少 allowlist/schema/base directory | TOOL-002..006、TOOL-011 | 实际网络、文件、解释器和命令边界 |
| Web exfiltration | 敏感上下文 + 动态网络目标/载荷；动态 Markdown 图片或链接 | FLOW-009、TOOL-017、OUT-009 | URL 路径/查询分片、连续导航、客户端取链行为 |
| Memory poisoning | 不可信写入持久记忆；无用户/租户命名空间；后续 Agent 读取 | KB-007/011/012、IN-008 | 跨会话是否保存、跨用户是否可见、后续回合是否服从 |
| Agentic supply chain | 工具未进入内部注册表，或缺少可信来源、固定版本和完整性控制 | TOOL-014 | 插件/工具代码签名、发布审批和真实依赖完整性 |
| Unexpected code execution | 外部内容经模型到 code/shell 节点；动态执行参数 | FLOW-010、TOOL-004 | 沙盒逃逸、真实解释器行为和副作用 |
| Inter-agent communication | LLM/Agent 到下游 Agent 的自由文本通道无 Schema/来源验证 | FLOW-011 | 消息身份伪造、上下文污染和跨 Agent 权限扩张 |
| Cascading failure | 多个副作用节点串联且无幂等、熔断、补偿、失败关闭 | FLOW-007/012 | 重试风暴、重复执行、部分失败和恢复行为 |
| Human-agent trust exploit | 面向人的审批、验证、可信或紧急声明无可验证来源 | OUT-010 | 用户界面是否诱导高风险操作、审批证据是否可伪造 |
| Rogue agents | 自主 Agent 接收不可信上下文、可达高危能力且缺少目标锁定/停止边界 | FLOW-013 | 是否偏离目标、隐藏行为或拒绝紧急停止 |

## 五阶段的本地映射

1. 用户已明确指定唯一 YAML/YML 时直接进入流程；仅在目标缺失或歧义时询问。扫描器在后台记录文件名和哈希以防对象被替换，不要求用户确认哈希。
2. 用户提供并确认业务种子输入及预期行为；不要求用户预先编写攻击集。
3. `01` 至 `04` 完成确定性静态解析、事实提取、全规则匹配和根因聚合；`04` 同时保留聚合前的全部命中。模型不参与规则裁决、状态、严重度或门禁。
4. `05-test-cluster.json` 从种子和静态根因派生正例、反例、边界、变形和规则定向用例；每项保留血缘与 `NOT_EXECUTED` 状态。
5. `08` 与 `09` 将静态根因和测试覆盖关联成报告及攻击面；可选模型只能补充未执行测试建议和非权威表述。

该顺序保证先检测再生成测试，避免模型根据自己生成的攻击样例反向证明风险。动态执行结果只有在独立沙盒记录请求、响应、断言和副作用证据后，才可进入后续验证流程。
