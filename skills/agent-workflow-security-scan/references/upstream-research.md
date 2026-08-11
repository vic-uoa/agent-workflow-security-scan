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

## 三阶段的本地映射

1. 信息收集映射为 `01-workflow-ir.json` 与 `03-semantic-inventory.json`：确定节点、能力、资产、信任边界、不变量和有前置条件的攻击假设。
2. 分类检测映射为 `02-security-facts.json`、`04-rule-candidates.json` 与 `05-test-cluster.json`：确定性规则先产生事实，模型只补充语义和安全测试变体。
3. 复核映射为 `06-llm-adjudication.json` 与 `07-verification.json`：独立模型只能降级或要求上下文，不能创造确定性事实或把候选提升为 `CONFIRMED`。

这种映射保留了上游“先收集、再分类检测、最后复核”的稳定性，同时避免把动态对话结果伪装成 DSL 静态结论。
