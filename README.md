# Agent Workflow Security Scan

面向公司内部 Dify 二开平台的 Workflow DSL 静态安全扫描器。

项目从导出的 YAML/JSON DSL 中提取节点、变量、参数绑定和图路径，结合安全规则生成证据、风险链、攻击面、质量门禁和报告。当前版本只做静态分析，不启动工作流，也不会执行生成的攻击输入。

## 适用范围

当前扫描范围包括：

- 输入节点、LLM 节点、工具节点、输出节点和知识库节点；
- 跨节点变量传递、污点传播、审批绕过和高风险调用路径；
- 用户输入样例扩展出的正例、反例、边界和攻击输入簇；
- 面向后续沙盒动态验证的测试计划，但不执行动态测试。

本项目固定面向内部 Dify 二开平台，并读取导出 DSL 的 `version`、节点类型和字段契约；未知或未来版本会形成覆盖缺口，不会按已知字段语义强行判定。

## 检测原理

规则匹配不是简单的关键词命中。扫描器会综合使用：

1. DSL 字段和配置条件；
2. 生产者到消费者的变量绑定；
3. 不可信或敏感数据到危险汇点的污点路径；
4. 绕过校验、授权或人工审批的图路径；
5. 工具注册信息、能力类型和参数可控性；
6. 带节点、事实和规则引用的受约束语义判断。

关键词只用于识别候选能力，不能单独证明一个安全控制或敏感资产存在，也不能直接产生确定性漏洞结论。扫描器会区分凭证明文、敏感字段名、模板占位符、明确标注示例、未标注代码块、安全说明、运行时数据和知识数据；Dify 原生 `secret/password/credential/token` 值类型直接作为类型化资产。降置信上下文不会抹掉提供商 Token 或具体凭证形态，只会将其降为待复核候选。Dify `End`/`Answer` 默认分别表示工作流调用方响应和当前用户输出，不等价于网络写入。

复合外泄链要求同时具备：不可信来源、指令绑定、类型化敏感资产、同一模型上下文、类型化载荷路径、攻击者可观察 Sink，以及不存在覆盖全部路径的已验证强制脱敏。任一关键前提未知时只能形成候选或覆盖缺口；字段名候选不能形成完整外泄链。只有所有路径均经过可信注册或可静态验证的强制控制时才记录为 `MITIGATED`，普通 DLP 字段和无法验证实现的自声明控制不会抑制风险。用户、知识或工具内容若被直接插入 system/developer 消息，按已确认配置缺陷处理；模型是否真正被劫持由独立动态测试记录。进入条件、机器消费、自动决策或高后果动作时再提高严重度。

扫描器同时检查生产者—消费者类型契约、`LLM → 解析代码 → 机器消费`、`不可信文本 → 解析字段 → 条件分支` 和条件分支专属模型的异常串联。固定代码只有在严格校验、拒绝未知/重复值并失败关闭时才可作为控制；模型端点、调用方身份和下游自动化若不在 DSL 中，仅记录覆盖缺口。

扫描链路如下：

```text
DSL 与输入样例
  -> Workflow IR
  -> 确定性安全事实
  -> 规则候选与输入簇
  -> 可选语义复核
  -> 引用与证据校验
  -> 最终 Findings
  -> 攻击面 / 动态测试计划 / 质量门禁 / 报告
```

## 规则覆盖

当前规则库包含 77 条规则：

| 规则族 | 数量 | 主要检查内容 |
|---|---:|---|
| `FLOW` | 16 | 图完整性、污点路径、审批绕过、注入与外泄链、类型契约、派生路由和跨分支完整性 |
| `IN` | 9 | 类型、长度、文件约束、规范化、敏感输入、持久化、直接 Prompt Injection |
| `LLM` | 12 | 指令层级、上下文信任、工具/解析代码控制、结构化输出、授权、预算、回退、Prompt 泄露和端点覆盖 |
| `TOOL` | 17 | 参数控制、SSRF、命令/SQL/路径注入、对象级授权、审批、密钥、超时、供应链 |
| `OUT` | 11 | 输出结构、敏感信息披露、富文本与链接风险、Web 外泄、引用、回退和下游消费边界 |
| `KB` | 12 | 数据集范围、租户过滤、检索阈值、间接注入、记忆污染、来源和运行时缺口 |

规则元数据位于 [`core-rules.yml`](skills/agent-workflow-security-scan/rules/core-rules.yml)，详细说明见 [`rule-catalog.md`](skills/agent-workflow-security-scan/references/rule-catalog.md)。

## 快速开始

环境要求：Python 3.10+。

```powershell
cd .\skills\agent-workflow-security-scan
python -m pip install -r .\scripts\requirements.txt
```

使用内置风险样例执行一次纯静态扫描：

```powershell
python .\scripts\scan_workflow.py scan `
  --dsl .\tests\fixtures\risky-workflow.yml `
  --samples .\tests\fixtures\samples.json `
  --output ..\..\outputs\demo-scan `
  --llm disabled
```

风险样例触发 `FAIL` 时，命令退出码为 `1`，这是质量门禁的预期结果，不代表程序运行异常。

扫描自己的 DSL：

```powershell
python .\scripts\scan_workflow.py scan `
  --dsl <workflow.yml> `
  --samples <samples.json> `
  --output <output-directory> `
  --llm disabled
```

`--samples` 可省略。样例文件格式可参考 [`demo-static-user-inputs.json`](skills/agent-workflow-security-scan/examples/demo-static-user-inputs.json)。

## 大模型参与方式

确定性解析、图分析、规则判断和质量门禁不依赖大模型。

- `--llm disabled`：完全离线，适合基线扫描和 CI；
- `--llm enabled`：强制启用语义复核，需要经过批准的 API Key 和数据发送策略。

大模型只负责补充业务语义、适用性、反证和假设，不能修改解析事实，也不能把候选问题提升为 `CONFIRMED`。模型返回的节点、事实、路径和规则引用会在进入最终报告前再次校验。

作为 Skill 使用时，Agent 可以直接解释扫描产物，但应以 `08-findings.json` 和确定性证据为准。

## 输出结果

每次扫描只输出一份自包含 HTML 报告，不保存 Workflow IR、规则候选、输入簇、Finding、攻击面或 Markdown 等中间文件。所有这些对象仅在扫描进程内用于确定性匹配、校验和页面渲染，进程结束后不会留在报告目录中。

`--output <报告根目录>` 会自动生成与上传 DSL 文件同名的目录：

```text
<报告根目录>/
└─ <工作流文件名>/
   └─ <工作流文件名>-安全扫描报告.html
```

报告包含：发布门禁与风险概览、由 DSL 转换的完整 Workflow 流程图、可筛选风险详情，以及每条风险逻辑链的高亮流程图。图形均为内嵌 SVG，不需要另存截图、加载第三方资源或打开额外中间文件。

## 结论与门禁

证据状态：

- `CONFIRMED`：存在确定的 DSL、配置、参数绑定或图路径证据；
- `PROBABLE`：结构路径成立，但仍依赖语义或运行时前提；
- `CANDIDATE`：需要人工或动态验证的候选问题；
- `COVERAGE_GAP`：DSL 无法提供所需运行时事实；
- `MITIGATED`：风险路径存在，但被已验证且不可绕过的强制控制阻断。

默认质量门禁：

| 结果 | 条件 |
|---|---|
| `FAIL` | 存在未豁免的 `CONFIRMED` 且严重度为 `CRITICAL` 或 `HIGH` |
| `REVIEW` | 没有阻断项，但存在 `MEDIUM` 及以上的 `CONFIRMED/PROBABLE/OBSERVED/CANDIDATE/COVERAGE_GAP` |
| `PASS` | 没有阻断项或中等级以上待复核项；LOW/INFO/OBSERVED 仍作为加固建议保留 |

`PASS` 只表示在当前规则、基线和 DSL 可见范围内没有阻断项，不表示工作流不存在任何漏洞。

## 验证

运行单元测试：

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

运行企业场景验证矩阵：

```powershell
python .\scripts\validate_enterprise_suite.py `
  --output ..\..\outputs\enterprise-validation
```

当前验证集包含安全基线、审批保护、审批绕过、关键词伪装控制、参数精度、非严格 Schema、间接注入和综合风险链等场景。

## 项目结构

```text
skills/agent-workflow-security-scan/
├─ SKILL.md                  # Agent 交互流程和安全约束
├─ config/                   # 内部基线与豁免示例
├─ examples/                 # DSL 和输入样例
├─ references/               # 规则、产物和运营说明
├─ rules/                    # 可审计的规则元数据
├─ schemas/                  # DSL、规则和中间产物 Schema
├─ scripts/                  # 扫描器、报告生成和验证脚本
└─ tests/                    # 单元测试与安全场景 DSL
```

## 静态扫描边界

仅凭 DSL 无法证明以下运行时事实：

- 实际 IAM、RBAC/ABAC 和对象级授权是否生效；
- 工具或插件内部实现是否安全；
- 网络出口策略和知识库 ACL 是否按声明执行；
- 模型在真实运行中的行为是否稳定；
- 动态执行环境是否具备有效沙盒隔离。

这些问题会记录为 `COVERAGE_GAP`、语义前提或动态测试任务，不会被包装成已经确认的漏洞。后续动态执行应在默认拒绝外网、使用合成凭据、禁止真实副作用并设置资源上限的隔离沙盒中完成。

## 参考与来源

规则设计参考 OWASP AISVS、OWASP Agentic Top 10、OWASP LLMSVS、MITRE ATLAS、NIST AI 100-2，并结合 [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) 中与 Agent/Workflow 相关的安全思路进行了适合静态 Dify DSL 的重新建模。具体映射和归属见 [`upstream-research.md`](skills/agent-workflow-security-scan/references/upstream-research.md)。
