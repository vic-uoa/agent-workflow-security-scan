# Workflow 静态安全扫描报告：non-strict-schema

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`940a278ec9308bfbcfdd6c19575fa11946573d11874376bbebf4066214d9f7e6`
- 节点/边：4 / 3
- 节点风险项：2
- 规则/路径证据实例：5（不重复计为风险项）
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：HIGH=2
- 证据状态：CONFIRMED=2、COVERAGE_GAP=1
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：4
- 类型分布：negative=4
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### HIGH · TOOL-008

攻击族：general_workflow_security

- 路径：`start → llm → tool`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-2041e398bda4, TC-b5743ca1f646, TC-67cf3348adad

### HIGH · LLM-005, LLM-006, OUT-006, LLM-008

攻击族：general_workflow_security

- 路径：`llm → tool`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-791f53f9564d, TC-2041e398bda4, TC-b5743ca1f646, TC-67cf3348adad

### MEDIUM · TOOL-011

攻击族：general_workflow_security

- 路径：`tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-791f53f9564d

## 节点风险项

### 节点 `tool` · send-email

节点类型：`TOOL`；风险项：2；最高等级：`HIGH`

#### [HIGH] structured_data_contract · send-email：结构化数据契约不足

责任节点“send-email”在“结构化数据契约不足”方面存在 2 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`llm → tool`；路径变体：2
- 合并证据实例：2
- 规则映射：LLM-005, TOOL-011, LLM-006, OUT-006
- DSL 位置：`/workflow/graph/nodes/2`, `/workflow/graph/nodes/1`
- 证据：`FACT-d2631fec976a`, `FACT-4251f6ea6034`, `FACT-b50035a187e1`, `FACT-22f64fdc334c`
- 风险项指纹：`RISK-d24112f5fd2c`
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

#### [HIGH] action_authorization · send-email：高影响动作授权控制不足

责任节点“send-email”在“高影响动作授权控制不足”方面存在 3 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 代表路径：`start → llm → tool`；路径变体：2
- 合并证据实例：3
- 规则映射：TOOL-008, FLOW-003, LLM-008
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-0c7f731b69a8`, `FACT-1ce58e786784`, `FACT-7641c3cbfc99`
- 风险项指纹：`RISK-808c4fa56b05`
- 建议动态测试：`high_impact_action_approval`, `source_to_high_impact_sink`, `high_impact_model_decision`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

## 覆盖缺口

- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
