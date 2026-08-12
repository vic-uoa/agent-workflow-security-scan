# Workflow 静态安全扫描报告：non-strict-schema

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`940a278ec9308bfbcfdd6c19575fa11946573d11874376bbebf4066214d9f7e6`
- 节点/边：4 / 3
- Finding 数：5
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：HIGH=4、MEDIUM=1
- 证据状态：CONFIRMED=3、PROBABLE=2、COVERAGE_GAP=1
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：4
- 类型分布：negative=4
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### HIGH · FLOW-003, TOOL-008

攻击族：general_workflow_security

- 路径：`start → llm → tool`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-8f84f3d9b496, TC-32c4f7cf49fb

### HIGH · LLM-005, LLM-006, OUT-006, LLM-008

攻击族：general_workflow_security

- 路径：`llm → tool`
- 状态：`CONFIRMED, PROBABLE`
- 建议测试用例（未执行）：TC-82600a16c1b4, TC-1fcf8b4bb548

## Findings

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm → tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-1ce58e786784`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] LLM-005 · 自由文本直接控制工具

LLM 自由文本输出可直接影响工具参数。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`llm → tool`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-4251f6ea6034`, `FACT-b50035a187e1`, `FACT-22f64fdc334c`
- 根因指纹：`ROOT-c97fbc9b9613`
- 关联规则（不重复计数）：LLM-006, OUT-006
- 建议动态测试：`free_text_tool_control`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] LLM-008 · 高影响决策无确定性复核

LLM 输出可触发高影响操作，路径中缺少确定性复核证据。

- 状态：`PROBABLE`；置信度：0.88
- 节点：`llm → tool`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-7641c3cbfc99`
- 建议动态测试：`high_impact_model_decision`（本次未执行）
- 修复建议：
  - 将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。

### [HIGH] TOOL-008 · 高影响操作缺少必经审批

高影响工具存在不经过审批节点的可达路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → llm → tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-0c7f731b69a8`
- 建议动态测试：`high_impact_action_approval`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-011 · 工具输入缺少严格 Schema

工具输入缺少可识别的严格 Schema。

- 状态：`PROBABLE`；置信度：0.80
- 节点：`tool`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-d2631fec976a`
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

## 覆盖缺口

- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
