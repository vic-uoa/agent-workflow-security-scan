# Workflow 静态安全扫描报告：keyword-spoofed-control

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`40460deac52ea45b02588aaef8ae4f3cc512ced4539c6c0a5bb078e726e6492e`
- 节点/边：4 / 3
- Finding 数：4
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：HIGH=4
- 证据状态：CONFIRMED=3、PROBABLE=1、COVERAGE_GAP=1
- 发布门禁：`FAIL`

## 关键攻击链

### HIGH · TOOL-002

攻击族：general_workflow_security

- 路径：`fake_control → delete_tool`
- 状态：`CONFIRMED`
- 动态用例：TC-73f3fe334555

### HIGH · FLOW-003, TOOL-008

攻击族：general_workflow_security

- 路径：`start → fake_control → delete_tool`
- 状态：`CONFIRMED`
- 动态用例：TC-e11095a39582, TC-e4d1f363b684

### HIGH · TOOL-015

攻击族：authorization_bypass

- 路径：`delete_tool`
- 状态：`PROBABLE`
- 动态用例：TC-ccc55054d931

## Findings

### [HIGH] FLOW-003 · 不可信输入到高危工具

不可信数据存在绕开确定性校验/审批到达高危工具的路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → fake_control → delete_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-0a5266f18265`
- 建议动态测试：`source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

### [HIGH] TOOL-002 · 高危工具参数由模型控制

高影响工具的安全敏感参数由模型或上游变量控制。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`fake_control → delete_tool`
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-7bf40816dbd9`
- 建议动态测试：`model_controlled_tool_argument`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-008 · 高影响操作缺少必经审批

高影响工具存在不经过审批节点的可达路径。

- 状态：`CONFIRMED`；置信度：1.00
- 节点：`start → fake_control → delete_tool`
- DSL 位置：`/workflow/graph/nodes/0`, `/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-5ce38353b965`
- 建议动态测试：`high_impact_action_approval`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [HIGH] TOOL-015 · 高影响工具缺少对象级授权约束

高影响工具未声明 subject-object-action、所有权或租户范围的确定性授权检查。

- 状态：`PROBABLE`；置信度：0.86
- 节点：`delete_tool`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-da3eb68a5f22`
- 缺失上下文：平台统一身份认证不等同于对象级授权；需要确认工具执行端是否重新授权。
- 建议动态测试：`authorization_bypass`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

### [MEDIUM] TOOL-009 · 工具能力超出业务目的

高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

- 状态：`COVERAGE_GAP`；置信度：1.00
- 节点：`delete_tool`
- DSL 位置：`/workflow/graph/nodes/2`
- 证据：`FACT-459ede83c546`
- 缺失上下文：tool_business_purpose；allowed_operations
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。

## 覆盖缺口

- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
