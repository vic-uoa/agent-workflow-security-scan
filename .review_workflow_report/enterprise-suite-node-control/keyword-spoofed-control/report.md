# Workflow 静态安全扫描报告：keyword-spoofed-control

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`40460deac52ea45b02588aaef8ae4f3cc512ced4539c6c0a5bb078e726e6492e`
- 节点/边：4 / 3
- 节点风险项：1
- 规则/路径证据实例：4（不重复计为风险项）
- 覆盖缺口数：1（不计入 Finding）
- 严重等级：HIGH=1
- 证据状态：CONFIRMED=1、COVERAGE_GAP=1
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：4
- 类型分布：negative=4
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### HIGH · TOOL-002

攻击族：general_workflow_security

- 路径：`fake_control → delete_tool`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-b57ee2b049a1, TC-683ced3d8628, TC-07320d749342, TC-7893dc175f34

### HIGH · TOOL-008

攻击族：general_workflow_security

- 路径：`start → fake_control → delete_tool`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-b57ee2b049a1, TC-683ced3d8628, TC-07320d749342, TC-7893dc175f34

### HIGH · TOOL-015

攻击族：general_workflow_security

- 路径：`delete_tool`
- 状态：`PROBABLE`
- 建议测试用例（未执行）：TC-b57ee2b049a1, TC-683ced3d8628, TC-07320d749342, TC-7893dc175f34

## 节点风险项

### [HIGH] TOOL-002 · delete resource：高影响动作授权控制不足

责任节点“delete resource”在“高影响动作授权控制不足”方面存在 4 个规则或路径实例；主项按最强静态证据定级，具体影响见实例明细。

- 状态：`CONFIRMED`；置信度：1.00
- 责任节点：`delete_tool`；控制域：`action_authorization`
- 代表路径：`fake_control → delete_tool`；路径变体：3
- 合并证据实例：4
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`, `/workflow/graph/nodes/0`
- 证据：`FACT-7bf40816dbd9`, `FACT-5ce38353b965`, `FACT-da3eb68a5f22`, `FACT-0a5266f18265`
- 根因指纹：`RISK-1a396cfa0e2b`
- 关联规则（不重复计数）：TOOL-008, TOOL-015, FLOW-003
- 缺失上下文：平台统一身份认证不等同于对象级授权；需要确认工具执行端是否重新授权。
- 建议动态测试：`model_controlled_tool_argument`, `high_impact_action_approval`, `authorization_bypass`, `source_to_high_impact_sink`（本次未执行）
- 修复建议：
  - 对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

## 覆盖缺口

- `TOOL-009`：高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
