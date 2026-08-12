# Workflow 静态安全扫描报告：approval-branch-bypass

## 扫描摘要

扫描已完成。报告中的确定性证据、语义候选和覆盖缺口已分开呈现。

- Workflow Hash：`027bcdc15888de1c4fc8a97414142f2b0604537927b9f39df3c6410e973c1ee8`
- 节点/边：4 / 4
- 节点风险项：1
- 规则/路径证据实例：1（不重复计为风险项）
- 覆盖缺口数：0（不计入 Finding）
- 严重等级：HIGH=1
- 证据状态：CONFIRMED=1
- 发布门禁：`FAIL`

## 输入簇与证据边界

- 用户种子样例：0
- 派生用例：1
- 类型分布：negative=1
- 血缘校验：`通过`
- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。

## 关键攻击链

### HIGH · FLOW-006

攻击族：general_workflow_security

- 路径：`approve → delete_tool`
- 状态：`CONFIRMED`
- 建议测试用例（未执行）：TC-1d98ed022c8a

## 节点风险项

### [HIGH] FLOW-006 · delete resource：高影响动作授权控制不足

人工审批的拒绝/取消分支仍可到达高影响工具。

- 状态：`CONFIRMED`；置信度：1.00
- 责任节点：`delete_tool`；控制域：`action_authorization`
- 代表路径：`approve → delete_tool`；路径变体：1
- 合并证据实例：1
- DSL 位置：`/workflow/graph/nodes/1`, `/workflow/graph/nodes/2`
- 证据：`FACT-2647bae3efca`
- 根因指纹：`RISK-1a396cfa0e2b`
- 建议动态测试：`approval_branch_bypass`（本次未执行）
- 修复建议：
  - 在风险路径的必经位置增加确定性控制，并验证不存在旁路。

## 覆盖缺口

本次未记录额外覆盖缺口。

## 动态阶段说明

本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。
