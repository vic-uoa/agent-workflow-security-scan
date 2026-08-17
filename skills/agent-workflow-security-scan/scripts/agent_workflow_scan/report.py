from __future__ import annotations

from collections import Counter
from typing import Any

from .models import Finding, WorkflowIR, stable_id, to_jsonable


def build_attack_surface(
    ir: WorkflowIR,
    semantic: dict[str, Any],
    findings: list[Finding],
    test_cluster: dict[str, Any],
) -> dict[str, Any]:
    entrypoints = []
    for node in ir.nodes:
        if node.type in {"INPUT", "KNOWLEDGE", "CONTENT"}:
            entrypoints.append({
                "entrypoint_id": stable_id("ENTRY", node.id),
                "node_id": node.id,
                "name": node.title,
                "type": node.type,
                "trust": "SEMI_TRUSTED" if node.type == "KNOWLEDGE" else "UNTRUSTED",
                "evidence": [node.json_pointer],
            })
        elif node.type == "TOOL":
            entrypoints.append({
                "entrypoint_id": stable_id("ENTRY", node.id, "output"),
                "node_id": node.id,
                "name": f"工具返回：{node.title}",
                "type": "TOOL_OUTPUT",
                "trust": "UNTRUSTED",
                "evidence": [node.json_pointer],
            })

    case_by_finding: dict[str, list[str]] = {}
    cases_by_id: dict[str, dict[str, Any]] = {}
    for case in test_cluster.get("cases", []):
        if not isinstance(case, dict):
            continue
        cases_by_id[str(case.get("case_id"))] = case
        for finding_id in case.get("finding_ids", []):
            case_by_finding.setdefault(str(finding_id), []).append(str(case.get("case_id")))

    paths = []
    for finding in findings:
        related_cases = []
        route_variants: list[dict[str, Any]] = []
        for case_id in case_by_finding.get(finding.id, []):
            case = cases_by_id.get(case_id, {})
            target_nodes = {str(item) for item in case.get("target_nodes", [])}
            if finding.anchor_node_id and finding.anchor_node_id not in target_nodes:
                continue
            matching_variants = [
                item for item in case.get("route_variants", [])
                if isinstance(item, dict)
                and str(item.get("finding_id")) == finding.id
                and (not finding.anchor_node_id or str(item.get("target_node")) == finding.anchor_node_id)
            ]
            if case.get("route_variants") and not matching_variants:
                continue
            related_cases.append(case_id)
            route_variants.extend(matching_variants or [{
                "finding_id": finding.id,
                "target_node": finding.anchor_node_id,
                "target_path": case.get("target_path", []),
                "route_status": case.get("route_status", "NOT_EVALUATED"),
                "route_constraints": case.get("route_constraints", []),
                "missing_route_context": case.get("missing_route_context", []),
            }])
        variant_paths = [
            item.get("target_path", []) for item in route_variants
            if isinstance(item.get("target_path"), list) and item.get("target_path")
        ]
        path_options = list({
            tuple(path): path for path in (variant_paths or finding.path_variants or [finding.node_ids])
        }.values())
        for path_index, path in enumerate(path_options):
            if len(path) < 2 and finding.severity not in {"HIGH", "CRITICAL"}:
                continue
            instance = next(
                (item for item in finding.instance_summaries if item.get("path") == path), {}
            )
            paths.append({
                "attack_path_id": stable_id("AP", finding.id, path_index, *path),
                "finding_id": finding.id,
                "anchor_node_id": finding.anchor_node_id,
                "control_domain": finding.control_domain,
                "rule_ids": instance.get("rule_ids", [finding.rule_id, *finding.related_rule_ids]),
                "attack_family": finding.attack_family,
                "entrypoint_node": path[0] if path else None,
                "target_node": path[-1] if path else None,
                "path": path,
                "status": instance.get("status", finding.status),
                "severity": instance.get("severity", finding.severity),
                "attack_preconditions": list(dict.fromkeys([
                    *finding.attack_preconditions,
                    *(
                        f"{item.get('variable')} {item.get('operator')} {item.get('value')!r}"
                        for variant in route_variants if variant.get("target_path") == path
                        for item in variant.get("route_constraints", [])
                    ),
                ])),
                "missing_runtime_context": list(dict.fromkeys([
                    *finding.missing_context,
                    *(
                        message
                        for variant in route_variants if variant.get("target_path") == path
                        for message in variant.get("missing_route_context", [])
                    ),
                ])),
                "test_case_ids": list(dict.fromkeys(related_cases)),
                "planned_test_coverage": bool(related_cases),
                "route_satisfiable": any(
                    variant.get("target_path") == path and variant.get("route_status") == "SATISFIABLE"
                    for variant in route_variants
                ),
                "execution_status": "NOT_EXECUTED",
                "description": instance.get("message", finding.message),
            })

    capabilities = [{
        "node_id": node.id,
        "name": node.title,
        "capabilities": node.capabilities,
        "external": node.external,
        "high_impact": node.high_impact,
    } for node in ir.nodes if node.capabilities]

    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    correlated: dict[tuple[str, ...], dict[str, Any]] = {}
    for item in paths:
        key = tuple(item.get("path", [])) or (str(item.get("target_node") or "global"),)
        bucket = correlated.setdefault(key, {
            "risk_chain_id": stable_id("CHAIN", *key),
            "path": list(key),
            "entrypoint_node": item.get("entrypoint_node"),
            "target_node": item.get("target_node"),
            "finding_ids": [],
            "rule_ids": [],
            "attack_families": [],
            "severity": item.get("severity", "INFO"),
            "statuses": [],
            "test_case_ids": [],
            "attack_preconditions": [],
            "missing_runtime_context": [],
        })
        bucket["finding_ids"].append(item["finding_id"])
        bucket["rule_ids"].extend(item.get("rule_ids", []))
        bucket["attack_families"].append(item.get("attack_family", "general_workflow_security"))
        bucket["statuses"].append(item.get("status"))
        bucket["test_case_ids"].extend(item.get("test_case_ids", []))
        bucket["attack_preconditions"].extend(item.get("attack_preconditions", []))
        bucket["missing_runtime_context"].extend(item.get("missing_runtime_context", []))
        if severity_rank.get(str(item.get("severity")), -1) > severity_rank.get(str(bucket["severity"]), -1):
            bucket["severity"] = item["severity"]
    risk_chains = []
    for bucket in correlated.values():
        for field in ("finding_ids", "rule_ids", "attack_families", "statuses", "test_case_ids", "attack_preconditions", "missing_runtime_context"):
            bucket[field] = list(dict.fromkeys(item for item in bucket[field] if item))
        risk_chains.append(bucket)
    risk_chains.sort(key=lambda item: (-severity_rank.get(item["severity"], -1), item["risk_chain_id"]))

    planned_findings = sorted({
        finding_id for case in test_cluster.get("cases", []) if isinstance(case, dict)
        for finding_id in case.get("finding_ids", [])
    })
    reachable_findings = sorted({
        str(variant.get("finding_id"))
        for case in test_cluster.get("cases", []) if isinstance(case, dict)
        for variant in case.get("route_variants", []) if isinstance(variant, dict)
        if variant.get("route_status") == "SATISFIABLE" and variant.get("finding_id")
    })
    return {
        "entrypoints": entrypoints,
        "assets": semantic.get("assets", []),
        "trust_boundaries": semantic.get("trust_boundaries", []),
        "capabilities": capabilities,
        "attack_paths": paths,
        "risk_chains": risk_chains,
        "semantic_attack_hypotheses": semantic.get("attack_hypotheses", []),
        "test_coverage": {
            "covered_finding_ids": planned_findings,
            "coverage_term_notice": "covered_finding_ids is planned static coverage, not executed validation",
            "planned_finding_ids": planned_findings,
            "route_satisfiable_finding_ids": reachable_findings,
            "executed_finding_ids": [],
            "passed_finding_ids": [],
            "unplanned_finding_ids": sorted(
                finding.id for finding in findings
                if finding.status != "COVERAGE_GAP" and finding.id not in planned_findings
            ),
            "execution_evidence_present": False,
            "note": "计划覆盖、路径可达覆盖和执行覆盖分开统计；所有用例均未执行，不能改变 Finding 的证据状态。",
        },
        "missing_runtime_context": sorted({
            item for finding in findings for item in finding.missing_context
        }),
    }


def build_dynamic_plan(ir: WorkflowIR, attack_surface: dict[str, Any], test_cluster: dict[str, Any]) -> dict[str, Any]:
    return {
        "workflow_id": ir.workflow_id,
        "workflow_hash": ir.workflow_hash,
        "execution_authorized": False,
        "sandbox_policy": {
            "default_level": "L2",
            "network": "deny_by_default",
            "credentials": "synthetic_short_lived_only",
            "filesystem": "read_only_fixtures",
            "side_effects": "mock_or_block",
            "high_consequence_actions": "mock_or_block; human confirmation only when the test itself requires user consent",
            "resource_limits_required": ["cpu", "memory", "wall_time", "token_budget", "max_iterations"],
        },
        "attack_paths": attack_surface.get("attack_paths", []),
        "risk_chains": attack_surface.get("risk_chains", []),
        "test_cases": test_cluster.get("cases", []),
    }


def build_report_json(
    ir: WorkflowIR,
    findings: list[Finding],
    semantic: dict[str, Any],
    tests: dict[str, Any],
    attack_surface: dict[str, Any],
    explanation: dict[str, Any],
    verification: dict[str, Any],
    quality_gate: dict[str, Any],
) -> dict[str, Any]:
    issues = [finding for finding in findings if finding.status != "COVERAGE_GAP"]
    gaps = [finding for finding in findings if finding.status == "COVERAGE_GAP"]
    serialized_findings: list[dict[str, Any]] = []
    for finding in findings:
        item = to_jsonable(finding)
        serialized_findings.append(item)
    severity_counts = Counter(finding.severity for finding in issues)
    status_counts = Counter(finding.status for finding in findings)
    deterministic_summary = (
        f"静态扫描形成 {len(issues)} 个节点风险项和 {len(gaps)} 个覆盖缺口；"
        f"其中 CONFIRMED={status_counts.get('CONFIRMED', 0)}、"
        f"PROBABLE={status_counts.get('PROBABLE', 0)}、"
        f"OBSERVED={status_counts.get('OBSERVED', 0)}、"
        f"CANDIDATE={status_counts.get('CANDIDATE', 0)}。"
        f"发布门禁为 {quality_gate.get('decision', 'UNKNOWN')}。"
    )
    node_map = ir.node_map()
    node_risk_summary = []
    for anchor in dict.fromkeys(finding.anchor_node_id or "workflow" for finding in issues):
        items = [finding for finding in issues if (finding.anchor_node_id or "workflow") == anchor]
        node = node_map.get(anchor)
        node_risk_summary.append({
            "node_id": anchor,
            "node_title": node.title if node else "Workflow",
            "node_type": node.type if node else "WORKFLOW",
            "risk_item_count": len(items),
            "risk_item_ids": [finding.id for finding in items],
            "control_domains": list(dict.fromkeys(finding.control_domain for finding in items)),
            "highest_severity": max(
                (finding.severity for finding in items),
                key=lambda value: {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value, -1),
            ),
        })
    return {
        "summary": {
            "workflow_id": ir.workflow_id,
            "workflow_hash": ir.workflow_hash,
            "node_count": len(ir.nodes),
            "edge_count": len(ir.edges),
            "finding_count": len(issues),
            "risk_item_count": len(issues),
            "evidence_instance_count": sum(len(finding.instance_summaries) or 1 for finding in issues),
            "raw_observation_count": len(findings),
            "coverage_gap_count": len(gaps),
            "severity_counts": dict(severity_counts),
            "status_counts": dict(status_counts),
            "waived_count": sum(finding.waived for finding in findings),
            "executive_summary": deterministic_summary,
            "agent_narrative": explanation.get("executive_summary", ""),
        },
        "workflow": {
            "nodes": [{"id": node.id, "title": node.title, "type": node.type, "capabilities": node.capabilities} for node in ir.nodes],
            "edges": [to_jsonable(edge) for edge in ir.edges],
        },
        "semantic_inventory": semantic,
        "findings": serialized_findings,
        "node_risk_summary": node_risk_summary,
        "attack_surface": attack_surface,
        "test_cluster_summary": {
            "case_count": len(tests.get("cases", [])),
            "case_ids": [case.get("case_id") for case in tests.get("cases", []) if isinstance(case, dict)],
            "case_type_counts": dict(Counter(
                str(case.get("case_type", "unknown"))
                for case in tests.get("cases", []) if isinstance(case, dict)
            )),
            "seed_sample_ids": tests.get("generation_audit", {}).get("seed_sample_ids", []),
            "lineage_verified": tests.get("generation_audit", {}).get("lineage_verified", False),
            "unique_input_count": tests.get("generation_audit", {}).get("unique_input_count", 0),
            "exact_duplicate_input_count": tests.get("generation_audit", {}).get("exact_duplicate_input_count", 0),
            "unchanged_derived_case_count": tests.get("generation_audit", {}).get("unchanged_derived_case_count", 0),
            "route_satisfiable_case_count": tests.get("generation_audit", {}).get("route_satisfiable_case_count", 0),
            "route_partial_case_count": tests.get("generation_audit", {}).get("route_partial_case_count", 0),
            "route_unreachable_case_count": tests.get("generation_audit", {}).get("route_unreachable_case_count", 0),
            "planned_case_count": tests.get("generation_audit", {}).get("planned_case_count", len(tests.get("cases", []))),
            "executed_case_count": tests.get("generation_audit", {}).get("executed_case_count", 0),
            "execution_evidence_present": False,
        },
        "priority_actions": explanation.get("priority_actions", []),
        "model_advisory_summary": verification.get("model_advisory", {
            "enabled": False,
            "authority": "none_over_findings_severity_or_gate",
            "allowed_uses": ["additional_inert_test_proposals", "non_authoritative_report_wording"],
        }),
        "verification": verification,
        "quality_gate": quality_gate,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    all_findings = report.get("findings", [])
    findings = [finding for finding in all_findings if finding.get("status") != "COVERAGE_GAP"]
    gate = report.get("quality_gate", {}).get("decision", "UNKNOWN")
    lines = [
        f"# Workflow 静态安全扫描报告：{summary['workflow_id']}",
        "",
        "## 一页结论",
        "",
        summary.get("executive_summary") or "扫描完成。",
        "",
        "| 指标 | 结果 | 如何理解 |",
        "|---|---:|---|",
        f"| 发布门禁 | `{gate}` | FAIL 表示存在未豁免的 CONFIRMED 高/严重风险；REVIEW 表示需要人工或运行时核验 |",
        f"| 节点风险项 | {summary.get('risk_item_count', summary['finding_count'])} | 已按“责任节点 + 控制域”去重，不等同于原始规则命中数 |",
        f"| 规则/路径证据实例 | {summary.get('evidence_instance_count', summary['finding_count'])} | 作为风险项明细保留，不重复计数 |",
        f"| 严重等级 | {_table_cell(_format_counts(summary.get('severity_counts', {})))} | 表示若风险成立的潜在影响 |",
        f"| 证据状态 | {_table_cell(_format_counts(summary.get('status_counts', {})))} | 表示静态证据强度，不等同于漏洞已被利用 |",
        f"| 覆盖缺口 | {summary.get('coverage_gap_count', 0)} | DSL 无法证明的运行时控制，不直接算作漏洞 |",
        f"| 工作流规模 | {summary['node_count']} 节点 / {summary['edge_count']} 边 | 本次静态分析范围 |",
        "",
        "### 风险项总览",
        "",
        "| 风险项 | 责任节点 | 控制域 | 等级 / 状态 | 为什么报告 | 优先措施 |",
        "|---|---|---|---|---|---|",
    ]
    if findings:
        for finding in findings:
            remediation = (finding.get("remediation") or ["人工复核并补充匹配控制"])[0]
            lines.append(
                f"| `{finding['id']}` | `{finding.get('anchor_node_id') or 'workflow'}` | "
                f"{_table_cell(_control_domain_label(finding.get('control_domain', '')))} | "
                f"`{finding['severity']}` / `{finding['status']}` | "
                f"{_table_cell(finding.get('message', ''))} | {_table_cell(remediation)} |"
            )
    else:
        lines.append("| — | — | — | — | 未形成风险项 | — |")

    cluster = report.get("test_cluster_summary", {})
    advisory = report.get("model_advisory_summary", {})
    advisory_enabled = bool(advisory.get("enabled"))
    lines.extend([
        "",
        "### 证据状态说明",
        "",
        "| 状态 | 含义 | 用户动作 |",
        "|---|---|---|",
        "| `CONFIRMED` | DSL 中存在确定的配置或可达路径事实 | 优先修复；模型不能降低或修改 |",
        "| `PROBABLE` | 路径成立，但利用条件或业务影响依赖语义/运行时 | 人工核对前提，并安排沙盒验证 |",
        "| `OBSERVED` | 确认存在某种弱点，但尚不足以证明安全影响 | 作为加固项评估 |",
        "| `CANDIDATE` | 确定性规则只能形成候选，尚缺充分成项证据 | 必须复核，不能静默 PASS |",
        "| `COVERAGE_GAP` | DSL 看不到相关运行时控制 | 补充平台/IAM/网络等证据 |",
        "",
        "## 输入簇与证据边界",
        "",
        "| 项目 | 结果 |",
        "|---|---|",
        f"| 用户确认的正常样例 | {len(cluster.get('seed_sample_ids', []))} |",
        f"| 派生用例总数 | {cluster.get('case_count', 0)} |",
        f"| 实际不同输入 | {cluster.get('unique_input_count', 0)} |",
        f"| 完全重复输入 | {cluster.get('exact_duplicate_input_count', 0)} |",
        f"| 未发生变化的派生用例 | {cluster.get('unchanged_derived_case_count', 0)} |",
        f"| 用例类型 | {_table_cell(_format_counts(cluster.get('case_type_counts', {})))} |",
        f"| 路径可满足 | {cluster.get('route_satisfiable_case_count', 0)} |",
        f"| 路径部分可解 | {cluster.get('route_partial_case_count', 0)} |",
        f"| 路径不可达 | {cluster.get('route_unreachable_case_count', 0)} |",
        f"| 血缘校验 | `{'通过' if cluster.get('lineage_verified') else '未通过或无样例'}` |",
        f"| 实际执行 | {cluster.get('executed_case_count', 0)}；输入簇只用于规划攻击面和生成沙盒计划，不能确认或排除 Finding |",
        "",
        "## 模型参与边界",
        "",
        f"本次模式：`{'确定性扫描 + 可选模型顾问' if advisory_enabled else '仅确定性扫描'}`。"
        + ("模型只补充未执行测试建议和非权威表述，不参与 Finding、严重度或门禁。" if advisory_enabled else "没有调用模型，全部风险结论和门禁均来自确定性逻辑。"),
        "",
        "| 组件 | 可以做什么 | 明确禁止 |",
        "|---|---|---|",
        "| 确定性扫描器 | 解析 DSL、提取事实、匹配规则、聚合根因、计算状态/严重度和门禁 | 根据模型意见改写结论 |",
        "| 可选模型顾问 | 补充安全且未执行的测试思路；润色非权威说明 | 新增、删除、升级或降级 Finding；修改严重度和门禁；声称测试已执行 |",
        "",
        "## 关键攻击链",
        "",
        "| 等级 | 状态 | 路径 | 规则映射 | 关联风险项 | 建议用例（未执行） |",
        "|---|---|---|---|---|---|",
    ])
    attack_paths = report.get("attack_surface", {}).get("risk_chains", [])
    if attack_paths:
        for path in attack_paths[:20]:
            chain = " → ".join(path.get("path", [])) or "单节点"
            lines.append(
                f"| `{path['severity']}` | {_table_cell(', '.join(path.get('statuses', [])))} | "
                f"`{_table_cell(chain)}` | {_table_cell(', '.join(path.get('rule_ids', [])))} | "
                f"{_table_cell(', '.join(path.get('finding_ids', [])))} | "
                f"{_table_cell(', '.join(path.get('test_case_ids', [])) or '待生成')} |"
            )
    else:
        lines.append("| — | — | — | — | — | 未形成可展示的攻击链 |")

    lines.extend(["", "完整的入口、资产、信任边界和能力清单见 `attack-surface.md`。", "", "## 节点风险项明细", ""])
    if not findings:
        lines.extend(["未发现规则命中；仍需查看覆盖缺口和运行时验证范围。", ""])
    node_summaries = report.get("node_risk_summary", [])
    for node_summary in node_summaries:
        node_id = node_summary["node_id"]
        node_findings = [finding for finding in findings if (finding.get("anchor_node_id") or "workflow") == node_id]
        lines.extend([
            f"### 节点 `{node_id}` · {node_summary['node_title']}",
            "",
            f"节点类型：`{node_summary['node_type']}`；风险项：{node_summary['risk_item_count']}；最高等级：`{node_summary['highest_severity']}`",
            "",
        ])
        for finding in node_findings:
            locations = ", ".join(f"`{item}`" for item in finding.get("dsl_locations", [])) or "无"
            evidence = ", ".join(f"`{item}`" for item in finding.get("evidence_refs", [])) or "无"
            nodes = " → ".join(finding.get("node_ids", [])) or "全局"
            lines.extend([
                f"#### [{finding['severity']}] {finding.get('control_domain', 'general_security_control')} · {finding['title']}",
                "",
                finding.get("message", ""),
                "",
                f"- 状态：`{finding['status']}`；置信度：{finding['confidence']:.2f}",
                f"- 当前证据等级：`{finding['severity']}`；最大潜在等级：`{finding.get('potential_severity') or finding['severity']}`",
                f"- 代表路径：`{nodes}`；路径变体：{len(finding.get('path_variants', [])) or 1}",
                f"- 合并证据实例：{len(finding.get('instance_summaries', [])) or 1}",
                f"- 规则映射：{', '.join([finding['rule_id'], *finding.get('related_rule_ids', [])])}",
                f"- DSL 位置：{locations}",
                f"- 证据：{evidence}",
            ])
            if finding.get("root_cause_id"):
                lines.append(f"- 风险项指纹：`{finding['root_cause_id']}`")
            if finding.get("missing_context"):
                lines.append(f"- 缺失上下文：{'；'.join(finding['missing_context'])}")
            if finding.get("dynamic_tests") or finding.get("dynamic_test"):
                tests = finding.get("dynamic_tests") or [finding["dynamic_test"]]
                lines.append(f"- 建议动态测试：{', '.join(f'`{item}`' for item in tests)}（本次未执行）")
            if finding.get("waived"):
                lines.append(f"- 豁免：`{finding.get('waiver_id')}`（风险项保留，仅从门禁阻断项中排除）")
            lines.extend(["- 修复建议："])
            for item in finding.get("remediation", []):
                lines.append(f"  - {item}")
            lines.append("")

    gaps = [finding for finding in all_findings if finding.get("status") == "COVERAGE_GAP"]
    lines.extend(["## 覆盖缺口", ""])
    if gaps:
        for finding in gaps:
            lines.append(f"- `{finding['rule_id']}`：{finding['message']}")
    else:
        lines.append("本次未记录额外覆盖缺口。")
    lines.extend([
        "",
        "## 使用边界",
        "",
        "本报告没有执行 Workflow。生成用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。文件哈希仅保存在机器产物中用于防止扫描对象被替换，不需要用户确认。",
        "",
    ])
    return "\n".join(lines)


def render_attack_surface_markdown(ir: WorkflowIR, attack_surface: dict[str, Any]) -> str:
    node_map = ir.node_map()

    def node_name(node_id: Any) -> str:
        key = str(node_id or "")
        node = node_map.get(key)
        return f"{key}（{node.title}）" if node else key or "—"

    lines = [
        f"# Workflow 攻击面：{ir.workflow_id}",
        "",
        "本文件是面向人工阅读的攻击面视图；`09-attack-surface.json` 保留相同信息供程序消费。所有测试用例均未执行。",
        "",
        "## 入口",
        "",
        "| 节点 | 类型 | 信任级别 | 证据位置 |",
        "|---|---|---|---|",
    ]
    for item in attack_surface.get("entrypoints", []):
        lines.append(
            f"| {_table_cell(node_name(item.get('node_id')))} | `{item.get('type', '')}` | "
            f"`{item.get('trust', '')}` | {_table_cell(', '.join(item.get('evidence', [])))} |"
        )
    if not attack_surface.get("entrypoints"):
        lines.append("| — | — | — | 未识别入口 |")

    lines.extend(["", "## 资产", "", "| 资产 | 敏感级别 | 关联节点 | 置信度 |", "|---|---|---|---:|"])
    for item in attack_surface.get("assets", []):
        lines.append(
            f"| {_table_cell(item.get('name', ''))} | `{item.get('sensitivity', '')}` | "
            f"{_table_cell(', '.join(node_name(value) for value in item.get('node_ids', [])))} | "
            f"{float(item.get('confidence', 0)):.2f} |"
        )
    if not attack_surface.get("assets"):
        lines.append("| — | — | — | 0.00 |")

    lines.extend(["", "## 信任边界", "", "| 来源域 | 目标域 | 经过节点 | 置信度 |", "|---|---|---|---:|"])
    for item in attack_surface.get("trust_boundaries", []):
        lines.append(
            f"| `{item.get('from_zone', '')}` | `{item.get('to_zone', '')}` | "
            f"{_table_cell(', '.join(node_name(value) for value in item.get('node_ids', [])))} | "
            f"{float(item.get('confidence', 0)):.2f} |"
        )
    if not attack_surface.get("trust_boundaries"):
        lines.append("| — | — | 未识别信任边界 | 0.00 |")

    lines.extend(["", "## 节点能力", "", "| 节点 | 能力 | 外部调用 | 高影响能力 |", "|---|---|---|---|"])
    for item in attack_surface.get("capabilities", []):
        lines.append(
            f"| {_table_cell(node_name(item.get('node_id')))} | {_table_cell(', '.join(item.get('capabilities', [])))} | "
            f"{'是' if item.get('external') else '否'} | {'是' if item.get('high_impact') else '否'} |"
        )
    if not attack_surface.get("capabilities"):
        lines.append("| — | — | — | — |")

    lines.extend([
        "",
        "## 攻击链",
        "",
        "| 等级 | 状态 | 入口 → 目标 | 完整路径 | 风险项 | 前提/缺失上下文 | 未执行用例 |",
        "|---|---|---|---|---|---|---|",
    ])
    for item in attack_surface.get("risk_chains", []):
        path = " → ".join(node_name(value) for value in item.get("path", [])) or "单节点"
        conditions = [*item.get("attack_preconditions", []), *item.get("missing_runtime_context", [])]
        lines.append(
            f"| `{item.get('severity', '')}` | {_table_cell(', '.join(item.get('statuses', [])))} | "
            f"{_table_cell(node_name(item.get('entrypoint_node')))} → {_table_cell(node_name(item.get('target_node')))} | "
            f"{_table_cell(path)} | {_table_cell(', '.join(item.get('finding_ids', [])))} | "
            f"{_table_cell('；'.join(conditions) or '无额外前提记录')} | "
            f"{_table_cell(', '.join(item.get('test_case_ids', [])) or '待生成')} |"
        )
    if not attack_surface.get("risk_chains"):
        lines.append("| — | — | — | — | — | 未形成可展示攻击链 | — |")

    coverage = attack_surface.get("test_coverage", {})
    lines.extend([
        "",
        "## 测试覆盖边界",
        "",
        f"- 已规划用例的风险项：{', '.join(coverage.get('planned_finding_ids', [])) or '无'}",
        f"- 已证明路径可满足的风险项：{', '.join(coverage.get('route_satisfiable_finding_ids', [])) or '无'}",
        f"- 已执行风险项：{', '.join(coverage.get('executed_finding_ids', [])) or '无'}",
        f"- 未规划风险项：{', '.join(coverage.get('unplanned_finding_ids', [])) or '无'}",
        "- 执行证据：无。计划覆盖或路径可达不代表漏洞已经得到动态确认。",
        "",
    ])
    return "\n".join(lines)


def _format_counts(counts: dict[str, int]) -> str:
    return "、".join(f"{key}={value}" for key, value in counts.items()) or "无"


def _table_cell(value: Any) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", "<br>")


def _control_domain_label(value: str) -> str:
    labels = {
        "structure_coverage": "结构与覆盖",
        "input_contract": "输入契约",
        "instruction_boundary": "指令边界",
        "memory_identity_scope": "记忆与身份隔离",
        "untrusted_content_boundary": "不可信内容边界",
        "action_authorization": "动作授权",
        "data_protection": "数据保护",
        "egress_control": "网络外发控制",
        "execution_boundary": "执行边界",
        "structured_data_contract": "结构化数据契约",
        "resilience_budget": "韧性与资源预算",
        "output_safety": "输出安全",
        "knowledge_governance": "知识治理",
        "supply_chain": "供应链",
        "agent_governance": "Agent 治理",
    }
    return labels.get(value, value or "通用安全控制")
