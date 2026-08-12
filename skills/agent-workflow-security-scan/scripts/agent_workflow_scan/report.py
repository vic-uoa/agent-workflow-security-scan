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

    case_by_rule: dict[str, list[str]] = {}
    case_by_finding: dict[str, list[str]] = {}
    for case in test_cluster.get("cases", []):
        if not isinstance(case, dict):
            continue
        for rule_id in case.get("rule_ids", []):
            case_by_rule.setdefault(str(rule_id), []).append(str(case.get("case_id")))
        for finding_id in case.get("finding_ids", []):
            case_by_finding.setdefault(str(finding_id), []).append(str(case.get("case_id")))

    paths = []
    for finding in findings:
        related_cases = [
            *case_by_finding.get(finding.id, []),
            *(case_id for rule_id in (finding.rule_id, *finding.related_rule_ids) for case_id in case_by_rule.get(rule_id, [])),
        ]
        for path_index, path in enumerate(finding.path_variants or [finding.node_ids]):
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
                "attack_preconditions": finding.attack_preconditions,
                "missing_runtime_context": finding.missing_context,
                "test_case_ids": list(dict.fromkeys(related_cases)),
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

    covered_findings = sorted({
        finding_id for case in test_cluster.get("cases", []) if isinstance(case, dict)
        for finding_id in case.get("finding_ids", [])
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
            "covered_finding_ids": covered_findings,
            "uncovered_finding_ids": sorted(
                finding.id for finding in findings
                if finding.status != "COVERAGE_GAP" and finding.id not in covered_findings
            ),
            "execution_evidence_present": False,
            "note": "输入簇与静态根因已关联，但所有用例均未执行，不能改变 Finding 的证据状态。",
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
            "high_impact_actions": "human_approval_required",
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
    severity_counts = Counter(finding.severity for finding in issues)
    status_counts = Counter(finding.status for finding in findings)
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
            "executive_summary": explanation.get("executive_summary", ""),
        },
        "workflow": {
            "nodes": [{"id": node.id, "title": node.title, "type": node.type, "capabilities": node.capabilities} for node in ir.nodes],
            "edges": [to_jsonable(edge) for edge in ir.edges],
        },
        "semantic_inventory": semantic,
        "findings": [to_jsonable(finding) for finding in findings],
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
            "execution_evidence_present": False,
        },
        "priority_actions": explanation.get("priority_actions", []),
        "verification": verification,
        "quality_gate": quality_gate,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    all_findings = report.get("findings", [])
    findings = [finding for finding in all_findings if finding.get("status") != "COVERAGE_GAP"]
    lines = [
        f"# Workflow 静态安全扫描报告：{summary['workflow_id']}",
        "",
        "## 扫描摘要",
        "",
        summary.get("executive_summary") or "扫描完成。",
        "",
        f"- Workflow Hash：`{summary['workflow_hash']}`",
        f"- 节点/边：{summary['node_count']} / {summary['edge_count']}",
        f"- 节点风险项：{summary.get('risk_item_count', summary['finding_count'])}",
        f"- 规则/路径证据实例：{summary.get('evidence_instance_count', summary['finding_count'])}（不重复计为风险项）",
        f"- 覆盖缺口数：{summary.get('coverage_gap_count', 0)}（不计入 Finding）",
        f"- 严重等级：{_format_counts(summary.get('severity_counts', {}))}",
        f"- 证据状态：{_format_counts(summary.get('status_counts', {}))}",
        f"- 发布门禁：`{report.get('quality_gate', {}).get('decision', 'UNKNOWN')}`",
        "",
        "## 输入簇与证据边界",
        "",
        f"- 用户种子样例：{len(report.get('test_cluster_summary', {}).get('seed_sample_ids', []))}",
        f"- 派生用例：{report.get('test_cluster_summary', {}).get('case_count', 0)}",
        f"- 类型分布：{_format_counts(report.get('test_cluster_summary', {}).get('case_type_counts', {}))}",
        f"- 血缘校验：`{'通过' if report.get('test_cluster_summary', {}).get('lineage_verified') else '未通过或无样例'}`",
        "- 执行证据：`无`。输入簇只用于攻击面覆盖和沙盒测试计划，不用于确认或排除漏洞。",
        "",
        "## 关键攻击链",
        "",
    ]
    attack_paths = report.get("attack_surface", {}).get("risk_chains", [])
    if attack_paths:
        for path in attack_paths[:20]:
            chain = " → ".join(path.get("path", [])) or "单节点"
            rule_ids = path.get("rule_ids", [])
            families = path.get("attack_families", [])
            lines.extend([
                f"### {path['severity']} · {', '.join(rule_ids)}",
                "",
                f"攻击族：{', '.join(families) or 'general_workflow_security'}",
                "",
                f"- 路径：`{chain}`",
                f"- 状态：`{', '.join(path.get('statuses', []))}`",
                f"- 建议测试用例（未执行）：{', '.join(path.get('test_case_ids', [])) or '待生成'}",
                "",
            ])
    else:
        lines.extend(["未形成可展示的跨节点攻击链。", ""])

    lines.extend(["## 节点风险项", ""])
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
        "## 动态阶段说明",
        "",
        "本报告没有执行 Workflow。生成的测试用例必须在默认禁网、假凭证、只读测试数据和资源配额约束的沙盒中运行。",
        "",
    ])
    return "\n".join(lines)


def _format_counts(counts: dict[str, int]) -> str:
    return "、".join(f"{key}={value}" for key, value in counts.items()) or "无"
