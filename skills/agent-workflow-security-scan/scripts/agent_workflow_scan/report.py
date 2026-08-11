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
    for case in test_cluster.get("cases", []):
        if not isinstance(case, dict):
            continue
        for rule_id in case.get("rule_ids", []):
            case_by_rule.setdefault(str(rule_id), []).append(str(case.get("case_id")))

    paths = []
    for finding in findings:
        if len(finding.node_ids) < 2 and finding.severity not in {"HIGH", "CRITICAL"}:
            continue
        paths.append({
            "attack_path_id": stable_id("AP", finding.id),
            "finding_id": finding.id,
            "rule_ids": [finding.rule_id],
            "attack_family": finding.attack_family,
            "entrypoint_node": finding.node_ids[0] if finding.node_ids else None,
            "target_node": finding.node_ids[-1] if finding.node_ids else None,
            "path": finding.node_ids,
            "status": finding.status,
            "severity": finding.severity,
            "attack_preconditions": finding.attack_preconditions,
            "missing_runtime_context": finding.missing_context,
            "test_case_ids": case_by_rule.get(finding.rule_id, []),
            "description": finding.message,
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

    return {
        "entrypoints": entrypoints,
        "assets": semantic.get("assets", []),
        "trust_boundaries": semantic.get("trust_boundaries", []),
        "capabilities": capabilities,
        "attack_paths": paths,
        "risk_chains": risk_chains,
        "semantic_attack_hypotheses": semantic.get("attack_hypotheses", []),
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
    severity_counts = Counter(finding.severity for finding in findings)
    status_counts = Counter(finding.status for finding in findings)
    return {
        "summary": {
            "workflow_id": ir.workflow_id,
            "workflow_hash": ir.workflow_hash,
            "node_count": len(ir.nodes),
            "edge_count": len(ir.edges),
            "finding_count": len(findings),
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
        "attack_surface": attack_surface,
        "test_cluster_summary": {
            "case_count": len(tests.get("cases", [])),
            "case_ids": [case.get("case_id") for case in tests.get("cases", []) if isinstance(case, dict)],
        },
        "priority_actions": explanation.get("priority_actions", []),
        "verification": verification,
        "quality_gate": quality_gate,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    findings = report.get("findings", [])
    lines = [
        f"# Workflow 静态安全扫描报告：{summary['workflow_id']}",
        "",
        "## 扫描摘要",
        "",
        summary.get("executive_summary") or "扫描完成。",
        "",
        f"- Workflow Hash：`{summary['workflow_hash']}`",
        f"- 节点/边：{summary['node_count']} / {summary['edge_count']}",
        f"- Finding 数：{summary['finding_count']}",
        f"- 严重等级：{_format_counts(summary.get('severity_counts', {}))}",
        f"- 证据状态：{_format_counts(summary.get('status_counts', {}))}",
        f"- 发布门禁：`{report.get('quality_gate', {}).get('decision', 'UNKNOWN')}`",
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
                f"- 动态用例：{', '.join(path.get('test_case_ids', [])) or '待生成'}",
                "",
            ])
    else:
        lines.extend(["未形成可展示的跨节点攻击链。", ""])

    lines.extend(["## Findings", ""])
    if not findings:
        lines.extend(["未发现规则命中；仍需查看覆盖缺口和运行时验证范围。", ""])
    for finding in findings:
        locations = ", ".join(f"`{item}`" for item in finding.get("dsl_locations", [])) or "无"
        evidence = ", ".join(f"`{item}`" for item in finding.get("evidence_refs", [])) or "无"
        nodes = " → ".join(finding.get("node_ids", [])) or "全局"
        lines.extend([
            f"### [{finding['severity']}] {finding['rule_id']} · {finding['title']}",
            "",
            finding.get("message", ""),
            "",
            f"- 状态：`{finding['status']}`；置信度：{finding['confidence']:.2f}",
            f"- 节点：`{nodes}`",
            f"- DSL 位置：{locations}",
            f"- 证据：{evidence}",
        ])
        if finding.get("missing_context"):
            lines.append(f"- 缺失上下文：{'；'.join(finding['missing_context'])}")
        if finding.get("dynamic_test"):
            lines.append(f"- 动态验证：`{finding['dynamic_test']}`")
        if finding.get("waived"):
            lines.append(f"- 豁免：`{finding.get('waiver_id')}`（Finding 保留，仅从门禁阻断项中排除）")
        lines.extend(["- 修复建议："])
        for item in finding.get("remediation", []):
            lines.append(f"  - {item}")
        lines.append("")

    gaps = [finding for finding in findings if finding.get("status") == "COVERAGE_GAP"]
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
