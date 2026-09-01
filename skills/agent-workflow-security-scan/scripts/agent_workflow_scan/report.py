from __future__ import annotations

from collections import Counter
from html import escape
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
    mitigated_paths = []
    coverage_gap_paths = []
    candidate_paths = []
    for finding in findings:
        if finding.status in {"MITIGATED", "NOT_APPLICABLE"}:
            mitigated_paths.append({
                "finding_id": finding.id,
                "rule_ids": [finding.rule_id, *finding.related_rule_ids],
                "path_variants": finding.path_variants or [finding.node_ids],
                "counter_evidence": finding.counter_evidence,
                "status": finding.status,
            })
            continue
        if finding.status == "CANDIDATE":
            candidate_paths.append({
                "finding_id": finding.id,
                "rule_ids": [finding.rule_id, *finding.related_rule_ids],
                "path_variants": finding.path_variants or [finding.node_ids],
                "missing_context": finding.missing_context,
                "status": finding.status,
            })
            continue
        if finding.status == "COVERAGE_GAP":
            coverage_gap_paths.append({
                "finding_id": finding.id,
                "rule_ids": [finding.rule_id, *finding.related_rule_ids],
                "path_variants": finding.path_variants or [finding.node_ids],
                "missing_context": finding.missing_context,
                "status": finding.status,
            })
            continue
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
            route_variants.extend([
                {**variant, "_case_id": case_id}
                for variant in (matching_variants or [{
                "finding_id": finding.id,
                "target_node": finding.anchor_node_id,
                "target_path": case.get("target_path", []),
                "route_status": case.get("route_status", "NOT_EVALUATED"),
                "route_constraints": case.get("route_constraints", []),
                "missing_route_context": case.get("missing_route_context", []),
                }])
            ])
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
            path_case_ids = list(dict.fromkeys(
                str(variant.get("_case_id"))
                for variant in route_variants
                if variant.get("target_path") == path and variant.get("_case_id")
            ))
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
                "test_case_ids": path_case_ids,
                "planned_test_coverage": bool(path_case_ids),
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
        if item.get("severity") in {"LOW", "INFO"}:
            continue
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
        "advisory_paths": [item for item in paths if item.get("severity") in {"LOW", "INFO"}],
        "mitigated_paths": mitigated_paths,
        "coverage_gap_paths": coverage_gap_paths,
        "candidate_paths": candidate_paths,
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
    issues = [
        finding for finding in findings
        if finding.status not in {"COVERAGE_GAP", "MITIGATED", "NOT_APPLICABLE"}
    ]
    gaps = [finding for finding in findings if finding.status == "COVERAGE_GAP"]
    mitigated = [finding for finding in findings if finding.status == "MITIGATED"]
    action_ids = set(quality_gate.get("blocking_finding_ids", [])) | set(quality_gate.get("review_finding_ids", []))
    action_items = [finding for finding in issues if finding.id in action_ids]
    advisories = [finding for finding in issues if finding.id not in action_ids]
    serialized_findings: list[dict[str, Any]] = []
    for finding in findings:
        item = to_jsonable(finding)
        serialized_findings.append(item)
    severity_counts = Counter(finding.severity for finding in issues)
    status_counts = Counter(finding.status for finding in findings)
    deterministic_summary = (
        f"静态扫描形成 {len(action_items)} 个需处理风险项、{len(advisories)} 个加固建议、"
        f"{len(gaps)} 个覆盖缺口和 {len(mitigated)} 个已缓解项；"
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
    workflow_nodes = []
    for node in ir.nodes:
        condition_presentation = _condition_presentation(node, node_map)
        workflow_nodes.append({
            "id": node.id,
            "title": node.title,
            "type": node.type,
            "capabilities": node.capabilities,
            "position": ir.raw_metadata.get("canvas_positions", {}).get(node.id),
            **condition_presentation,
        })
    return {
        "summary": {
            "workflow_id": ir.workflow_id,
            "workflow_hash": ir.workflow_hash,
            "node_count": len(ir.nodes),
            "edge_count": len(ir.edges),
            "finding_count": len(issues),
            "risk_item_count": len(issues),
            "action_item_count": len(action_items),
            "advisory_count": len(advisories),
            "mitigated_count": len(mitigated),
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
            "nodes": workflow_nodes,
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


def render_html_report(report: dict[str, Any]) -> str:
    """Render a self-contained, evidence-first HTML report."""
    summary = report["summary"]
    workflow = report.get("workflow", {})
    node_by_id = {str(item.get("id")): item for item in workflow.get("nodes", []) if isinstance(item, dict)}
    findings = [
        item for item in report.get("findings", [])
        if item.get("status") not in {"COVERAGE_GAP", "MITIGATED", "NOT_APPLICABLE"}
    ]
    gate_payload = report.get("quality_gate", {})
    gate = str(gate_payload.get("decision", "UNKNOWN"))
    attack_paths = report.get("attack_surface", {}).get("attack_paths", [])
    severity_counts = summary.get("severity_counts", {})
    report_title = f"{summary.get('workflow_id', 'workflow')} · 安全扫描报告"

    def esc(value: Any) -> str:
        return escape(str(value if value not in (None, "") else "—"), quote=True)

    def severity_label(value: Any) -> str:
        return {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "INFO": "信息"}.get(str(value), str(value))

    def status_label(value: Any) -> str:
        return {
            "CONFIRMED": "已确认",
            "PROBABLE": "较可能",
            "OBSERVED": "加固项",
            "CANDIDATE": "待验证",
        }.get(str(value), str(value))

    def gate_label(value: str) -> str:
        return {"FAIL": "阻断", "REVIEW": "需复核", "PASS": "通过"}.get(value, value)

    def severity_badge(value: Any) -> str:
        key = str(value or "INFO")
        return f'<span class="badge severity {esc(key)}">{esc(severity_label(key))}</span>'

    def status_badge(value: Any) -> str:
        key = str(value or "UNKNOWN")
        return f'<span class="badge status {esc(key)}">{esc(status_label(key))}</span>'

    def node_label(node_id: Any) -> str:
        node = node_by_id.get(str(node_id), {})
        return str(node.get("title") or node_id or "工作流")

    metrics = [
        ("需处理", summary.get("action_item_count", 0)),
        ("已确认", summary.get("status_counts", {}).get("CONFIRMED", 0)),
        ("较可能", summary.get("status_counts", {}).get("PROBABLE", 0)),
        ("工作流", f"{summary.get('node_count', 0)} 节点 · {summary.get('edge_count', 0)} 连线"),
    ]
    metrics_html = "".join(
        f'<div class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>'
        for label, value in metrics
    )

    severity_cards = "".join(
        f'<span class="count-chip {esc(level)}">{esc(severity_label(level))} {esc(count)}</span>'
        for level, count in sorted(severity_counts.items(), key=lambda item: _severity_rank(item[0]), reverse=True)
    ) or '<span class="muted">未形成风险项</span>'
    highest_severity = max(
        (level for level, count in severity_counts.items() if count),
        key=_severity_rank,
        default=None,
    )
    highest_risk_html = (
        severity_badge(highest_severity)
        if highest_severity else '<span class="no-risk">未形成风险项</span>'
    )

    finding_rows = []
    for finding in findings:
        severity = str(finding.get("severity", "INFO"))
        status = str(finding.get("status", "UNKNOWN"))
        remediation = (finding.get("remediation") or ["人工复核并补充匹配控制"])[0]
        node_ids = finding.get("affected_node_ids") or finding.get("node_ids") or []
        path_labels = " → ".join(node_label(node_id) for node_id in node_ids) or "工作流级"
        rules = ", ".join(dict.fromkeys(filter(None, [
            str(finding.get("rule_id", "")),
            *map(str, finding.get("related_rule_ids", [])),
        ])))
        confidence = float(finding.get("confidence") or 0)
        preconditions = "；".join(map(str, finding.get("attack_preconditions", []))) or "—"
        missing_context = "；".join(map(str, finding.get("missing_context", []))) or "—"
        dynamic_tests = list(dict.fromkeys(filter(None, [
            *map(str, finding.get("dynamic_tests", [])),
            str(finding.get("dynamic_test") or ""),
        ])))
        validation = f"本期未纳入 · {', '.join(dynamic_tests)}" if dynamic_tests else "—"
        related_chains = [
            path_item for path_item in attack_paths
            if finding.get("id") == path_item.get("finding_id")
        ]
        bound_chain_sections = []
        for chain_index, chain in enumerate(related_chains):
            path = [str(value) for value in chain.get("path", [])]
            chain_severity = severity
            path_copy = " → ".join(node_label(node_id) for node_id in path) or "未形成节点路径"
            chain_svg_id = f"finding-{finding.get('id')}-{chain_index}"
            open_attribute = " open" if len(related_chains) == 1 else ""
            bound_chain_sections.append(
                f'<details class="bound-chain"{open_attribute}>'
                '<summary class="bound-chain-head"><div><h4>对应逻辑链</h4>'
                f'<p>{esc(path_copy)}</p></div><span>{esc(str(len(path)))} 个节点 · 展开</span></summary>'
                f'<div class="bound-chain-frame">{render_risk_chain_svg(workflow, path, chain_svg_id, chain_severity)}</div>'
                '<div class="bound-chain-meta">'
                f'<span><b>规则</b>{esc("、".join(chain.get("rule_ids", [])) or "—")}</span>'
                '</div></details>'
            )
        bound_chains_html = "".join(bound_chain_sections)
        if not bound_chains_html:
            bound_chains_html = (
                '<div class="bound-chain-empty"><strong>暂无完整逻辑链</strong></div>'
            )
        finding_rows.append(
            '<details class="finding issue-item" '
            f'data-severity="{esc(severity)}" data-status="{esc(status)}">'
            '<summary>'
            '<span class="disclosure" aria-hidden="true">›</span>'
            f'<div class="finding-heading"><div class="badge-row">{severity_badge(severity)}{status_badge(status)}</div>'
            f'<div class="finding-title">{esc(finding.get("title"))}</div>'
            f'<div class="finding-path">{esc(path_labels)}</div></div>'
            f'<span class="finding-side"><span>{esc(str(len(related_chains)))} 条逻辑链</span></span></summary>'
            '<div class="finding-body"><div class="evidence-panel"><h4>判定依据</h4>'
            f'<p>{esc(finding.get("message"))}</p>'
            '</div><div class="remediation-panel"><h4>修复建议</h4>'
            f'<p>{esc(remediation)}</p></div>'
            '<details class="technical"><summary>技术证据</summary><dl>'
            f'<dt>风险编号</dt><dd>{esc(finding.get("id"))}</dd>'
            f'<dt>责任节点</dt><dd>{esc(node_label(finding.get("anchor_node_id")))}</dd>'
            f'<dt>规则映射</dt><dd>{esc(rules or "—")}</dd>'
            f'<dt>证据状态</dt><dd>{esc(status)} · 置信度 {confidence:.2f}</dd>'
            f'<dt>后续验证</dt><dd>{esc(validation)}</dd>'
            f'<dt>攻击前提</dt><dd>{esc(preconditions)}</dd>'
            f'<dt>待核实信息</dt><dd>{esc(missing_context)}</dd>'
            f'<dt>DSL 位置</dt><dd>{esc("； ".join(map(str, finding.get("dsl_locations", []))) or "未记录")}</dd>'
            f'</dl></details>{bound_chains_html}</div></details>'
        )
    findings_html = "".join(finding_rows) or '<div class="empty">未发现需要处理的风险项。</div>'

    workflow_svg = render_workflow_svg(workflow, [], "workflow")
    gate_copy = {
        "FAIL": "存在已确认的高危或严重风险，建议阻断发布。",
        "REVIEW": "存在中危以上的静态证据，需要人工复核后决定是否发布。",
        "PASS": "当前静态证据未触发发布阻断或人工复核。",
    }.get(gate, "请结合风险详情人工判断。")
    style = """
:root{color-scheme:light;--ink:#162033;--muted:#5d6b7d;--canvas:#f5f7fa;--line:#d7e0ea;--surface:#fff;--navy:#142033;--blue:#2563eb;--amber:#9a6700}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.6 Inter,"Microsoft YaHei",Arial,sans-serif}
a{color:inherit}header{background:var(--navy);color:#fff;padding:28px max(24px,calc((100vw - 1220px)/2)) 62px}header h1{margin:0;font-size:28px;letter-spacing:-.02em}header p{margin:4px 0 0;color:#cbd5e1;font-size:13px}
main{max-width:1220px;margin:-38px auto 0;padding:0 22px 32px}.summary-shell{display:grid;grid-template-columns:300px 1fr;background:#fff;border:1px solid rgba(203,213,225,.85);border-radius:16px;overflow:hidden}.decision{padding:20px 24px;background:#f8fafc;border-right:1px solid var(--line)}.decision>small{display:block;color:var(--muted);font-weight:700}.decision>strong{display:block;margin:4px 0;font-size:28px}.decision.REVIEW>strong{color:#9a6700}.decision.FAIL>strong{color:#b42318}.decision.PASS>strong{color:#157f3d}.decision p{margin:4px 0 0;color:#475569;font-size:13px}.decision-risk{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}.decision-risk>span:first-child{color:#475569;font-size:12px}.decision-risk .badge{font-size:12px}.no-risk{color:#157f3d;font-size:12px;font-weight:800}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));align-items:center}.metric{padding:20px;border-right:1px solid #edf1f6}.metric:last-child{border:0}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:4px;font-size:19px;line-height:1.3}
.jump-nav{display:flex;gap:8px;margin:16px 0 2px;overflow:auto}.jump-nav a{text-decoration:none;background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 13px;color:#475569;font-size:13px;white-space:nowrap}.jump-nav a:hover{border-color:#94a3b8;color:#0f172a}.report-section{padding:30px 0;border-bottom:1px solid var(--line);scroll-margin-top:12px}.section-head{display:flex;justify-content:space-between;align-items:end;gap:18px;margin-bottom:16px}.section-head h2{margin:0;font-size:22px;letter-spacing:-.015em}.section-head p{max-width:720px;margin:4px 0 0;color:var(--muted)}
.count-row,.badge-row{display:flex;gap:7px;flex-wrap:wrap}.badge,.count-chip{display:inline-flex;align-items:center;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:800;white-space:nowrap}.severity.CRITICAL,.count-chip.CRITICAL{background:#fee2e2;color:#991b1b}.severity.HIGH,.count-chip.HIGH{background:#ffedd5;color:#9a3412}.severity.MEDIUM,.count-chip.MEDIUM{background:#fef3c7;color:#854d0e}.severity.LOW,.count-chip.LOW{background:#e0f2fe;color:#075985}.severity.INFO,.count-chip.INFO{background:#dcfce7;color:#166534}.status{background:#eef2f7;color:#475569}.status.CONFIRMED{background:#fee2e2;color:#991b1b}.status.PROBABLE{background:#fff7d6;color:#7c5700}.status.OBSERVED{background:#e0f2fe;color:#075985}.status.CANDIDATE{background:#f1f5f9;color:#475569}
.diagram-frame{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px}.workflow-svg{display:block;min-width:780px;width:100%;height:auto}.diagram-note{display:flex;justify-content:flex-end;margin-top:10px;color:var(--muted);font-size:12px}.legend{display:flex;flex-wrap:wrap;gap:12px}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}
.filters{display:flex;gap:10px;flex-wrap:wrap}.filters label{display:grid;gap:4px;color:var(--muted);font-size:12px}.filters select{height:36px;min-width:140px;border:1px solid #cbd5e1;border-radius:8px;padding:0 9px;background:#fff;color:var(--ink)}#findings{display:grid;gap:10px}.finding{background:#fff;border:1px solid var(--line);border-radius:12px;overflow:hidden}.finding>summary{cursor:pointer;list-style:none;padding:15px 17px;display:grid;grid-template-columns:18px minmax(0,1fr) auto;gap:12px;align-items:center}.finding>summary::-webkit-details-marker,.technical>summary::-webkit-details-marker,.bound-chain>summary::-webkit-details-marker{display:none}.disclosure{font-size:24px;color:#94a3b8;transition:transform .18s}.finding[open] .disclosure{transform:rotate(90deg)}.finding-heading{display:grid;grid-template-columns:auto 1fr;gap:5px 12px;align-items:center}.finding-heading .badge-row{grid-row:1/3}.finding-title{font-weight:800}.finding-path{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.finding-side{display:grid;justify-items:end;color:#64748b;font-size:11px}.finding-body{display:grid;grid-template-columns:1.25fr 1fr;gap:14px;padding:0 17px 17px 47px;border-top:1px solid #edf1f6}.finding-body h4{margin:14px 0 6px}.finding-body p{margin:0}.technical{grid-column:1/-1;border-top:1px dashed var(--line);padding-top:10px}.technical>summary{cursor:pointer;color:#475569;font-size:13px}.technical dl{display:grid;grid-template-columns:84px 1fr;gap:5px 10px;margin:10px 0 0;font-size:12px}.technical dt{color:var(--muted)}.technical dd{margin:0;word-break:break-word}.bound-chain{grid-column:1/-1;margin-top:2px;padding-top:14px;border-top:1px solid var(--line)}.bound-chain-head{display:flex;justify-content:space-between;gap:12px;align-items:end;margin-bottom:10px;cursor:pointer;list-style:none}.bound-chain-head h4{margin:0}.bound-chain-head p{margin-top:2px;color:#475569;font-size:12px}.bound-chain-head>span{color:var(--muted);font-size:11px}.bound-chain[open] .bound-chain-head>span{color:#334155}.bound-chain-frame{overflow:auto;background:#f8fafc;border-radius:8px}.bound-chain-frame .workflow-svg{min-width:720px}.bound-chain-meta{display:flex;flex-wrap:wrap;gap:8px 20px;margin-top:8px;color:#64748b;font-size:11px}.bound-chain-meta b{margin-right:5px;color:#334155}.bound-chain-empty{grid-column:1/-1;padding-top:12px;border-top:1px solid var(--line);color:#64748b;font-size:12px}.bound-chain-empty strong{color:#334155}.empty{padding:26px;text-align:center;color:var(--muted)}footer{padding:18px 0;color:var(--muted);font-size:12px}
@media(max-width:880px){header{padding:26px 18px 58px}main{padding:0 12px 24px}.summary-shell{grid-template-columns:1fr}.decision{border-right:0;border-bottom:1px solid var(--line)}.metrics{grid-template-columns:1fr 1fr}.metric:nth-child(2){border-right:0}.metric:nth-child(-n+2){border-bottom:1px solid #edf1f6}.finding-body{grid-template-columns:1fr;padding-left:17px}.technical{grid-column:auto}.finding-heading{display:block}.finding-path{margin-top:5px}.section-head{display:block}.filters{margin-top:12px}}@media print{body{background:#fff}header{padding:18px 20px 48px}main{max-width:none}.jump-nav,.filters{display:none}.report-section{break-inside:avoid}.diagram-frame{box-shadow:none}details{display:block}}
"""
    script = """
const sf=document.getElementById('severityFilter');const st=document.getElementById('statusFilter');
function filterFindings(){document.querySelectorAll('.issue-item').forEach(x=>{x.hidden=!!((sf.value&&x.dataset.severity!==sf.value)||(st.value&&x.dataset.status!==st.value))})}
sf.addEventListener('change',filterFindings);st.addEventListener('change',filterFindings);
"""
    return f'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(report_title)}</title>
<style>{style}</style>
</head>
<body><header><h1>{esc(report_title)}</h1><p>静态规则扫描</p></header>
<main>
<section class="summary-shell" id="overview"><div class="decision {esc(gate)}"><small>发布门禁</small><strong>{esc(gate_label(gate))}</strong><p>{esc(gate_copy)}</p><div class="decision-risk"><span>最高风险程度</span>{highest_risk_html}</div></div><div class="metrics">{metrics_html}</div></section>
<nav class="jump-nav" aria-label="报告导航"><a href="#overview">概览</a><a href="#workflow">工作流图</a><a href="#findings-section">风险与逻辑链</a></nav>
<section class="report-section" id="workflow"><div class="section-head"><h2>工作流图</h2><div class="count-row">{severity_cards}</div></div><div class="diagram-frame">{workflow_svg}</div><div class="diagram-note"><span class="legend"><span><i style="background:#dbeafe"></i>输入/内容</span><span><i style="background:#ede9fe"></i>LLM/处理</span><span><i style="background:#fef3c7"></i>条件</span><span><i style="background:#dcfce7"></i>输出/工具</span></span></div></section>
<section class="report-section" id="findings-section"><div class="section-head"><div><h2>风险与逻辑链</h2><p>严重度表示影响，证据状态表示静态确定性。</p></div><div class="filters"><label>严重度<select id="severityFilter"><option value="">全部</option><option value="CRITICAL">严重</option><option value="HIGH">高危</option><option value="MEDIUM">中危</option><option value="LOW">低危</option><option value="INFO">信息</option></select></label><label>证据状态<select id="statusFilter"><option value="">全部</option><option value="CONFIRMED">已确认</option><option value="PROBABLE">较可能</option><option value="OBSERVED">加固项</option><option value="CANDIDATE">待验证</option></select></label></div></div><div id="findings">{findings_html}</div></section>
<footer>静态安全扫描</footer>
</main>
<script>{script}</script>
</body></html>'''


def render_workflow_svg(workflow: dict[str, Any], highlight_path: list[str], svg_id: str) -> str:
    """Draw the full workflow, preserving source canvas coordinates when present."""
    nodes = [item for item in workflow.get("nodes", []) if isinstance(item, dict)]
    edges = [item for item in workflow.get("edges", []) if isinstance(item, dict)]
    node_by_id = {str(item.get("id")): item for item in nodes}
    positions, width, height, layout_source = _workflow_positions(nodes, edges)
    node_w, node_h = 176, 72
    marker = f"arrow-{escape(svg_id, quote=True)}"
    outgoing_edges: dict[str, list[dict[str, Any]]] = {}
    incoming_edges: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source in positions and target in positions:
            outgoing_edges.setdefault(source, []).append(edge)
            incoming_edges.setdefault(target, []).append(edge)
    for source, items in outgoing_edges.items():
        items.sort(key=lambda item: positions[str(item.get("target"))][1])
    for target, items in incoming_edges.items():
        items.sort(key=lambda item: positions[str(item.get("source"))][1])
    edge_svg = []
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source not in positions or target not in positions:
            continue
        x1, y1 = positions[source]; x2, y2 = positions[target]
        source_items = outgoing_edges.get(source, [edge]); target_items = incoming_edges.get(target, [edge])
        source_index = source_items.index(edge); target_index = target_items.index(edge)
        sy = y1 + node_h * (source_index + 1) / (len(source_items) + 1)
        ty = y2 + node_h * (target_index + 1) / (len(target_items) + 1)
        sx, tx = x1 + node_w, x2
        if tx > sx + 26:
            # Keep control points ordered even for the shortest valid gutter;
            # crossing them makes a forward edge look like a tiny self-loop.
            control = max(12, min(96, (tx - sx) * .42))
            path_d = f"M {sx:.1f} {sy:.1f} C {sx + control:.1f} {sy:.1f}, {tx - control:.1f} {ty:.1f}, {tx:.1f} {ty:.1f}"
        else:
            lane_y = max(y1 + node_h, y2 + node_h) + 26 + 10 * source_index
            path_d = f"M {sx:.1f} {sy:.1f} H {sx + 24:.1f} V {lane_y:.1f} H {tx - 24:.1f} V {ty:.1f} H {tx:.1f}"
        edge_svg.append(f'<path d="{path_d}" fill="none" stroke="#8fa1b5" stroke-width="1.6" marker-end="url(#{marker})"><title>{escape(node_label_for_svg(node_by_id, source))} → {escape(node_label_for_svg(node_by_id, target))}</title></path>')
        if len(source_items) > 1:
            branch = _branch_label(
                edge.get("source_handle") or edge.get("sourceHandle"),
                source_index,
                node_by_id.get(source),
            )
            visible_branch = _compact_branch_label(
                edge.get("source_handle") or edge.get("sourceHandle"),
                source_index,
                node_by_id.get(source),
            )
            label_x, label_y = sx + 12, sy - 7
            label_w = max(36, 9 * len(visible_branch) + 12)
            edge_svg.append(f'<g><title>{escape(branch)}</title><rect x="{label_x:.1f}" y="{label_y - 11:.1f}" width="{label_w}" height="17" rx="7" fill="#fff" stroke="#dbe3ee"/><text x="{label_x + 6:.1f}" y="{label_y + 1:.1f}" font-size="9" fill="#53657a">{escape(visible_branch)}</text></g>')
    node_svg = []
    for node_id, node in node_by_id.items():
        x, y = positions[node_id]
        node_type = str(node.get("type", "UNKNOWN"))
        fill = _node_fill(node_type)
        title = _svg_text(node.get("title") or node_id, 19)
        type_copy = _condition_type_copy(node, node_type)
        node_svg.append(
            f'<g><rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="9" fill="{fill}" stroke="#b9c6d5" stroke-width="1"/>'
            f'<text x="{x + 11}" y="{y + 25}" font-size="12" font-weight="700" fill="#172033">{escape(title)}</text>'
            f'<text x="{x + 11}" y="{y + 51}" font-size="10" fill="#475569">{escape(_svg_text(type_copy, 24))}</text></g>'
        )
    return f'<svg class="workflow-svg" data-layout="{layout_source}" viewBox="0 0 {width} {height}" role="img" aria-label="Workflow 流程图"><defs><marker id="{marker}" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#8fa1b5"/></marker></defs>{"".join(edge_svg)}{"".join(node_svg)}</svg>'


def render_risk_chain_svg(workflow: dict[str, Any], path: list[str], svg_id: str, severity: str) -> str:
    """Draw a focused, numbered risk path instead of recolouring the full graph."""
    nodes = {str(item.get("id")): item for item in workflow.get("nodes", []) if isinstance(item, dict)}
    edges = [item for item in workflow.get("edges", []) if isinstance(item, dict)]
    visible = [node_id for node_id in path if node_id in nodes]
    width = max(760, 74 + 226 * len(visible))
    height = 164
    node_w, node_h, node_y = 176, 74, 44
    color = _risk_color(severity)
    marker = f"focus-arrow-{escape(svg_id, quote=True)}"
    body: list[str] = []
    for index in range(len(visible) - 1):
        source, target = visible[index], visible[index + 1]
        sx = 42 + index * 226 + node_w
        tx = 42 + (index + 1) * 226
        cy = node_y + node_h / 2
        edge = next((item for item in edges if str(item.get("source")) == source and str(item.get("target")) == target), {})
        handle = edge.get("source_handle") or edge.get("sourceHandle")
        label = _branch_label(handle, 0, nodes.get(source)) if handle not in (None, "", "source") else ""
        visible_label = _compact_branch_label(handle, 0, nodes.get(source)) if label else ""
        body.append(f'<path d="M {sx} {cy:.1f} H {tx}" fill="none" stroke="{color}" stroke-width="2.4" marker-end="url(#{marker})"/>')
        if visible_label:
            mid = (sx + tx) / 2
            body.append(f'<text x="{mid:.1f}" y="{cy - 9:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="{color}"><title>{escape(label)}</title>{escape(visible_label)}</text>')
    for index, node_id in enumerate(visible):
        node = nodes[node_id]; x = 42 + index * 226
        title = _svg_text(node.get("title") or node_id, 19)
        node_type = _svg_text(_condition_type_copy(node, str(node.get("type", "UNKNOWN"))), 23)
        body.append(
            f'<g><rect x="{x}" y="{node_y}" width="{node_w}" height="{node_h}" rx="9" fill="{_node_fill(str(node.get("type", "UNKNOWN")))}" stroke="{color}" stroke-width="1.7"/>'
            f'<circle cx="{x + 15}" cy="{node_y + 15}" r="10" fill="{color}"/><text x="{x + 15}" y="{node_y + 18.5}" text-anchor="middle" font-size="9" font-weight="800" fill="#fff">{index + 1}</text>'
            f'<text x="{x + 31}" y="{node_y + 20}" font-size="11.5" font-weight="700" fill="#172033">{escape(title)}</text>'
            f'<text x="{x + 12}" y="{node_y + 53}" font-size="10" fill="#53657a">{escape(node_type)}</text></g>'
        )
    if not visible:
        body.append('<text x="28" y="55" font-size="13" fill="#64748b">该风险没有可展示的节点路径。</text>')
    return f'<svg class="workflow-svg" viewBox="0 0 {width} {height}" role="img" aria-label="风险逻辑链"><defs><marker id="{marker}" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="{color}"/></marker></defs>{"".join(body)}</svg>'


def _workflow_positions(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> tuple[dict[str, tuple[int, int]], int, int, str]:
    canvas: dict[str, tuple[float, float]] = {}
    for node in nodes:
        position = node.get("position")
        if not isinstance(position, dict):
            continue
        try:
            canvas[str(node.get("id"))] = (float(position["x"]), float(position["y"]))
        except (KeyError, TypeError, ValueError):
            continue
    positions: dict[str, tuple[int, int]] = {}
    if canvas:
        min_x = min(value[0] for value in canvas.values()); min_y = min(value[1] for value in canvas.values())
        # Dify stores free-form canvas coordinates. Nearby x values usually
        # represent one visual column, while adjacent columns can be closer
        # than the fixed report node width. Cluster those columns and enforce
        # a safe horizontal gutter so a short forward edge is never mistaken
        # for a self-loop/back-edge by the SVG router.
        x_clusters: list[list[float]] = []
        for x in sorted({value[0] for value in canvas.values()}):
            if x_clusters and x - x_clusters[-1][-1] <= 80:
                x_clusters[-1].append(x)
            else:
                x_clusters.append([x])
        normalized_x: dict[float, int] = {}
        previous_column: int | None = None
        for cluster in x_clusters:
            representative = sum(cluster) / len(cluster)
            desired = 44 + int((representative - min_x) * .72)
            assigned = desired if previous_column is None else max(desired, previous_column + 300)
            for raw_x in cluster:
                normalized_x[raw_x] = assigned
            previous_column = assigned
        by_column: dict[int, list[tuple[str, float]]] = {}
        for node_id, (x, y) in canvas.items():
            by_column.setdefault(normalized_x[x], []).append((node_id, y))
        for column_x, column_nodes in by_column.items():
            previous_y: int | None = None
            for node_id, raw_y in sorted(column_nodes, key=lambda item: item[1]):
                desired_y = 38 + int((raw_y - min_y) * .72)
                assigned_y = desired_y if previous_y is None else max(desired_y, previous_y + 92)
                positions[node_id] = (column_x, assigned_y)
                previous_y = assigned_y
        bottom = max(y for _, y in positions.values()) + 112
        for index, node in enumerate(item for item in nodes if str(item.get("id")) not in positions):
            positions[str(node.get("id"))] = (44, bottom + index * 104)
        width = max(800, max(x for x, _ in positions.values()) + 224)
        height = max(230, max(y for _, y in positions.values()) + 122)
        return positions, width, height, "dsl-canvas"

    node_ids = [str(item.get("id")) for item in nodes]
    incoming = {node_id: 0 for node_id in node_ids}; outgoing: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    for edge in edges:
        source, target = str(edge.get("source")), str(edge.get("target"))
        if source in outgoing and target in incoming:
            outgoing[source].append(target); incoming[target] += 1
    queue = sorted(node_id for node_id, count in incoming.items() if count == 0); ranks = {node_id: 0 for node_id in queue}
    while queue:
        current = queue.pop(0)
        for target in sorted(outgoing[current]):
            ranks[target] = max(ranks.get(target, 0), ranks[current] + 1); incoming[target] -= 1
            if incoming[target] == 0:
                queue.append(target)
    for node_id in node_ids:
        ranks.setdefault(node_id, max(ranks.values(), default=-1) + 1)
    columns: dict[int, list[str]] = {}
    for node_id, rank in ranks.items():
        columns.setdefault(rank, []).append(node_id)
    for rank in sorted(columns):
        columns[rank].sort(key=lambda node_id: sum(ranks.get(source, 0) for source in node_ids if node_id in outgoing.get(source, [])))
        for index, node_id in enumerate(columns[rank]):
            positions[node_id] = (44 + rank * 244, 38 + index * 106)
    return positions, max(800, max((x for x, _ in positions.values()), default=0) + 224), max(230, max((y for _, y in positions.values()), default=0) + 122), "derived-layered"


def _branch_label(handle: Any, index: int, source_node: dict[str, Any] | None = None) -> str:
    value = str(handle or "")
    branch_conditions = source_node.get("branch_conditions", {}) if isinstance(source_node, dict) else {}
    if isinstance(branch_conditions, dict) and value in branch_conditions:
        return str(branch_conditions[value])
    if value == "true":
        return "是 / true"
    if value == "false":
        return "否则"
    if value in {"source", ""}:
        return f"分支 {index + 1}"
    return f"分支 {index + 1}"


def _compact_branch_label(handle: Any, index: int, source_node: dict[str, Any] | None = None) -> str:
    value = str(handle or "")
    branch_conditions = source_node.get("branch_conditions", {}) if isinstance(source_node, dict) else {}
    if isinstance(branch_conditions, dict) and value in branch_conditions:
        if str(branch_conditions[value]) == "否则" or value == "false":
            return "否则"
        ordered_handles = [key for key in branch_conditions if key != "false"]
        return f"条件 {ordered_handles.index(value) + 1}"
    if value == "true":
        return "是"
    if value == "false":
        return "否则"
    return f"分支 {index + 1}"


def _condition_presentation(node: Any, node_map: dict[str, Any]) -> dict[str, Any]:
    if getattr(node, "type", None) != "CONDITION":
        return {}
    cases = node.config.get("cases") if isinstance(node.config, dict) else None
    if not isinstance(cases, list):
        return {}
    labels: dict[str, str] = {}
    subjects: list[str] = []
    for case_index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        handle = str(case.get("case_id") or case.get("id") or f"case-{case_index + 1}")
        conditions = [item for item in case.get("conditions", []) if isinstance(item, dict)]
        fragments: list[str] = []
        for condition in conditions:
            selector = condition.get("variable_selector")
            producer_id = str(selector[0]) if isinstance(selector, list) and selector else ""
            producer = node_map.get(producer_id)
            subject = str(getattr(producer, "title", "") or (selector[-1] if isinstance(selector, list) and selector else "条件值"))
            subjects.append(subject)
            operator = _condition_operator_label(condition.get("comparison_operator"))
            value = condition.get("value")
            fragments.append(f"{operator}「{value}」")
        joiner = " 或 " if str(case.get("logical_operator", "and")).lower() == "or" else " 且 "
        labels[handle] = joiner.join(fragments) or f"条件 {case_index + 1}"
    if labels:
        labels.setdefault("false", "否则")
    unique_subjects = list(dict.fromkeys(subjects))
    return {
        "branch_conditions": labels,
        "condition_subject": " / ".join(unique_subjects),
        "condition_case_count": len(labels) - (1 if "false" in labels else 0),
    }


def _condition_operator_label(operator: Any) -> str:
    return {
        "contains": "包含",
        "not contains": "不包含",
        "not_contains": "不包含",
        "is": "等于",
        "is not": "不等于",
        "is_not": "不等于",
        "starts with": "开头为",
        "starts_with": "开头为",
        "ends with": "结尾为",
        "ends_with": "结尾为",
        "empty": "为空",
        "not empty": "不为空",
        "not_empty": "不为空",
        ">": "大于",
        "<": "小于",
        ">=": "大于等于",
        "<=": "小于等于",
    }.get(str(operator or "").lower(), str(operator or "满足"))


def _condition_type_copy(node: dict[str, Any], fallback: str) -> str:
    if fallback != "CONDITION":
        return fallback
    subject = str(node.get("condition_subject") or "条件值")
    count = int(node.get("condition_case_count") or 0)
    return f"条件 · {subject} · {count} 个分支"


def node_label_for_svg(nodes: dict[str, dict[str, Any]], node_id: str) -> str:
    return str(nodes.get(node_id, {}).get("title") or node_id)


def _risk_color(severity: str) -> str:
    return {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#b7791f", "LOW": "#0284c7"}.get(severity, "#64748b")


def _status_explanation(status: str) -> str:
    return {
        "CONFIRMED": "规则已获得足够的静态直接证据，但仍不代表攻击已实际发生。",
        "PROBABLE": "路径和危险模式成立，仍需结合业务约束或运行时行为人工确认。",
        "OBSERVED": "已观察到需要加固的模式，通常不单独触发发布阻断。",
        "CANDIDATE": "存在风险线索，但上下文不足，当前不应当作已确认漏洞。",
    }.get(status, "请结合技术证据人工判断。")


def _node_fill(node_type: str) -> str:
    if node_type in {"INPUT", "CONTENT", "KNOWLEDGE"}:
        return "#dbeafe"
    if node_type in {"CONDITION", "HUMAN", "LOOP", "ITERATION", "STRUCTURAL"}:
        return "#fef3c7"
    if node_type in {"TOOL", "OUTPUT"}:
        return "#dcfce7"
    return "#ede9fe"


def _svg_text(value: Any, limit: int) -> str:
    text = str(value if value is not None else "")
    return text if len(text) <= limit else f"{text[:max(1, limit - 1)]}…"


def _severity_rank(value: Any) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(str(value), -1)


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    all_findings = report.get("findings", [])
    findings = [
        finding for finding in all_findings
        if finding.get("status") not in {"COVERAGE_GAP", "MITIGATED", "NOT_APPLICABLE"}
    ]
    gate_payload = report.get("quality_gate", {})
    gate = gate_payload.get("decision", "UNKNOWN")
    action_ids = set(gate_payload.get("blocking_finding_ids", [])) | set(gate_payload.get("review_finding_ids", []))
    action_findings = [finding for finding in findings if finding.get("id") in action_ids]
    advisory_findings = [finding for finding in findings if finding.get("id") not in action_ids]
    lines = [
        f"# Workflow 静态安全扫描报告：{summary['workflow_id']}",
        "",
        "## 一页结论",
        "",
        summary.get("executive_summary") or "扫描完成。",
        "",
        "| 指标 | 结果 | 如何理解 |",
        "|---|---:|---|",
        f"| 发布门禁 | `{gate}` | FAIL 仅由已确认高/严重风险触发；REVIEW 由中等级以上待处理证据触发 |",
        f"| 需处理风险项 | {summary.get('action_item_count', 0)} | 影响发布门禁或需要人工补证 |",
        f"| 加固建议 | {summary.get('advisory_count', 0)} | LOW/INFO 观察与可靠性项，不单独触发门禁 |",
        f"| 已缓解项 | {summary.get('mitigated_count', 0)} | 风险路径存在，但全部路径已被确定性控制覆盖 |",
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
    if action_findings:
        for finding in action_findings:
            remediation = (finding.get("remediation") or ["人工复核并补充匹配控制"])[0]
            lines.append(
                f"| `{finding['id']}` | `{finding.get('anchor_node_id') or 'workflow'}` | "
                f"{_table_cell(_control_domain_label(finding.get('control_domain', '')))} | "
                f"`{finding['severity']}` / `{finding['status']}` | "
                f"{_table_cell(finding.get('message', ''))} | {_table_cell(remediation)} |"
            )
    else:
        lines.append("| — | — | — | — | 未形成影响门禁的风险项 | — |")

    lines.extend(["", "### 加固建议摘要", ""])
    if advisory_findings:
        lines.extend([
            "| 风险项 | 影响节点 | 等级 / 状态 | 建议 |",
            "|---|---|---|---|",
        ])
        for finding in advisory_findings:
            affected = finding.get("affected_node_ids") or finding.get("node_ids", [])
            remediation = (finding.get("remediation") or ["纳入后续加固"])[0]
            lines.append(
                f"| `{finding['id']}` | {_table_cell(', '.join(affected))} | "
                f"`{finding['severity']}` / `{finding['status']}` | {_table_cell(remediation)} |"
            )
    else:
        lines.append("本次没有额外加固建议。")

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
        "| `MITIGATED` | 风险路径存在，但所有已识别路径均经过不可绕过的确定性控制 | 保留证据并防止控制退化 |",
        "",
        "## 审计附录：输入簇与证据边界",
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
        "## 审计附录：模型参与边界",
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
    attack_paths = [
        path for path in report.get("attack_surface", {}).get("risk_chains", [])
        if set(path.get("finding_ids", [])) & action_ids
    ]
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

    lines.extend(["", "完整的入口、资产、信任边界和能力清单见 `attack-surface.md`。", "", "## 审计附录：风险项明细", ""])
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
            if finding.get("affected_node_ids"):
                lines.append(f"- 受影响节点：{', '.join(f'`{item}`' for item in finding['affected_node_ids'])}")
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
    mitigated = [finding for finding in all_findings if finding.get("status") == "MITIGATED"]
    lines.extend(["", "## 已缓解项", ""])
    if mitigated:
        for finding in mitigated:
            controls = "；".join(finding.get("counter_evidence", [])) or "存在覆盖全部路径的确定性控制。"
            lines.append(
                f"- `{finding['id']}`（{', '.join([finding['rule_id'], *finding.get('related_rule_ids', [])])}）："
                f"{finding.get('message', '')} 反证：{controls}"
            )
    else:
        lines.append("本次未记录已缓解项。")
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
