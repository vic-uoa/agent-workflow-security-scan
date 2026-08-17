from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import re

import yaml

from . import __version__
from .engine import execute_rules
from .llm import (
    ModelAdvisor,
    deterministic_semantic_inventory,
    deterministic_test_cluster,
    redact_for_model,
    validate_input_against_ir,
    validate_references,
)
from .models import SCHEMA_VERSION, Finding, WorkflowIR, file_sha256, stable_id, to_jsonable, utc_now, write_artifact
from .parser import parse_dify_dsl
from .report import (
    build_attack_surface,
    build_dynamic_plan,
    build_report_json,
    render_attack_surface_markdown,
    render_markdown,
)


def load_samples(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"samples": []}
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(payload, list):
        return {"samples": payload}
    if not isinstance(payload, dict) or not isinstance(payload.get("samples", []), list):
        raise ValueError("samples JSON must be an object containing a samples array")
    return payload


def validate_seed_samples(samples: dict[str, Any], ir: WorkflowIR) -> None:
    if samples.get("confirmed_by_user") is not True:
        raise ValueError("seed samples must set confirmed_by_user=true after user review")
    confirmed_hash = str(samples.get("confirmed_dsl_sha256") or "").strip().lower()
    if not confirmed_hash:
        raise ValueError(
            "assessment requires confirmed_dsl_sha256 from the DSL selection checkpoint"
        )
    if confirmed_hash != ir.workflow_hash.lower():
        raise ValueError(
            "confirmed_dsl_sha256 does not match the DSL being scanned; reconfirm the DSL and seed inputs"
        )
    cases = [item for item in samples.get("samples", []) if isinstance(item, dict)]
    if not cases:
        raise ValueError("assessment requires at least one user-confirmed seed sample")
    for index, item in enumerate(cases):
        if not isinstance(item.get("input"), dict) or not item["input"]:
            raise ValueError(f"seed sample {index + 1} requires a non-empty input object")
        input_errors = validate_input_against_ir(item["input"], ir)
        if input_errors:
            raise ValueError(
                f"seed sample {index + 1} does not satisfy the DSL input contract: "
                + ", ".join(input_errors)
            )
        has_oracle = any(item.get(field) for field in (
            "expected_business_intent", "expected_output_properties",
            "expected_security_invariants", "expected_security_invariant",
        ))
        if not has_oracle:
            raise ValueError(
                f"seed sample {index + 1} requires expected_business_intent, "
                "expected_output_properties, or expected_security_invariants"
            )


def verify_test_cluster(
    cluster: dict[str, Any], samples: dict[str, Any], findings: list[Finding], ir: WorkflowIR,
) -> tuple[dict[str, Any], dict[str, Any]]:
    allowed_seeds = {
        str(item.get("sample_id") or f"SEED-{index + 1:03d}")
        for index, item in enumerate(samples.get("samples", [])) if isinstance(item, dict)
    }
    allowed_findings = {finding.id for finding in findings}
    allowed_rules = {rule_id for finding in findings for rule_id in (finding.rule_id, *finding.related_rule_ids)}
    allowed_nodes = {node.id for node in ir.nodes}
    seed_inputs = {
        str(item.get("sample_id") or f"SEED-{index + 1:03d}"): item.get("input", {})
        for index, item in enumerate(samples.get("samples", [])) if isinstance(item, dict)
    }
    edge_pairs = {(edge.source, edge.target) for edge in ir.edges}
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for case in cluster.get("cases", []):
        if not isinstance(case, dict):
            rejected.append({"case_id": "<non-object>", "reasons": ["not_an_object"]})
            continue
        reasons: list[str] = []
        if not isinstance(case.get("input"), dict):
            reasons.append("input_not_object")
        if case.get("execution_status") != "NOT_EXECUTED":
            reasons.append("invalid_execution_status")
        target_path = [str(item) for item in case.get("target_path", [])]
        if target_path and any(pair not in edge_pairs for pair in zip(target_path, target_path[1:])):
            reasons.append("target_path_is_not_a_control_flow_path")
        if target_path and case.get("target_nodes") and target_path[-1] not in {
            str(item) for item in case.get("target_nodes", [])
        }:
            reasons.append("target_path_does_not_end_at_target_node")
        if case.get("route_status") not in {"SATISFIABLE", "PARTIAL", "UNREACHABLE", "NOT_EVALUATED", None}:
            reasons.append("invalid_route_status")
        for field, allowed in (
            ("seed_sample_ids", allowed_seeds), ("finding_ids", allowed_findings),
            ("rule_ids", allowed_rules), ("target_nodes", allowed_nodes), ("target_path", allowed_nodes),
        ):
            unknown = {str(item) for item in case.get(field, [])} - allowed
            if unknown:
                reasons.append(f"unknown_{field}:{','.join(sorted(unknown))}")
        if reasons:
            rejected.append({"case_id": str(case.get("case_id") or "<missing>"), "reasons": reasons})
            if case.get("oracle_source") != "model_proposal":
                raise ValueError(f"deterministic test case failed verification: {reasons}")
            continue
        if case.get("case_type") != "positive":
            unchanged_from_seed = any(
                json.dumps(case.get("input"), ensure_ascii=False, sort_keys=True)
                == json.dumps(seed_inputs.get(seed_id), ensure_ascii=False, sort_keys=True)
                for seed_id in case.get("seed_sample_ids", []) if seed_id in seed_inputs
            )
            if unchanged_from_seed:
                reasons.append("derived_input_is_identical_to_seed")
        declared_input_errors = validate_input_against_ir(case.get("input", {}), ir)
        if case.get("generation_source") == "rule_targeted" and declared_input_errors:
            reasons.append("rule_targeted_input_violates_dsl_contract:" + ",".join(declared_input_errors))
        if not isinstance(case.get("oracle"), dict) or not case.get("oracle"):
            reasons.append("missing_machine_readable_oracle")
        if reasons:
            rejected.append({"case_id": str(case.get("case_id") or "<missing>"), "reasons": reasons})
            if case.get("oracle_source") != "model_proposal":
                raise ValueError(f"deterministic test case failed verification: {reasons}")
            continue
        accepted.append(case)

    deduplicated: list[dict[str, Any]] = []
    seen_inputs: dict[str, dict[str, Any]] = {}
    for case in accepted:
        canonical = json.dumps(case.get("input", {}), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        previous = seen_inputs.get(canonical)
        if previous is None:
            seen_inputs[canonical] = case
            deduplicated.append(case)
            continue
        if case.get("oracle_source") == "model_proposal":
            rejected.append({
                "case_id": str(case.get("case_id") or "<missing>"),
                "reasons": [f"exact_duplicate_input_of:{previous.get('case_id')}"],
            })
            continue
        raise ValueError(
            f"deterministic test cases have identical concrete inputs: "
            f"{previous.get('case_id')} and {case.get('case_id')}"
        )
    accepted = deduplicated
    case_types = {str(case.get("case_type")) for case in accepted}
    if allowed_seeds:
        missing_types = {"positive", "negative", "boundary"} - case_types
        if missing_types:
            raise ValueError(f"test cluster missing required generated case types: {sorted(missing_types)}")
    verified = deepcopy(cluster)
    verified["cases"] = accepted
    audit = verified.setdefault("generation_audit", {})
    audit["accepted_case_count"] = len(accepted)
    audit["rejected_model_cases"] = rejected
    audit["required_case_types_present"] = not allowed_seeds or not ({"positive", "negative", "boundary"} - case_types)
    audit["lineage_verified"] = True
    audit["execution_evidence_present"] = False
    canonical_inputs = [
        json.dumps(case.get("input", {}), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for case in accepted
    ]
    audit["unique_input_count"] = len(set(canonical_inputs))
    audit["exact_duplicate_input_count"] = len(canonical_inputs) - len(set(canonical_inputs))
    audit["unchanged_derived_case_count"] = 0
    audit["route_satisfiable_case_count"] = sum(
        case.get("route_status") == "SATISFIABLE" for case in accepted
    )
    audit["route_partial_case_count"] = sum(case.get("route_status") == "PARTIAL" for case in accepted)
    audit["route_unreachable_case_count"] = sum(
        case.get("route_status") == "UNREACHABLE" for case in accepted
    )
    audit["planned_case_count"] = len(accepted)
    audit["executed_case_count"] = 0
    return verified, audit


def load_baseline(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("baseline YAML root must be an object")
    return payload


def load_waivers(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"waivers": []}
    text = path.read_text(encoding="utf-8-sig")
    payload = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    if not isinstance(payload, dict) or not isinstance(payload.get("waivers", []), list):
        raise ValueError("waiver file must be an object containing a waivers array")
    return payload


def apply_waivers(findings: list[Finding], waiver_payload: dict[str, Any], workflow_hash: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    applied: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    for index, item in enumerate(waiver_payload.get("waivers", [])):
        if not isinstance(item, dict):
            rejected.append({"waiver_id": f"index-{index}", "reason": "not_an_object"})
            continue
        waiver_id = str(item.get("waiver_id") or f"index-{index}")
        justification = str(item.get("justification") or "").strip()
        approver = str(item.get("approver") or "").strip()
        expires_at = str(item.get("expires_at") or "")
        if not justification or not approver or not expires_at:
            rejected.append({"waiver_id": waiver_id, "reason": "missing_justification_approver_or_expiry"})
            continue
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError:
            rejected.append({"waiver_id": waiver_id, "reason": "invalid_expiry"})
            continue
        if expiry <= now:
            rejected.append({"waiver_id": waiver_id, "reason": "expired"})
            continue
        scoped_hash = str(item.get("workflow_hash") or "")
        if not scoped_hash:
            rejected.append({"waiver_id": waiver_id, "reason": "missing_workflow_hash"})
            continue
        if scoped_hash != workflow_hash:
            rejected.append({"waiver_id": waiver_id, "reason": "workflow_hash_mismatch"})
            continue
        finding_id = str(item.get("finding_id") or "")
        rule_id = str(item.get("rule_id") or "")
        matches = [
            finding for finding in findings
            if (finding_id and finding.id == finding_id)
            or (not finding_id and rule_id and rule_id in {finding.rule_id, *finding.related_rule_ids})
        ]
        if not matches:
            rejected.append({"waiver_id": waiver_id, "reason": "no_matching_finding"})
            continue
        if not finding_id and any(len({finding.rule_id, *finding.related_rule_ids}) > 1 for finding in matches):
            rejected.append({
                "waiver_id": waiver_id,
                "reason": "ambiguous_rule_scope_after_node_control_aggregation_use_finding_id",
            })
            continue
        for finding in matches:
            finding.waived = True
            finding.waiver_id = waiver_id
            applied.append({"waiver_id": waiver_id, "finding_id": finding.id})
    return {"applied": applied, "rejected": rejected}


def evaluate_quality_gate(findings: list[Finding], baseline: dict[str, Any], waiver_audit: dict[str, Any]) -> dict[str, Any]:
    policy = baseline.get("quality_gate", {}) if isinstance(baseline.get("quality_gate", {}), dict) else {}
    blocking_severities = {str(item) for item in policy.get("blocking_severities", ["CRITICAL", "HIGH"])}
    blocking_statuses = {str(item) for item in policy.get("blocking_statuses", ["CONFIRMED"])}
    review_statuses = {str(item) for item in policy.get("review_statuses", ["OBSERVED", "PROBABLE", "CANDIDATE", "COVERAGE_GAP"])}
    blockers = [
        finding for finding in findings
        if not finding.waived and finding.severity in blocking_severities and finding.status in blocking_statuses
    ]
    reviews = [finding for finding in findings if not finding.waived and finding.status in review_statuses]
    decision = "FAIL" if blockers else ("REVIEW" if reviews else "PASS")
    return {
        "decision": decision,
        "exit_code": 1 if decision == "FAIL" else 0,
        "policy": {
            "blocking_severities": sorted(blocking_severities),
            "blocking_statuses": sorted(blocking_statuses),
            "review_statuses": sorted(review_statuses),
            "waivers_require_workflow_hash_approver_justification_and_expiry": True,
        },
        "blocking_finding_ids": [finding.id for finding in blockers],
        "review_finding_ids": [finding.id for finding in reviews],
        "blocking_count": len(blockers),
        "review_count": len(reviews),
        "waived_count": sum(finding.waived for finding in findings),
        "waiver_audit": waiver_audit,
    }


def write_artifact_index(output_dir: Path, scan_id: str, workflow_hash: str) -> None:
    expected = {
        "00-scan-manifest.json", "01-workflow-ir.json", "02-security-facts.json",
        "03-semantic-inventory.json", "04-rule-candidates.json", "05-test-cluster.json",
        "06-model-advisory.json", "07-verification.json", "08-findings.json",
        "09-attack-surface.json", "attack-surface.md", "10-dynamic-test-plan.json", "11-quality-gate.json",
        "report.json", "report.md",
    }
    entries = []
    for path in sorted(item for item in output_dir.iterdir() if item.is_file() and item.name in expected):
        entries.append({"name": path.name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    unexpected = sorted(item.name for item in output_dir.iterdir() if item.is_file() and item.name not in expected | {"12-artifact-index.json"})
    write_artifact(
        output_dir / "12-artifact-index.json",
        artifact({"artifacts": entries, "unexpected_files": unexpected}, scan_id, "artifact-integrity-index", workflow_hash),
    )


def apply_baseline(ir: WorkflowIR, baseline: dict[str, Any]) -> None:
    registry = baseline.get("tool_registry", [])
    if not isinstance(registry, list):
        return
    for node in ir.nodes:
        if node.type not in {"TOOL", "CODE"}:
            continue
        fields = {
            "original_type": node.original_type.lower(),
            "title": node.title.lower(),
            "provider_id": " ".join(str(value).lower() for value in _baseline_values(node.config, ("provider_id", "provider_name"))),
            "tool_name": " ".join(str(value).lower() for value in _baseline_values(node.config, ("tool_name", "name"))),
        }
        for item in registry:
            if not isinstance(item, dict):
                continue
            match = str(item.get("match", "")).lower()
            match_field = str(item.get("match_field") or "").lower()
            match_type = str(item.get("match_type") or "exact").lower()
            values = [fields.get(match_field, "")] if match_field else list(fields.values())
            if match_type == "contains":
                matched = any(match in value for value in values)
            elif match_type == "regex":
                try:
                    matched = any(re.fullmatch(match, value) is not None for value in values)
                except re.error:
                    matched = False
            else:
                matched = any(match == value for value in values)
            if not match or not matched:
                continue
            configured = {str(value) for value in item.get("capabilities", [])}
            node.capabilities = sorted((set(node.capabilities) - {"UNKNOWN_TOOL_CAPABILITY"}) | configured)
            node.external = bool(item.get("external", node.external))
            node.high_impact = bool(item.get("high_impact", node.high_impact))
            node.config["_scanner_registry"] = {
                "matched": True,
                "trusted_source": bool(item.get("trusted_source", False)),
                "definition_version": item.get("definition_version"),
                "integrity_control": item.get("integrity_control"),
            }
            break


def _baseline_values(config: Any, keys: tuple[str, ...]) -> list[Any]:
    wanted = {key.lower() for key in keys}
    values: list[Any] = []
    if isinstance(config, dict):
        for key, value in config.items():
            if str(key).lower() in wanted and value not in (None, "", [], {}):
                values.append(value)
            values.extend(_baseline_values(value, keys))
    elif isinstance(config, list):
        for value in config:
            values.extend(_baseline_values(value, keys))
    return values


def artifact(payload: dict[str, Any], scan_id: str, producer: str, workflow_hash: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "producer": producer,
        "producer_version": __version__,
        "workflow_hash": workflow_hash,
        "created_at": utc_now(),
        **payload,
    }


def verify_deterministic_findings(
    ir: WorkflowIR,
    findings: list[Finding],
    facts: list[Any],
    candidates: dict[str, Any],
) -> dict[str, Any]:
    allowed_nodes = {node.id for node in ir.nodes}
    allowed_facts = {fact.id for fact in facts}
    invalid_finding_refs = []
    for finding in findings:
        invalid_finding_refs.extend(
            f"{finding.id}:node:{node_id}" for node_id in finding.node_ids if node_id not in allowed_nodes
        )
        invalid_finding_refs.extend(
            f"{finding.id}:fact:{fact_id}" for fact_id in finding.evidence_refs if fact_id not in allowed_facts
        )
    verification = {
        "valid": not invalid_finding_refs,
        "invalid_finding_refs": sorted(set(invalid_finding_refs)),
        "policy": {
            "finding_status_and_severity_are_deterministic": True,
            "model_advisory_can_modify_findings": False,
            "model_advisory_can_modify_quality_gate": False,
            "llm_generated_tests_are_finding_evidence": False,
            "root_cause_aggregation_may_drop_rule_coverage": False,
            "unknown_deterministic_references_rejected": True,
        },
    }
    raw_rule_ids = {str(item) for item in candidates.get("raw_rule_ids", [])}
    final_rule_ids = {rule_id for finding in findings for rule_id in (finding.rule_id, *finding.related_rule_ids)}
    lost_rule_ids = sorted(raw_rule_ids - final_rule_ids)
    verification["coverage_accounting"] = {
        "catalog_rule_count": candidates.get("rule_count", 0),
        "raw_match_count": candidates.get("raw_match_count", len(candidates.get("candidates", []))),
        "root_finding_count": len(findings),
        "node_control_risk_item_count": len(findings),
        "raw_rule_ids": sorted(raw_rule_ids),
        "final_primary_or_related_rule_ids": sorted(final_rule_ids),
        "lost_rule_ids": lost_rule_ids,
        "lossless_root_cause_aggregation": not lost_rule_ids,
    }
    if lost_rule_ids:
        raise ValueError(f"root-cause aggregation lost rule coverage: {lost_rule_ids}")
    if invalid_finding_refs:
        raise ValueError(f"deterministic findings contain unknown references: {invalid_finding_refs}")
    return verification


def run_scan(
    *,
    dsl_path: Path,
    samples_path: Path | None,
    baseline_path: Path | None,
    output_dir: Path,
    rules_path: Path,
    llm_mode: str,
    advisory_model: str = "gpt-5.6-terra",
    waivers_path: Path | None = None,
    scan_mode: str = "structure-only",
) -> dict[str, Any]:
    if scan_mode not in {"structure-only", "assessment"}:
        raise ValueError("scan_mode must be structure-only or assessment")
    if llm_mode not in {"disabled", "enabled"}:
        raise ValueError("llm_mode must be disabled or enabled")
    if scan_mode == "assessment" and samples_path is None:
        raise ValueError("assessment mode requires --samples with user-confirmed seed inputs and expected behavior")
    output_dir.mkdir(parents=True, exist_ok=True)
    ir, _document = parse_dify_dsl(dsl_path)
    baseline = load_baseline(baseline_path)
    waivers = load_waivers(waivers_path)
    apply_baseline(ir, baseline)
    samples = load_samples(samples_path)
    if scan_mode == "assessment":
        validate_seed_samples(samples, ir)
    scan_id = stable_id("SCAN", ir.workflow_hash, utc_now())
    llm_enabled = llm_mode == "enabled"

    manifest = artifact({
        "dsl_file": dsl_path.name,
        "samples_file": samples_path.name if samples_path else None,
        "baseline_file": baseline_path.name if baseline_path else None,
        "rules_file": rules_path.name,
        "rules_hash": file_sha256(rules_path),
        "baseline_hash": file_sha256(baseline_path) if baseline_path else None,
        "waivers_file": waivers_path.name if waivers_path else None,
        "waivers_hash": file_sha256(waivers_path) if waivers_path else None,
        "llm_requested": llm_mode,
        "llm_enabled": llm_enabled,
        "scan_mode": scan_mode,
        "advisory_model": advisory_model if llm_enabled else None,
        "model_authority": "non_authoritative_test_and_wording_advisor",
        "scope": {
            "platform_detection": False,
            "runtime_iam": False,
            "container_security": False,
            "workflow_execution": False,
        },
        "pipeline_order": [
            "1-resolve-explicit-dsl-or-ask-if-ambiguous-and-bind-internal-hash",
            "2-confirm-seed-inputs-and-oracles",
            "3-deterministic-static-analysis",
            "4-generate-unexecuted-input-cluster",
            "5-correlate-report-and-attack-surface",
        ],
    }, scan_id, "scanner", ir.workflow_hash)
    write_artifact(output_dir / "00-scan-manifest.json", manifest)
    write_artifact(
        output_dir / "01-workflow-ir.json",
        artifact({"workflow_ir": redact_for_model(to_jsonable(ir))}, scan_id, "dify-parser", ir.workflow_hash),
    )

    facts, initial_findings, candidates = execute_rules(ir, rules_path)
    write_artifact(output_dir / "02-security-facts.json", artifact({"facts": [to_jsonable(fact) for fact in facts]}, scan_id, "rule-engine", ir.workflow_hash))

    advisory_pipeline = ModelAdvisor(llm_enabled, advisory_model, scan_id)
    semantic = deterministic_semantic_inventory(ir)
    write_artifact(output_dir / "03-semantic-inventory.json", artifact({"semantic_inventory": semantic}, scan_id, "deterministic-semantic-inventory", ir.workflow_hash))

    write_artifact(output_dir / "04-rule-candidates.json", artifact(candidates, scan_id, "rule-engine", ir.workflow_hash))

    # Stage 3 is fully deterministic. Optional model output never receives
    # authority over Finding status, severity, aggregation, or the quality gate.
    final_findings = initial_findings
    verification = verify_deterministic_findings(ir, final_findings, facts, candidates)
    model_advisory = {
        "enabled": llm_enabled,
        "model": advisory_model if llm_enabled else None,
        "authority": "none_over_findings_severity_or_gate",
        "allowed_uses": ["additional_inert_test_proposals", "non_authoritative_report_wording"],
    }
    write_artifact(
        output_dir / "06-model-advisory.json",
        artifact({"model_advisory": model_advisory}, scan_id, "model-advisory-boundary", ir.workflow_hash),
    )

    # Stage 4 derives the input cluster from the deterministic static result.
    # Optional model proposals are validated and remain NOT_EXECUTED.
    base_tests = deterministic_test_cluster(samples, final_findings, ir)
    tests = advisory_pipeline.enrich_tests(ir, samples, final_findings, base_tests)
    tests, cluster_verification = verify_test_cluster(tests, samples, final_findings, ir)
    write_artifact(output_dir / "05-test-cluster.json", artifact({"test_cluster": tests}, scan_id, tests.get("producer", "test-designer"), ir.workflow_hash))

    verification["test_cluster"] = cluster_verification
    waiver_audit = apply_waivers(final_findings, waivers, ir.workflow_hash)
    quality_gate = evaluate_quality_gate(final_findings, baseline, waiver_audit)
    if scan_mode == "structure-only" and quality_gate["decision"] == "PASS" and any(
        finding.status in {"OBSERVED", "PROBABLE", "CANDIDATE", "COVERAGE_GAP"} for finding in final_findings
    ):
        quality_gate["decision"] = "REVIEW"
        quality_gate["exit_code"] = 0
    verification["model_advisory"] = model_advisory
    explanation = advisory_pipeline.explain_report(final_findings)
    invalid_explanation_refs = validate_references(explanation, {finding.id for finding in final_findings})
    if invalid_explanation_refs:
        explanation = {
            "executive_summary": "",
            "priority_actions": [],
            "producer": "deterministic-fallback-invalid-model-references",
        }
    verification["report_explanation"] = {
        "producer": explanation.get("producer"),
        "invalid_references": invalid_explanation_refs,
        "authoritative_for_finding_status_or_counts": False,
    }
    verification["llm_errors"] = advisory_pipeline.errors
    write_artifact(output_dir / "07-verification.json", artifact({"verification": verification}, scan_id, "evidence-verifier", ir.workflow_hash))
    write_artifact(output_dir / "08-findings.json", artifact({"findings": [to_jsonable(finding) for finding in final_findings]}, scan_id, "finding-merger", ir.workflow_hash))

    attack_surface = build_attack_surface(ir, semantic, final_findings, tests)
    write_artifact(output_dir / "09-attack-surface.json", artifact({"attack_surface": attack_surface}, scan_id, "attack-surface-builder", ir.workflow_hash))
    (output_dir / "attack-surface.md").write_text(
        render_attack_surface_markdown(ir, attack_surface), encoding="utf-8"
    )

    dynamic_plan = build_dynamic_plan(ir, attack_surface, tests)
    write_artifact(output_dir / "10-dynamic-test-plan.json", artifact({"dynamic_test_plan": dynamic_plan}, scan_id, "dynamic-plan-builder", ir.workflow_hash))
    write_artifact(output_dir / "11-quality-gate.json", artifact({"quality_gate": quality_gate}, scan_id, "quality-gate", ir.workflow_hash))

    report = build_report_json(ir, final_findings, semantic, tests, attack_surface, explanation, verification, quality_gate)
    report_payload = artifact({"report": report}, scan_id, "report-builder", ir.workflow_hash)
    write_artifact(output_dir / "report.json", report_payload)
    (output_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    write_artifact_index(output_dir, scan_id, ir.workflow_hash)

    return {
        "scan_id": scan_id,
        "output_dir": str(output_dir.resolve()),
        "finding_count": sum(finding.status != "COVERAGE_GAP" for finding in final_findings),
        "observation_count": sum(finding.status == "OBSERVED" for finding in final_findings),
        "coverage_gap_count": sum(finding.status == "COVERAGE_GAP" for finding in final_findings),
        "critical_or_high": sum(
            finding.status != "COVERAGE_GAP" and finding.severity in {"CRITICAL", "HIGH"}
            for finding in final_findings
        ),
        "llm_enabled": llm_enabled,
        "llm_errors": advisory_pipeline.errors,
        "verification_valid": verification["valid"],
        "quality_gate": quality_gate["decision"],
        "exit_code": quality_gate["exit_code"],
    }
