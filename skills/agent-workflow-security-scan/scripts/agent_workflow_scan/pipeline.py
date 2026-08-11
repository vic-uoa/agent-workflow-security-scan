from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import os
import re

import yaml

from . import __version__
from .engine import execute_rules
from .llm import SemanticPipeline, deterministic_test_cluster, redact_for_model, validate_references
from .models import SCHEMA_VERSION, Finding, WorkflowIR, file_sha256, stable_id, to_jsonable, utc_now, write_artifact
from .parser import parse_dify_dsl
from .report import build_attack_surface, build_dynamic_plan, build_report_json, render_markdown


def load_samples(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"samples": []}
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(payload, list):
        return {"samples": payload}
    if not isinstance(payload, dict) or not isinstance(payload.get("samples", []), list):
        raise ValueError("samples JSON must be an object containing a samples array")
    return payload


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
        matches = [finding for finding in findings if (finding_id and finding.id == finding_id) or (not finding_id and rule_id and finding.rule_id == rule_id)]
        if not matches:
            rejected.append({"waiver_id": waiver_id, "reason": "no_matching_finding"})
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
    review_statuses = {str(item) for item in policy.get("review_statuses", ["PROBABLE", "COVERAGE_GAP"])}
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
        "06-llm-adjudication.json", "07-verification.json", "08-findings.json",
        "09-attack-surface.json", "10-dynamic-test-plan.json", "11-quality-gate.json",
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


def _verify_and_merge(
    ir: WorkflowIR,
    findings: list[Finding],
    facts: list[Any],
    candidates: dict[str, Any],
    adjudication: dict[str, Any],
    review: dict[str, Any],
) -> tuple[list[Finding], dict[str, Any]]:
    allowed_nodes = {node.id for node in ir.nodes}
    allowed_facts = {fact.id for fact in facts}
    allowed_rules = {finding.rule_id for finding in findings}
    allowed_findings = {finding.id for finding in findings}
    allowed_candidates = {item["candidate_id"] for item in candidates.get("candidates", [])}
    allowed = allowed_nodes | allowed_facts | allowed_rules | allowed_findings | allowed_candidates
    invalid_adjudication_refs = validate_references(adjudication, allowed)
    invalid_review_refs = validate_references(review, allowed)

    result = deepcopy(findings)
    by_id = {finding.id: finding for finding in result}
    candidate_to_finding = {item["candidate_id"]: item["finding_id"] for item in candidates.get("candidates", [])}
    applied_adjudications: list[dict[str, Any]] = []
    if not invalid_adjudication_refs:
        for item in adjudication.get("adjudications", []):
            if not isinstance(item, dict):
                continue
            finding = by_id.get(candidate_to_finding.get(str(item.get("candidate_id")), ""))
            if finding is None:
                continue
            if finding.status != "CONFIRMED":
                if item.get("applicable") is False:
                    finding.status = "CANDIDATE"
                    finding.confidence = min(finding.confidence, float(item.get("confidence", 0.5)))
                recommended = item.get("recommended_status")
                if recommended in {"CANDIDATE", "COVERAGE_GAP", "MITIGATED"}:
                    finding.status = str(recommended)
            finding.attack_preconditions = list(dict.fromkeys([*finding.attack_preconditions, *item.get("attack_preconditions", [])]))
            finding.missing_context = list(dict.fromkeys([*finding.missing_context, *item.get("missing_context", [])]))
            finding.counter_evidence = list(dict.fromkeys([*finding.counter_evidence, *item.get("counter_evidence_refs", [])]))
            applied_adjudications.append({"candidate_id": item.get("candidate_id"), "finding_id": finding.id})

    applied_reviews: list[dict[str, Any]] = []
    if not invalid_review_refs:
        for item in review.get("reviews", []):
            if not isinstance(item, dict):
                continue
            finding = by_id.get(str(item.get("finding_id")))
            if finding is None:
                continue
            decision = item.get("decision")
            if finding.status != "CONFIRMED":
                if decision in {"DOWNGRADE", "REJECT"}:
                    finding.status = "CANDIDATE"
                    finding.confidence = min(finding.confidence, 0.6)
                elif decision == "NEEDS_CONTEXT":
                    finding.status = "COVERAGE_GAP"
                    finding.confidence = min(finding.confidence, 0.7)
            applied_reviews.append({"finding_id": finding.id, "decision": decision})

    verification = {
        "valid": not invalid_adjudication_refs and not invalid_review_refs,
        "invalid_adjudication_refs": invalid_adjudication_refs,
        "invalid_review_refs": invalid_review_refs,
        "applied_adjudications": applied_adjudications,
        "applied_reviews": applied_reviews,
        "policy": {
            "llm_can_modify_confirmed": False,
            "llm_can_promote_to_confirmed": False,
            "unknown_references_rejected": True,
        },
    }
    return result, verification


def run_scan(
    *,
    dsl_path: Path,
    samples_path: Path | None,
    baseline_path: Path | None,
    output_dir: Path,
    rules_path: Path,
    llm_mode: str,
    analyst_model: str,
    reviewer_model: str,
    waivers_path: Path | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ir, _document = parse_dify_dsl(dsl_path)
    baseline = load_baseline(baseline_path)
    waivers = load_waivers(waivers_path)
    apply_baseline(ir, baseline)
    samples = load_samples(samples_path)
    scan_id = stable_id("SCAN", ir.workflow_hash, utc_now())
    llm_enabled = llm_mode == "enabled" or (llm_mode == "auto" and bool(os.environ.get("OPENAI_API_KEY")))

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
        "analyst_model": analyst_model,
        "reviewer_model": reviewer_model,
        "scope": {
            "platform_detection": False,
            "runtime_iam": False,
            "container_security": False,
            "workflow_execution": False,
        },
    }, scan_id, "scanner", ir.workflow_hash)
    write_artifact(output_dir / "00-scan-manifest.json", manifest)
    write_artifact(
        output_dir / "01-workflow-ir.json",
        artifact({"workflow_ir": redact_for_model(to_jsonable(ir))}, scan_id, "dify-parser", ir.workflow_hash),
    )

    facts, initial_findings, candidates = execute_rules(ir, rules_path)
    write_artifact(output_dir / "02-security-facts.json", artifact({"facts": [to_jsonable(fact) for fact in facts]}, scan_id, "rule-engine", ir.workflow_hash))

    semantic_pipeline = SemanticPipeline(llm_enabled, analyst_model, reviewer_model, scan_id)
    semantic = semantic_pipeline.semantic_inventory(ir)
    write_artifact(output_dir / "03-semantic-inventory.json", artifact({"semantic_inventory": semantic}, scan_id, semantic.get("producer", "semantic-pipeline"), ir.workflow_hash))

    write_artifact(output_dir / "04-rule-candidates.json", artifact(candidates, scan_id, "rule-engine", ir.workflow_hash))

    base_tests = deterministic_test_cluster(samples, initial_findings)
    tests = semantic_pipeline.enrich_tests(ir, samples, initial_findings, base_tests)
    write_artifact(output_dir / "05-test-cluster.json", artifact({"test_cluster": tests}, scan_id, tests.get("producer", "test-designer"), ir.workflow_hash))

    adjudication = semantic_pipeline.adjudicate(ir, candidates, initial_findings, tests)
    write_artifact(output_dir / "06-llm-adjudication.json", artifact({"adjudication": adjudication}, scan_id, adjudication.get("producer", "risk-adjudicator"), ir.workflow_hash))

    review = semantic_pipeline.review(initial_findings, adjudication)
    final_findings, verification = _verify_and_merge(ir, initial_findings, facts, candidates, adjudication, review)
    waiver_audit = apply_waivers(final_findings, waivers, ir.workflow_hash)
    quality_gate = evaluate_quality_gate(final_findings, baseline, waiver_audit)
    verification["review"] = review
    verification["llm_errors"] = semantic_pipeline.errors
    write_artifact(output_dir / "07-verification.json", artifact({"verification": verification}, scan_id, "evidence-verifier", ir.workflow_hash))
    write_artifact(output_dir / "08-findings.json", artifact({"findings": [to_jsonable(finding) for finding in final_findings]}, scan_id, "finding-merger", ir.workflow_hash))

    attack_surface = build_attack_surface(ir, semantic, final_findings, tests)
    write_artifact(output_dir / "09-attack-surface.json", artifact({"attack_surface": attack_surface}, scan_id, "attack-surface-builder", ir.workflow_hash))

    dynamic_plan = build_dynamic_plan(ir, attack_surface, tests)
    write_artifact(output_dir / "10-dynamic-test-plan.json", artifact({"dynamic_test_plan": dynamic_plan}, scan_id, "dynamic-plan-builder", ir.workflow_hash))
    write_artifact(output_dir / "11-quality-gate.json", artifact({"quality_gate": quality_gate}, scan_id, "quality-gate", ir.workflow_hash))

    explanation = semantic_pipeline.explain_report(final_findings)
    report = build_report_json(ir, final_findings, semantic, tests, attack_surface, explanation, verification, quality_gate)
    report_payload = artifact({"report": report}, scan_id, "report-builder", ir.workflow_hash)
    write_artifact(output_dir / "report.json", report_payload)
    (output_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    write_artifact_index(output_dir, scan_id, ir.workflow_hash)

    return {
        "scan_id": scan_id,
        "output_dir": str(output_dir.resolve()),
        "finding_count": len(final_findings),
        "critical_or_high": sum(finding.severity in {"CRITICAL", "HIGH"} for finding in final_findings),
        "llm_enabled": llm_enabled,
        "llm_errors": semantic_pipeline.errors,
        "verification_valid": verification["valid"],
        "quality_gate": quality_gate["decision"],
        "exit_code": quality_gate["exit_code"],
    }
