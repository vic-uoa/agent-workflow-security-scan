#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from agent_workflow_scan.pipeline import run_scan  # noqa: E402


CASES = [
    {"name": "safe-workflow", "gate": "PASS", "present": set(), "absent": {"FLOW-003", "TOOL-003", "TOOL-008"}, "zero": True},
    {"name": "approval-protected-workflow", "gate": "PASS", "present": set(), "absent": {"FLOW-003", "FLOW-006", "TOOL-008"}, "zero": True},
    {"name": "approval-bypass-workflow", "gate": "FAIL", "present": {"FLOW-006"}, "absent": set()},
    {"name": "keyword-spoofed-control", "gate": "FAIL", "present": {"FLOW-003", "TOOL-008"}, "absent": set(), "max_findings": 2},
    {"name": "parameter-precision-workflow", "gate": "PASS", "present": set(), "absent": {"TOOL-003", "TOOL-017"}, "zero": True},
    {"name": "text-optimization-workflow", "gate": "REVIEW", "present": {"LLM-001"}, "absent": {"IN-002", "OUT-001", "OUT-008"}, "max_findings": 1},
    {"name": "review-only-workflow", "gate": "PASS", "present": set(), "absent": {"LLM-006", "LLM-009", "LLM-010"}, "zero": True},
    {"name": "safe-code-transform-workflow", "gate": "PASS", "present": set(), "absent": {"FLOW-003", "FLOW-010", "TOOL-002", "TOOL-004", "TOOL-008"}, "zero": True},
    {"name": "simple-rag-readonly-workflow", "gate": "PASS", "present": set(), "absent": {"KB-001", "KB-002", "KB-003", "KB-008", "KB-009", "KB-010"}, "zero": True},
    {"name": "non-strict-schema-workflow", "gate": "FAIL", "present": {"LLM-006", "TOOL-011"}, "absent": set(), "max_findings": 3},
    {"name": "document-indirect-injection-workflow", "gate": "FAIL", "present": {"FLOW-005", "LLM-003", "FLOW-010"}, "absent": set(), "max_findings": 6},
    {"name": "risky-workflow", "gate": "FAIL", "present": {"FLOW-005", "TOOL-003", "TOOL-010", "KB-005"}, "absent": set(), "max_findings": 20},
    {"name": "tencent-inspired-workflow", "gate": "FAIL", "present": {"FLOW-009", "FLOW-010", "FLOW-011", "FLOW-012", "FLOW-013", "TOOL-016", "TOOL-017", "KB-012", "OUT-009"}, "absent": set(), "max_findings": 40},
    {"name": "dify-example-content-workflow", "gate": "REVIEW", "present": {"LLM-001"}, "absent": {"FLOW-004", "FLOW-008", "FLOW-009", "LLM-004", "LLM-011", "OUT-002", "OUT-004", "OUT-005", "OUT-009"}, "max_findings": 1},
    {"name": "dify-security-instruction-workflow", "gate": "REVIEW", "present": {"LLM-001"}, "absent": {"LLM-007", "OUT-003", "OUT-008", "OUT-010"}, "max_findings": 1},
    {"name": "dify-security-adjacent-credential-workflow", "gate": "REVIEW", "present": {"LLM-011"}, "absent": {"LLM-004", "FLOW-009"}, "max_findings": 2},
    {"name": "dify-unknown-audience-output-workflow", "gate": "REVIEW", "present": {"OUT-002"}, "absent": {"FLOW-004", "FLOW-009"}, "max_findings": 1},
    {"name": "dify-env-secret-type-egress-workflow", "gate": "FAIL", "present": {"FLOW-004", "TOOL-007"}, "absent": {"FLOW-009"}, "max_findings": 2},
    {"name": "dify-candidate-password-public-output-workflow", "gate": "REVIEW", "present": {"FLOW-004", "OUT-002"}, "absent": {"FLOW-009"}, "max_findings": 1},
    {"name": "dify-decision-output-injection-workflow", "gate": "FAIL", "present": {"LLM-001"}, "absent": {"FLOW-003", "LLM-007"}, "max_findings": 1},
    {"name": "dify-mixed-authorization-instruction-workflow", "gate": "REVIEW", "present": {"LLM-007"}, "absent": {"OUT-003"}, "max_findings": 1},
    {"name": "dify-confirmed-egress-workflow", "gate": "FAIL", "present": {"FLOW-004", "FLOW-009", "TOOL-007", "TOOL-017"}, "absent": set(), "max_findings": 8},
    {"name": "dify-redacted-egress-workflow", "gate": "PASS", "present": {"FLOW-004", "TOOL-007"}, "absent": {"FLOW-009", "TOOL-017"}, "zero": True},
    {"name": "dify-public-output-workflow", "gate": "FAIL", "present": {"FLOW-004", "FLOW-009", "OUT-002"}, "absent": {"TOOL-007", "TOOL-017"}, "max_findings": 4},
    {"name": "dify-field-specific-loop-workflow", "gate": "REVIEW", "present": {"LLM-001"}, "absent": {"IN-002", "FLOW-007"}, "max_findings": 1},
    {"name": "dify-output-type-mismatch-workflow", "gate": "REVIEW", "present": {"FLOW-014"}, "absent": {"FLOW-009"}, "max_findings": 2},
    {"name": "dify-regex-derived-route-workflow", "gate": "REVIEW", "present": {"FLOW-015"}, "absent": {"FLOW-003", "TOOL-004"}, "max_findings": 2},
    {"name": "dify-llm-code-parser-workflow", "gate": "REVIEW", "present": {"LLM-006", "LLM-012", "OUT-011"}, "absent": {"FLOW-010", "TOOL-004"}, "max_findings": 4},
    {"name": "dify-conflicting-branch-prompts-workflow", "gate": "REVIEW", "present": {"FLOW-016"}, "absent": {"FLOW-011"}, "max_findings": 2},
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the enterprise DSL security validation matrix.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    fixtures = SKILL_ROOT / "tests" / "fixtures"
    rules = SKILL_ROOT / "rules" / "core-rules.yml"
    baseline = SKILL_ROOT / "config" / "internal-baseline.yml"
    results = []
    for case in CASES:
        name = case["name"]
        run = run_scan(
            dsl_path=fixtures / f"{name}.yml",
            samples_path=fixtures / "samples.json" if name in {"risky-workflow", "tencent-inspired-workflow"} else None,
            baseline_path=baseline,
            output_dir=args.output,
            rules_path=rules,
            llm_mode="disabled",
        )
        rule_ids = set(run["finding_rule_ids"])
        missing = sorted(case["present"] - rule_ids)
        unexpected = sorted(case["absent"] & rule_ids)
        zero_ok = not case.get("zero") or run["report_summary"]["finding_count"] == 0
        count_ok = run["report_summary"]["finding_count"] <= case.get("max_findings", 10_000)
        passed = run["quality_gate"] == case["gate"] and not missing and not unexpected and zero_ok and count_ok
        results.append({
            "case": name,
            "expected_gate": case["gate"],
            "actual_gate": run["quality_gate"],
            "finding_count": run["report_summary"]["finding_count"],
            "risk_chain_count": run["risk_chain_count"],
            "test_case_count": run["test_case_count"],
            "expected_present": sorted(case["present"]),
            "expected_absent": sorted(case["absent"]),
            "missing_rules": missing,
            "unexpected_rules": unexpected,
            "count_within_limit": count_ok,
            "passed": passed,
        })
    summary = {"suite": "enterprise-dify-workflow-security", "passed": all(item["passed"] for item in results), "cases": results}
    (args.output / "validation-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# Enterprise Workflow Scanner Validation", "", f"Overall: **{'PASS' if summary['passed'] else 'FAIL'}**", "", "| Case | Gate | Findings | Risk chains | Result |", "|---|---:|---:|---:|---:|"]
    for item in results:
        lines.append(f"| {item['case']} | {item['actual_gate']} | {item['finding_count']} | {item['risk_chain_count']} | {'PASS' if item['passed'] else 'FAIL'} |")
    (args.output / "validation-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
