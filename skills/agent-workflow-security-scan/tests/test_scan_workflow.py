from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import re
import sys
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from agent_workflow_scan.engine import execute_rules  # noqa: E402
from agent_workflow_scan.llm import OpenAIResponsesClient, SemanticPipeline, redact_for_model  # noqa: E402
from agent_workflow_scan.parser import parse_dify_dsl  # noqa: E402
from agent_workflow_scan.pipeline import apply_baseline, load_baseline, run_scan  # noqa: E402


FIXTURES = ROOT / "tests" / "fixtures"
RULES = ROOT / "rules" / "core-rules.yml"
BASELINE = ROOT / "config" / "internal-baseline.yml"


def all_rule_ids(findings) -> set[str]:
    return {
        rule_id
        for finding in findings
        for rule_id in [finding.rule_id, *finding.related_rule_ids]
    }


class ParserTests(unittest.TestCase):
    def test_parses_internal_dify_graph_and_variable_refs(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "risky-workflow.yml")
        self.assertEqual(5, len(ir.nodes))
        self.assertEqual(4, len(ir.edges))
        self.assertTrue(any(ref.producer_node_id == "kb" and ref.consumer_node_id == "llm" for ref in ir.variable_refs))
        self.assertTrue(any(ref.producer_node_id == "llm" and ref.consumer_node_id == "http" for ref in ir.variable_refs))

    def test_redacts_secrets_before_model(self) -> None:
        value = {"api_key": "secret-value", "text": "Authorization: Bearer abcdefghijklmnop"}
        redacted = redact_for_model(value)
        self.assertEqual("<REDACTED_SECRET>", redacted["api_key"])
        self.assertNotIn("abcdefghijklmnop", redacted["text"])

    def test_responses_request_uses_strict_schema_and_no_storage(self) -> None:
        schema = {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
            "additionalProperties": False,
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps({"output_text": json.dumps({"result": "ok"})}).encode("utf-8")

        captured = {}

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-only-key"}), patch("agent_workflow_scan.llm.urlopen", fake_urlopen):
            client = OpenAIResponsesClient("gpt-5.6-terra")
            result = client.call_json(
                role="unit-test",
                instructions="Return structured test data.",
                payload={"untrusted": "data"},
                schema=schema,
                scan_id="SCAN-test",
            )
        self.assertEqual({"result": "ok"}, result)
        self.assertFalse(captured["body"]["store"])
        self.assertTrue(captured["body"]["text"]["format"]["strict"])


class RuleTests(unittest.TestCase):
    def test_every_catalog_rule_has_an_engine_evaluator_reference(self) -> None:
        catalog = yaml.safe_load(RULES.read_text(encoding="utf-8"))
        rule_ids = {item["id"] for item in catalog["rules"]}
        engine_text = (SCRIPTS / "agent_workflow_scan" / "engine.py").read_text(encoding="utf-8")
        evaluator_ids = set(re.findall(r'"([A-Z]+-[0-9]{3})"', engine_text))
        self.assertFalse(rule_ids - evaluator_ids, sorted(rule_ids - evaluator_ids))

    def test_risky_chain_triggers_expected_rules(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "risky-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        for rule_id in {"FLOW-005", "LLM-001", "LLM-003", "TOOL-003", "TOOL-010", "KB-005"}:
            self.assertIn(rule_id, rule_ids)
        confirmed_high = [finding for finding in findings if finding.status == "CONFIRMED" and finding.severity in {"HIGH", "CRITICAL"}]
        self.assertTrue(confirmed_high)

    def test_safe_fixture_has_no_secret_or_high_impact_tool_findings(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "safe-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertNotIn("FLOW-008", rule_ids)
        self.assertNotIn("TOOL-008", rule_ids)

    def test_text_optimization_workflow_has_one_prompt_root_cause_without_output_false_positives(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "text-optimization-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        prompt_findings = [finding for finding in findings if finding.root_cause_id and "LLM-001" in {finding.rule_id, *finding.related_rule_ids}]
        self.assertEqual(1, len(prompt_findings))
        self.assertEqual("OBSERVED", prompt_findings[0].status)
        self.assertEqual("MEDIUM", prompt_findings[0].severity)
        self.assertTrue({"IN-007", "IN-009", "LLM-002"}.issubset(set(prompt_findings[0].related_rule_ids)))
        self.assertFalse({"OUT-001", "OUT-008"} & all_rule_ids(findings))
        self.assertIn("IN-002", all_rule_ids(findings))

    def test_tencent_inspired_static_precursors_are_detected(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "tencent-inspired-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, candidates = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        expected = {
            "IN-009", "FLOW-009", "FLOW-010", "FLOW-011", "FLOW-012", "FLOW-013",
            "TOOL-015", "TOOL-016", "TOOL-017", "OUT-009", "OUT-010",
            "KB-011", "KB-012",
        }
        self.assertTrue(expected.issubset(rule_ids), sorted(expected - rule_ids))
        self.assertTrue(all("attack_family" in item for item in candidates["candidates"]))

    def test_registered_tool_integrity_suppresses_supply_chain_coverage_gap(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "risky-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        self.assertFalse(any(f.rule_id == "TOOL-014" and "http" in f.node_ids for f in findings))

    def test_human_approval_route_blocks_high_impact_path(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "approval-protected-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        self.assertTrue(any(node.type == "HUMAN" for node in ir.nodes))
        self.assertFalse({"FLOW-003", "FLOW-006", "TOOL-008"} & {finding.rule_id for finding in findings})

    def test_reject_branch_to_tool_is_confirmed_bypass(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "approval-bypass-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        bypass = [finding for finding in findings if finding.rule_id == "FLOW-006"]
        self.assertTrue(bypass)
        self.assertTrue(all(finding.status == "CONFIRMED" for finding in bypass))

    def test_security_keywords_do_not_create_a_control(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "keyword-spoofed-control.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertIn("FLOW-003", rule_ids)
        self.assertIn("TOOL-008", rule_ids)

    def test_dynamic_body_does_not_imply_dynamic_url(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "parameter-precision-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertNotIn("TOOL-003", rule_ids)
        self.assertNotIn("TOOL-017", rule_ids)

    def test_schema_presence_is_not_enough_when_additional_properties_are_allowed(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "non-strict-schema-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertIn("LLM-006", rule_ids)
        self.assertIn("TOOL-011", rule_ids)

    def test_document_extractor_is_an_untrusted_indirect_injection_source(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "document-indirect-injection-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertTrue(any(node.type == "CONTENT" for node in ir.nodes))
        self.assertIn("FLOW-005", rule_ids)
        self.assertIn("LLM-003", rule_ids)
        self.assertIn("FLOW-010", rule_ids)

    def test_node_control_aggregation_merges_paths_but_keeps_distinct_controls(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "tencent-inspired-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, candidates = execute_rules(ir, RULES)
        code_items = [finding for finding in findings if finding.anchor_node_id == "code"]
        domains = {finding.control_domain for finding in code_items}
        self.assertIn("action_authorization", domains)
        self.assertIn("execution_boundary", domains)
        self.assertIn("structured_data_contract", domains)
        authorization = next(finding for finding in code_items if finding.control_domain == "action_authorization")
        self.assertGreater(len(authorization.instance_summaries), 1)
        self.assertIn("FLOW-003", {authorization.rule_id, *authorization.related_rule_ids})
        agent_governance = next(finding for finding in findings if finding.control_domain == "agent_governance")
        self.assertEqual("llm2", agent_governance.anchor_node_id)
        self.assertTrue(candidates["raw_match_count"] > len(findings))
        self.assertEqual(
            set(candidates["raw_rule_ids"]),
            {rule_id for finding in findings for rule_id in (finding.rule_id, *finding.related_rule_ids)},
        )

    def test_sensitive_start_field_does_not_taint_unrelated_model_input(self) -> None:
        ir, _ = parse_dify_dsl(ROOT / "examples" / "demo-static-employee-assistant.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        self.assertTrue(any(f.rule_id == "TOOL-017" and "callback" in f.node_ids for f in findings))
        self.assertFalse(any(
            f.rule_id == "FLOW-009" and f.node_ids == ["start", "decision_llm", "answer"]
            for f in findings
        ))


class PipelineTests(unittest.TestCase):
    def test_user_seed_derives_positive_negative_boundary_and_metamorphic_cluster(self) -> None:
        from agent_workflow_scan.llm import deterministic_test_cluster

        cluster = deterministic_test_cluster({"samples": [
            {"sample_id": "seed-1", "input": {"query": "ok"}, "expected_business_intent": "answer normally"},
        ]}, [])
        self.assertEqual({"positive", "negative", "boundary", "metamorphic"}, {
            case["case_type"] for case in cluster["cases"]
        })
        self.assertTrue(all(case["seed_sample_ids"] == ["seed-1"] for case in cluster["cases"]))
        self.assertTrue(all(case["execution_status"] == "NOT_EXECUTED" for case in cluster["cases"]))
        self.assertEqual("user", next(case for case in cluster["cases"] if case["case_type"] == "positive")["oracle_source"])

    def test_assessment_mode_requires_confirmed_complete_samples(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "confirmed_by_user"):
                run_scan(
                    dsl_path=FIXTURES / "text-optimization-workflow.yml",
                    samples_path=FIXTURES / "samples.json",
                    baseline_path=BASELINE,
                    output_dir=Path(directory),
                    rules_path=RULES,
                    llm_mode="disabled",
                    analyst_model="gpt-5.6-terra",
                    reviewer_model="gpt-5.6-sol",
                    scan_mode="assessment",
                )

    def test_assessment_mode_accepts_one_seed_and_generates_required_cluster(self) -> None:
        with TemporaryDirectory() as directory:
            result = run_scan(
                dsl_path=FIXTURES / "text-optimization-workflow.yml",
                samples_path=FIXTURES / "assessment-samples.json",
                baseline_path=BASELINE,
                output_dir=Path(directory),
                rules_path=RULES,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
                scan_mode="assessment",
            )
            self.assertEqual("REVIEW", result["quality_gate"])
            self.assertEqual(1, result["observation_count"])
            cluster = json.loads((Path(directory) / "05-test-cluster.json").read_text(encoding="utf-8"))["test_cluster"]
            self.assertTrue({"positive", "negative", "boundary"}.issubset({case["case_type"] for case in cluster["cases"]}))
            self.assertTrue(cluster["generation_audit"]["lineage_verified"])
            self.assertFalse(cluster["generation_audit"]["execution_evidence_present"])
            verification = json.loads((Path(directory) / "07-verification.json").read_text(encoding="utf-8"))["verification"]
            self.assertTrue(verification["coverage_accounting"]["lossless_root_cause_aggregation"])
            self.assertEqual([], verification["coverage_accounting"]["lost_rule_ids"])
            self.assertGreater(
                verification["coverage_accounting"]["raw_match_count"],
                verification["coverage_accounting"]["root_finding_count"],
            )

    def test_unexecuted_generated_cases_are_excluded_from_llm_adjudication(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "text-optimization-workflow.yml")
        _, findings, candidates = execute_rules(ir, RULES)
        captured: dict[str, object] = {}

        def fake_call(_client, **kwargs):
            captured.update(kwargs["payload"])
            return {"adjudications": []}

        with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-test-key"}), patch.object(
            OpenAIResponsesClient, "call_json", fake_call,
        ):
            pipeline = SemanticPipeline(True, "test-analyst", "test-reviewer", "SCAN-test")
            pipeline.adjudicate(ir, candidates, findings, {"cases": [{"case_id": "unexecuted"}]})
        self.assertNotIn("test_cases", captured)
        self.assertNotIn("cases", captured)

    def test_offline_scan_writes_all_artifacts(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory)
            result = run_scan(
                dsl_path=FIXTURES / "risky-workflow.yml",
                samples_path=FIXTURES / "samples.json",
                baseline_path=BASELINE,
                output_dir=output,
                rules_path=RULES,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertGreater(result["finding_count"], 0)
            for filename in (
                "00-scan-manifest.json", "01-workflow-ir.json", "02-security-facts.json",
                "03-semantic-inventory.json", "04-rule-candidates.json", "05-test-cluster.json",
                "06-llm-adjudication.json", "07-verification.json", "08-findings.json",
                "09-attack-surface.json", "10-dynamic-test-plan.json", "report.json", "report.md",
                "11-quality-gate.json", "12-artifact-index.json",
            ):
                self.assertTrue((output / filename).exists(), filename)
            artifact_schema = json.loads((ROOT / "schemas" / "intermediate-artifacts.schema.json").read_text(encoding="utf-8"))
            artifact_validator = Draft202012Validator(artifact_schema)
            for filename in (
                "00-scan-manifest.json", "01-workflow-ir.json", "02-security-facts.json",
                "03-semantic-inventory.json", "04-rule-candidates.json", "05-test-cluster.json",
                "06-llm-adjudication.json", "07-verification.json", "08-findings.json",
                "09-attack-surface.json", "10-dynamic-test-plan.json", "report.json",
                "11-quality-gate.json", "12-artifact-index.json",
            ):
                payload = json.loads((output / filename).read_text(encoding="utf-8"))
                self.assertFalse(list(artifact_validator.iter_errors(payload)), filename)
            findings = json.loads((output / "08-findings.json").read_text(encoding="utf-8"))["findings"]
            ir_text = (output / "01-workflow-ir.json").read_text(encoding="utf-8")
            self.assertNotIn("ScannerSecret123", ir_text)
            self.assertNotIn("scanner-test-token-123456", ir_text)
            fact_ids = {
                fact["id"] for fact in json.loads((output / "02-security-facts.json").read_text(encoding="utf-8"))["facts"]
            }
            self.assertTrue(all(set(item["evidence_refs"]).issubset(fact_ids) for item in findings))

    def test_quality_gate_and_audited_waiver(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            failed = run_scan(
                dsl_path=FIXTURES / "approval-bypass-workflow.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=root / "failed",
                rules_path=RULES,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertEqual("FAIL", failed["quality_gate"])
            workflow_hash = json.loads((root / "failed" / "00-scan-manifest.json").read_text(encoding="utf-8"))["workflow_hash"]
            invalid_waiver = root / "invalid-waivers.json"
            invalid_waiver.write_text(json.dumps({"waivers": [{
                "waiver_id": "W-INVALID",
                "rule_id": "FLOW-006",
                "approver": "security-owner",
                "justification": "Missing workflow binding must never bypass the gate.",
                "expires_at": "2099-01-01T00:00:00Z",
            }]}), encoding="utf-8")
            rejected = run_scan(
                dsl_path=FIXTURES / "approval-bypass-workflow.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=root / "rejected-waiver",
                rules_path=RULES,
                waivers_path=invalid_waiver,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertEqual("FAIL", rejected["quality_gate"])
            rejected_gate = json.loads((root / "rejected-waiver" / "11-quality-gate.json").read_text(encoding="utf-8"))
            self.assertTrue(any(
                item["reason"] == "missing_workflow_hash"
                for item in rejected_gate["quality_gate"]["waiver_audit"]["rejected"]
            ))
            waiver = root / "waivers.json"
            waiver.write_text(json.dumps({"waivers": [{
                "waiver_id": "W-001",
                "rule_id": "FLOW-006",
                "workflow_hash": workflow_hash,
                "approver": "security-owner",
                "justification": "Synthetic unit-test exception only.",
                "expires_at": "2099-01-01T00:00:00Z",
            }]}), encoding="utf-8")
            passed = run_scan(
                dsl_path=FIXTURES / "approval-bypass-workflow.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=root / "waived",
                rules_path=RULES,
                waivers_path=waiver,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertEqual("PASS", passed["quality_gate"])
            payload = json.loads((root / "waived" / "08-findings.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["findings"][0]["waived"])

    def test_review_gate_for_non_blocking_runtime_gaps(self) -> None:
        with TemporaryDirectory() as directory:
            result = run_scan(
                dsl_path=FIXTURES / "review-only-workflow.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=Path(directory),
                rules_path=RULES,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertEqual("REVIEW", result["quality_gate"])
            gate = json.loads((Path(directory) / "11-quality-gate.json").read_text(encoding="utf-8"))["quality_gate"]
            self.assertEqual(0, gate["blocking_count"])
            self.assertGreater(gate["review_count"], 0)

    def test_rule_waiver_cannot_hide_other_rules_in_aggregated_item(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            initial = run_scan(
                dsl_path=FIXTURES / "keyword-spoofed-control.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=root / "initial",
                rules_path=RULES,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            workflow_hash = json.loads((root / "initial" / "00-scan-manifest.json").read_text(encoding="utf-8"))["workflow_hash"]
            waiver = root / "ambiguous-waiver.json"
            waiver.write_text(json.dumps({"waivers": [{
                "waiver_id": "W-AMBIGUOUS",
                "rule_id": "FLOW-003",
                "workflow_hash": workflow_hash,
                "approver": "security-owner",
                "justification": "Must not hide TOOL-008 in the same risk item.",
                "expires_at": "2099-01-01T00:00:00Z",
            }]}), encoding="utf-8")
            result = run_scan(
                dsl_path=FIXTURES / "keyword-spoofed-control.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=root / "waived",
                rules_path=RULES,
                waivers_path=waiver,
                llm_mode="disabled",
                analyst_model="gpt-5.6-terra",
                reviewer_model="gpt-5.6-sol",
            )
            self.assertEqual("FAIL", initial["quality_gate"])
            self.assertEqual("FAIL", result["quality_gate"])
            gate = json.loads((root / "waived" / "11-quality-gate.json").read_text(encoding="utf-8"))["quality_gate"]
            self.assertEqual(
                "ambiguous_rule_scope_after_node_control_aggregation_use_finding_id",
                gate["waiver_audit"]["rejected"][0]["reason"],
            )


if __name__ == "__main__":
    unittest.main()
