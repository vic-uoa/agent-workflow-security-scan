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

from agent_workflow_scan.engine import RuleCatalog, execute_rules  # noqa: E402
from agent_workflow_scan.llm import (  # noqa: E402
    ModelAdvisor,
    OpenAIResponsesClient,
    deterministic_semantic_inventory,
    deterministic_test_cluster,
    redact_for_model,
)
from agent_workflow_scan.models import Finding  # noqa: E402
from agent_workflow_scan.parser import classify_secret_occurrences, parse_dify_dsl  # noqa: E402
from agent_workflow_scan.pipeline import (  # noqa: E402
    apply_baseline,
    evaluate_quality_gate,
    load_baseline,
    run_scan,
    validate_seed_samples,
    verify_deterministic_findings,
)
from agent_workflow_scan.report import build_attack_surface  # noqa: E402


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
    def test_secret_context_classifier_separates_examples_from_live_literals(self) -> None:
        sample = "输出样例：\n```json\n{\"password\": \"password=abc12345\"}\n```"
        live = "production password=RealSecret123"
        self.assertEqual({"example_content"}, {
            item["value_kind"] for item in classify_secret_occurrences(sample)
        })
        self.assertEqual({"credential_literal"}, {
            item["value_kind"] for item in classify_secret_occurrences(live)
        })

    def test_secret_context_reduces_confidence_without_erasing_concrete_values(self) -> None:
        fenced = "```env\napi_key=ABCDEFGH12345678\n```"
        adjacent = "安全规范：不得泄露或记录凭证。\napi_key=ABCDEFGH12345678"
        strong_example = "输出示例：sk-proj-ABCDEFGHIJKLMNOPQRSTUV"
        for value in (fenced, adjacent, strong_example):
            occurrences = classify_secret_occurrences(value)
            self.assertEqual({"credential_literal_candidate"}, {
                item["value_kind"] for item in occurrences
            })
            self.assertEqual({"candidate"}, {
                item["credential_likelihood"] for item in occurrences
            })

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

    def test_dify_07_contract_normalizes_official_nodes_and_virtual_sources(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-0.7-contract-workflow.yml")
        nodes = ir.node_map()
        self.assertEqual("0.7.0", ir.raw_metadata["dsl_version"])
        self.assertEqual("advanced-chat", ir.raw_metadata["app_mode"])
        self.assertEqual("LOOP", nodes["loop"].type)
        self.assertEqual("ITERATION", nodes["iteration"].type)
        self.assertEqual("STRUCTURAL", nodes["loop-start"].type)
        self.assertEqual("STRUCTURAL", nodes["iteration-start"].type)
        self.assertEqual("LLM", nodes["agent-v2"].type)
        self.assertEqual("CONTENT", nodes["source"].type)
        self.assertEqual("INPUT", nodes["trigger"].type)
        self.assertEqual("INPUT", nodes["sys"].type)
        self.assertEqual([], ir.coverage_gaps)
        self.assertTrue(any(
            ref.producer_node_id == "sys"
            and ref.variable_name == "query"
            and ref.consumer_node_id == "llm"
            for ref in ir.variable_refs
        ))
        recipient_refs = [
            ref for ref in ir.variable_refs
            if ref.consumer_node_id == "mail" and ref.producer_node_id == "llm"
        ]
        self.assertTrue(recipient_refs)
        self.assertEqual({"recipient"}, {ref.consumer_field for ref in recipient_refs})

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
    def test_dify_example_password_url_and_end_are_not_sensitive_egress(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-example-content-workflow.yml")
        facts, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertFalse({
            "FLOW-004", "FLOW-008", "FLOW-009", "LLM-004", "LLM-011",
            "OUT-002", "OUT-004", "OUT-005", "OUT-009",
        } & rule_ids)
        prompt_findings = [finding for finding in findings if "LLM-001" in {finding.rule_id, *finding.related_rule_ids}]
        self.assertEqual(1, len(prompt_findings))
        self.assertEqual(("LOW", "OBSERVED"), (prompt_findings[0].severity, prompt_findings[0].status))
        self.assertEqual([], ir.raw_metadata["secret_locations"])
        self.assertIn("API_RESPONSE", ir.node_map()["end"].capabilities)
        asset_facts = [fact for fact in facts if fact.kind == "sensitive_asset_classification"]
        self.assertTrue(any(fact.data["value_kind"] == "example_content" for fact in asset_facts))
        self.assertFalse(any(fact.data["eligible_for_egress_chain"] for fact in asset_facts))

    def test_confirmed_classified_asset_dynamic_write_forms_complete_chain(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-confirmed-egress-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertTrue({"FLOW-004", "FLOW-009", "TOOL-007", "TOOL-017"}.issubset(rule_ids))
        chain = next(finding for finding in findings if "FLOW-009" in {finding.rule_id, *finding.related_rule_ids})
        self.assertEqual(("CRITICAL", "CONFIRMED"), (chain.severity, chain.status))
        self.assertGreaterEqual(len(chain.attack_preconditions), 5)

    def test_mandatory_redaction_marks_all_egress_paths_mitigated(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-redacted-egress-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        egress = [
            finding for finding in findings
            if {finding.rule_id, *finding.related_rule_ids} & {"FLOW-004", "TOOL-007"}
        ]
        self.assertTrue(egress)
        self.assertTrue(all(finding.status == "MITIGATED" for finding in egress))
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("PASS", gate["decision"])
        self.assertTrue(gate["mitigated_finding_ids"])

    def test_declared_or_passthrough_redaction_cannot_suppress_egress(self) -> None:
        for mutation in ("weak_marker", "passthrough"):
            document = yaml.safe_load(
                (FIXTURES / "dify-redacted-egress-workflow.yml").read_text(encoding="utf-8")
            )
            redact = document["workflow"]["graph"]["nodes"][0]["data"]
            if mutation == "weak_marker":
                redact.pop("security_control")
                redact["output_dlp"] = "planned"
            else:
                redact["code"] = "def main(secret):\n    return dict(masked=secret)\n"
            with TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "mutated.yml"
                path.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")
                ir, _ = parse_dify_dsl(path)
                _, findings, _ = execute_rules(ir, RULES)
            egress = next(
                finding for finding in findings
                if {finding.rule_id, *finding.related_rule_ids} & {"FLOW-004", "TOOL-007"}
            )
            self.assertNotEqual("MITIGATED", egress.status, mutation)
            gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
            self.assertEqual("FAIL", gate["decision"], mutation)

    def test_explicit_public_output_can_be_an_attacker_observable_sink(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-public-output-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertTrue({"FLOW-004", "FLOW-009", "OUT-002"}.issubset(rule_ids))
        chain = next(finding for finding in findings if "FLOW-009" in {finding.rule_id, *finding.related_rule_ids})
        self.assertEqual(("CRITICAL", "CONFIRMED"), (chain.severity, chain.status))

    def test_dify_secret_value_type_is_a_confirmed_asset_without_custom_classification(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-env-secret-type-egress-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        egress = next(
            finding for finding in findings
            if "FLOW-004" in {finding.rule_id, *finding.related_rule_ids}
        )
        self.assertEqual(("HIGH", "CONFIRMED"), (egress.severity, egress.status))

    def test_sensitive_field_name_to_public_output_is_review_not_confirmed(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-candidate-password-public-output-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        output = next(
            finding for finding in findings
            if "OUT-002" in {finding.rule_id, *finding.related_rule_ids}
        )
        self.assertEqual("CANDIDATE", output.status)
        self.assertNotIn("FLOW-009", all_rule_ids(findings))
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])
        surface = build_attack_surface(ir, deterministic_semantic_inventory(ir), findings, {"cases": []})
        self.assertEqual([], surface["risk_chains"])
        self.assertTrue(surface["candidate_paths"])

    def test_machine_decision_output_escalates_prompt_boundary_impact(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-decision-output-injection-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        prompt = next(
            finding for finding in findings
            if "LLM-001" in {finding.rule_id, *finding.related_rule_ids}
        )
        self.assertEqual(("HIGH", "PROBABLE"), (prompt.severity, prompt.status))

    def test_unrelated_disclosure_negation_does_not_hide_authorization_delegation(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-mixed-authorization-instruction-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        authorization = next(finding for finding in findings if finding.rule_id == "LLM-007")
        self.assertEqual(("HIGH", "PROBABLE"), (authorization.severity, authorization.status))

    def test_security_instruction_adjacent_credential_requires_review_not_fail(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-security-adjacent-credential-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        candidate = next(finding for finding in findings if finding.rule_id == "LLM-011")
        self.assertEqual(("HIGH", "CANDIDATE"), (candidate.severity, candidate.status))
        self.assertNotIn("LLM-004", all_rule_ids(findings))
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])

    def test_only_the_field_bound_to_loop_requires_a_resource_limit(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-field-specific-loop-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        self.assertNotIn("IN-002", all_rule_ids(findings))
        self.assertNotIn("FLOW-007", all_rule_ids(findings))

    def test_every_rule_has_exactly_one_dify_dsl_binding(self) -> None:
        catalog = RuleCatalog(RULES)
        self.assertEqual(set(catalog.rules), set(catalog.dify_bindings))
        self.assertTrue(all(binding["dsl_fields"] for binding in catalog.dify_bindings.values()))

    def test_node_rule_matrix_covers_every_catalog_rule_once(self) -> None:
        catalog = yaml.safe_load(RULES.read_text(encoding="utf-8"))
        expected = {item["id"] for item in catalog["rules"]}
        matrix_text = (ROOT / "references" / "node-rule-matrix.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| ((?:FLOW|IN|LLM|TOOL|OUT|KB)-\d{3}) \|", matrix_text, re.MULTILINE)
        self.assertEqual(expected, set(rows))
        self.assertEqual(len(expected), len(rows))

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

    def test_official_loop_iteration_input_and_tool_contracts_do_not_false_positive(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-0.7-contract-workflow.yml")
        _, findings, candidates = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertNotIn("FLOW-007", rule_ids)
        self.assertNotIn("IN-003", rule_ids)
        self.assertNotIn("IN-005", rule_ids)
        self.assertNotIn("TOOL-011", rule_ids)
        self.assertTrue(all(item["dify_binding"]["dsl_fields"] for item in candidates["candidates"]))

        ir.node_map()["loop"].config["loop_count"] = 0
        _, invalid_findings, _ = execute_rules(ir, RULES)
        self.assertIn("FLOW-007", all_rule_ids(invalid_findings))

        single_file_ir, _ = parse_dify_dsl(FIXTURES / "dify-0.7-contract-workflow.yml")
        single_file = single_file_ir.node_map()["start"].config["variables"][0]
        single_file["type"] = "file"
        single_file.pop("max_length", None)
        _, single_file_findings, _ = execute_rules(single_file_ir, RULES)
        self.assertNotIn("IN-002", all_rule_ids(single_file_findings))

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
        self.assertEqual("LOW", prompt_findings[0].severity)
        self.assertTrue({"IN-007", "IN-009", "LLM-002"}.issubset(set(prompt_findings[0].related_rule_ids)))
        self.assertFalse({"OUT-001", "OUT-008"} & all_rule_ids(findings))
        self.assertNotIn("IN-002", all_rule_ids(findings))

    def test_security_instructions_are_not_positive_authorization_or_disclosure_evidence(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-security-instruction-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertIn("LLM-001", rule_ids)
        self.assertFalse({"LLM-007", "OUT-003", "OUT-008", "OUT-010"} & rule_ids)

    def test_sensitive_asset_to_ordinary_end_is_audience_gap_not_confirmed_egress(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-unknown-audience-output-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        output = next(finding for finding in findings if finding.rule_id == "OUT-002")
        self.assertEqual("COVERAGE_GAP", output.status)
        self.assertFalse({"FLOW-004", "FLOW-009"} & all_rule_ids(findings))

    def test_fixed_sandboxed_code_treats_variables_as_data_not_commands(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "safe-code-transform-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        code = next(node for node in ir.nodes if node.id == "code")
        self.assertIn("SANDBOXED_CODE", code.capabilities)
        self.assertNotIn("CODE_EXECUTION", code.capabilities)
        self.assertFalse({"FLOW-003", "FLOW-010", "TOOL-002", "TOOL-004", "TOOL-008"} & all_rule_ids(findings))

    def test_static_single_dataset_rag_is_not_treated_as_cross_tenant_or_poisoned(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "simple-rag-readonly-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        self.assertFalse({"KB-001", "KB-002", "KB-003", "KB-008", "KB-009", "KB-010"} & all_rule_ids(findings))

    def test_tencent_inspired_static_precursors_are_detected(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "tencent-inspired-workflow.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, candidates = execute_rules(ir, RULES)
        web_reader = next(node for node in ir.nodes if node.id == "web")
        self.assertIn("NETWORK_READ", web_reader.capabilities)
        self.assertNotIn("NETWORK_WRITE", web_reader.capabilities)
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

    def test_output_contract_severity_depends_on_machine_consumption(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "output-contract-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        output = next(item for item in findings if item.rule_id == "OUT-001")
        self.assertEqual("CONFIRMED", output.status)
        self.assertEqual("LOW", output.severity)
        self.assertTrue(output.missing_context)

        end = next(node for node in ir.nodes if node.id == "end")
        end.config["machine_consumed"] = True
        _, machine_findings, _ = execute_rules(ir, RULES)
        machine_output = next(item for item in machine_findings if item.rule_id == "OUT-001")
        self.assertEqual("MEDIUM", machine_output.severity)
        self.assertEqual([], machine_output.missing_context)

    def test_declared_producer_consumer_type_mismatch_requires_review(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-output-type-mismatch-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertIn("FLOW-014", rule_ids)
        mismatch = next(item for item in findings if "FLOW-014" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(("MEDIUM", "CONFIRMED"), (mismatch.severity, mismatch.status))
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])

    def test_untrusted_regex_parser_to_condition_is_a_derived_control_path(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-regex-derived-route-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        route = next(item for item in findings if "FLOW-015" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(("MEDIUM", "PROBABLE"), (route.severity, route.status))
        self.assertEqual(["start", "parse-status", "route"], route.node_ids)
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])

    def test_llm_output_parsed_by_code_is_machine_consumed_and_keeps_deployment_gaps(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-llm-code-parser-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        rule_ids = all_rule_ids(findings)
        self.assertTrue({"LLM-006", "LLM-012", "OUT-011"}.issubset(rule_ids))
        parser_contract = next(item for item in findings if "LLM-006" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(("MEDIUM", "CONFIRMED"), (parser_contract.severity, parser_contract.status))
        gaps = [item for item in findings if item.status == "COVERAGE_GAP"]
        self.assertTrue(all(item.severity == "INFO" for item in gaps))
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])

    def test_conflicting_business_state_prompt_edge_is_candidate_only(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "dify-conflicting-branch-prompts-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        branch = next(item for item in findings if "FLOW-016" in {item.rule_id, *item.related_rule_ids})
        self.assertEqual(("MEDIUM", "CANDIDATE"), (branch.severity, branch.status))
        self.assertEqual(["non-issue", "transferred"], branch.node_ids)
        gate = evaluate_quality_gate(findings, load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", gate["decision"])

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

    def test_sensitive_field_name_creates_review_candidate_without_model_chain(self) -> None:
        ir, _ = parse_dify_dsl(ROOT / "examples" / "demo-static-employee-assistant.yml")
        apply_baseline(ir, load_baseline(BASELINE))
        _, findings, _ = execute_rules(ir, RULES)
        tool_candidate = next(f for f in findings if f.rule_id == "TOOL-017")
        self.assertEqual("CANDIDATE", tool_candidate.status)
        self.assertEqual(["start", "callback"], tool_candidate.node_ids)
        self.assertFalse(any(
            "FLOW-009" in {f.rule_id, *f.related_rule_ids}
            for f in findings
        ))


class PipelineTests(unittest.TestCase):
    def test_quality_gate_evaluates_all_aggregated_instances_without_axis_collapse(self) -> None:
        mixed = Finding(
            id="RISK-mixed", rule_id="OUT-001", title="mixed", status="CONFIRMED",
            severity="LOW", confidence=1.0, node_ids=["end"], evidence_refs=[],
            dsl_locations=[], message="mixed evidence", remediation=[],
            instance_summaries=[
                {"finding_id": "low", "rule_ids": ["OUT-001"], "status": "CONFIRMED", "severity": "LOW", "path": ["end"]},
                {"finding_id": "high", "rule_ids": ["OUT-002"], "status": "PROBABLE", "severity": "HIGH", "path": ["kb", "end"]},
            ],
        )
        review = evaluate_quality_gate([mixed], load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("REVIEW", review["decision"])
        self.assertEqual("high", review["review_instances"][0]["finding_id"])

        mixed.instance_summaries.append({
            "finding_id": "blocker", "rule_ids": ["FLOW-004"], "status": "CONFIRMED",
            "severity": "HIGH", "path": ["secret", "http"],
        })
        failed = evaluate_quality_gate([mixed], load_baseline(BASELINE), {"applied": [], "rejected": []})
        self.assertEqual("FAIL", failed["decision"])
        self.assertEqual("blocker", failed["blocking_instances"][0]["finding_id"])

    def test_user_seed_derives_positive_negative_boundary_and_metamorphic_cluster(self) -> None:
        cluster = deterministic_test_cluster({"samples": [
            {"sample_id": "seed-1", "input": {"query": "ok"}, "expected_business_intent": "answer normally"},
        ]}, [])
        self.assertEqual({"positive", "negative", "boundary", "metamorphic"}, {
            case["case_type"] for case in cluster["cases"]
        })
        self.assertTrue(all(case["seed_sample_ids"] == ["seed-1"] for case in cluster["cases"]))
        self.assertTrue(all(case["execution_status"] == "NOT_EXECUTED" for case in cluster["cases"]))
        self.assertEqual("user", next(case for case in cluster["cases"] if case["case_type"] == "positive")["oracle_source"])

    def test_field_aware_mutations_change_text_and_never_duplicate_seed(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "branch-routing-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        seed = {"content": "正常缺陷描述", "bugType": "01"}
        cluster = deterministic_test_cluster({"samples": [{
            "sample_id": "seed-route",
            "input": seed,
            "expected_business_intent": "按缺陷类型质检",
        }]}, findings, ir)
        positive = next(case for case in cluster["cases"] if case["case_type"] == "positive")
        derived = [case for case in cluster["cases"] if case["case_type"] != "positive"]
        self.assertTrue(derived)
        self.assertTrue(all(case["input"] != positive["input"] for case in derived))
        self.assertEqual(0, cluster["generation_audit"]["exact_duplicate_input_count"])
        self.assertEqual(0, cluster["generation_audit"]["unchanged_derived_case_count"])
        metamorphic = next(case for case in derived if case["case_type"] == "metamorphic")
        self.assertNotEqual(seed["content"], metamorphic["input"]["content"])
        self.assertEqual("01", metamorphic["input"]["bugType"])

    def test_array_object_mutation_targets_text_not_id_and_respects_max_length(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "array-input-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        cluster = deterministic_test_cluster({"samples": [{
            "sample_id": "array-seed",
            "input": {"content": [{"id": 7, "text": "查询响应较慢"}], "bugType": "01"},
            "expected_business_intent": "缺陷质检",
        }]}, findings, ir)
        targeted = [case for case in cluster["cases"] if case.get("route_variants")]
        self.assertTrue(targeted)
        for case in targeted:
            self.assertEqual(7, case["input"]["content"][0]["id"])
            self.assertLessEqual(len(case["input"]["content"][0]["text"]), 48)
            self.assertIn(["content", 0, "text"], case["mutated_paths"])
            self.assertTrue(case["input_validation"]["valid_against_declared_schema"])

    def test_route_aware_cases_cover_direct_branches_with_full_graph_paths(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "branch-routing-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        cluster = deterministic_test_cluster({"samples": [{
            "sample_id": "seed-route",
            "input": {"content": "正常缺陷描述", "bugType": "01"},
            "expected_business_intent": "按缺陷类型质检",
        }]}, findings, ir)
        targeted = [case for case in cluster["cases"] if case.get("route_variants")]
        security_cases = [case for case in targeted if "llm-security" in case["target_nodes"]]
        generic_cases = [case for case in targeted if "llm-generic" in case["target_nodes"]]
        self.assertTrue(security_cases)
        self.assertTrue(generic_cases)
        self.assertTrue(all(case["input"]["bugType"] == "03" for case in security_cases))
        self.assertTrue(all(case["input"]["bugType"] not in {"01", "03"} for case in generic_cases))
        self.assertTrue(all(case["route_status"] == "SATISFIABLE" for case in targeted))
        self.assertTrue(all("route" in case["target_path"] for case in targeted))
        edge_pairs = {(edge.source, edge.target) for edge in ir.edges}
        self.assertTrue(all(
            all(pair in edge_pairs for pair in zip(case["target_path"], case["target_path"][1:]))
            for case in targeted
        ))

    def test_attack_surface_uses_exact_finding_target_case_mapping(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "branch-routing-workflow.yml")
        _, findings, _ = execute_rules(ir, RULES)
        cluster = deterministic_test_cluster({"samples": [{
            "sample_id": "seed-route",
            "input": {"content": "正常缺陷描述", "bugType": "01"},
            "expected_business_intent": "按缺陷类型质检",
        }]}, findings, ir)
        surface = build_attack_surface(ir, deterministic_semantic_inventory(ir), findings, cluster)
        cases = {case["case_id"]: case for case in cluster["cases"]}
        self.assertTrue(surface["attack_paths"])
        for path in surface["attack_paths"]:
            for case_id in path["test_case_ids"]:
                case = cases[case_id]
                self.assertIn(path["finding_id"], case["finding_ids"])
                self.assertIn(path["target_node"], case["target_nodes"])
        self.assertEqual([], surface["test_coverage"]["executed_finding_ids"])
        self.assertEqual([], surface["test_coverage"]["passed_finding_ids"])

    def test_structured_contract_finding_gets_a_machine_readable_test(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "branch-routing-workflow.yml")
        finding = Finding(
            id="RISK-output-contract", rule_id="OUT-001", title="输出契约", status="CONFIRMED",
            severity="MEDIUM", confidence=1.0, node_ids=["end"], evidence_refs=[],
            dsl_locations=["/workflow/graph/nodes/5"], message="输出缺少严格契约", remediation=[],
            anchor_node_id="end", control_domain="structured_data_contract",
        )
        cluster = deterministic_test_cluster({"samples": [{
            "sample_id": "seed-route",
            "input": {"content": "正常缺陷描述", "bugType": "01"},
            "expected_business_intent": "按缺陷类型质检",
        }]}, [finding], ir)
        case = next(
            item for item in cluster["cases"]
            if "structured_output_contract" in item["attack_techniques"]
        )
        self.assertTrue(case["oracle"]["must_parse_as_json"])
        self.assertTrue(case["oracle"]["must_validate_declared_schema"])
        self.assertEqual("end", case["oracle"]["must_reach_target"])

    def test_seed_validation_enforces_declared_max_length(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "branch-routing-workflow.yml")
        start = next(node for node in ir.nodes if node.id == "start")
        content_spec = next(item for item in start.config["variables"] if item["variable"] == "content")
        content_spec["max_length"] = 3
        samples = {
            "confirmed_by_user": True,
            "confirmed_dsl_sha256": ir.workflow_hash,
            "samples": [{
                "sample_id": "too-long",
                "input": {"content": "超过长度", "bugType": "01"},
                "expected_business_intent": "质检",
            }],
        }
        with self.assertRaisesRegex(ValueError, "max_length_3_exceeded"):
            validate_seed_samples(samples, ir)

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
                scan_mode="assessment",
            )
            self.assertEqual("PASS", result["quality_gate"])
            self.assertEqual(1, result["observation_count"])
            cluster = json.loads((Path(directory) / "05-test-cluster.json").read_text(encoding="utf-8"))["test_cluster"]
            self.assertTrue({"positive", "negative", "boundary"}.issubset({case["case_type"] for case in cluster["cases"]}))
            self.assertTrue(cluster["generation_audit"]["lineage_verified"])
            self.assertFalse(cluster["generation_audit"]["execution_evidence_present"])
            self.assertEqual(0, cluster["generation_audit"]["exact_duplicate_input_count"])
            self.assertEqual(0, cluster["generation_audit"]["unchanged_derived_case_count"])
            self.assertEqual(0, cluster["generation_audit"]["executed_case_count"])
            verification = json.loads((Path(directory) / "07-verification.json").read_text(encoding="utf-8"))["verification"]
            self.assertTrue(verification["coverage_accounting"]["lossless_root_cause_aggregation"])
            self.assertEqual([], verification["coverage_accounting"]["lost_rule_ids"])
            self.assertGreater(
                verification["coverage_accounting"]["raw_match_count"],
                verification["coverage_accounting"]["root_finding_count"],
            )
            manifest = json.loads((Path(directory) / "00-scan-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual([
                "1-resolve-explicit-dsl-or-ask-if-ambiguous-and-bind-internal-hash",
                "2-confirm-seed-inputs-and-oracles",
                "3-deterministic-static-analysis",
                "4-generate-unexecuted-input-cluster",
                "5-correlate-report-and-attack-surface",
            ], manifest["pipeline_order"])

    def test_assessment_rejects_seed_confirmation_for_a_different_dsl(self) -> None:
        with TemporaryDirectory() as directory:
            samples_path = Path(directory) / "mismatched-samples.json"
            payload = json.loads((FIXTURES / "assessment-samples.json").read_text(encoding="utf-8"))
            payload["confirmed_dsl_sha256"] = "0" * 64
            samples_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                run_scan(
                    dsl_path=FIXTURES / "text-optimization-workflow.yml",
                    samples_path=samples_path,
                    baseline_path=BASELINE,
                    output_dir=Path(directory) / "output",
                    rules_path=RULES,
                    llm_mode="disabled",
                    scan_mode="assessment",
                )

    def test_deterministic_verifier_preserves_findings_and_rule_coverage(self) -> None:
        ir, _ = parse_dify_dsl(FIXTURES / "text-optimization-workflow.yml")
        facts, findings, candidates = execute_rules(ir, RULES)
        original = [(finding.id, finding.status, finding.severity, finding.confidence) for finding in findings]
        verification = verify_deterministic_findings(ir, findings, facts, candidates)
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["coverage_accounting"]["lossless_root_cause_aggregation"])
        self.assertEqual(original, [(finding.id, finding.status, finding.severity, finding.confidence) for finding in findings])

    def test_model_pipeline_has_no_finding_adjudication_or_review_methods(self) -> None:
        pipeline = ModelAdvisor(False, "test-advisor", "SCAN-test")
        self.assertFalse(hasattr(pipeline, "adjudicate"))
        self.assertFalse(hasattr(pipeline, "review"))

    def test_optional_model_advisor_cannot_change_findings_or_quality_gate(self) -> None:
        def fake_call(_client, **kwargs):
            if kwargs["role"] == "test-cluster":
                return {"cases": []}
            if kwargs["role"] == "report-explanation":
                return {"executive_summary": "Non-authoritative wording.", "priority_actions": []}
            raise AssertionError(f"unexpected model role: {kwargs['role']}")

        with TemporaryDirectory() as directory:
            root = Path(directory)
            common = {
                "dsl_path": FIXTURES / "text-optimization-workflow.yml",
                "samples_path": FIXTURES / "assessment-samples.json",
                "baseline_path": BASELINE,
                "rules_path": RULES,
                "scan_mode": "assessment",
            }
            disabled = run_scan(output_dir=root / "disabled", llm_mode="disabled", **common)
            with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-test-key"}), patch.object(
                OpenAIResponsesClient, "call_json", fake_call,
            ):
                enabled = run_scan(
                    output_dir=root / "enabled",
                    llm_mode="enabled",
                    advisory_model="test-advisor",
                    **common,
                )
            disabled_findings = json.loads((root / "disabled" / "08-findings.json").read_text(encoding="utf-8"))["findings"]
            enabled_findings = json.loads((root / "enabled" / "08-findings.json").read_text(encoding="utf-8"))["findings"]
            self.assertEqual(disabled_findings, enabled_findings)
            self.assertEqual(disabled["quality_gate"], enabled["quality_gate"])
            advisory = json.loads((root / "enabled" / "06-model-advisory.json").read_text(encoding="utf-8"))["model_advisory"]
            self.assertEqual("none_over_findings_severity_or_gate", advisory["authority"])

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
            )
            self.assertGreater(result["finding_count"], 0)
            for filename in (
                "00-scan-manifest.json", "01-workflow-ir.json", "02-security-facts.json",
                "03-semantic-inventory.json", "04-rule-candidates.json", "05-test-cluster.json",
                "06-model-advisory.json", "07-verification.json", "08-findings.json",
                "09-attack-surface.json", "attack-surface.md", "10-dynamic-test-plan.json", "report.json", "report.md",
                "11-quality-gate.json", "12-artifact-index.json",
            ):
                self.assertTrue((output / filename).exists(), filename)
            artifact_schema = json.loads((ROOT / "schemas" / "intermediate-artifacts.schema.json").read_text(encoding="utf-8"))
            artifact_validator = Draft202012Validator(artifact_schema)
            for filename in (
                "00-scan-manifest.json", "01-workflow-ir.json", "02-security-facts.json",
                "03-semantic-inventory.json", "04-rule-candidates.json", "05-test-cluster.json",
                "06-model-advisory.json", "07-verification.json", "08-findings.json",
                "09-attack-surface.json", "10-dynamic-test-plan.json", "report.json",
                "11-quality-gate.json", "12-artifact-index.json",
            ):
                payload = json.loads((output / filename).read_text(encoding="utf-8"))
                self.assertFalse(list(artifact_validator.iter_errors(payload)), filename)
            findings = json.loads((output / "08-findings.json").read_text(encoding="utf-8"))["findings"]
            report_markdown = (output / "report.md").read_text(encoding="utf-8")
            attack_surface_markdown = (output / "attack-surface.md").read_text(encoding="utf-8")
            self.assertIn("| 风险项 | 责任节点 | 控制域 | 等级 / 状态 |", report_markdown)
            self.assertIn("本次模式：`仅确定性扫描`", report_markdown)
            self.assertIn("本次模式：`仅确定性扫描`", report_markdown)
            self.assertNotIn("分析员", report_markdown)
            self.assertNotIn("独立复核员", report_markdown)
            self.assertIn("| 节点 | 类型 | 信任级别 | 证据位置 |", attack_surface_markdown)
            self.assertIn("| 等级 | 状态 | 入口 → 目标 | 完整路径 |", attack_surface_markdown)
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
            )
            self.assertEqual("PASS", passed["quality_gate"])
            payload = json.loads((root / "waived" / "08-findings.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["findings"][0]["waived"])

    def test_bounded_text_only_workflow_does_not_require_runtime_security_gaps(self) -> None:
        with TemporaryDirectory() as directory:
            result = run_scan(
                dsl_path=FIXTURES / "review-only-workflow.yml",
                samples_path=None,
                baseline_path=BASELINE,
                output_dir=Path(directory),
                rules_path=RULES,
                llm_mode="disabled",
            )
            self.assertEqual("PASS", result["quality_gate"])
            gate = json.loads((Path(directory) / "11-quality-gate.json").read_text(encoding="utf-8"))["quality_gate"]
            self.assertEqual(0, gate["blocking_count"])
            self.assertEqual(0, gate["review_count"])

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
