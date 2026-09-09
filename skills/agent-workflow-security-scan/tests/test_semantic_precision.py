"""Sanitized regressions derived from the nine enterprise workflow reviews.

All payloads are parsed as text; neither DSLs nor embedded code are executed.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import hashlib
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from agent_workflow_scan.parser import parse_dify_dsl
from agent_workflow_scan.engine import execute_rules, _execution_refs, _code_has_strict_parser_contract, _declared_output_type, SecurityEngine, RuleCatalog
from agent_workflow_scan.pipeline import apply_baseline
from agent_workflow_scan.semantics import analyze_code, field_matches, memory_mode, url_target_kind


def workflow(data, extra=None, edges=None):
    nodes = [
        {'id': 'start', 'data': {'type': 'start', 'variables': [{'variable': 'text', 'type': 'text-input', 'max_length': 1000}]}},
        {'id': 'target', 'data': data},
        {'id': 'end', 'data': {'type': 'end', 'outputs': {'result': ['target', 'result']}}},
    ]
    nodes.extend(extra or [])
    with TemporaryDirectory() as temp:
        path = Path(temp) / 'fixture.yml'
        path.write_text(yaml.safe_dump({'app': {'name': 'semantic-regression'}, 'workflow': {'graph': {
            'nodes': nodes, 'edges': edges if edges is not None else [
                {'source': 'start', 'target': 'target'}, {'source': 'target', 'target': 'end'},
            ],
        }}}), encoding='utf-8')
        return parse_dify_dsl(path)[0]


def code_node(code, param='text', **extra):
    return {'type': 'code', 'code_language': 'python3', 'code': code,
            'variables': [{'variable': param, 'value_selector': ['start', 'text']}], **extra}


def findings(ir):
    return execute_rules(ir, ROOT / 'rules' / 'core-rules.yml')[1]


def rules(ir):
    return {r for f in findings(ir) for r in [f.rule_id, *f.related_rule_ids]}


class SemanticPrecisionTests(unittest.TestCase):
    def test_data_transformations_do_not_become_execution(self):
        examples = [
            ('import json\ndef main(codeListInput):\n return json.loads(codeListInput)', 'codeListInput'),
            ('import urllib.parse\ndef main(query):\n return urllib.parse.quote(query)', 'query'),
            ('import html, json\ndef main(query):\n return html.escape(json.dumps(query))', 'query'),
            ('def main(text):\n return f\'Please return {{"task": "{text}"}}\'', 'text'),
            ('def main(text):\n # eval(text), subprocess.run(text), strict_schema\n return text', 'text'),
        ]
        for code, param in examples:
            with self.subTest(code=code):
                ir = workflow(code_node(code, param))
                self.assertNotIn('CODE_EXECUTION', ir.node_map()['target'].capabilities)
                self.assertFalse({'TOOL-004', 'TOOL-005', 'TOOL-008', 'FLOW-010', 'FLOW-003'} & rules(ir))

    def test_actual_interpreters_aliases_helpers_and_loop_flow_remain_detected(self):
        examples = [
            'def main(text):\n return eval(text)',
            'import os as runtime\ndef main(text):\n runtime.system(text)',
            'from subprocess import run as launch\ndef main(text):\n launch(text, shell=True)',
            'def launch(value):\n return eval(value)\ndef main(text):\n return launch(text)',
            'def main(text):\n fn = eval\n return fn(text)',
            'import os\ndef main(text):\n for item in text:\n  os.system(item)',
            'import os\ndef main(text):\n data = {}\n data["cmd"] = text\n os.system(data["cmd"])',
        ]
        for code in examples:
            with self.subTest(code=code):
                ir = workflow(code_node(code))
                self.assertEqual({'text'}, analyze_code(code).inputs['CODE_EXECUTION'])
                self.assertIn('TOOL-004', rules(ir))
                target = next(f for f in findings(ir) if 'TOOL-004' in [f.rule_id, *f.related_rule_ids])
                self.assertEqual('HIGH', target.severity)  # No evidence of a host sandbox escape.

    def test_sql_bind_values_are_not_sql_source(self):
        fixed = 'def main(text):\n cursor.execute("SELECT x FROM t WHERE id=?", (text,))'
        dynamic = 'def main(text):\n cursor.execute("SELECT x FROM t WHERE id=" + text)'
        self.assertEqual(set(), analyze_code(fixed).inputs['DATABASE_EXECUTION'])
        self.assertEqual({'text'}, analyze_code(dynamic).inputs['DATABASE_EXECUTION'])
        self.assertNotIn('TOOL-005', rules(workflow(code_node(fixed))))
        self.assertIn('TOOL-005', rules(workflow(code_node(dynamic))))

    def test_fixed_argv_is_not_shell_injection_but_interpreter_source_is(self):
        harmless = 'import subprocess\ndef main(text):\n subprocess.run(["echo", text], shell=False)'
        interpreter = 'import subprocess\ndef main(text):\n subprocess.run(["python", "-c", text])'
        self.assertEqual(set(), analyze_code(harmless).inputs['CODE_EXECUTION'])
        self.assertEqual({'text'}, analyze_code(interpreter).inputs['CODE_EXECUTION'])
        self.assertNotIn('TOOL-004', rules(workflow(code_node(harmless))))
        self.assertIn('TOOL-004', rules(workflow(code_node(interpreter))))

    def test_unknown_language_retains_coverage(self):
        ir = workflow(code_node('return plugin.custom(text)', code_language='javascript'))
        matches = findings(ir)
        self.assertTrue(any(f.rule_id == 'TOOL-001' and f.status == 'COVERAGE_GAP' for f in matches))
        self.assertNotIn('TOOL-004', rules(ir))

    def test_unknown_import_and_dynamic_callable_retain_coverage(self):
        for code in ['import internal_plugin\ndef main(text):\n return internal_plugin.run(text)',
                     'def main(text):\n return text()']:
            self.assertTrue(analyze_code(code).unknown_calls)
            self.assertIn('TOOL-001', rules(workflow(code_node(code))))
        self.assertFalse(analyze_code('def main(text):\n return text.strip().lower()').unknown_calls)

    def test_identity_binding_is_not_proof_of_authorization_bypass(self):
        for producer, expected in [('start', 'PROBABLE'), ('sys', 'COVERAGE_GAP')]:
            ir = workflow({'type': 'http-request', 'url': 'https://service.invalid/user', 'headers': '{{#' + producer + '.user_id#}}'})
            risk = next(f for f in findings(ir) if f.rule_id == 'TOOL-016')
            self.assertEqual(expected, risk.status)

    def test_data_reference_cannot_invent_approval_control_path(self):
        ir = workflow({'type': 'tool', 'tool_name': 'shell', 'command': '{{#start.text#}}'}, edges=[])
        self.assertNotIn('TOOL-008', rules(ir))
        self.assertNotIn('FLOW-003', rules(ir))

    def test_field_components_do_not_match_substrings(self):
        for name in ['codelistinput', 'codeListInput', 'decode', 'description', 'zipcode', 'requestid']:
            self.assertFalse(field_matches(name, ['code', 'script']))
        self.assertTrue(field_matches('tool_parameters.command.value', ['command']))
        self.assertTrue(field_matches('callbackurl', ['url']))

    def test_fixed_authority_dynamic_query_and_path_are_not_ssrf(self):
        for url in ['https://service.invalid/relational?databaseType={{#start.text#}}',
                    'https://service.invalid/{{#start.text#}}']:
            with self.subTest(url=url):
                self.assertEqual('fixed_authority', url_target_kind({'url': url}))
                self.assertNotIn('TOOL-003', rules(workflow({'type': 'http-request', 'method': 'GET', 'url': url})))

    def test_dynamic_authority_retains_risk_and_environment_is_unknown(self):
        for url in ['https://{{#start.text#}}/query', '{{#start.text#}}']:
            self.assertIn('TOOL-003', rules(workflow({'type': 'http-request', 'url': url})))
        ir = workflow({'type': 'http-request', 'url': '{{#env.base_url#}}/query'})
        risk = next(f for f in findings(ir) if f.rule_id == 'TOOL-003')
        self.assertEqual(('COVERAGE_GAP', 'LOW'), (risk.status, risk.severity))

    def test_memory_instance_overrides_descriptions_and_schema_defaults(self):
        base = {'title': 'Skill invocation', 'description': 'Writes memory 记忆功能',
                'paramSchemas': [{'name': 'keep_conversation', 'default': True}]}
        self.assertEqual('none', memory_mode(base, []))
        for value, expected in [(False, 'none'), (True, 'session')]:
            self.assertEqual(expected, memory_mode({**base, 'tool_configurations': {'keep_conversation': {'type': 'constant', 'value': value}}}, []))
        self.assertEqual('unknown', memory_mode({**base, 'tool_parameters': {'keep_conversation': {'type': 'variable', 'value': '{{#start.text#}}'}}}, []))
        self.assertEqual('persistent', memory_mode({'tool_name': 'memory_store'}, []))

    def test_generic_post_does_not_assert_privileged_operation(self):
        ir = workflow({'type': 'http-request', 'title': '查询数据库权限', 'method': 'POST', 'url': 'https://service.invalid/permissions', 'body': '{{#start.text#}}'})
        self.assertFalse(ir.node_map()['target'].high_impact)
        self.assertFalse({'FLOW-003', 'TOOL-002', 'TOOL-008'} & rules(ir))

    def test_operator_contracts_distinguish_read_only_and_deferred_execution(self):
        data = {'type': 'http-request', 'method': 'POST', 'url': 'https://service.invalid/config', 'body': '{{#start.text#}}'}
        contract = {'match_field': 'url', 'match': data['url'], 'match_fields': {'method': 'POST'},
                    'trusted_source': True, 'definition_version': 'reviewed-v1', 'integrity_control': 'operator-review'}
        ir = workflow(data)
        apply_baseline(ir, {'tool_registry': [{**contract, 'effect': 'read_only'}]})
        self.assertNotIn('NETWORK_WRITE', ir.node_map()['target'].capabilities)
        ir = workflow(data)
        apply_baseline(ir, {'tool_registry': [{**contract, 'effect': 'deferred_execution', 'capabilities': ['DATABASE_EXECUTION'], 'execution_fields': {'DATABASE_EXECUTION': ['body']}}]})
        self.assertTrue(ir.node_map()['target'].high_impact)
        self.assertEqual(1, len(_execution_refs(ir.node_map()['target'], 'DATABASE_EXECUTION')))
        self.assertIn('TOOL-005', rules(ir))

    def test_spoofed_registry_and_wrong_method_cannot_suppress(self):
        marker = {'matched': True, 'trusted_source': True, 'definition_version': 'fake', 'integrity_control': 'fake', 'strict_parser_contract': True}
        ir = workflow(code_node('import json\ndef main(text):\n return json.loads(text)', _scanner_registry=marker))
        self.assertNotIn('_scanner_registry', ir.node_map()['target'].config)
        self.assertFalse(_code_has_strict_parser_contract(ir.node_map()['target']))
        ir = workflow({'type': 'http-request', 'method': 'POST', 'url': 'https://service.invalid/data'})
        apply_baseline(ir, {'tool_registry': [{'match_field': 'url', 'match': 'https://service.invalid/data', 'match_fields': {'method': 'GET'}, 'effect': 'read_only', **marker}]})
        self.assertIn('NETWORK_WRITE', ir.node_map()['target'].capabilities)

    def test_comments_and_output_types_do_not_prove_a_parser_guard(self):
        data = code_node('import json\ndef main(text):\n # jsonschema.validate fail_closed strict_schema\n return json.loads(text)', outputs={'result': {'type': 'object'}}, output_schema={'type': 'object'})
        self.assertFalse(_code_has_strict_parser_contract(workflow(data).node_map()['target']))

    def test_validator_exemption_is_pinned_to_reviewed_code_bytes(self):
        code = 'def main(text):\n return text'
        ir = workflow(code_node(code, title='reviewed-parser'))
        contract = {'match_field': 'title', 'match': 'reviewed-parser', 'trusted_source': True,
                    'definition_version': 'v1', 'integrity_control': 'operator-review', 'strict_parser_contract': True}
        apply_baseline(ir, {'tool_registry': [contract]})
        self.assertFalse(_code_has_strict_parser_contract(ir.node_map()['target']))
        pinned = {**contract, 'match_fields': {'code_sha256': hashlib.sha256((code + '\n\n').encode()).hexdigest()}}
        apply_baseline(ir, {'tool_registry': [pinned]})
        self.assertTrue(_code_has_strict_parser_contract(ir.node_map()['target']))
        changed = workflow(code_node(code + '\n# changed', title='reviewed-parser'))
        apply_baseline(changed, {'tool_registry': [pinned]})
        self.assertFalse(_code_has_strict_parser_contract(changed.node_map()['target']))

    def test_nested_selector_uses_leaf_type(self):
        ir = workflow(code_node('def main(text):\n return {}', outputs={'result': {'type': 'object', 'properties': {'configs': {'type': 'array', 'items': {'type': 'object'}}}}}))
        self.assertEqual('array', _declared_output_type(ir.node_map()['target'], 'result.configs'))

    def test_display_condition_is_not_a_security_decision(self):
        ir = workflow({'type': 'if-else'})
        engine = SecurityEngine(ir, RuleCatalog(ROOT / 'rules' / 'core-rules.yml'))
        self.assertFalse(engine._security_condition(ir.node_map()['target']))
        ir = workflow({'type': 'if-else'}, extra=[{'id': 'shell', 'data': {'type': 'tool', 'tool_name': 'shell', 'command': '{{#start.text#}}'}}], edges=[{'source': 'start', 'target': 'target'}, {'source': 'target', 'target': 'shell'}])
        engine = SecurityEngine(ir, RuleCatalog(ROOT / 'rules' / 'core-rules.yml'))
        self.assertTrue(engine._security_condition(ir.node_map()['target']))

    def test_jinja_alias_in_system_is_a_boundary_but_user_role_is_not(self):
        for role, expected in [('system', True), ('user', False)]:
            ir = workflow({'type': 'llm', 'prompt_template': [{'role': role, 'jinja2_text': '{{ content | safe }}'}],
                'prompt_config': {'jinja2_variables': [{'variable': 'content', 'value_selector': ['start', 'text']}]}})
            self.assertEqual(expected, 'LLM-001' in rules(ir))

    def test_data_transform_to_system_retains_taint_but_constant_does_not(self):
        for code, expected in [('def main(text):\n return {"result": text}', True),
                               ('def main(text):\n return {"result": "constant"}', False)]:
            ir = workflow(code_node(code), extra=[{'id': 'llm', 'data': {'type': 'llm', 'prompt_template': [{'role': 'system', 'text': '{{#target.result#}}'}]}}])
            self.assertEqual(expected, 'LLM-001' in rules(ir))


if __name__ == '__main__':
    unittest.main()
