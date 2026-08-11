from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterable
import json
import re

import yaml
from jsonschema import Draft202012Validator

from .models import Fact, Finding, Node, NodeType, Severity, Status, WorkflowIR, stable_id
from .parser import contains_secret, contains_template, flatten_text, walk


APPROVAL_WORDS = ("approval", "approve", "human", "人工", "审批", "确认后", "review")
VALIDATION_WORDS = (
    "validate", "validation", "allowlist", "whitelist", "schema", "sanitize",
    "canonical", "校验", "白名单", "规范化", "过滤", "验证",
)
INJECTION_GUARD_WORDS = (
    "untrusted data", "treat as data", "do not follow", "ignore instructions in",
    "不可信数据", "仅作为数据", "不得执行其中指令", "忽略其中的指令",
)
SENSITIVE_WORDS = (
    "password", "passwd", "secret", "token", "credential", "api_key", "apikey",
    "身份证", "手机号", "银行卡", "病例", "薪资", "密钥", "密码", "令牌",
)
DANGEROUS_ARG_WORDS = (
    "url", "host", "command", "cmd", "script", "code", "sql", "query", "path",
    "file", "recipient", "email", "amount", "resource", "user_id", "role",
)
SCHEMA_KEYS = (
    "schema", "json_schema", "input_schema", "output_schema", "structured_output", "response_format",
)
TIMEOUT_KEYS = ("timeout", "connect_timeout", "read_timeout", "max_execution_time")
LIMIT_KEYS = ("max_tokens", "max_iterations", "max_retries", "retry", "timeout", "limit")
FILTER_KEYS = ("metadata_filtering_conditions", "metadata_filter", "filters", "scope")
MEMORY_WRITE_WORDS = ("memory", "remember", "persist", "store", "write memory", "记忆", "持久化")
MEMORY_SCOPE_KEYS = ("namespace", "tenant_id", "user_id", "session_id", "scope_key", "partition_key")
AUTHZ_CONTROL_KEYS = (
    "authorization_policy", "permission_check", "policy_engine", "rbac", "abac",
    "subject_binding", "resource_binding", "tenant_enforced", "ownership_check",
)
IDENTITY_RESOURCE_WORDS = (
    "user_id", "userid", "tenant_id", "tenantid", "org_id", "account_id",
    "resource_id", "owner_id", "role", "subject", "用户id", "租户id", "资源id",
)
EGRESS_CONTROL_KEYS = ("egress_policy", "dlp", "data_loss_prevention", "body_allowlist", "payload_filter")
TRUST_CLAIM_WORDS = (
    "security verification", "verified", "approved", "trusted", "administrator requires",
    "安全验证", "已验证", "已审批", "可信", "管理员要求", "紧急",
)
APPROVE_WORDS = ("approve", "approved", "confirm", "yes", "allow", "同意", "批准", "确认", "允许")
REJECT_WORDS = ("reject", "deny", "cancel", "no", "拒绝", "驳回", "取消", "不允许")


DEFAULT_REMEDIATIONS: dict[str, list[str]] = {
    "input": ["为输入定义严格类型、长度、枚举和额外字段策略。"],
    "llm": ["将外部内容作为不可信数据隔离，并在模型输出进入行为层前执行确定性校验。"],
    "tool": ["对高危参数使用 Allowlist/Schema，并在副作用前设置不可绕过的审批或策略门。"],
    "output": ["在输出离开安全边界前执行结构校验、敏感数据过滤和上下文编码。"],
    "knowledge": ["限制数据集和元数据范围，将检索内容视为不可信数据并保留来源。"],
    "flow": ["在风险路径的必经位置增加确定性控制，并验证不存在旁路。"],
}


def _lower(value: Any) -> str:
    return flatten_text(value).lower()


def _key_matches(config: Any, candidates: Iterable[str]) -> bool:
    wanted = {item.lower() for item in candidates}
    for path, value in walk(config):
        if path and str(path[-1]).lower() in wanted:
            if value not in (None, "", [], {}, False):
                return True
    return False


def _key_values(config: Any, candidates: Iterable[str]) -> list[Any]:
    wanted = {item.lower() for item in candidates}
    result: list[Any] = []
    for path, value in walk(config):
        if path and str(path[-1]).lower() in wanted:
            result.append(value)
    return result


def _has_words(text: str, words: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(word.lower() in lowered for word in words)


def _schema_documents(node: Node) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for value in _key_values(node.config, SCHEMA_KEYS):
        if isinstance(value, dict):
            documents.append(value)
    return documents


def _has_schema(node: Node) -> bool:
    """Only count an object schema as strict when unknown properties are rejected."""
    for schema in _schema_documents(node):
        if schema.get("type") == "object" and schema.get("additionalProperties") is False:
            properties = schema.get("properties")
            if isinstance(properties, dict) and properties:
                return True
    return False


def _has_timeout(node: Node) -> bool:
    return _key_matches(node.config, TIMEOUT_KEYS)


def _has_limits(node: Node) -> bool:
    return _key_matches(node.config, LIMIT_KEYS)


def _is_approval(node: Node) -> bool:
    control = node.config.get("security_control") or node.config.get("x_security_control")
    if isinstance(control, dict):
        return str(control.get("type", "")).lower() in {"approval", "human_approval"} and control.get("mandatory", True) is not False
    if node.type != NodeType.HUMAN.value:
        return False
    actions = node.config.get("actions") or node.config.get("user_actions") or node.config.get("buttons") or []
    action_text = flatten_text(actions)
    return _has_words(action_text, APPROVE_WORDS) and _has_words(action_text, REJECT_WORDS)


def _is_validation(node: Node) -> bool:
    control = node.config.get("security_control") or node.config.get("x_security_control")
    if isinstance(control, dict):
        return str(control.get("type", "")).lower() in {"validation", "policy", "guardrail", "authorization"} and control.get("mandatory", True) is not False
    has_policy = _key_matches(node.config, ("allowlist", "allowed_values", "validation_schema", "policy_id", "guardrail_id"))
    blocks_failure = _has_words(_lower(node.config), ("block", "deny", "fail_closed", "reject", "阻断", "拒绝"))
    return has_policy and blocks_failure


def _is_sensitive(node: Node) -> bool:
    if node.type == NodeType.INPUT.value:
        return any(
            _has_words(
                f"{item.get('variable', '')} {item.get('name', '')} {item.get('label', '')}",
                SENSITIVE_WORDS,
            )
            for item in _input_variables(node)
        )
    if node.type == NodeType.KNOWLEDGE.value:
        return _has_words(f"{node.title}\n{node.text}", SENSITIVE_WORDS)
    if node.type == NodeType.LLM.value:
        prompt = _system_prompt_text(node)
        return _has_words(prompt, SENSITIVE_WORDS) or contains_secret(prompt)
    return _has_words(node.title, SENSITIVE_WORDS)


def _sensitive_input_variable_names(node: Node) -> set[str]:
    if node.type != NodeType.INPUT.value:
        return set()
    return {
        str(item.get("variable") or item.get("name") or "").lower()
        for item in _input_variables(node)
        if _has_words(
            f"{item.get('variable', '')} {item.get('name', '')} {item.get('label', '')}",
            SENSITIVE_WORDS,
        )
        and str(item.get("variable") or item.get("name") or "")
    }


def _ref_names(node: Node) -> str:
    return " ".join(ref.variable_name for ref in node.variable_refs).lower()


def _refs_for_fields(node: Node, words: Iterable[str]) -> list[Any]:
    wanted = tuple(word.lower() for word in words)
    return [
        ref for ref in node.variable_refs
        if any(word in ref.consumer_field.lower() for word in wanted)
    ]


def _has_registry_integrity(node: Node) -> bool:
    marker = node.config.get("_scanner_registry")
    return bool(
        isinstance(marker, dict)
        and marker.get("matched")
        and marker.get("trusted_source")
        and marker.get("definition_version")
        and marker.get("integrity_control")
    )


def _approval_action_ids(node: Node) -> tuple[set[str], set[str]]:
    actions = node.config.get("actions") or node.config.get("user_actions") or node.config.get("buttons") or []
    approved: set[str] = set()
    rejected: set[str] = set()
    if isinstance(actions, list):
        for item in actions:
            if not isinstance(item, dict):
                continue
            action_id = str(item.get("id") or item.get("value") or item.get("name") or "").lower()
            label = f"{action_id} {item.get('title', '')} {item.get('label', '')}".lower()
            if action_id and _has_words(label, APPROVE_WORDS):
                approved.add(action_id)
            if action_id and _has_words(label, REJECT_WORDS):
                rejected.add(action_id)
    return approved, rejected


def _system_prompt_text(node: Node) -> str:
    chunks: list[str] = []
    prompts = node.config.get("prompt_template")
    if isinstance(prompts, list):
        for item in prompts:
            if isinstance(item, dict) and str(item.get("role", "")).lower() in {"system", "developer"}:
                chunks.append(str(item.get("text") or item.get("content") or ""))
    for key in ("system_prompt", "instruction", "instructions"):
        value = node.config.get(key)
        if isinstance(value, str):
            chunks.append(value)
    return "\n".join(chunks)


def _prompt_references_node(prompt: str, node_id: str) -> bool:
    escaped = re.escape(node_id)
    return bool(re.search(rf"\{{\{{#?\s*{escaped}\.", prompt))


def _input_variables(node: Node) -> list[dict[str, Any]]:
    values = node.config.get("variables") or node.config.get("inputs") or []
    if isinstance(values, dict):
        values = [dict({"name": key}, **(item if isinstance(item, dict) else {"value": item})) for key, item in values.items()]
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


class GraphIndex:
    def __init__(self, ir: WorkflowIR) -> None:
        self.ir = ir
        self.nodes = ir.node_map()
        self.control: dict[str, set[str]] = {node.id: set() for node in ir.nodes}
        self.data: dict[str, set[str]] = {node.id: set() for node in ir.nodes}
        self.out_edges: dict[str, list[Any]] = {node.id: [] for node in ir.nodes}
        for edge in ir.edges:
            if edge.source in self.control and edge.target in self.control:
                self.control[edge.source].add(edge.target)
                self.out_edges[edge.source].append(edge)
        for ref in ir.variable_refs:
            if ref.producer_node_id in self.data and ref.consumer_node_id in self.data:
                self.data[ref.producer_node_id].add(ref.consumer_node_id)
        self.combined = {
            node_id: self.control[node_id] | self.data[node_id] for node_id in self.nodes
        }

    def path(
        self,
        source: str,
        target: str,
        *,
        data_preferred: bool = False,
        excluded: set[str] | None = None,
        max_depth: int = 64,
    ) -> list[str] | None:
        excluded = excluded or set()
        if source in excluded or target in excluded:
            return None
        adjacency = self.data if data_preferred else self.combined
        queue: deque[list[str]] = deque([[source]])
        visited = {source}
        while queue:
            current = queue.popleft()
            if len(current) > max_depth:
                continue
            head = current[-1]
            if head == target:
                return current
            for nxt in adjacency.get(head, set()):
                if nxt not in visited and nxt not in excluded:
                    visited.add(nxt)
                    queue.append([*current, nxt])
        return None

    def any_path(self, sources: Iterable[Node], targets: Iterable[Node], **kwargs: Any) -> list[str] | None:
        for source in sources:
            for target in targets:
                result = self.path(source.id, target.id, **kwargs)
                if result:
                    return result
        return None

    def data_path_from_variables(
        self,
        source: str,
        target: str,
        variable_names: set[str],
        max_depth: int = 64,
    ) -> list[str] | None:
        """Follow data flow only when the first hop references a named source field."""
        first_hops = {
            ref.consumer_node_id
            for ref in self.ir.variable_refs
            if ref.producer_node_id == source and ref.variable_name.lower() in variable_names
        }
        queue: deque[list[str]] = deque([[source, item] for item in first_hops])
        visited = {source, *first_hops}
        while queue:
            current = queue.popleft()
            if len(current) > max_depth:
                continue
            head = current[-1]
            if head == target:
                return current
            for nxt in self.data.get(head, set()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append([*current, nxt])
        return None

    def predecessors(self, node_id: str) -> set[str]:
        return {source for source, targets in self.combined.items() if node_id in targets}


class RuleCatalog:
    def __init__(self, path: Path) -> None:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules = payload.get("rules", []) if isinstance(payload, dict) else []
        defaults = payload.get("rule_defaults", {}) if isinstance(payload, dict) else {}
        self.rules = {
            str(rule["id"]): {**defaults, **rule}
            for rule in rules if isinstance(rule, dict) and rule.get("id")
        }
        required = {"id", "title", "severity", "detectability", "standards", "applicability", "confidence_policy", "evidence_policy"}
        for rule_id, rule in self.rules.items():
            missing = sorted(required - set(rule))
            if missing:
                raise ValueError(f"Rule {rule_id} is missing metadata: {', '.join(missing)}")
        schema_path = path.parent.parent / "schemas" / "rule.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for rule_id, rule in self.rules.items():
            errors = sorted(validator.iter_errors(rule), key=lambda error: list(error.path))
            if errors:
                raise ValueError(f"Rule {rule_id} schema validation failed: {errors[0].message}")

    def get(self, rule_id: str) -> dict[str, Any]:
        if rule_id not in self.rules:
            raise KeyError(f"Unknown rule ID: {rule_id}")
        return self.rules[rule_id]


class SecurityEngine:
    def __init__(self, ir: WorkflowIR, catalog: RuleCatalog) -> None:
        self.ir = ir
        self.graph = GraphIndex(ir)
        self.catalog = catalog
        self.facts: list[Fact] = []
        self.findings: list[Finding] = []
        self._dedupe: set[tuple[str, tuple[str, ...], str]] = set()

    def _emit(
        self,
        rule_id: str,
        node_ids: list[str],
        message: str,
        *,
        status: Status | str,
        severity: Severity | str | None = None,
        confidence: float = 1.0,
        evidence: list[str] | None = None,
        remediation: list[str] | None = None,
        missing_context: list[str] | None = None,
        dynamic_test: str | None = None,
        attack_preconditions: list[str] | None = None,
        counter_evidence: list[str] | None = None,
    ) -> None:
        key = (rule_id, tuple(node_ids), message)
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        metadata = self.catalog.get(rule_id)
        fact_id = stable_id("FACT", rule_id, *node_ids, message)
        locations = [self.graph.nodes[node_id].json_pointer for node_id in node_ids if node_id in self.graph.nodes]
        fact = Fact(fact_id, rule_id, node_ids, evidence or locations, {"message": message})
        self.facts.append(fact)
        finding_id = stable_id("FINDING", rule_id, *node_ids, message)
        family = rule_id.split("-")[0].lower()
        family = {"in": "input", "kb": "knowledge"}.get(family, family)
        self.findings.append(
            Finding(
                id=finding_id,
                rule_id=rule_id,
                title=str(metadata["title"]),
                status=status.value if isinstance(status, Status) else str(status),
                severity=(severity.value if isinstance(severity, Severity) else str(severity or metadata.get("severity", "MEDIUM"))),
                confidence=confidence,
                node_ids=node_ids,
                evidence_refs=[fact_id],
                dsl_locations=locations,
                message=message,
                remediation=remediation or DEFAULT_REMEDIATIONS.get(family, DEFAULT_REMEDIATIONS["flow"]),
                attack_family=str(metadata.get("attack_family", "general_workflow_security")),
                standards=[str(item) for item in metadata.get("standards", [])],
                attack_preconditions=attack_preconditions or [],
                counter_evidence=counter_evidence or [],
                missing_context=missing_context or [],
                dynamic_test=dynamic_test,
            )
        )

    def run(self) -> tuple[list[Fact], list[Finding]]:
        self._global_rules()
        for node in self.ir.nodes:
            {
                NodeType.INPUT.value: self._input_rules,
                NodeType.LLM.value: self._llm_rules,
                NodeType.TOOL.value: self._tool_rules,
                NodeType.CODE.value: self._tool_rules,
                NodeType.OUTPUT.value: self._output_rules,
                NodeType.KNOWLEDGE.value: self._knowledge_rules,
                NodeType.LOOP.value: self._loop_rules,
            }.get(node.type, lambda _: None)(node)
        self._cross_node_rules()
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda finding: (severity_rank.get(finding.severity, 9), finding.rule_id, finding.id))
        return self.facts, self.findings

    def _global_rules(self) -> None:
        for gap in self.ir.coverage_gaps:
            rule_id = "FLOW-001" if gap.get("reason") == "dangling_edge" else "FLOW-002"
            node_ids = [gap["node_id"]] if gap.get("node_id") else []
            self._emit(
                rule_id,
                node_ids,
                f"DSL 存在未覆盖结构：{gap.get('reason')}。",
                status=Status.COVERAGE_GAP,
                confidence=1.0,
                missing_context=[str(gap)],
            )
        if self.ir.raw_metadata.get("secret_locations"):
            llms = [node.id for node in self.ir.nodes if node.type == NodeType.LLM.value]
            self._emit(
                "FLOW-008",
                llms,
                "DSL 中检测到疑似明文凭证；若其位于 Prompt 或节点变量中，模型可能观察到凭证。",
                status=Status.CONFIRMED,
                confidence=0.98,
                evidence=list(self.ir.raw_metadata["secret_locations"]),
                remediation=["从 DSL 移除明文凭证，使用运行时密钥引用，并保证凭证不进入模型上下文。"],
                dynamic_test="credential_context_exposure",
            )

    def _input_rules(self, node: Node) -> None:
        variables = _input_variables(node)
        if not variables:
            self._emit("IN-001", [node.id], "输入节点没有可识别的字段 Schema。", status=Status.COVERAGE_GAP, confidence=0.9)
            return
        for variable in variables:
            name = str(variable.get("variable") or variable.get("name") or variable.get("label") or "unnamed")
            value_type = str(variable.get("type") or variable.get("value_type") or "").lower()
            if not value_type:
                self._emit("IN-001", [node.id], f"输入字段 {name} 未声明类型。", status=Status.CONFIRMED)
            if value_type in {"text-input", "paragraph", "string", "text", "array", "list", "file", "file-list", "files"}:
                if not any(key in variable for key in ("max_length", "maxLength", "max_items", "maxItems", "size_limit", "max_files")):
                    self._emit("IN-002", [node.id], f"输入字段 {name} 缺少长度或数量上限。", status=Status.CONFIRMED)
            if "file" in value_type:
                has_file_controls = any(key in variable for key in ("allowed_file_types", "allowed_extensions", "mime_types", "size_limit"))
                if not has_file_controls:
                    self._emit("IN-003", [node.id], f"文件字段 {name} 缺少类型或大小限制。", status=Status.CONFIRMED, dynamic_test="malicious_file_upload")
            if value_type in {"object", "json", "map"} and variable.get("additionalProperties", True) is not False:
                self._emit("IN-005", [node.id], f"对象字段 {name} 未禁止额外属性。", status=Status.CONFIRMED)
            if _has_words(name + " " + str(variable.get("label", "")), SENSITIVE_WORDS):
                self._emit(
                    "IN-006", [node.id], f"输入字段 {name} 可能包含敏感信息，需要验证下游传播和脱敏。",
                    status=Status.PROBABLE, confidence=0.75, dynamic_test="sensitive_input_propagation",
                )
        if not _key_matches(node.config, ("normalization", "unicode_normalization", "canonicalization")):
            self._emit(
                "IN-004", [node.id], "DSL 未声明输入解码和 Unicode 规范化控制。",
                status=Status.COVERAGE_GAP, confidence=1.0,
                missing_context=["输入规范化可能由平台统一实现，DSL 无法验证。"],
                dynamic_test="encoding_unicode_smuggling",
            )

    def _llm_rules(self, node: Node) -> None:
        system_text = _system_prompt_text(node)
        untrusted_producers = {
            ref.producer_node_id for ref in node.variable_refs
            if self.graph.nodes.get(ref.producer_node_id)
            and self.graph.nodes[ref.producer_node_id].type in {NodeType.INPUT.value, NodeType.KNOWLEDGE.value, NodeType.CONTENT.value, NodeType.TOOL.value}
        }
        system_has_ref = any(_prompt_references_node(system_text, producer) for producer in untrusted_producers)
        if system_has_ref:
            self._emit("LLM-001", [*sorted(untrusted_producers), node.id], "不可信变量被插入系统或高权限指令区域。", status=Status.CONFIRMED, dynamic_test="direct_or_indirect_prompt_injection")
        if untrusted_producers and not _has_words(system_text, INJECTION_GUARD_WORDS):
            self._emit("LLM-002", [*sorted(untrusted_producers), node.id], "外部内容进入 LLM，但系统指令中未发现明确的数据/指令隔离约束。", status=Status.PROBABLE, confidence=0.72, dynamic_test="instruction_data_boundary")
        if contains_secret(node.text):
            self._emit("LLM-004", [node.id], "LLM 节点文本中包含疑似明文凭证。", status=Status.CONFIRMED, severity=Severity.CRITICAL)
        if (_has_words(system_text, SENSITIVE_WORDS) or contains_secret(system_text)) and not _key_matches(
            node.config, ("prompt_disclosure_guard", "secret_redaction", "context_dlp")
        ):
            self._emit(
                "LLM-011", [node.id],
                "系统指令区包含敏感信息或凭证迹象，但未发现提示词防泄露/上下文 DLP 控制。",
                status=Status.PROBABLE, confidence=0.9,
                dynamic_test="system_prompt_and_credential_leakage",
            )
        if not _has_limits(node):
            self._emit("LLM-009", [node.id], "LLM 节点缺少可识别的 Token、重试、超时或预算限制。", status=Status.PROBABLE, confidence=0.8, dynamic_test="resource_budget")
        if _has_words(node.text, ("authorize", "permission", "approve", "是否允许", "审批", "授权")):
            self._emit("LLM-007", [node.id], "Prompt 显示模型可能承担授权或审批决策。", status=Status.PROBABLE, confidence=0.72, remediation=["将授权决策移至应用逻辑或策略引擎，模型只能提供辅助意见。"])
        if not _key_matches(node.config, ("fallback", "error_strategy", "fail_closed", "on_error")):
            self._emit("LLM-010", [node.id], "DSL 未显示模型失败、拒答或解析失败后的安全回退策略。", status=Status.COVERAGE_GAP, confidence=1.0, missing_context=["运行时可能统一处理模型错误。"])

    def _tool_rules(self, node: Node) -> None:
        text = node.text.lower()
        dynamic = bool(node.variable_refs) or contains_template(node.config)
        dangerous_refs = _refs_for_fields(node, DANGEROUS_ARG_WORDS)
        url_refs = _refs_for_fields(node, ("url", "uri", "host", "endpoint", "callback"))
        exec_refs = _refs_for_fields(node, ("command", "cmd", "script", "code", "expression"))
        query_refs = _refs_for_fields(node, ("sql", "query", "statement", "filter"))
        path_refs = _refs_for_fields(node, ("path", "file", "filename", "directory", "archive"))
        if "UNKNOWN_TOOL_CAPABILITY" in node.capabilities:
            self._emit("TOOL-001", [node.id], "工具能力无法从内部基线或 DSL 描述中确定。", status=Status.COVERAGE_GAP, confidence=1.0, missing_context=["需要在 internal-baseline.yml 登记工具能力和副作用。"])
        unsafe_dangerous_refs = [
            ref for ref in dangerous_refs
            if self.graph.nodes.get(ref.producer_node_id)
            and self.graph.nodes[ref.producer_node_id].type != NodeType.HUMAN.value
        ]
        if node.high_impact and (unsafe_dangerous_refs or (node.type == NodeType.CODE.value and node.variable_refs)):
            refs = unsafe_dangerous_refs or node.variable_refs
            self._emit("TOOL-002", [*sorted({ref.producer_node_id for ref in refs}), node.id], "高影响工具的安全敏感参数由模型或上游变量控制。", status=Status.CONFIRMED, dynamic_test="model_controlled_tool_argument")
        if url_refs and not _key_matches(node.config, ("allowlist", "allowed_hosts", "allowed_domains", "network_policy")):
            self._emit("TOOL-003", [node.id], "动态 URL/Host 缺少域名或地址 Allowlist。", status=Status.CONFIRMED, dynamic_test="ssrf")
        if exec_refs or (node.type == NodeType.CODE.value and node.variable_refs):
            self._emit("TOOL-004", [node.id], "动态变量可到达命令、代码或脚本执行能力。", status=Status.CONFIRMED, severity=Severity.CRITICAL, dynamic_test="command_injection")
        if query_refs and any(word in text for word in ("sql", "database", "query")) and not _key_matches(node.config, ("parameters", "parameterized", "prepared_statement")):
            self._emit("TOOL-005", [node.id], "动态变量可能拼接进入 SQL/查询。", status=Status.PROBABLE, confidence=0.85, dynamic_test="sql_injection")
        if path_refs and not _key_matches(node.config, ("base_directory", "allowed_paths", "path_allowlist")):
            self._emit("TOOL-006", [node.id], "动态文件路径缺少固定根目录或路径 Allowlist。", status=Status.PROBABLE, confidence=0.85, dynamic_test="path_traversal")
        if node.high_impact:
            approvals = {item.id for item in self.ir.nodes if _is_approval(item)}
            untrusted = [item for item in self.ir.nodes if item.type in {NodeType.INPUT.value, NodeType.KNOWLEDGE.value, NodeType.CONTENT.value}]
            path = self.graph.any_path(untrusted, [node], excluded=approvals)
            if path:
                self._emit("TOOL-008", path, "高影响工具存在不经过审批节点的可达路径。", status=Status.CONFIRMED, dynamic_test="high_impact_action_approval")
        if node.high_impact and not _key_matches(node.config, ("purpose", "business_purpose", "allowed_operations", "capability_scope")):
            self._emit(
                "TOOL-009", [node.id],
                "高影响工具未声明业务目的或允许操作范围，无法验证最小能力原则。",
                status=Status.COVERAGE_GAP, confidence=1.0,
                missing_context=["tool_business_purpose", "allowed_operations"],
            )
        if contains_secret(node.text):
            self._emit("TOOL-010", [node.id], "工具配置中存在疑似明文凭证。", status=Status.CONFIRMED, severity=Severity.CRITICAL)
        if not _has_schema(node):
            self._emit("TOOL-011", [node.id], "工具输入缺少可识别的严格 Schema。", status=Status.PROBABLE, confidence=0.8)
        if not _has_timeout(node):
            self._emit("TOOL-013", [node.id], "工具缺少可识别的超时设置。", status=Status.PROBABLE, confidence=0.85, dynamic_test="tool_timeout")
        if not _has_registry_integrity(node) and not _key_matches(node.config, ("trusted_source", "integrity", "signature", "version", "checksum")):
            self._emit("TOOL-014", [node.id], "DSL 无法证明工具来源、版本完整性或定义变更审批。", status=Status.COVERAGE_GAP, confidence=1.0, missing_context=["工具供应链与插件代码不在 DSL 中。"])
        authz_relevant = _has_words(
            f"{node.title}\n{node.text}\n{' '.join(node.capabilities)}",
            ("admin", "permission", "role", "tenant", "user", "resource", "account", "update", "delete", "grant", "payment", "transfer", "send", "管理员", "权限", "租户", "用户", "资源"),
        )
        if node.high_impact and authz_relevant and not _key_matches(node.config, AUTHZ_CONTROL_KEYS):
            self._emit(
                "TOOL-015", [node.id],
                "高影响工具未声明 subject-object-action、所有权或租户范围的确定性授权检查。",
                status=Status.PROBABLE, confidence=0.86,
                missing_context=["平台统一身份认证不等同于对象级授权；需要确认工具执行端是否重新授权。"],
                dynamic_test="authorization_bypass",
            )
        ref_names = f"{_ref_names(node)} {' '.join(ref.consumer_field for ref in node.variable_refs)}"
        if _has_words(ref_names, IDENTITY_RESOURCE_WORDS):
            producers = sorted({ref.producer_node_id for ref in node.variable_refs})
            if any(self.graph.nodes.get(item) and self.graph.nodes[item].type == NodeType.INPUT.value for item in producers):
                self._emit(
                    "TOOL-016", [*producers, node.id],
                    "用户输入中的身份、租户、角色或资源标识直接绑定到工具参数。",
                    status=Status.CONFIRMED,
                    attack_preconditions=["攻击者可修改对象标识", "工具端未重新执行对象级授权"],
                    dynamic_test="cross_tenant_object_access",
                )

    def _output_rules(self, node: Node) -> None:
        dynamic = bool(node.variable_refs) or contains_template(node.config)
        if dynamic and not _has_schema(node):
            self._emit("OUT-001", [node.id], "动态输出缺少结构化 Schema。", status=Status.CONFIRMED)
        if dynamic and _has_words(node.text, ("html", "markdown", "md")) and not _key_matches(node.config, ("escape", "sanitize", "encoding")):
            self._emit("OUT-004", [node.id], "动态 HTML/Markdown 输出缺少可识别的上下文编码。", status=Status.PROBABLE, confidence=0.82, dynamic_test="rich_text_injection")
        if dynamic and _has_words(node.text, ("http://", "https://", "url", "link", "链接")) and not _key_matches(node.config, ("allowed_protocols", "url_allowlist")):
            self._emit("OUT-005", [node.id], "模型或上游内容可生成链接，但未发现协议/域名限制。", status=Status.PROBABLE, confidence=0.75, dynamic_test="unsafe_link")
        if dynamic and _has_words(node.text, ("markdown", "![", "](", "image", "图片")) and not _key_matches(
            node.config, ("remote_image_proxy", "disable_remote_images", "url_allowlist", "content_security_policy")
        ):
            self._emit(
                "OUT-009", [node.id],
                "动态 Markdown 链接或图片目标未受限，可通过客户端取链或 URL 路径编码形成隐蔽外带。",
                status=Status.CONFIRMED,
                dynamic_test="markdown_url_exfiltration",
            )
        if dynamic and _has_words(node.text, TRUST_CLAIM_WORDS) and not _key_matches(
            node.config, ("provenance", "signed_result", "approval_evidence", "source_attribution")
        ):
            self._emit(
                "OUT-010", [node.id],
                "模型生成的安全验证、审批或紧急声明面向用户展示，但未绑定可验证来源。",
                status=Status.PROBABLE, confidence=0.76,
                dynamic_test="human_agent_trust_exploit",
            )
        if _has_words(node.text, ("system prompt", "stack trace", "debug", "系统提示词", "错误堆栈")):
            self._emit("OUT-003", [node.id], "输出模板可能暴露系统 Prompt、调试或错误信息。", status=Status.PROBABLE, confidence=0.8, dynamic_test="system_context_disclosure")
        if not _key_matches(node.config, ("fallback", "uncertainty", "confidence", "on_error")):
            self._emit("OUT-008", [node.id], "输出节点未显示低置信或失败回退行为。", status=Status.COVERAGE_GAP, confidence=1.0)

    def _knowledge_rules(self, node: Node) -> None:
        dataset_values = _key_values(node.config, ("dataset_ids", "dataset_id", "knowledge_id"))
        if not dataset_values or any(value in (None, "", [], {}) for value in dataset_values):
            self._emit("KB-001", [node.id], "知识检索数据集范围未固定或无法识别。", status=Status.PROBABLE, confidence=0.85)
        if not _key_matches(node.config, FILTER_KEYS):
            self._emit("KB-002", [node.id], "知识检索未配置可识别的租户、用户或业务元数据过滤。", status=Status.PROBABLE, confidence=0.85, missing_context=["若平台在 DSL 外强制租户隔离，应在内部基线中登记。"])
        top_k_values = _key_values(node.config, ("top_k",))
        score_values = _key_values(node.config, ("score_threshold",))
        risky_top_k = any(isinstance(value, (int, float)) and value > 10 for value in top_k_values)
        risky_threshold = not score_values or any(isinstance(value, (int, float)) and value < 0.2 for value in score_values)
        if risky_top_k or risky_threshold:
            self._emit("KB-003", [node.id], "Top-K 过大或相似度阈值缺失/过低，可能扩大无关内容和投毒内容暴露面。", status=Status.PROBABLE, confidence=0.82)
        if not _key_matches(node.config, ("source", "document_metadata", "citation", "metadata")):
            self._emit("KB-008", [node.id], "DSL 未显示检索来源和引用元数据要求。", status=Status.PROBABLE, confidence=0.8)
        if not _key_matches(node.config, ("prompt_injection_filter", "content_screening", "quarantine", "trusted_content")):
            self._emit("KB-009", [node.id], "检索内容进入模型前缺少可识别的注入筛查或隔离控制。", status=Status.PROBABLE, confidence=0.85, dynamic_test="rag_indirect_prompt_injection")
        self._emit(
            "KB-010", [node.id], "知识库 ACL、文档来源、内容隔离、过期和撤销策略不在 DSL 中，静态扫描无法验证。",
            status=Status.COVERAGE_GAP, severity=Severity.INFO, confidence=1.0,
            missing_context=["knowledge_acl", "document_provenance", "retention", "quarantine"],
        )

    def _loop_rules(self, node: Node) -> None:
        if not _has_limits(node):
            self._emit("FLOW-007", [node.id], "循环/迭代节点缺少次数、时间或预算上限。", status=Status.CONFIRMED, dynamic_test="runaway_loop")

    def _cross_node_rules(self) -> None:
        nodes = self.ir.nodes
        inputs = [node for node in nodes if node.type == NodeType.INPUT.value]
        knowledge = [node for node in nodes if node.type == NodeType.KNOWLEDGE.value]
        content_sources = [node for node in nodes if node.type == NodeType.CONTENT.value]
        tools = [node for node in nodes if node.type in {NodeType.TOOL.value, NodeType.CODE.value}]
        llms = [node for node in nodes if node.type == NodeType.LLM.value]
        outputs = [node for node in nodes if node.type == NodeType.OUTPUT.value]
        dangerous_tools = [node for node in tools if node.high_impact or node.external or "CODE_EXECUTION" in node.capabilities]
        controls = {node.id for node in nodes if _is_validation(node) or _is_approval(node)}

        for approval in [node for node in nodes if _is_approval(node)]:
            approved_ids, rejected_ids = _approval_action_ids(approval)
            for edge in self.graph.out_edges.get(approval.id, []):
                handle = str(edge.source_handle or "").lower()
                downstream_path = self.graph.any_path(
                    [self.graph.nodes[edge.target]] if edge.target in self.graph.nodes else [],
                    dangerous_tools,
                )
                if not downstream_path:
                    continue
                explicitly_rejected = any(item and item in handle for item in rejected_ids) or _has_words(handle, REJECT_WORDS)
                explicitly_approved = any(item and item in handle for item in approved_ids) or _has_words(handle, APPROVE_WORDS)
                if explicitly_rejected:
                    self._emit(
                        "FLOW-006", [approval.id, *downstream_path],
                        "人工审批的拒绝/取消分支仍可到达高影响工具。",
                        status=Status.CONFIRMED,
                        dynamic_test="approval_branch_bypass",
                    )
                elif not handle and len(self.graph.out_edges.get(approval.id, [])) > 1:
                    self._emit(
                        "FLOW-006", [approval.id, *downstream_path],
                        "人工审批存在多个出边，但 DSL 未提供可验证的动作路由标识，无法证明仅批准分支可达高影响工具。",
                        status=Status.COVERAGE_GAP, confidence=1.0,
                        missing_context=["human_input_action_routing"],
                    )
                elif handle and not explicitly_approved:
                    self._emit(
                        "FLOW-006", [approval.id, *downstream_path],
                        f"人工审批的非批准动作分支 {handle} 可到达高影响工具。",
                        status=Status.CONFIRMED,
                        dynamic_test="approval_branch_bypass",
                    )

        for source in inputs:
            for llm in llms:
                path = [source.id, llm.id] if llm.id in self.graph.data.get(source.id, set()) else None
                if path and not _has_words(_system_prompt_text(llm), INJECTION_GUARD_WORDS):
                    self._emit(
                        "IN-009", path,
                        "用户消息可直接到达模型，且系统指令未声明对角色覆盖、目标劫持或提示词提取的防护边界。",
                        status=Status.CONFIRMED,
                        dynamic_test="direct_prompt_injection",
                    )
                if path and _prompt_references_node(_system_prompt_text(llm), source.id):
                    self._emit(
                        "IN-007", path,
                        "用户输入变量被插入系统/开发者指令区域。",
                        status=Status.CONFIRMED,
                        dynamic_test="direct_prompt_injection",
                    )

        for source in [*inputs, *knowledge, *content_sources]:
            for sink in dangerous_tools:
                path = self.graph.path(source.id, sink.id, excluded=controls)
                if path:
                    self._emit("FLOW-003", path, "不可信数据存在绕开确定性校验/审批到达高危工具的路径。", status=Status.CONFIRMED, dynamic_test="source_to_high_impact_sink")

        for kb in knowledge:
            for llm in llms:
                first = self.graph.path(kb.id, llm.id, data_preferred=True)
                if not first:
                    continue
                if _prompt_references_node(_system_prompt_text(llm), kb.id):
                    self._emit("KB-004", first, "知识检索内容被插入 LLM 高权限 Prompt。", status=Status.CONFIRMED, dynamic_test="rag_system_prompt_injection")
                for tool in dangerous_tools:
                    second = self.graph.path(llm.id, tool.id)
                    if second:
                        chain = [*first, *second[1:]]
                        self._emit("FLOW-005", chain, "知识库内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。", status=Status.PROBABLE, confidence=0.9, dynamic_test="rag_to_tool_injection")
                        self._emit("LLM-003", chain, "间接外部内容进入具备工具影响能力的 LLM。", status=Status.CONFIRMED, dynamic_test="indirect_prompt_injection")
                        self._emit("KB-005", chain, "知识内容可经模型传播到工具。", status=Status.CONFIRMED, dynamic_test="knowledge_controlled_tool")

        for source in content_sources:
            for llm in llms:
                first = self.graph.path(source.id, llm.id, data_preferred=True)
                if not first:
                    continue
                for tool in dangerous_tools:
                    second = self.graph.path(llm.id, tool.id)
                    if second:
                        chain = [*first, *second[1:]]
                        self._emit(
                            "FLOW-005", chain,
                            "上传文档或提取内容可经 LLM 影响高危工具，形成间接 Prompt Injection 攻击链。",
                            status=Status.PROBABLE, confidence=0.9,
                            dynamic_test="rag_to_tool_injection",
                        )
                        self._emit(
                            "LLM-003", chain,
                            "文档提取内容进入具备工具影响能力的 LLM。",
                            status=Status.CONFIRMED,
                            dynamic_test="indirect_prompt_injection",
                        )

        sensitive_sources = [node for node in nodes if _is_sensitive(node)]
        external_sinks = [node for node in [*tools, *outputs] if node.external or node.type == NodeType.OUTPUT.value]
        for source in sensitive_sources:
            for sink in external_sinks:
                sensitive_variables = _sensitive_input_variable_names(source)
                path = (
                    self.graph.data_path_from_variables(source.id, sink.id, sensitive_variables)
                    if sensitive_variables
                    else self.graph.path(source.id, sink.id, data_preferred=True)
                )
                if path:
                    self._emit("FLOW-004", path, "疑似敏感数据可达外部工具或输出边界。", status=Status.PROBABLE, confidence=0.78, dynamic_test="sensitive_data_exfiltration")
                    rule_id = "KB-006" if source.type == NodeType.KNOWLEDGE.value else "OUT-002"
                    self._emit(rule_id, path, "敏感内容存在到达外部边界的静态路径。", status=Status.PROBABLE, confidence=0.78, dynamic_test="sensitive_data_exfiltration")
                    if sink.type in {NodeType.TOOL.value, NodeType.CODE.value}:
                        self._emit(
                            "TOOL-007", path,
                            "敏感数据存在经工具离开工作流信任边界的路径。",
                            status=Status.PROBABLE, confidence=0.82,
                            dynamic_test="sensitive_data_exfiltration",
                        )
                    if any(self.graph.nodes[item].type == NodeType.LLM.value for item in path if item in self.graph.nodes):
                        self._emit(
                            "FLOW-009", path,
                            "敏感资产经模型传播到外部通道；与提示注入组合后可形成完整数据外泄链。",
                            status=Status.CONFIRMED,
                            attack_preconditions=["模型上下文可观察敏感资产", "外部目标或载荷可被动态影响"],
                            dynamic_test="web_exfiltration_chain",
                        )
                    if sink.type in {NodeType.TOOL.value, NodeType.CODE.value} and "NETWORK_WRITE" in sink.capabilities:
                        target_refs = _refs_for_fields(sink, ("url", "uri", "host", "endpoint", "callback"))
                        dynamic_target = bool(target_refs)
                        if dynamic_target and not _key_matches(sink.config, EGRESS_CONTROL_KEYS):
                            target_controllers = [
                                self.graph.nodes[ref.producer_node_id]
                                for ref in target_refs
                                if ref.producer_node_id in self.graph.nodes
                                and self.graph.nodes[ref.producer_node_id].type == NodeType.LLM.value
                            ]
                            combined_path = path
                            for controller in target_controllers:
                                controller_path = (
                                    self.graph.data_path_from_variables(source.id, controller.id, sensitive_variables)
                                    if sensitive_variables
                                    else self.graph.path(source.id, controller.id, data_preferred=True)
                                )
                                if controller_path:
                                    combined_path = [*controller_path, sink.id]
                                    break
                            self._emit(
                                "TOOL-017", combined_path,
                                "敏感载荷可进入具有动态目标的网络写工具，且未发现 DLP/出站载荷策略。",
                                status=Status.CONFIRMED,
                                dynamic_test="web_exfiltration_chain",
                            )
                            if target_controllers:
                                self._emit(
                                    "FLOW-009", combined_path,
                                    "敏感资产作为网络载荷，同时模型可控制外部目标，形成完整的复合外泄链。",
                                    status=Status.CONFIRMED, severity=Severity.CRITICAL,
                                    attack_preconditions=["模型可影响网络目标", "敏感资产可进入请求载荷"],
                                    dynamic_test="web_exfiltration_chain",
                                )

        external_content = [
            node for node in [*knowledge, *content_sources, *tools]
            if node.type in {NodeType.KNOWLEDGE.value, NodeType.CONTENT.value} or node.external or "NETWORK_READ" in node.capabilities
        ]
        code_sinks = [node for node in tools if node.type == NodeType.CODE.value or "CODE_EXECUTION" in node.capabilities]
        for source in external_content:
            for llm in llms:
                first = self.graph.path(source.id, llm.id, data_preferred=True)
                if not first:
                    continue
                for sink in code_sinks:
                    second = self.graph.path(llm.id, sink.id, data_preferred=True)
                    if second:
                        chain = [*first, *second[1:]]
                        self._emit(
                            "FLOW-010", chain,
                            "外部或检索内容可经模型输出进入代码/命令执行节点。",
                            status=Status.CONFIRMED, severity=Severity.CRITICAL,
                            dynamic_test="external_content_to_code_execution",
                        )

        for first_llm in llms:
            for second_llm in llms:
                if first_llm.id == second_llm.id:
                    continue
                path = self.graph.path(first_llm.id, second_llm.id, data_preferred=True)
                if path and (not _has_schema(first_llm) or not _has_words(_system_prompt_text(second_llm), INJECTION_GUARD_WORDS)):
                    self._emit(
                        "FLOW-011", path,
                        "上游 Agent 的自由文本被下游 Agent 信任，缺少消息 Schema、来源身份或不可信指令隔离。",
                        status=Status.CONFIRMED,
                        dynamic_test="inter_agent_message_injection",
                    )

        side_effect_tools = [node for node in tools if node.high_impact or "NETWORK_WRITE" in node.capabilities]
        for first_tool in side_effect_tools:
            for second_tool in side_effect_tools:
                if first_tool.id == second_tool.id:
                    continue
                path = self.graph.path(first_tool.id, second_tool.id)
                if path and not any(_has_limits(self.graph.nodes[item]) or _key_matches(
                    self.graph.nodes[item].config, ("circuit_breaker", "compensation", "idempotency_key", "fail_closed")
                ) for item in path if item in self.graph.nodes):
                    self._emit(
                        "FLOW-012", path,
                        "多个副作用节点串联，但路径上未发现幂等、熔断、补偿或失败关闭控制。",
                        status=Status.PROBABLE, confidence=0.84,
                        dynamic_test="cascading_failure",
                    )

        autonomous_agents = [
            node for node in llms
            if node.original_type.lower() == "agent" or _key_matches(node.config, ("agent_parameters", "agent_strategy", "planning_strategy"))
        ]
        for agent in autonomous_agents:
            incoming = self.graph.any_path([*inputs, *knowledge, *tools], [agent], data_preferred=True)
            downstream = self.graph.any_path([agent], dangerous_tools)
            has_containment = _key_matches(
                agent.config,
                ("goal_lock", "allowed_goals", "kill_switch", "emergency_stop", "stop_conditions", "max_iterations"),
            )
            if incoming and downstream and not has_containment:
                chain = [*incoming, *downstream[1:]]
                self._emit(
                    "FLOW-013", chain,
                    "自主 Agent 接收不可信上下文并可影响高危能力，但 DSL 未声明目标锁定、停止条件或紧急停止控制。",
                    status=Status.PROBABLE, confidence=0.82,
                    missing_context=["运行时规划行为与停止指令服从性只能在沙盒确认。"],
                    dynamic_test="rogue_agent_containment",
                )

        for tool in tools:
            for llm in llms:
                path = self.graph.path(tool.id, llm.id, data_preferred=True)
                if path and not _has_schema(tool):
                    self._emit("TOOL-012", path, "工具输出未经严格 Schema 验证进入 LLM 上下文。", status=Status.CONFIRMED, dynamic_test="tool_output_prompt_injection")

        for llm in llms:
            for tool in dangerous_tools:
                path = self.graph.path(llm.id, tool.id, data_preferred=True)
                if path:
                    if not _has_schema(llm):
                        self._emit("LLM-005", path, "LLM 自由文本输出可直接影响工具参数。", status=Status.CONFIRMED, dynamic_test="free_text_tool_control")
                        self._emit("LLM-006", path, "下游工具依赖 LLM 输出，但节点未声明严格结构化输出。", status=Status.CONFIRMED)
                        self._emit("OUT-006", path, "未经严格结构验证的模型输出进入下游执行节点。", status=Status.CONFIRMED, dynamic_test="free_text_tool_control")
                    if tool.high_impact:
                        has_deterministic_gate = any(item in controls for item in path[1:-1])
                        if not has_deterministic_gate:
                            self._emit("LLM-008", path, "LLM 输出可触发高影响操作，路径中缺少确定性复核证据。", status=Status.PROBABLE, confidence=0.88, dynamic_test="high_impact_model_decision")

        for output in outputs:
            for kb in knowledge:
                path = self.graph.path(kb.id, output.id, data_preferred=True)
                if path and not _key_matches(output.config, ("citation", "sources", "references")):
                    self._emit("OUT-007", path, "知识库回答到达输出，但未发现引用元数据绑定。", status=Status.CONFIRMED)

        for node in nodes:
            memory_capable = node.type in {NodeType.TOOL.value, NodeType.KNOWLEDGE.value, NodeType.AGGREGATOR.value}
            if memory_capable and _has_words(f"{node.title}\n{node.text}", MEMORY_WRITE_WORDS):
                incoming_untrusted = self.graph.any_path([*inputs, *knowledge, *content_sources, *tools], [node], data_preferred=True)
                if incoming_untrusted and not _is_validation(node):
                    rule_id = "KB-007" if any(self.graph.nodes[item].type == NodeType.KNOWLEDGE.value for item in incoming_untrusted if item in self.graph.nodes) else "IN-008"
                    self._emit(rule_id, incoming_untrusted, "不可信内容可能未经验证写入持久化记忆。", status=Status.PROBABLE, confidence=0.75, dynamic_test="memory_poisoning")
                if not _key_matches(node.config, MEMORY_SCOPE_KEYS):
                    self._emit(
                        "KB-011", [node.id],
                        "持久记忆节点未声明用户、租户或会话命名空间。",
                        status=Status.CONFIRMED,
                        dynamic_test="cross_user_memory_isolation",
                    )
                if incoming_untrusted:
                    downstream_agents = [item for item in llms if item.id != node.id]
                    outgoing = self.graph.any_path([node], downstream_agents, data_preferred=True)
                    if outgoing:
                        chain = [*incoming_untrusted, *outgoing[1:]]
                        self._emit(
                            "KB-012", chain,
                            "不可信内容可写入持久记忆并被后续 Agent 读取，形成可持续指令投毒闭环。",
                            status=Status.CONFIRMED,
                            dynamic_test="persistent_memory_poisoning",
                        )


def execute_rules(ir: WorkflowIR, catalog_path: Path) -> tuple[list[Fact], list[Finding], dict[str, Any]]:
    catalog = RuleCatalog(catalog_path)
    engine = SecurityEngine(ir, catalog)
    facts, findings = engine.run()
    candidates = {
        "rule_count": len(catalog.rules),
        "candidate_count": len(findings),
        "candidates": [
            {
                "candidate_id": stable_id("CANDIDATE", finding.id),
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "attack_family": catalog.get(finding.rule_id).get("attack_family", "general_workflow_security"),
                "standards": catalog.get(finding.rule_id).get("standards", []),
                "detectability": catalog.get(finding.rule_id).get("detectability"),
                "references": catalog.get(finding.rule_id).get("references", []),
                "node_ids": finding.node_ids,
                "evidence_refs": finding.evidence_refs,
                "recommended_status": finding.status,
                "recommended_severity": finding.severity,
            }
            for finding in findings
        ],
    }
    return facts, findings, candidates
