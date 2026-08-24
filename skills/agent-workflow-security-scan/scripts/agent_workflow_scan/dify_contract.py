from __future__ import annotations

from typing import Any, Iterable
import json

from .models import Node, NodeType


# The adapter is pinned to the public Dify application DSL contract.  Parsing
# remains tolerant of older aliases, while rule predicates use the normalized
# node semantics below instead of guessing from generic field names.
CURRENT_DIFY_APP_DSL_VERSION = "0.7.0"

VIRTUAL_SOURCE_NAMESPACES = {"sys", "env", "environment", "conversation"}
VIRTUAL_SOURCE_NODE_TYPES = {
    "sys": NodeType.INPUT,
    "conversation": NodeType.INPUT,
    # Environment variables are deployment-controlled data, not attacker input.
    "env": NodeType.AGGREGATOR,
    "environment": NodeType.AGGREGATOR,
}

NODE_TYPE_MAP = {
    "start": NodeType.INPUT,
    "input": NodeType.INPUT,
    "trigger-webhook": NodeType.INPUT,
    "trigger_webhook": NodeType.INPUT,
    "trigger-schedule": NodeType.INPUT,
    "trigger_schedule": NodeType.INPUT,
    "trigger-plugin": NodeType.INPUT,
    "trigger_plugin": NodeType.INPUT,
    "llm": NodeType.LLM,
    "agent": NodeType.LLM,
    "agent-v2": NodeType.LLM,
    "agent_v2": NodeType.LLM,
    "tool": NodeType.TOOL,
    "http-request": NodeType.TOOL,
    "http_request": NodeType.TOOL,
    "api": NodeType.TOOL,
    "end": NodeType.OUTPUT,
    "answer": NodeType.OUTPUT,
    "output": NodeType.OUTPUT,
    "knowledge-retrieval": NodeType.KNOWLEDGE,
    "knowledge_retrieval": NodeType.KNOWLEDGE,
    "knowledge-index": NodeType.KNOWLEDGE,
    "knowledge_index": NodeType.KNOWLEDGE,
    "retrieval": NodeType.KNOWLEDGE,
    "if-else": NodeType.CONDITION,
    "question-classifier": NodeType.CONDITION,
    "condition": NodeType.CONDITION,
    "iteration": NodeType.ITERATION,
    "loop": NodeType.LOOP,
    "code": NodeType.CODE,
    "template-transform": NodeType.TEMPLATE,
    "template": NodeType.TEMPLATE,
    "variable-aggregator": NodeType.AGGREGATOR,
    "parameter-extractor": NodeType.AGGREGATOR,
    "document-extractor": NodeType.CONTENT,
    "document_extractor": NodeType.CONTENT,
    "file-reader": NodeType.CONTENT,
    "datasource": NodeType.CONTENT,
    "variable-assigner": NodeType.AGGREGATOR,
    "variable_assigner": NodeType.AGGREGATOR,
    "assigner": NodeType.AGGREGATOR,
    "list-operator": NodeType.AGGREGATOR,
    "list_operator": NodeType.AGGREGATOR,
    "human-input": NodeType.HUMAN,
    "human_input": NodeType.HUMAN,
    # Canvas/container helpers are legitimate Dify graph nodes.  They preserve
    # topology but do not own a security rule or capability themselves.
    "start-placeholder": NodeType.STRUCTURAL,
    "iteration-start": NodeType.STRUCTURAL,
    "loop-start": NodeType.STRUCTURAL,
    "loop-end": NodeType.STRUCTURAL,
    "datasource-empty": NodeType.STRUCTURAL,
}


def normalize_node_type(raw_type: str) -> NodeType:
    normalized = raw_type.strip().lower().replace(" ", "-")
    return NODE_TYPE_MAP.get(normalized, NodeType.UNKNOWN)


def normalize_dsl_version(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    parts = text.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return text


def _value_at_path(config: Any, path: list[Any]) -> Any:
    current = config
    for part in path:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and isinstance(part, int) and 0 <= part < len(current):
            current = current[part]
        else:
            return None
    return current


def semantic_consumer_field(config: dict[str, Any], path: list[Any]) -> str:
    """Return the Dify parameter name rather than a generic wrapper leaf.

    Dify serializes plugin and Agent parameters as
    ``tool_parameters.<name>.value`` / ``agent_parameters.<name>.value``.
    Treating every reference as field ``value`` hides URL, SQL, path, identity
    and amount semantics from the security rules.
    """
    for container in ("tool_parameters", "tool_configurations", "agent_parameters"):
        if container in path:
            index = path.index(container)
            if index + 1 < len(path) and isinstance(path[index + 1], str):
                return str(path[index + 1]).lower()

    # HTTP body/headers/params are often arrays of {key, value} records.
    for index in range(len(path), 0, -1):
        parent = _value_at_path(config, path[:index])
        if isinstance(parent, dict):
            key = parent.get("key") or parent.get("name") or parent.get("variable")
            if isinstance(key, str) and key.strip():
                return key.strip().lower()

    generic = {"value", "selector", "value_selector", "data", "config", "parameters", "inputs", "variables"}
    for part in reversed(path):
        if isinstance(part, str) and part.lower() not in generic:
            return part.lower()
    return str(path[-1]).lower() if path else ""


def parse_json_schema(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def is_strict_object_schema(value: Any) -> bool:
    schema = parse_json_schema(value)
    return bool(
        schema
        and schema.get("type") == "object"
        and schema.get("additionalProperties") is False
        and isinstance(schema.get("properties"), dict)
        and schema.get("properties")
    )


def input_object_schema(variable: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("json_schema", "schema", "input_schema"):
        schema = parse_json_schema(variable.get(key))
        if schema is not None:
            return schema
    if str(variable.get("type") or "").lower() in {"object", "map"}:
        return variable
    return None


def input_limit_values(variable: dict[str, Any]) -> list[Any]:
    keys = (
        "max_length", "maxLength", "max_items", "maxItems", "number_limits",
        "size_limit", "max_files",
    )
    return [variable.get(key) for key in keys if key in variable]


def file_contract_issues(variable: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    allowed_types = variable.get("allowed_file_types")
    upload_methods = variable.get("allowed_file_upload_methods") or variable.get("allowed_upload_methods")
    extensions = variable.get("allowed_file_extensions")
    if not isinstance(allowed_types, list) or not allowed_types:
        issues.append("allowed_file_types")
    if not isinstance(upload_methods, list) or not upload_methods:
        issues.append("allowed_file_upload_methods")
    if isinstance(allowed_types, list) and "custom" in allowed_types and not extensions:
        issues.append("allowed_file_extensions(custom)")
    return issues


def prompt_instruction_text(node: Node) -> str:
    chunks: list[str] = []
    prompts = node.config.get("prompt_template")
    items = prompts if isinstance(prompts, list) else [prompts] if isinstance(prompts, dict) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").lower()
        # Completion-mode LLM nodes use one PromptItem without a role.  It is
        # the node's highest-priority instruction surface.
        if role in {"", "system", "developer"}:
            for key in ("text", "jinja2_text", "content"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    chunks.append(value)

    for key in ("system_prompt", "instruction", "instructions"):
        value = node.config.get(key)
        if isinstance(value, str):
            chunks.append(value)

    agent_parameters = node.config.get("agent_parameters")
    if isinstance(agent_parameters, dict):
        for key in ("instruction", "system_prompt", "instructions"):
            parameter = agent_parameters.get(key)
            if isinstance(parameter, dict):
                value = parameter.get("value")
                if isinstance(value, str):
                    chunks.append(value)
    return "\n".join(chunks)


def has_dify_tool_parameter_contract(node: Node) -> bool:
    """Recognize Dify/plugin parameter declarations as a closed name set."""
    for key in ("paramSchemas", "param_schemas", "parameter_schemas"):
        schemas = node.config.get(key)
        if isinstance(schemas, list) and schemas:
            return all(
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and bool(item.get("name"))
                and bool(item.get("type"))
                for item in schemas
            )
    return False


def has_explicit_timeout(config: dict[str, Any]) -> bool:
    timeout = config.get("timeout")
    if isinstance(timeout, (int, float)):
        return timeout > 0
    if isinstance(timeout, dict):
        # max_* fields are editor/deployment caps, not the node's operational
        # connect/read/write timeout.
        return any(
            isinstance(timeout.get(key), (int, float)) and timeout.get(key) > 0
            for key in ("connect", "read", "write")
        )
    return any(
        isinstance(config.get(key), (int, float)) and config.get(key) > 0
        for key in ("connect_timeout", "read_timeout", "write_timeout", "max_execution_time")
    )


def knowledge_filter_state(config: dict[str, Any]) -> str:
    mode = str(config.get("metadata_filtering_mode") or "").lower()
    conditions = config.get("metadata_filtering_conditions")
    if mode == "disabled":
        return "disabled"
    if mode == "manual":
        if isinstance(conditions, dict) and conditions.get("conditions"):
            return "manual"
        return "missing"
    if mode == "automatic":
        return "automatic"
    if conditions not in (None, "", [], {}, False):
        return "manual"
    return "missing"


def has_positive_limit(config: Any, keys: Iterable[str]) -> bool:
    wanted = {key.lower() for key in keys}
    stack = [config]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if str(key).lower() in wanted:
                    if isinstance(value, bool):
                        if value:
                            return True
                    elif isinstance(value, (int, float)) and value > 0:
                        return True
                    elif value not in (None, "", [], {}, False, 0):
                        return True
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
    return False
