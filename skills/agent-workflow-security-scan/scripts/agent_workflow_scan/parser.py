from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any
import json
import re

import yaml
from jsonschema import Draft202012Validator
from yaml.events import AliasEvent

from .models import Edge, Node, NodeType, VariableRef, WorkflowIR, file_sha256, stable_id
from .dify_contract import (
    CURRENT_DIFY_APP_DSL_VERSION,
    VIRTUAL_SOURCE_NAMESPACES,
    VIRTUAL_SOURCE_NODE_TYPES,
    normalize_dsl_version,
    normalize_node_type,
    semantic_consumer_field,
)


MAX_DSL_BYTES = 5 * 1024 * 1024
MAX_ALIAS_COUNT = 64
MAX_DEPTH = 80
MAX_NODES = 5000


SECRET_RE = re.compile(
    r"(?ix)(?:"
    r"(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret|password|passwd|authorization)"
    r"\s*[:=]\s*(?:bearer\s+)?['\"]?[A-Za-z0-9_\-./+=]{8,}"
    r"|bearer\s+[A-Za-z0-9._~+/=-]{12,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    r"|\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"
    r"|-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----"
    r"|\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@[^\s]+"
    r")"
)

PLACEHOLDER_SECRET_RE = re.compile(
    r"(?ix)(?:your[_-]?(?:api[_-]?key|token|secret|password)|example|placeholder|dummy|<redacted>|\*{3,})"
)


def contains_secret(value: str) -> bool:
    """Return true for credential-like values while excluding obvious examples/placeholders."""
    return bool(SECRET_RE.search(value)) and not bool(PLACEHOLDER_SECRET_RE.search(value))


class BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader with basic anti-resource-exhaustion limits."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._alias_count = 0
        self._compose_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            self._alias_count += 1
            if self._alias_count > MAX_ALIAS_COUNT:
                raise yaml.YAMLError("DSL contains too many YAML aliases")
        self._compose_depth += 1
        if self._compose_depth > MAX_DEPTH:
            raise yaml.YAMLError("DSL nesting depth exceeds scanner limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1


EXTERNAL_WORDS = {
    "http", "webhook", "email", "mail", "slack", "feishu", "wechat",
    "telegram", "request", "upload", "publish", "browser", "api",
}
# These terms are intentionally narrower than generic CRUD verbs.  Words such as
# "create", "update" and "write" occur frequently in descriptions and prompts;
# treating any occurrence as a privileged side effect caused severe over-reporting.
HIGH_IMPACT_ACTION_WORDS = {
    "delete", "remove", "drop", "terminate", "destroy", "purge",
    "payment", "transfer", "refund", "withdraw", "charge",
    "permission", "grant", "revoke", "role", "admin",
    "deploy", "publish", "send-email", "send email", "broadcast",
    "删除", "销毁", "转账", "付款", "退款", "授权", "提权", "管理员", "发布", "群发",
}
DANGEROUS_CODE_PATTERNS = (
    r"\b(?:eval|exec)\s*\(", r"\bsubprocess\b", r"\bos\.system\s*\(",
    r"\bpopen\s*\(", r"shell\s*=\s*true", r"\b(?:socket|requests|urllib)\b",
)


def _json_pointer(parts: list[Any]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped)


def walk(value: Any, path: list[Any] | None = None) -> Iterator[tuple[list[Any], Any]]:
    path = path or []
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, [*path, key])
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, [*path, index])


def flatten_text(value: Any) -> str:
    chunks: list[str] = []
    for _, item in walk(value):
        if isinstance(item, str):
            chunks.append(item)
    return "\n".join(chunks)


def contains_template(value: Any) -> bool:
    return bool(re.search(r"\{\{[^}]+\}\}|\$\{[^}]+\}", flatten_text(value)))


def secret_locations(value: Any, prefix: list[Any] | None = None) -> list[str]:
    locations: list[str] = []
    for path, item in walk(value, prefix):
        if isinstance(item, str) and contains_secret(item):
            locations.append(_json_pointer(path))
    return locations


def _load_document(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_DSL_BYTES:
        raise ValueError(f"DSL exceeds {MAX_DSL_BYTES} byte limit")
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        document = json.loads(text)
    else:
        document = yaml.load(text, Loader=BoundedSafeLoader)
    if not isinstance(document, dict):
        raise ValueError("DSL root must be an object")
    return document


def _extract_graph(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    workflow = document.get("workflow")
    if not isinstance(workflow, dict):
        workflow = document
    graph = workflow.get("graph")
    if not isinstance(graph, dict):
        graph = document.get("graph")
    if not isinstance(graph, dict):
        raise ValueError("Expected internal Dify DSL field workflow.graph")
    return workflow, graph


def _validate_internal_schema(document: dict[str, Any]) -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "internal-dify-workflow.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"/{'/'.join(str(item) for item in error.absolute_path)}: {error.message}"
            for error in errors[:5]
        )
        raise ValueError(f"Internal Dify DSL schema validation failed: {details}")


def _map_type(raw_type: str) -> NodeType:
    return normalize_node_type(raw_type)


def _classify_capabilities(node_type: NodeType, original_type: str, config: dict[str, Any]) -> tuple[list[str], bool, bool]:
    identity_values = [original_type]
    for key in (
        "title", "name", "tool_name", "provider_name", "operation", "action",
        "api_name", "endpoint_name", "resource_type",
    ):
        value = config.get(key)
        if isinstance(value, (str, int, float)):
            identity_values.append(str(value))
    identity_text = "\n".join(identity_values).lower()
    capabilities: set[str] = set()
    explicit_high_impact = config.get("high_impact") is True or str(config.get("risk_level", "")).lower() in {
        "high", "critical",
    }
    external = node_type == NodeType.TOOL and (
        original_type.lower().replace("_", "-") in {"http-request", "api"}
        or any(word in identity_text for word in EXTERNAL_WORDS)
        or any(key in config for key in ("url", "endpoint", "base_url"))
    )
    high_impact = explicit_high_impact or any(word in identity_text for word in HIGH_IMPACT_ACTION_WORDS)
    if node_type == NodeType.TOOL and str(config.get("method") or "").upper() == "DELETE":
        high_impact = True

    if node_type == NodeType.CODE:
        # A Dify Code node normally executes fixed workflow code in the platform
        # sandbox.  Supplying data arguments to that function is not by itself
        # command injection.  Escalate only when dangerous interpreters, process
        # launchers or network primitives are actually present.
        capabilities.add("SANDBOXED_CODE")
        code_text = "\n".join(
            str(config.get(key) or "") for key in ("code", "script", "source")
        ).lower()
        if contains_template(code_text) or any(re.search(pattern, code_text) for pattern in DANGEROUS_CODE_PATTERNS):
            capabilities.add("CODE_EXECUTION")
            high_impact = True
    if node_type == NodeType.KNOWLEDGE:
        capabilities.add("DATABASE_READ")
    if node_type == NodeType.OUTPUT:
        capabilities.add("USER_OUTPUT")
    if node_type == NodeType.HUMAN:
        capabilities.add("HUMAN_DECISION")
    if node_type == NodeType.CONTENT:
        capabilities.add("UNTRUSTED_CONTENT")
    if node_type == NodeType.TOOL:
        if external:
            capabilities.add("NETWORK_READ")
            method = str(config.get("method") or "").upper()
            if method and method not in {"GET", "HEAD", "OPTIONS"}:
                capabilities.add("NETWORK_WRITE")
            elif any(word in identity_text for word in ("send", "upload", "publish", "webhook", "callback")):
                capabilities.add("NETWORK_WRITE")
        if any(word in identity_text for word in ("file", "path", "directory")):
            capabilities.add("FILE_WRITE" if high_impact else "FILE_READ")
        if any(word in identity_text for word in ("sql", "database", "query")):
            capabilities.add("DATABASE_WRITE" if high_impact else "DATABASE_READ")
        if any(word in identity_text for word in ("email", "mail", "message", "slack", "send")):
            capabilities.add("MESSAGE_SEND")
        if any(word in identity_text for word in ("shell", "command", "exec", "script")):
            capabilities.add("CODE_EXECUTION")
            high_impact = True
        if any(word in identity_text for word in ("delete", "remove", "drop", "terminate", "destroy", "purge")):
            capabilities.add("RESOURCE_DELETE")
            high_impact = True
        if any(word in identity_text for word in ("permission", "role", "admin", "grant", "revoke")):
            capabilities.add("PERMISSION_CHANGE")
            high_impact = True
        if not capabilities:
            capabilities.add("UNKNOWN_TOOL_CAPABILITY")
    return sorted(capabilities), external, high_impact


def _selector_from_list(value: list[Any], known_sources: set[str]) -> tuple[str, str] | None:
    if len(value) < 2 or not isinstance(value[0], str):
        return None
    if value[0] not in known_sources:
        return None
    remainder = ".".join(str(part) for part in value[1:])
    return value[0], remainder


def _template_refs(text: str, known_sources: set[str]) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    patterns = [r"\{\{#([^#.}]+)\.([^#}]+)#\}\}", r"\{\{\s*([^}.\s]+)\.([^}\s]+)\s*\}\}"]
    for pattern in patterns:
        for producer, variable in re.findall(pattern, text):
            if producer in known_sources:
                results.append((producer, variable))
    return results


def parse_dify_dsl(path: Path) -> tuple[WorkflowIR, dict[str, Any]]:
    document = _load_document(path)
    _validate_internal_schema(document)
    workflow, graph = _extract_graph(document)
    workflow_features = workflow.get("features") if isinstance(workflow.get("features"), dict) else {}
    raw_nodes = graph.get("nodes", [])
    raw_edges = graph.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ValueError("workflow.graph.nodes and edges must be arrays")
    if len(raw_nodes) > MAX_NODES:
        raise ValueError(f"DSL contains more than {MAX_NODES} nodes")

    known_node_ids = {
        str(item.get("id")) for item in raw_nodes if isinstance(item, dict) and item.get("id") is not None
    }
    known_sources = known_node_ids | VIRTUAL_SOURCE_NAMESPACES
    nodes: list[Node] = []
    variable_refs: list[VariableRef] = []
    coverage_gaps: list[dict[str, Any]] = []

    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict):
            coverage_gaps.append({"pointer": f"/workflow/graph/nodes/{index}", "reason": "node_not_object"})
            continue
        node_id = str(raw_node.get("id", f"missing-{index}"))
        config = raw_node.get("data") if isinstance(raw_node.get("data"), dict) else {}
        raw_type = str(config.get("type") or raw_node.get("type") or "unknown")
        mapped_type = _map_type(raw_type)
        pointer = f"/workflow/graph/nodes/{index}"
        refs: list[VariableRef] = []
        for relative_path, value in walk(config):
            consumer_field = semantic_consumer_field(config, relative_path)
            selector = _selector_from_list(value, known_sources) if isinstance(value, list) else None
            if selector:
                refs.append(VariableRef(selector[0], selector[1], node_id, _json_pointer(["workflow", "graph", "nodes", index, "data", *relative_path]), consumer_field))
            if isinstance(value, str):
                for producer, variable in _template_refs(value, known_sources):
                    refs.append(VariableRef(producer, variable, node_id, _json_pointer(["workflow", "graph", "nodes", index, "data", *relative_path]), consumer_field))
        deduped: dict[tuple[str, str, str], VariableRef] = {}
        for ref in refs:
            deduped[(ref.producer_node_id, ref.variable_name, ref.json_pointer)] = ref
        refs = list(deduped.values())
        variable_refs.extend(refs)
        capabilities, external, high_impact = _classify_capabilities(mapped_type, raw_type, config)
        title = str(config.get("title") or config.get("name") or raw_node.get("title") or node_id)
        nodes.append(
            Node(
                id=node_id,
                original_type=raw_type,
                type=mapped_type.value,
                title=title,
                json_pointer=pointer,
                config=config,
                text=flatten_text(config),
                variable_refs=refs,
                capabilities=capabilities,
                external=external,
                high_impact=high_impact,
            )
        )
        if mapped_type == NodeType.UNKNOWN:
            coverage_gaps.append({
                "node_id": node_id,
                "pointer": pointer,
                "reason": "unsupported_internal_node_type",
                "original_type": raw_type,
            })

    virtual_producers = sorted({
        ref.producer_node_id for ref in variable_refs
        if ref.producer_node_id in VIRTUAL_SOURCE_NAMESPACES and ref.producer_node_id not in known_node_ids
    })
    for namespace in virtual_producers:
        virtual_type = VIRTUAL_SOURCE_NODE_TYPES[namespace]
        virtual_variables: list[dict[str, Any]] = []
        referenced_names = {
            ref.variable_name.split(".", 1)[0]
            for ref in variable_refs if ref.producer_node_id == namespace
        }
        if namespace == "sys" and "files" in referenced_names:
            upload = workflow_features.get("file_upload")
            if isinstance(upload, dict) and upload.get("enabled") is True:
                number_limit = upload.get("number_limits")
                virtual_variables.append({
                    "variable": "files",
                    "type": "file-list",
                    "required": False,
                    "max_length": number_limit,
                    "allowed_file_types": upload.get("allowed_file_types"),
                    "allowed_file_extensions": upload.get("allowed_file_extensions"),
                    "allowed_file_upload_methods": upload.get("allowed_file_upload_methods"),
                })
        nodes.append(Node(
            id=namespace,
            original_type=f"virtual-{namespace}",
            type=virtual_type.value,
            title=f"Dify {namespace} variables",
            json_pointer=f"/workflow/virtual_sources/{namespace}",
            config={"type": f"virtual-{namespace}", "virtual": True, "variables": virtual_variables},
            text="",
            variable_refs=[],
            capabilities=[],
            external=False,
            high_impact=False,
        ))

    edges: list[Edge] = []
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict):
            coverage_gaps.append({"pointer": f"/workflow/graph/edges/{index}", "reason": "edge_not_object"})
            continue
        source = str(raw_edge.get("source", ""))
        target = str(raw_edge.get("target", ""))
        edge_id = str(raw_edge.get("id") or stable_id("EDGE", source, target, index))
        edges.append(Edge(edge_id, source, target, raw_edge.get("sourceHandle"), raw_edge.get("targetHandle")))
        if source not in known_node_ids or target not in known_node_ids:
            coverage_gaps.append({
                "edge_id": edge_id,
                "pointer": f"/workflow/graph/edges/{index}",
                "reason": "dangling_edge",
                "source": source,
                "target": target,
            })

    workflow_id = str(
        document.get("app", {}).get("name") if isinstance(document.get("app"), dict) else ""
    ) or str(workflow.get("id") or path.stem)
    dsl_version = normalize_dsl_version(document.get("version"))
    if document.get("kind") == "app":
        if dsl_version is None:
            coverage_gaps.append({
                "pointer": "/version",
                "reason": "missing_or_invalid_dify_dsl_version",
                "supported_contract": CURRENT_DIFY_APP_DSL_VERSION,
            })
        elif tuple(map(int, dsl_version.split("."))) > tuple(map(int, CURRENT_DIFY_APP_DSL_VERSION.split("."))):
            coverage_gaps.append({
                "pointer": "/version",
                "reason": "future_dify_dsl_version",
                "imported_version": dsl_version,
                "supported_contract": CURRENT_DIFY_APP_DSL_VERSION,
            })
    app = document.get("app") if isinstance(document.get("app"), dict) else {}
    ir = WorkflowIR(
        workflow_id=workflow_id,
        workflow_hash=file_sha256(path),
        nodes=nodes,
        edges=edges,
        variable_refs=variable_refs,
        coverage_gaps=coverage_gaps,
        raw_metadata={
            "source_file": path.name,
            "dsl_kind": document.get("kind"),
            "dsl_version": dsl_version,
            "dify_contract_version": CURRENT_DIFY_APP_DSL_VERSION,
            "app_mode": app.get("mode"),
            "workflow_features": workflow_features,
            "node_count": len(raw_nodes),
            "ir_node_count": len(nodes),
            "virtual_source_count": len(virtual_producers),
            "edge_count": len(edges),
            "secret_locations": secret_locations(document),
        },
    )
    return ir, document
