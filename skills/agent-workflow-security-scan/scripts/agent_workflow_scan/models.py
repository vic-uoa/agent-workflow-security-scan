from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any
import json


SCHEMA_VERSION = "1.5.0"


class NodeType(str, Enum):
    INPUT = "INPUT"
    LLM = "LLM"
    TOOL = "TOOL"
    OUTPUT = "OUTPUT"
    KNOWLEDGE = "KNOWLEDGE"
    CONDITION = "CONDITION"
    LOOP = "LOOP"
    ITERATION = "ITERATION"
    CODE = "CODE"
    TEMPLATE = "TEMPLATE"
    AGGREGATOR = "AGGREGATOR"
    HUMAN = "HUMAN"
    CONTENT = "CONTENT"
    STRUCTURAL = "STRUCTURAL"
    UNKNOWN = "UNKNOWN"


class Status(str, Enum):
    OBSERVED = "OBSERVED"
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    CANDIDATE = "CANDIDATE"
    COVERAGE_GAP = "COVERAGE_GAP"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MITIGATED = "MITIGATED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class VariableRef:
    producer_node_id: str
    variable_name: str
    consumer_node_id: str
    json_pointer: str
    consumer_field: str = ""


@dataclass
class Node:
    id: str
    original_type: str
    type: str
    title: str
    json_pointer: str
    config: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    variable_refs: list[VariableRef] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    external: bool = False
    high_impact: bool = False


@dataclass
class Edge:
    id: str
    source: str
    target: str
    source_handle: str | None = None
    target_handle: str | None = None


@dataclass
class Fact:
    id: str
    kind: str
    node_ids: list[str]
    evidence: list[str]
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    status: str
    severity: str
    confidence: float
    node_ids: list[str]
    evidence_refs: list[str]
    dsl_locations: list[str]
    message: str
    remediation: list[str]
    attack_family: str = "general_workflow_security"
    standards: list[str] = field(default_factory=list)
    attack_preconditions: list[str] = field(default_factory=list)
    counter_evidence: list[str] = field(default_factory=list)
    missing_context: list[str] = field(default_factory=list)
    dynamic_test: str | None = None
    root_cause_id: str | None = None
    related_rule_ids: list[str] = field(default_factory=list)
    anchor_node_id: str | None = None
    control_domain: str = "general_security_control"
    potential_severity: str | None = None
    finding_instance_ids: list[str] = field(default_factory=list)
    path_variants: list[list[str]] = field(default_factory=list)
    instance_summaries: list[dict[str, Any]] = field(default_factory=list)
    dynamic_tests: list[str] = field(default_factory=list)
    waived: bool = False
    waiver_id: str | None = None


@dataclass
class WorkflowIR:
    workflow_id: str
    workflow_hash: str
    nodes: list[Node]
    edges: list[Edge]
    variable_refs: list[VariableRef]
    coverage_gaps: list[dict[str, Any]]
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def node_map(self) -> dict[str, Node]:
        return {node.id: node for node in self.nodes}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts)
    return f"{prefix}-{sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value


def write_artifact(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )
