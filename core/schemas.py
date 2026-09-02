"""Schemas for scientific KOTH/CTF reasoning and evidence tracking.

Workflow:
    Observation -> Hypothesis -> Safe Test -> Result -> Conclusion -> Finding

All schemas use Python standard library dataclasses with strict validation.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional, Self


class ValidationError(ValueError):
    """Raised when schema validation fails."""
    pass


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    VALIDATED = "validated"
    REFUTED = "refuted"
    ABANDONED = "abandoned"


class TestStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


class ConclusionStatus(str, Enum):
    VALIDATED = "validated"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _validate_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Field '{field_name}' must be a non-empty string")
    return value.strip()


def _validate_safe_identifier(value: Any, field_name: str) -> str:
    cleaned = _validate_non_empty_str(value, field_name)
    forbidden = {"\x00", "\n", "\r", "/", "\\", ".."}
    for f in forbidden:
        if f in cleaned:
            raise ValidationError(f"Field '{field_name}' contains illegal character or sequence: {f}")
    if any(ord(c) < 32 for c in cleaned):
        raise ValidationError(f"Field '{field_name}' contains control characters")
    return cleaned


def _current_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvidenceRecord:
    """Represents an immutable piece of evidence collected during testing."""
    evidence_id: str
    timestamp: str
    source_tool: str
    target: str
    payload: Any
    sha256: str
    file_path: str

    def __post_init__(self):
        self.evidence_id = _validate_non_empty_str(self.evidence_id, "evidence_id")
        if not re.fullmatch(r"^[0-9a-f]{64}$", self.evidence_id):
            raise ValidationError("Field 'evidence_id' must be a 64-character lowercase hex SHA-256 hash")
        
        self.sha256 = _validate_non_empty_str(self.sha256, "sha256")
        if self.sha256 != self.evidence_id:
            raise ValidationError(f"'sha256' ({self.sha256}) must match 'evidence_id' ({self.evidence_id})")

        self.timestamp = _validate_non_empty_str(self.timestamp, "timestamp")
        self.source_tool = _validate_safe_identifier(self.source_tool, "source_tool")
        self.target = _validate_safe_identifier(self.target, "target")
        self.file_path = _validate_non_empty_str(self.file_path, "file_path")
        
        if self.payload is None:
            raise ValidationError("Field 'payload' cannot be None")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            evidence_id=data["evidence_id"],
            timestamp=data["timestamp"],
            source_tool=data["source_tool"],
            target=data["target"],
            payload=data["payload"],
            sha256=data["sha256"],
            file_path=data["file_path"],
        )


@dataclass
class Observation:
    """Factual observation directly backed by an immutable evidence record."""
    observation_id: str
    evidence_ref: str
    timestamp: str
    target: str
    description: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.observation_id = _validate_safe_identifier(self.observation_id, "observation_id")
        self.evidence_ref = _validate_safe_identifier(self.evidence_ref, "evidence_ref")
        self.timestamp = _validate_non_empty_str(self.timestamp, "timestamp")
        self.target = _validate_safe_identifier(self.target, "target")
        self.description = _validate_non_empty_str(self.description, "description")
        if not isinstance(self.attributes, dict):
            raise ValidationError("Field 'attributes' must be a dictionary")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            observation_id=data["observation_id"],
            evidence_ref=data["evidence_ref"],
            timestamp=data["timestamp"],
            target=data["target"],
            description=data["description"],
            attributes=data.get("attributes", {}),
        )


@dataclass
class Hypothesis:
    """A testable claim formulated based on one or more observations."""
    hypothesis_id: str
    based_on_observations: List[str]
    claim: str
    status: str = HypothesisStatus.PROPOSED.value
    created_at: str = field(default_factory=_current_iso_utc)
    updated_at: str = field(default_factory=_current_iso_utc)

    def __post_init__(self):
        self.hypothesis_id = _validate_safe_identifier(self.hypothesis_id, "hypothesis_id")
        if not isinstance(self.based_on_observations, list) or not self.based_on_observations:
            raise ValidationError("Field 'based_on_observations' must be a non-empty list of observation IDs")
        for obs_id in self.based_on_observations:
            _validate_safe_identifier(obs_id, "based_on_observations item")

        self.claim = _validate_non_empty_str(self.claim, "claim")
        valid_statuses = {s.value for s in HypothesisStatus}
        if self.status not in valid_statuses:
            raise ValidationError(f"Invalid status '{self.status}'. Expected one of {valid_statuses}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            hypothesis_id=data["hypothesis_id"],
            based_on_observations=data["based_on_observations"],
            claim=data["claim"],
            status=data.get("status", HypothesisStatus.PROPOSED.value),
            created_at=data.get("created_at", _current_iso_utc()),
            updated_at=data.get("updated_at", _current_iso_utc()),
        )


@dataclass
class SafeTest:
    """A safe, strictly bounded test proposed to validate or refute a hypothesis."""
    test_id: str
    hypothesis_id: str
    tool: str
    safety_justification: str
    expected_outcome: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_current_iso_utc)

    def __post_init__(self):
        self.test_id = _validate_safe_identifier(self.test_id, "test_id")
        self.hypothesis_id = _validate_safe_identifier(self.hypothesis_id, "hypothesis_id")
        self.tool = _validate_safe_identifier(self.tool, "tool")
        self.safety_justification = _validate_non_empty_str(self.safety_justification, "safety_justification")
        self.expected_outcome = _validate_non_empty_str(self.expected_outcome, "expected_outcome")
        if not isinstance(self.parameters, dict):
            raise ValidationError("Field 'parameters' must be a dictionary")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            test_id=data["test_id"],
            hypothesis_id=data["hypothesis_id"],
            tool=data["tool"],
            safety_justification=data["safety_justification"],
            expected_outcome=data["expected_outcome"],
            parameters=data.get("parameters", {}),
            created_at=data.get("created_at", _current_iso_utc()),
        )


@dataclass
class TestResult:
    """Outcome of running a SafeTest, linked to newly generated immutable evidence."""
    result_id: str
    test_id: str
    evidence_ref: str
    status: str
    summary: str
    timestamp: str = field(default_factory=_current_iso_utc)

    def __post_init__(self):
        self.result_id = _validate_safe_identifier(self.result_id, "result_id")
        self.test_id = _validate_safe_identifier(self.test_id, "test_id")
        self.evidence_ref = _validate_safe_identifier(self.evidence_ref, "evidence_ref")
        valid_statuses = {s.value for s in TestStatus}
        if self.status not in valid_statuses:
            raise ValidationError(f"Invalid test result status '{self.status}'. Expected one of {valid_statuses}")
        self.summary = _validate_non_empty_str(self.summary, "summary")
        self.timestamp = _validate_non_empty_str(self.timestamp, "timestamp")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            result_id=data["result_id"],
            test_id=data["test_id"],
            evidence_ref=data["evidence_ref"],
            status=data["status"],
            summary=data["summary"],
            timestamp=data.get("timestamp", _current_iso_utc()),
        )


@dataclass
class Conclusion:
    """Deductive conclusion evaluating a hypothesis against test results."""
    conclusion_id: str
    hypothesis_id: str
    result_refs: List[str]
    status: str
    rationale: str
    timestamp: str = field(default_factory=_current_iso_utc)

    def __post_init__(self):
        self.conclusion_id = _validate_safe_identifier(self.conclusion_id, "conclusion_id")
        self.hypothesis_id = _validate_safe_identifier(self.hypothesis_id, "hypothesis_id")
        if not isinstance(self.result_refs, list) or not self.result_refs:
            raise ValidationError("Field 'result_refs' must be a non-empty list of test result IDs")
        for res_id in self.result_refs:
            _validate_safe_identifier(res_id, "result_refs item")
        valid_statuses = {s.value for s in ConclusionStatus}
        if self.status not in valid_statuses:
            raise ValidationError(f"Invalid conclusion status '{self.status}'. Expected one of {valid_statuses}")
        self.rationale = _validate_non_empty_str(self.rationale, "rationale")
        self.timestamp = _validate_non_empty_str(self.timestamp, "timestamp")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            conclusion_id=data["conclusion_id"],
            hypothesis_id=data["hypothesis_id"],
            result_refs=data["result_refs"],
            status=data["status"],
            rationale=data["rationale"],
            timestamp=data.get("timestamp", _current_iso_utc()),
        )


@dataclass
class Finding:
    """A verified finding summarizing a security conclusion and its entire chain of evidence."""
    finding_id: str
    title: str
    target: str
    severity: str
    conclusion_ref: str
    evidence_chain: Dict[str, Any]
    description: str
    impact: str
    remediation: str = ""
    timestamp: str = field(default_factory=_current_iso_utc)

    def __post_init__(self):
        self.finding_id = _validate_safe_identifier(self.finding_id, "finding_id")
        self.title = _validate_non_empty_str(self.title, "title")
        self.target = _validate_safe_identifier(self.target, "target")
        valid_severities = {s.value for s in FindingSeverity}
        if self.severity not in valid_severities:
            raise ValidationError(f"Invalid finding severity '{self.severity}'. Expected one of {valid_severities}")
        self.conclusion_ref = _validate_safe_identifier(self.conclusion_ref, "conclusion_ref")
        if not isinstance(self.evidence_chain, dict):
            raise ValidationError("Field 'evidence_chain' must be a dictionary")
        self.description = _validate_non_empty_str(self.description, "description")
        self.impact = _validate_non_empty_str(self.impact, "impact")
        self.timestamp = _validate_non_empty_str(self.timestamp, "timestamp")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Self:
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            target=data["target"],
            severity=data["severity"],
            conclusion_ref=data["conclusion_ref"],
            evidence_chain=data.get("evidence_chain", {}),
            description=data["description"],
            impact=data["impact"],
            remediation=data.get("remediation", ""),
            timestamp=data.get("timestamp", _current_iso_utc()),
        )
