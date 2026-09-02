"""Session state management for the KOTH AI scientific reasoning engine.

Requirements:
- Python standard library only.
- Strict scientific workflow:
    Observation -> Hypothesis -> Safe Test -> Result -> Conclusion -> Finding
- Explicit hypothesis state transitions and validation.
- Mandatory failed_approaches section converting failed tests into reusable negative knowledge.
- Sessions stored under sessions/<session_id>.json.
- Atomic persistence using temporary files and POSIX replacement.
- Immutable evidence references by hash/ID (no raw payload duplication or overwriting).
- Path traversal prevention and symlink defense.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Dict, List, Optional, Set, Union

from .evidence import EvidenceCollector, SecurityError, canonicalize_json
from .schemas import (
    Conclusion,
    ConclusionStatus,
    FailedApproach,
    Finding,
    FindingSeverity,
    Hypothesis,
    HypothesisStatus,
    InvalidStateTransitionError,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
    _current_iso_utc,
    _validate_non_empty_str,
    _validate_safe_identifier,
)


class SessionError(Exception):
    """Base exception for session state errors."""
    pass


class SessionSecurityError(SessionError, SecurityError):
    """Raised when path traversal, symlink violations, or unauthorized paths are detected."""
    pass


class SessionValidationError(SessionError, ValidationError):
    """Raised when session data or scientific workflow validation fails."""
    pass


class ApproachAlreadyFailedError(SessionValidationError):
    """Raised when attempting to execute a safe test that previously failed."""
    pass


SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
EVIDENCE_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _validate_session_id(session_id: Any) -> str:
    """Validate that session_id is a safe, strictly constrained identifier."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise SessionValidationError("Field 'session_id' must be a non-empty string")
    cleaned = session_id.strip()

    forbidden = {"\x00", "\n", "\r", "/", "\\", ".."}
    for f in forbidden:
        if f in cleaned:
            raise SessionSecurityError(f"Session ID contains illegal character or sequence: {f}")

    if any(ord(c) < 32 for c in cleaned):
        raise SessionSecurityError("Session ID contains control characters")

    if not SESSION_ID_PATTERN.fullmatch(cleaned):
        raise SessionSecurityError(
            f"Invalid session ID '{cleaned}'. Must be 1-64 alphanumeric characters, underscores, or hyphens."
        )

    return cleaned


def _validate_safe_session_path(session_file: Path, expected_dir: Path) -> Path:
    """Ensure session file is strictly located inside expected_dir and not a symlink."""
    target_resolved = session_file.resolve()
    parent_resolved = expected_dir.resolve()

    if not target_resolved.is_relative_to(parent_resolved):
        raise SessionSecurityError(f"Path traversal detected: {session_file} is outside {expected_dir}")

    if session_file.is_symlink():
        raise SessionSecurityError(f"Symlinks are prohibited for session files: {session_file}")

    curr = session_file.parent
    while curr != curr.parent:
        if curr.is_symlink():
            raise SessionSecurityError(f"Symlink in path hierarchy prohibited: {curr}")
        if curr == parent_resolved:
            break
        curr = curr.parent

    # Evidence directory guard: ensure session file does not overwrite or collide with evidence artifacts
    evidence_base = (Path.home() / "koth-ai" / "evidence").resolve()
    if target_resolved.is_relative_to(evidence_base):
        raise SessionSecurityError(
            f"Prohibited: session file path {session_file} cannot reside in evidence directory {evidence_base}"
        )

    return session_file


class Session:
    """Manages the full lifecycle and scientific workflow of an authorized KOTH session."""

    def __init__(
        self,
        session_id: str,
        active_target: str,
        configuration_snapshot: Optional[Dict[str, Any]] = None,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        auto_save: bool = False,
    ):
        self.session_id = _validate_session_id(session_id)
        self.active_target = _validate_safe_identifier(active_target, "active_target")
        self.configuration_snapshot = dict(configuration_snapshot or {})
        
        if sessions_dir is None:
            sessions_dir = Path.home() / "koth-ai" / "sessions"
        self.sessions_dir = Path(sessions_dir).resolve()
        
        self.evidence_collector = evidence_collector
        self.start_time = start_time or _current_iso_utc()
        self.end_time = end_time
        self.auto_save = auto_save

        # Scientific workflow registries (insertion-ordered mapping by entity ID)
        self._observations: Dict[str, Observation] = {}
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._safe_tests: Dict[str, SafeTest] = {}
        self._test_results: Dict[str, TestResult] = {}
        self._conclusions: Dict[str, Conclusion] = {}
        self._findings: Dict[str, Finding] = {}
        self._failed_approaches: List[FailedApproach] = []

    # Read-only collection properties
    @property
    def observations(self) -> List[Observation]:
        return list(self._observations.values())

    @property
    def hypotheses(self) -> List[Hypothesis]:
        return list(self._hypotheses.values())

    @property
    def safe_tests(self) -> List[SafeTest]:
        return list(self._safe_tests.values())

    @property
    def test_results(self) -> List[TestResult]:
        return list(self._test_results.values())

    @property
    def conclusions(self) -> List[Conclusion]:
        return list(self._conclusions.values())

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings.values())

    @property
    def failed_approaches(self) -> List[FailedApproach]:
        return list(self._failed_approaches)

    # Lookup helpers
    def get_observation(self, observation_id: str) -> Observation:
        if observation_id not in self._observations:
            raise KeyError(f"Observation '{observation_id}' not found in session")
        return self._observations[observation_id]

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis:
        if hypothesis_id not in self._hypotheses:
            raise KeyError(f"Hypothesis '{hypothesis_id}' not found in session")
        return self._hypotheses[hypothesis_id]

    def get_safe_test(self, test_id: str) -> SafeTest:
        if test_id not in self._safe_tests:
            raise KeyError(f"SafeTest '{test_id}' not found in session")
        return self._safe_tests[test_id]

    def get_test_result(self, result_id: str) -> TestResult:
        if result_id not in self._test_results:
            raise KeyError(f"TestResult '{result_id}' not found in session")
        return self._test_results[result_id]

    def get_conclusion(self, conclusion_id: str) -> Conclusion:
        if conclusion_id not in self._conclusions:
            raise KeyError(f"Conclusion '{conclusion_id}' not found in session")
        return self._conclusions[conclusion_id]

    def get_finding(self, finding_id: str) -> Finding:
        if finding_id not in self._findings:
            raise KeyError(f"Finding '{finding_id}' not found in session")
        return self._findings[finding_id]

    def get_failed_approach(self, approach_id: str) -> Optional[FailedApproach]:
        for fa in self._failed_approaches:
            if fa.approach_id == approach_id:
                return fa
        return None

    # Step 1: Observation
    def add_observation(
        self,
        observation_id: str,
        evidence_ref: str,
        description: str,
        target: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Observation:
        """Add an observation backed by an immutable evidence record."""
        obs_id = _validate_safe_identifier(observation_id, "observation_id")
        if obs_id in self._observations:
            raise SessionValidationError(f"Observation ID '{obs_id}' already exists in session")

        ev_ref = _validate_safe_identifier(evidence_ref, "evidence_ref")
        if not EVIDENCE_HASH_PATTERN.fullmatch(ev_ref):
            raise SessionValidationError(
                f"Field 'evidence_ref' ({ev_ref}) must be a 64-character lowercase hex SHA-256 hash"
            )

        if self.evidence_collector is not None:
            self.evidence_collector.verify_evidence(ev_ref, raise_on_error=True)

        tgt = target or self.active_target
        if tgt != self.active_target:
            raise SessionValidationError(
                f"Observation target '{tgt}' does not match active session target '{self.active_target}'"
            )

        obs = Observation(
            observation_id=obs_id,
            evidence_ref=ev_ref,
            timestamp=timestamp or _current_iso_utc(),
            target=tgt,
            description=description,
            attributes=attributes or {},
        )
        self._observations[obs_id] = obs
        if self.auto_save:
            self.save()
        return obs

    # Step 2: Hypothesis
    def add_hypothesis(
        self,
        hypothesis_id: str,
        based_on_observations: List[str],
        claim: str,
    ) -> Hypothesis:
        """Formulate a new testable hypothesis based on existing observations."""
        hyp_id = _validate_safe_identifier(hypothesis_id, "hypothesis_id")
        if hyp_id in self._hypotheses:
            raise SessionValidationError(f"Hypothesis ID '{hyp_id}' already exists in session")

        if not isinstance(based_on_observations, list) or not based_on_observations:
            raise SessionValidationError("Field 'based_on_observations' must be a non-empty list of observation IDs")

        for obs_id in based_on_observations:
            if obs_id not in self._observations:
                raise SessionValidationError(
                    f"Observation '{obs_id}' referenced by hypothesis does not exist in session"
                )

        hyp = Hypothesis(
            hypothesis_id=hyp_id,
            based_on_observations=list(based_on_observations),
            claim=claim,
            status=HypothesisStatus.PROPOSED.value,
            created_at=_current_iso_utc(),
            updated_at=_current_iso_utc(),
        )
        self._hypotheses[hyp_id] = hyp
        if self.auto_save:
            self.save()
        return hyp

    def transition_hypothesis(
        self,
        hypothesis_id: str,
        new_status: Union[str, HypothesisStatus],
        reason: Optional[str] = None,
    ) -> Hypothesis:
        """Explicitly transition a hypothesis state according to lifecycle rules."""
        if hypothesis_id not in self._hypotheses:
            raise SessionValidationError(f"Hypothesis '{hypothesis_id}' not found in session")

        hyp = self._hypotheses[hypothesis_id]
        hyp.transition_to(new_status)
        if self.auto_save:
            self.save()
        return hyp

    # Step 3: Safe Test
    def add_safe_test(
        self,
        test_id: str,
        hypothesis_id: str,
        tool: str,
        safety_justification: str,
        expected_outcome: str,
        parameters: Optional[Dict[str, Any]] = None,
        allow_failed_repeat: bool = False,
    ) -> SafeTest:
        """Plan a strictly bounded safe test for a hypothesis."""
        t_id = _validate_safe_identifier(test_id, "test_id")
        if t_id in self._safe_tests:
            raise SessionValidationError(f"SafeTest ID '{t_id}' already exists in session")

        if hypothesis_id not in self._hypotheses:
            raise SessionValidationError(f"Hypothesis '{hypothesis_id}' not found in session")

        hyp = self._hypotheses[hypothesis_id]

        # Prevent testing terminal hypotheses
        if hyp.status in (HypothesisStatus.VALIDATED.value, HypothesisStatus.REFUTED.value, HypothesisStatus.ABANDONED.value):
            raise SessionValidationError(
                f"Cannot add safe test to hypothesis '{hypothesis_id}' in terminal status '{hyp.status}'"
            )

        params = dict(parameters or {})

        # Prevent repeating known failed approaches unless explicitly overridden
        if not allow_failed_repeat and self.is_approach_failed(tool=tool, parameters=params):
            fa = self.get_failed_approach_by_signature(tool=tool, parameters=params)
            reason_str = fa.reason if fa else "Prior test failed"
            knowledge_str = fa.negative_knowledge if fa else "Avoid repeating failed approaches."
            raise ApproachAlreadyFailedError(
                f"Approach with tool '{tool}' and parameters {params} has already failed on target "
                f"'{self.active_target}': {reason_str}. Reusable negative knowledge: {knowledge_str}"
            )

        # Transition hypothesis to testing if currently proposed
        if hyp.status == HypothesisStatus.PROPOSED.value:
            hyp.transition_to(HypothesisStatus.TESTING)

        safe_test = SafeTest(
            test_id=t_id,
            hypothesis_id=hypothesis_id,
            tool=tool,
            safety_justification=safety_justification,
            expected_outcome=expected_outcome,
            parameters=params,
            created_at=_current_iso_utc(),
        )
        self._safe_tests[t_id] = safe_test
        if self.auto_save:
            self.save()
        return safe_test

    # Step 4: Test Result
    def record_test_result(
        self,
        result_id: str,
        test_id: str,
        evidence_ref: str,
        status: Union[str, TestStatus],
        summary: str,
        timestamp: Optional[str] = None,
        failure_reason: Optional[str] = None,
        negative_knowledge: Optional[str] = None,
    ) -> TestResult:
        """Record the outcome of a safe test linked to immutable evidence."""
        r_id = _validate_safe_identifier(result_id, "result_id")
        if r_id in self._test_results:
            raise SessionValidationError(f"TestResult ID '{r_id}' already exists in session")

        if test_id not in self._safe_tests:
            raise SessionValidationError(f"SafeTest '{test_id}' not found in session")

        ev_ref = _validate_safe_identifier(evidence_ref, "evidence_ref")
        if not EVIDENCE_HASH_PATTERN.fullmatch(ev_ref):
            raise SessionValidationError(
                f"Field 'evidence_ref' ({ev_ref}) must be a 64-character lowercase hex SHA-256 hash"
            )

        if self.evidence_collector is not None:
            self.evidence_collector.verify_evidence(ev_ref, raise_on_error=True)

        stat_str = status.value if isinstance(status, TestStatus) else status
        valid_statuses = {s.value for s in TestStatus}
        if stat_str not in valid_statuses:
            raise SessionValidationError(f"Invalid TestResult status '{stat_str}'. Expected one of {valid_statuses}")

        test_result = TestResult(
            result_id=r_id,
            test_id=test_id,
            evidence_ref=ev_ref,
            status=stat_str,
            summary=summary,
            timestamp=timestamp or _current_iso_utc(),
        )
        self._test_results[r_id] = test_result

        # Mandatory: Failed approach capture for negative knowledge reuse
        if stat_str in (TestStatus.FAILURE.value, TestStatus.ERROR.value):
            safe_test = self._safe_tests[test_id]
            fa_reason = failure_reason or summary
            fa_knowledge = (
                negative_knowledge
                or f"Approach using tool '{safe_test.tool}' failed on target '{self.active_target}': {fa_reason}. Avoid repeating."
            )
            self.record_failed_approach(
                approach_id=f"fa-{r_id}",
                hypothesis_id=safe_test.hypothesis_id,
                test_id=test_id,
                target=self.active_target,
                tool=safe_test.tool,
                parameters=safe_test.parameters,
                reason=fa_reason,
                negative_knowledge=fa_knowledge,
                evidence_ref=ev_ref,
                timestamp=test_result.timestamp,
            )

        if self.auto_save:
            self.save()
        return test_result

    # Failed Approaches Section (Mandatory Reusable Negative Knowledge)
    def record_failed_approach(
        self,
        approach_id: str,
        hypothesis_id: str,
        test_id: str,
        target: str,
        tool: str,
        parameters: Dict[str, Any],
        reason: str,
        negative_knowledge: str,
        evidence_ref: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> FailedApproach:
        """Explicitly record a failed approach as reusable negative knowledge."""
        fa_id = _validate_safe_identifier(approach_id, "approach_id")
        if any(fa.approach_id == fa_id for fa in self._failed_approaches):
            raise SessionValidationError(f"FailedApproach ID '{fa_id}' already exists in session")

        if hypothesis_id not in self._hypotheses:
            raise SessionValidationError(f"Hypothesis '{hypothesis_id}' not found in session")

        if test_id not in self._safe_tests:
            raise SessionValidationError(f"SafeTest '{test_id}' not found in session")

        if evidence_ref is not None:
            evidence_ref = _validate_safe_identifier(evidence_ref, "evidence_ref")
            if not EVIDENCE_HASH_PATTERN.fullmatch(evidence_ref):
                raise SessionValidationError("evidence_ref must be a 64-character lowercase hex SHA-256 hash")
            if self.evidence_collector is not None:
                self.evidence_collector.verify_evidence(evidence_ref, raise_on_error=True)

        fa = FailedApproach(
            approach_id=fa_id,
            hypothesis_id=hypothesis_id,
            test_id=test_id,
            target=target,
            tool=tool,
            parameters=dict(parameters),
            reason=reason,
            negative_knowledge=negative_knowledge,
            evidence_ref=evidence_ref,
            timestamp=timestamp or _current_iso_utc(),
        )
        self._failed_approaches.append(fa)
        if self.auto_save:
            self.save()
        return fa

    def is_approach_failed(
        self,
        tool: str,
        parameters: Dict[str, Any],
        target: Optional[str] = None,
    ) -> bool:
        """Check if an identical approach (tool, target, parameters) has previously failed."""
        tgt = target or self.active_target
        param_canonical = canonicalize_json(parameters)
        for fa in self._failed_approaches:
            if fa.tool == tool and fa.target == tgt:
                if canonicalize_json(fa.parameters) == param_canonical:
                    return True
        return False

    def get_failed_approach_by_signature(
        self,
        tool: str,
        parameters: Dict[str, Any],
        target: Optional[str] = None,
    ) -> Optional[FailedApproach]:
        """Retrieve the recorded failed approach matching tool, target, and parameters."""
        tgt = target or self.active_target
        param_canonical = canonicalize_json(parameters)
        for fa in self._failed_approaches:
            if fa.tool == tool and fa.target == tgt:
                if canonicalize_json(fa.parameters) == param_canonical:
                    return fa
        return None

    # Step 5: Conclusion
    def add_conclusion(
        self,
        conclusion_id: str,
        hypothesis_id: str,
        result_refs: List[str],
        status: Union[str, ConclusionStatus],
        rationale: str,
        timestamp: Optional[str] = None,
    ) -> Conclusion:
        """Deduce a conclusion on a hypothesis backed by test results."""
        c_id = _validate_safe_identifier(conclusion_id, "conclusion_id")
        if c_id in self._conclusions:
            raise SessionValidationError(f"Conclusion ID '{c_id}' already exists in session")

        if hypothesis_id not in self._hypotheses:
            raise SessionValidationError(f"Hypothesis '{hypothesis_id}' not found in session")

        hyp = self._hypotheses[hypothesis_id]
        if hyp.status != HypothesisStatus.TESTING.value:
            raise SessionValidationError(
                f"Cannot conclude on hypothesis '{hypothesis_id}' with status '{hyp.status}'. "
                f"Hypothesis must be in 'testing' status."
            )

        if not isinstance(result_refs, list) or not result_refs:
            raise SessionValidationError("Conclusion must reference at least one test result ID")

        # Scientific workflow verification: test results must belong to tests for this hypothesis
        for r_id in result_refs:
            if r_id not in self._test_results:
                raise SessionValidationError(f"Test result '{r_id}' not found in session")
            res = self._test_results[r_id]
            safe_test = self._safe_tests.get(res.test_id)
            if safe_test and safe_test.hypothesis_id != hypothesis_id:
                raise SessionValidationError(
                    f"Test result '{r_id}' belongs to SafeTest '{safe_test.test_id}' for hypothesis "
                    f"'{safe_test.hypothesis_id}', not conclusion hypothesis '{hypothesis_id}'"
                )

        stat_str = status.value if isinstance(status, ConclusionStatus) else status
        valid_statuses = {s.value for s in ConclusionStatus}
        if stat_str not in valid_statuses:
            raise SessionValidationError(f"Invalid Conclusion status '{stat_str}'. Expected one of {valid_statuses}")

        # Auto-transition hypothesis status based on conclusion
        if stat_str == ConclusionStatus.VALIDATED.value:
            hyp.transition_to(HypothesisStatus.VALIDATED)
        elif stat_str == ConclusionStatus.REFUTED.value:
            hyp.transition_to(HypothesisStatus.REFUTED)
        # INCONCLUSIVE keeps hypothesis in TESTING state

        concl = Conclusion(
            conclusion_id=c_id,
            hypothesis_id=hypothesis_id,
            result_refs=list(result_refs),
            status=stat_str,
            rationale=rationale,
            timestamp=timestamp or _current_iso_utc(),
        )
        self._conclusions[c_id] = concl
        if self.auto_save:
            self.save()
        return concl

    # Step 6: Finding
    def add_finding(
        self,
        finding_id: str,
        title: str,
        severity: Union[str, FindingSeverity],
        conclusion_ref: str,
        evidence_chain: Dict[str, Any],
        description: str,
        impact: str,
        remediation: str = "",
        timestamp: Optional[str] = None,
    ) -> Finding:
        """Create a verified security finding from a validated conclusion and evidence chain."""
        f_id = _validate_safe_identifier(finding_id, "finding_id")
        if f_id in self._findings:
            raise SessionValidationError(f"Finding ID '{f_id}' already exists in session")

        if conclusion_ref not in self._conclusions:
            raise SessionValidationError(f"Conclusion '{conclusion_ref}' not found in session")

        concl = self._conclusions[conclusion_ref]
        if concl.status != ConclusionStatus.VALIDATED.value:
            raise SessionValidationError(
                f"Cannot create finding from conclusion '{conclusion_ref}' with status '{concl.status}'. "
                f"Findings require a validated conclusion."
            )

        if not isinstance(evidence_chain, dict):
            raise SessionValidationError("evidence_chain must be a dictionary")

        # Verify evidence chain consistency
        if "conclusion" in evidence_chain and evidence_chain["conclusion"] != conclusion_ref:
            raise SessionValidationError("evidence_chain['conclusion'] does not match conclusion_ref")

        if "hypothesis" in evidence_chain and evidence_chain["hypothesis"] != concl.hypothesis_id:
            raise SessionValidationError("evidence_chain['hypothesis'] does not match conclusion's hypothesis_id")

        if "test" in evidence_chain:
            test_chain_id = evidence_chain["test"]
            if test_chain_id not in self._safe_tests:
                raise SessionValidationError(f"Test '{test_chain_id}' in evidence_chain not found in session")
            if self._safe_tests[test_chain_id].hypothesis_id != concl.hypothesis_id:
                raise SessionValidationError(f"Test '{test_chain_id}' does not test hypothesis '{concl.hypothesis_id}'")

        if "result" in evidence_chain:
            res_chain_id = evidence_chain["result"]
            if res_chain_id not in concl.result_refs:
                raise SessionValidationError(f"Result '{res_chain_id}' is not in conclusion '{conclusion_ref}'")

        if "observation" in evidence_chain:
            obs_chain_id = evidence_chain["observation"]
            hyp = self._hypotheses.get(concl.hypothesis_id)
            if hyp and obs_chain_id not in hyp.based_on_observations:
                raise SessionValidationError(
                    f"Observation '{obs_chain_id}' is not in hypothesis '{concl.hypothesis_id}' based_on_observations"
                )

        sev_str = severity.value if isinstance(severity, FindingSeverity) else severity
        valid_severities = {s.value for s in FindingSeverity}
        if sev_str not in valid_severities:
            raise SessionValidationError(f"Invalid Finding severity '{sev_str}'. Expected one of {valid_severities}")

        finding = Finding(
            finding_id=f_id,
            title=title,
            target=self.active_target,
            severity=sev_str,
            conclusion_ref=conclusion_ref,
            evidence_chain=evidence_chain,
            description=description,
            impact=impact,
            remediation=remediation,
            timestamp=timestamp or _current_iso_utc(),
        )
        self._findings[f_id] = finding
        if self.auto_save:
            self.save()
        return finding

    # Session Lifecycle
    def close(self) -> None:
        """Close session and record end_time."""
        if not self.end_time:
            self.end_time = _current_iso_utc()
        if self.auto_save:
            self.save()

    def end_session(self) -> None:
        """Alias for close()."""
        self.close()

    # Serialization & Atomic Persistence
    def to_dict(self) -> Dict[str, Any]:
        """Convert session state to dictionary."""
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "active_target": self.active_target,
            "configuration_snapshot": self.configuration_snapshot,
            "observations": [obs.to_dict() for obs in self.observations],
            "hypotheses": [hyp.to_dict() for hyp in self.hypotheses],
            "safe_tests": [test.to_dict() for test in self.safe_tests],
            "test_results": [res.to_dict() for res in self.test_results],
            "conclusions": [concl.to_dict() for concl in self.conclusions],
            "findings": [finding.to_dict() for finding in self.findings],
            "failed_approaches": [fa.to_dict() for fa in self.failed_approaches],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize session state to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self) -> Path:
        """Persist session state atomically to sessions/<session_id>.json."""
        _validate_session_id(self.session_id)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        session_file = self.sessions_dir / f"{self.session_id}.json"
        _validate_safe_session_path(session_file, self.sessions_dir)

        payload_bytes = self.to_json(indent=2).encode("utf-8")

        temp_fd, temp_path_str = tempfile.mkstemp(
            dir=str(self.sessions_dir),
            prefix=f".{self.session_id}_",
            suffix=".tmp",
        )
        temp_path = Path(temp_path_str)
        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(payload_bytes)
                f.flush()
                os.fsync(f.fileno())

            os.chmod(temp_path, 0o600)
            os.replace(temp_path, session_file)
        except Exception:
            if temp_path.exists():
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            raise

        return session_file

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
    ) -> "Session":
        """Reconstruct a Session object from a dictionary."""
        for req in ("session_id", "active_target"):
            if req not in data:
                raise SessionValidationError(f"Missing required session field: '{req}'")

        session = cls(
            session_id=data["session_id"],
            active_target=data["active_target"],
            configuration_snapshot=data.get("configuration_snapshot", {}),
            sessions_dir=sessions_dir,
            evidence_collector=evidence_collector,
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            auto_save=False,
        )

        for obs_data in data.get("observations", []):
            obs = Observation.from_dict(obs_data)
            session._observations[obs.observation_id] = obs

        for hyp_data in data.get("hypotheses", []):
            hyp = Hypothesis.from_dict(hyp_data)
            session._hypotheses[hyp.hypothesis_id] = hyp

        for test_data in data.get("safe_tests", []):
            test = SafeTest.from_dict(test_data)
            session._safe_tests[test.test_id] = test

        for res_data in data.get("test_results", []):
            res = TestResult.from_dict(res_data)
            session._test_results[res.result_id] = res

        for concl_data in data.get("conclusions", []):
            concl = Conclusion.from_dict(concl_data)
            session._conclusions[concl.conclusion_id] = concl

        for finding_data in data.get("findings", []):
            finding = Finding.from_dict(finding_data)
            session._findings[finding.finding_id] = finding

        for fa_data in data.get("failed_approaches", []):
            fa = FailedApproach.from_dict(fa_data)
            session._failed_approaches.append(fa)

        return session

    @classmethod
    def load(
        cls,
        session_id: str,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
    ) -> "Session":
        """Load and validate a persisted session by session_id."""
        cleaned_id = _validate_session_id(session_id)
        s_dir = Path(sessions_dir or (Path.home() / "koth-ai" / "sessions")).resolve()
        session_file = s_dir / f"{cleaned_id}.json"
        _validate_safe_session_path(session_file, s_dir)

        if not session_file.exists():
            raise FileNotFoundError(f"Session file not found: {session_file}")

        with open(session_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise SessionValidationError(f"Malformed session file '{session_file}': {exc}")

        return cls.from_dict(data, sessions_dir=s_dir, evidence_collector=evidence_collector)

    @classmethod
    def create(
        cls,
        session_id: str,
        active_target: str,
        configuration_snapshot: Optional[Dict[str, Any]] = None,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
        auto_save: bool = False,
    ) -> "Session":
        """Factory method to create a new session."""
        sess = cls(
            session_id=session_id,
            active_target=active_target,
            configuration_snapshot=configuration_snapshot,
            sessions_dir=sessions_dir,
            evidence_collector=evidence_collector,
            auto_save=auto_save,
        )
        if auto_save:
            sess.save()
        return sess


class SessionManager:
    """Manages session lifecycle, listing, and storage directory operations."""

    def __init__(
        self,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
    ):
        if sessions_dir is None:
            sessions_dir = Path.home() / "koth-ai" / "sessions"
        self.sessions_dir = Path(sessions_dir).resolve()
        self.evidence_collector = evidence_collector
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create_session(
        self,
        session_id: str,
        active_target: str,
        configuration_snapshot: Optional[Dict[str, Any]] = None,
        auto_save: bool = False,
    ) -> Session:
        """Create a new managed session."""
        return Session.create(
            session_id=session_id,
            active_target=active_target,
            configuration_snapshot=configuration_snapshot,
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
            auto_save=auto_save,
        )

    def load_session(self, session_id: str) -> Session:
        """Load an existing session from the managed sessions directory."""
        return Session.load(
            session_id=session_id,
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

    def list_sessions(self) -> List[str]:
        """List all valid session IDs stored under the managed sessions directory."""
        if not self.sessions_dir.exists():
            return []
        sessions = []
        for p in sorted(self.sessions_dir.glob("*.json")):
            if p.is_file() and not p.name.startswith("."):
                sessions.append(p.stem)
        return sessions

    def session_exists(self, session_id: str) -> bool:
        """Check whether a session exists."""
        try:
            cleaned = _validate_session_id(session_id)
            target = self.sessions_dir / f"{cleaned}.json"
            return target.is_file()
        except Exception:
            return False
