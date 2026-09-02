"""Bounded Autonomous Research Controller for authorized KOTH challenges.

Enforces:
1. Pure orchestration of existing safe components:
   TargetRegistry -> Session -> ReconPlanner -> GatewayOrchestrator -> Evidence.
2. The Gateway remains the FINAL AUTHORITY.
3. Controller does NOT execute shell commands, docker commands, or subprocesses.
4. Controller does NOT accept arbitrary commands or AI-supplied IPs.
5. Strict bounded execution:
   - max_tests
   - max_duration_seconds
   - max_consecutive_failures
   - max_repeated_observations
   - stop_on_finding
   - allowed_tools
6. State persistence and seamless resume:
   - Preserves previous hypotheses, failed approaches, evidence references.
   - Safe to stop and restart without repeating failed approaches.
7. Full observability and auditability.
"""

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

from core.evidence import EvidenceCollector, SecurityError
from core.schemas import (
    Conclusion,
    ConclusionStatus,
    Hypothesis,
    HypothesisStatus,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
    _current_iso_utc,
)
from core.session import ApproachAlreadyFailedError, Session, SessionManager
from gateway.orchestrator import (
    AISuppliedIPError,
    ArbitraryCommandError,
    DisabledTargetError,
    GatewayOrchestrator,
    GatewaySecurityError,
    InvalidMethodError,
    MaliciousParameterError,
    RepeatedFailedApproachError,
    UnauthorizedToolError,
    UnregisteredTargetError,
    execute_safe_test,
)
from .recon.agent import TargetRegistry
from .recon.planner import ReconPlanner


class ControllerError(Exception):
    """Base exception for controller errors."""
    pass


@dataclass
class ResearchLimits:
    """Configurable boundaries for autonomous research execution."""
    max_tests: int = 10
    max_duration_seconds: float = 60.0
    max_consecutive_failures: int = 3
    max_repeated_observations: int = 5
    stop_on_finding: bool = False
    allowed_tools: Set[str] = field(default_factory=lambda: {"http_probe"})

    def validate(self) -> None:
        if self.max_tests <= 0:
            raise ValidationError("max_tests must be positive")
        if self.max_duration_seconds <= 0:
            raise ValidationError("max_duration_seconds must be positive")
        if self.max_consecutive_failures <= 0:
            raise ValidationError("max_consecutive_failures must be positive")
        if not self.allowed_tools or not isinstance(self.allowed_tools, (set, list)):
            raise ValidationError("allowed_tools must be a non-empty collection")


@dataclass
class ResearchRunSummary:
    """Structured summary returned upon controller completion."""
    session_id: str
    target_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    tests_executed: int
    tests_succeeded: int
    tests_failed: int
    tests_rejected: int
    consecutive_failures: int
    findings_count: int
    stop_reason: str
    evidence_refs: List[str] = field(default_factory=list)
    hypotheses_evaluated: int = 0
    conclusions_count: int = 0

    @property
    def failures(self) -> int:
        return self.tests_failed

    @property
    def findings(self) -> int:
        return self.findings_count

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["failures"] = self.tests_failed
        d["findings"] = self.findings_count
        return d


class ResearchController:
    """Deterministic bounded autonomous controller enforcing strict safety boundaries."""

    def __init__(
        self,
        targets_config_path: Optional[Union[str, Path]] = None,
        allowlist_path: Optional[Union[str, Path]] = None,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_dir: Optional[Union[str, Path]] = None,
        audit_log_path: Optional[Union[str, Path]] = None,
        orchestrator: Optional[GatewayOrchestrator] = None,
        target_registry: Optional[TargetRegistry] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
        planner: Optional[ReconPlanner] = None,
    ):
        base_dir = Path.home() / "koth-ai"
        self.evidence_collector = evidence_collector or EvidenceCollector(evidence_dir=evidence_dir)
        self.sessions_dir = Path(sessions_dir or (base_dir / "sessions")).resolve()
        self.session_manager = SessionManager(
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )
        self.target_registry = target_registry or TargetRegistry(
            config_path=targets_config_path,
            allowlist_path=allowlist_path,
        )
        self.orchestrator = orchestrator or GatewayOrchestrator(
            config_path=targets_config_path,
            allowlist_path=allowlist_path,
            evidence_collector=self.evidence_collector,
            audit_log_path=audit_log_path,
        )
        self.planner = planner or ReconPlanner()
        self.audit_log_path = Path(audit_log_path or (base_dir / "logs" / "controller.jsonl")).resolve()
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def execute_command(self, *args, **kwargs) -> Any:
        """Strictly forbidden: controller must never execute arbitrary shell commands."""
        raise ArbitraryCommandError(
            "ResearchController is a bounded reasoning component and does not support arbitrary shell command execution."
        )

    def _audit_action(self, event: Dict[str, Any]) -> None:
        record = {
            "timestamp": time.time(),
            **event,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _seed_baseline_observation(self, session: Session, target_info: Dict[str, Any]) -> None:
        if session.observations:
            return
        target_id = target_info["id"]
        ev = self.evidence_collector.store_evidence(
            source_tool="target_registry",
            target=target_id,
            payload={
                "source": "authoritative_registry",
                "target": target_info,
                "timestamp": _current_iso_utc(),
            },
        )
        session.add_observation(
            observation_id=f"obs-{target_id}-init",
            evidence_ref=ev.evidence_id,
            description=f"Target '{target_id}' registered on {target_info['protocol']} port {target_info['port']}",
            attributes={
                "target": target_id,
                "protocol": target_info["protocol"],
                "port": target_info["port"],
            },
        )
        session.save()

    def run(
        self,
        session: Union[Session, str],
        target_id: Optional[str] = None,
        limits: Optional[ResearchLimits] = None,
    ) -> ResearchRunSummary:
        start_mono = time.monotonic()
        start_iso = _current_iso_utc()
        limits = limits or ResearchLimits()
        limits.validate()

        # 1. Resolve Session
        if isinstance(session, str):
            sess_id = session
            if not target_id:
                raise ValidationError("target_id must be provided when session is passed as string ID")
            if self.session_manager.session_exists(sess_id):
                active_session = self.session_manager.load_session(sess_id)
            else:
                active_session = self.session_manager.create_session(
                    session_id=sess_id,
                    active_target=target_id,
                    configuration_snapshot={"agent": "ResearchController", "mode": "authorized-lab-only"},
                )
        elif isinstance(session, Session):
            active_session = session
            sess_id = active_session.session_id
            if target_id and active_session.active_target != target_id:
                raise ValidationError(f"Session target '{active_session.active_target}' does not match target_id '{target_id}'")
        else:
            raise ValidationError("session must be a Session instance or string session_id")

        active_target_id = target_id or active_session.active_target

        # 2. Authoritative Target Validation
        target_info = self.target_registry.get_target(active_target_id)
        if not target_info.get("enabled", False):
            raise DisabledTargetError(f"Target '{active_target_id}' is disabled in authoritative configuration")

        # 3. Seed initial observation if new session
        self._seed_baseline_observation(active_session, target_info)

        tests_executed = 0
        tests_succeeded = 0
        tests_failed = 0
        tests_rejected = 0
        consecutive_failures = 0
        consecutive_no_new_obs = 0
        evidence_refs: List[str] = []
        hypotheses_evaluated = 0
        conclusions_count = 0
        stop_reason = "completed"
        rejected_test_ids: Set[str] = set()

        prev_obs_count = len(active_session.observations)
        step_index = len(active_session.safe_tests)

        while True:
            # Check boundaries before step
            now_mono = time.monotonic()
            if (now_mono - start_mono) >= limits.max_duration_seconds:
                stop_reason = "max_duration"
                break

            if (tests_executed + tests_rejected) >= limits.max_tests:
                stop_reason = "max_tests"
                break

            if consecutive_failures >= limits.max_consecutive_failures:
                stop_reason = "max_consecutive_failures"
                break

            if limits.stop_on_finding and len(active_session.findings) > 0:
                stop_reason = "stop_on_finding"
                break

            if consecutive_no_new_obs >= limits.max_repeated_observations:
                stop_reason = "max_repeated_observations"
                break

            step_index += 1
            step_id = f"step-{step_index:03d}"

            # Check for existing unexecuted SafeTest in session
            pending_test = next(
                (t for t in active_session.safe_tests if t.test_id not in rejected_test_ids and not any(r.test_id == t.test_id for r in active_session.test_results)),
                None,
            )

            if pending_test:
                safe_test = pending_test
                active_hyp = active_session.get_hypothesis(safe_test.hypothesis_id)
                tool_name = safe_test.tool
                if tool_name not in limits.allowed_tools:
                    tests_rejected += 1
                    self._audit_action({
                        "session_id": sess_id,
                        "target_id": active_target_id,
                        "action": "tool_rejected_by_limits",
                        "tool": tool_name,
                        "allowed_tools": list(limits.allowed_tools),
                    })
                    raise UnauthorizedToolError(f"Tool '{tool_name}' is not permitted by controller limits: {limits.allowed_tools}")
            else:
                # Step A: Find or propose hypothesis
                active_hyp = next(
                    (h for h in active_session.hypotheses if h.status in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value)),
                    None,
                )

                target_path_hint = None
                if not active_hyp:
                    prop = self.planner.propose_hypothesis(active_session, target_info)
                    if not prop:
                        stop_reason = "no_more_hypotheses"
                        break

                    hyp_id = f"hyp-{active_target_id}-{step_index:03d}"
                    active_hyp = active_session.add_hypothesis(
                        hypothesis_id=hyp_id,
                        based_on_observations=prop["based_on_observations"],
                        claim=prop["claim"],
                    )
                    target_path_hint = prop.get("target_path")

                # Step B: Propose safe test
                test_plan = self.planner.propose_safe_test(
                    session=active_session,
                    hypothesis=active_hyp,
                    target_info=target_info,
                    target_path=target_path_hint,
                )

                if not test_plan:
                    if active_hyp.status in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value):
                        active_session.transition_hypothesis(active_hyp.hypothesis_id, HypothesisStatus.ABANDONED)
                    prop_check = self.planner.propose_hypothesis(active_session, target_info)
                    if not prop_check:
                        stop_reason = "no_more_hypotheses"
                        break
                    continue

                # Step C: Tool limit check
                tool_name = test_plan["tool"]
                if tool_name not in limits.allowed_tools:
                    tests_rejected += 1
                    self._audit_action({
                        "session_id": sess_id,
                        "target_id": active_target_id,
                        "action": "tool_rejected_by_limits",
                        "tool": tool_name,
                        "allowed_tools": list(limits.allowed_tools),
                    })
                    raise UnauthorizedToolError(f"Tool '{tool_name}' is not permitted by controller limits: {limits.allowed_tools}")

                # Step D: Negative knowledge avoidance (never repeat failed approaches)
                if active_session.is_approach_failed(tool_name, test_plan["parameters"], target=active_target_id):
                    self._audit_action({
                        "session_id": sess_id,
                        "target_id": active_target_id,
                        "action": "skipped_failed_approach",
                        "tool": tool_name,
                        "parameters": test_plan["parameters"],
                    })
                    if active_hyp.status in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value):
                        active_session.transition_hypothesis(active_hyp.hypothesis_id, HypothesisStatus.ABANDONED)
                    prop_check = self.planner.propose_hypothesis(active_session, target_info)
                    if not prop_check:
                        stop_reason = "no_more_hypotheses"
                        break
                    continue

                # Step E: Construct SafeTest
                test_id = f"test-{active_target_id}-{step_index:03d}"
                safe_test = active_session.add_safe_test(
                    test_id=test_id,
                    hypothesis_id=active_hyp.hypothesis_id,
                    tool=tool_name,
                    safety_justification=test_plan["safety_justification"],
                    expected_outcome=test_plan["expected_outcome"],
                    parameters=test_plan["parameters"],
                )

            # Step F: Execute SafeTest ONLY through the Gateway Orchestrator
            orch_res = self.orchestrator.execute_safe_test(
                safe_test=safe_test,
                session=active_session,
                evidence_collector=self.evidence_collector,
                raise_on_denial=False,
            )

            if not orch_res.get("allowed", False):
                tests_rejected += 1
                rejected_test_ids.add(safe_test.test_id)
                self._audit_action({
                    "session_id": sess_id,
                    "target_id": active_target_id,
                    "action": "gateway_rejection",
                    "test_id": safe_test.test_id,
                    "reason": orch_res.get("error", "Gateway denied execution"),
                })
                if active_hyp.status in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value):
                    active_session.transition_hypothesis(active_hyp.hypothesis_id, HypothesisStatus.ABANDONED)
                prop_check = self.planner.propose_hypothesis(active_session, target_info)
                if not prop_check:
                    stop_reason = "no_more_hypotheses"
                    break
                continue

            tests_executed += 1
            ev_id = orch_res["evidence_id"]
            evidence_refs.append(ev_id)

            is_success = orch_res["status"] == TestStatus.SUCCESS.value
            if is_success:
                tests_succeeded += 1
                consecutive_failures = 0
            else:
                tests_failed += 1
                consecutive_failures += 1

            # Step G: Evaluate Result and add Conclusion
            test_res = orch_res["test_result"]
            eval_outcome = self.planner.evaluate_result(
                session=active_session,
                safe_test=safe_test,
                test_result=test_res,
                evidence_payload=orch_res["execution_output"],
            )

            concl_id = f"concl-{active_target_id}-{step_index:03d}"
            active_session.add_conclusion(
                conclusion_id=concl_id,
                hypothesis_id=active_hyp.hypothesis_id,
                result_refs=[test_res.result_id],
                status=eval_outcome["conclusion_status"],
                rationale=eval_outcome["rationale"],
            )
            hypotheses_evaluated += 1
            conclusions_count += 1

            # Step H: Add new observations
            new_obs_added = 0
            for i, obs_info in enumerate(eval_outcome.get("new_observations", []), start=1):
                obs_id = f"obs-{active_target_id}-{step_index:03d}-{i}"
                if obs_id not in [o.observation_id for o in active_session.observations]:
                    active_session.add_observation(
                        observation_id=obs_id,
                        evidence_ref=ev_id,
                        description=obs_info["description"],
                        attributes=obs_info.get("attributes", {}),
                    )
                    new_obs_added += 1

            if len(active_session.observations) == prev_obs_count:
                consecutive_no_new_obs += 1
            else:
                consecutive_no_new_obs = 0
                prev_obs_count = len(active_session.observations)

            self._audit_action({
                "session_id": sess_id,
                "target_id": active_target_id,
                "action": "step_completed",
                "test_id": safe_test.test_id,
                "result_id": test_res.result_id,
                "status": orch_res["status"],
                "evidence_ref": ev_id,
            })

            active_session.save()

        end_mono = time.monotonic()
        end_iso = _current_iso_utc()
        duration = round(end_mono - start_mono, 4)

        summary = ResearchRunSummary(
            session_id=sess_id,
            target_id=active_target_id,
            start_time=start_iso,
            end_time=end_iso,
            duration_seconds=duration,
            tests_executed=tests_executed,
            tests_succeeded=tests_succeeded,
            tests_failed=tests_failed,
            tests_rejected=tests_rejected,
            consecutive_failures=consecutive_failures,
            findings_count=len(active_session.findings),
            stop_reason=stop_reason,
            evidence_refs=evidence_refs,
            hypotheses_evaluated=hypotheses_evaluated,
            conclusions_count=conclusions_count,
        )

        self._audit_action({
            "session_id": sess_id,
            "target_id": active_target_id,
            "action": "controller_run_finished",
            "summary": summary.to_dict(),
        })

        return summary

