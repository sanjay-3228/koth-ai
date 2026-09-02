"""Reconnaissance Agent for authorized KOTH challenges.

Enforces:
- Pure reasoning and planning; no direct arbitrary shell execution.
- Strict scientific loop: Observation -> Hypothesis -> Safe Test -> Execution -> Evidence -> Result -> Conclusion.
- Authoritative target registry enforcement via config/targets.yaml and targets/allowlist.yaml.
- Rejection of unregistered targets and arbitrary commands.
- Never repeats known failed approaches.
"""

import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

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
from core.session import Session, SessionManager

from .planner import ReconPlanner
from .tools import (
    ArbitraryCommandError,
    ExecutionAdapter,
    HttpProbeTool,
    MockExecutionAdapter,
    PolicyViolationError,
    ToolError,
    ToolRegistry,
)


from gateway.orchestrator import DisabledTargetError, GatewaySecurityError, UnregisteredTargetError

ReconError = GatewaySecurityError


class TargetRegistry:
    """Authoritative loader and validator for target configurations."""

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        allowlist_path: Optional[Union[str, Path]] = None,
    ):
        base_dir = Path.home() / "koth-ai"
        self.config_path = Path(config_path or (base_dir / "config" / "targets.yaml")).resolve()
        self.allowlist_path = Path(allowlist_path or (base_dir / "targets" / "allowlist.yaml")).resolve()
        self.targets: Dict[str, Dict[str, Any]] = {}
        self.blocked_networks: List[str] = ["127.0.0.0/8", "169.254.0.0/16"]
        self._load_configurations()

    def _parse_yaml_file(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            if HAVE_YAML:
                return yaml.safe_load(f) or {}
            # Minimal fallback parser if PyYAML is unavailable
            content = f.read()
            return json.loads(content)

    def _load_configurations(self) -> None:
        # 1. Load allowlist
        if self.allowlist_path.exists():
            al_data = self._parse_yaml_file(self.allowlist_path)
            self.blocked_networks = al_data.get("blocked_networks", self.blocked_networks)

        # 2. Load targets
        if self.config_path.exists():
            cfg_data = self._parse_yaml_file(self.config_path)
            for t in cfg_data.get("targets", []):
                t_id = t.get("id")
                if t_id:
                    self.targets[t_id] = {
                        "id": t_id,
                        "container": t.get("container", f"koth-{t_id}"),
                        "protocol": t.get("protocol", "http"),
                        "port": int(t.get("port", 8080)),
                        "enabled": t.get("enabled", False),
                        "network": cfg_data.get("network", "koth-lab"),
                        "ip": t.get("ip"),
                    }

    def get_target(self, target_id: str) -> Dict[str, Any]:
        """Retrieve authorized target or raise UnregisteredTargetError / DisabledTargetError."""
        if not target_id or not isinstance(target_id, str):
            raise UnregisteredTargetError("Target ID must be a non-empty string")

        if target_id not in self.targets:
            raise UnregisteredTargetError(
                f"Target '{target_id}' is not registered in authoritative targets registry: {self.config_path}"
            )

        target = self.targets[target_id]
        if not target.get("enabled", False):
            raise DisabledTargetError(f"Target '{target_id}' is disabled in targets registry")

        return dict(target)

    def list_targets(self) -> List[str]:
        return sorted(list(self.targets.keys()))

    def is_target_allowlisted(self, target_id: str) -> bool:
        return target_id in self.targets and self.targets[target_id].get("enabled", False)


class ReconAgent:
    """Reasoning and planning reconnaissance agent operating strictly within security policies."""

    def __init__(
        self,
        target_id: str,
        targets_config_path: Optional[Union[str, Path]] = None,
        allowlist_path: Optional[Union[str, Path]] = None,
        sessions_dir: Optional[Union[str, Path]] = None,
        evidence_dir: Optional[Union[str, Path]] = None,
        execution_adapter: Optional[ExecutionAdapter] = None,
        session_id: Optional[str] = None,
        auto_init_target_obs: bool = True,
    ):
        # 1. Authoritative target registry validation
        self.target_registry = TargetRegistry(
            config_path=targets_config_path,
            allowlist_path=allowlist_path,
        )
        self.target_info = self.target_registry.get_target(target_id)
        self.target_id = self.target_info["id"]

        # 2. Immutable evidence layer
        self.evidence_collector = EvidenceCollector(evidence_dir=evidence_dir)

        # 3. Session state management
        base_dir = Path.home() / "koth-ai"
        self.sessions_dir = Path(sessions_dir or (base_dir / "sessions")).resolve()
        self.session_manager = SessionManager(
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

        sess_id = session_id or f"recon-{self.target_id}"
        if self.session_manager.session_exists(sess_id):
            self.session = self.session_manager.load_session(sess_id)
        else:
            self.session = self.session_manager.create_session(
                session_id=sess_id,
                active_target=self.target_id,
                configuration_snapshot={
                    "target_info": self.target_info,
                    "agent": "ReconAgent",
                    "mode": "authorized-lab-only",
                },
                auto_save=True,
            )

        # 4. Tool Registry and Execution Adapter
        self.tool_registry = ToolRegistry()
        self.execution_adapter = execution_adapter or MockExecutionAdapter()

        # 5. Reasoning Planner
        self.planner = ReconPlanner()

        # Step counter
        self._step_counter = len(self.session.safe_tests)

        # Baseline target observation if new session
        if auto_init_target_obs and not self.session.observations:
            self._initialize_baseline_observation()

    def _initialize_baseline_observation(self) -> None:
        """Record initial authoritative target configuration observation."""
        init_payload = {
            "source": "authoritative_registry",
            "target": self.target_info,
            "timestamp": _current_iso_utc(),
        }
        ev = self.evidence_collector.store_evidence(
            source_tool="target_registry",
            target=self.target_id,
            payload=init_payload,
        )
        proto = self.target_info.get("protocol", "http")
        port_num = self.target_info.get("port", 8080)
        self.session.add_observation(
            observation_id=f"obs-{self.target_id}-init",
            evidence_ref=ev.evidence_id,
            description=f"Target '{self.target_id}' registered on protocol {proto} port {port_num}",
            attributes={
                "target": self.target_id,
                "protocol": proto,
                "port": port_num,
            },
        )

    def execute_command(self, *args, **kwargs) -> Any:
        """Explicitly reject arbitrary shell execution."""
        raise ArbitraryCommandError("ReconAgent is a planning component and does not support arbitrary shell command execution.")

    def step(self) -> Optional[Dict[str, Any]]:
        """Execute one complete scientific loop iteration.
        
        Observation -> Hypothesis -> Safe Test -> Gateway Execution -> Evidence -> Test Result -> Conclusion
        """
        self._step_counter += 1
        step_id = f"step-{self._step_counter:03d}"

        # 1. Propose hypothesis if none are currently open (PROPOSED or TESTING)
        active_hyp = next(
            (h for h in self.session.hypotheses if h.status in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value)),
            None,
        )

        target_path_hint = None
        if not active_hyp:
            prop = self.planner.propose_hypothesis(self.session, self.target_info)
            if not prop:
                # No more hypotheses can be derived from current observations
                return None

            hyp_id = f"hyp-{self.target_id}-{self._step_counter:03d}"
            active_hyp = self.session.add_hypothesis(
                hypothesis_id=hyp_id,
                based_on_observations=prop["based_on_observations"],
                claim=prop["claim"],
            )
            target_path_hint = prop.get("target_path")

        # 2. Propose Safe Test for active hypothesis
        test_plan = self.planner.propose_safe_test(
            session=self.session,
            hypothesis=active_hyp,
            target_info=self.target_info,
            target_path=target_path_hint,
        )

        if not test_plan:
            # Cannot plan a safe test for this hypothesis (e.g. approaches already failed)
            # Transition hypothesis to abandoned so we don't get stuck
            if active_hyp.status == HypothesisStatus.PROPOSED.value:
                self.session.transition_hypothesis(active_hyp.hypothesis_id, HypothesisStatus.ABANDONED)
            return {
                "step_id": step_id,
                "action": "hypothesis_abandoned",
                "hypothesis_id": active_hyp.hypothesis_id,
                "reason": "Safe test could not be planned or approaches have already failed",
            }

        # 3. Add SafeTest to session (auto-transitions PROPOSED -> TESTING)
        test_id = f"test-{self.target_id}-{self._step_counter:03d}"
        safe_test = self.session.add_safe_test(
            test_id=test_id,
            hypothesis_id=active_hyp.hypothesis_id,
            tool=test_plan["tool"],
            safety_justification=test_plan["safety_justification"],
            expected_outcome=test_plan["expected_outcome"],
            parameters=test_plan["parameters"],
            allow_failed_repeat=False,
        )

        # 4. Execute test strictly via registered tool and controlled execution interface
        tool = self.tool_registry.get(safe_test.tool)
        execution_result = tool.execute(
            target=self.target_info,
            params=safe_test.parameters,
            adapter=self.execution_adapter,
        )

        # 5. Record raw output as immutable evidence
        ev = self.evidence_collector.store_evidence(
            source_tool=tool.name,
            target=self.target_id,
            payload=execution_result,
        )

        # 6. Record TestResult linked to evidence
        is_success = execution_result.get("success", False)
        status = TestStatus.SUCCESS.value if is_success else TestStatus.FAILURE.value
        summary = (
            f"HTTP {execution_result.get('status_code')} response for path '{safe_test.parameters.get('path')}'"
            if "status_code" in execution_result
            else execution_result.get("error", "Execution failed")
        )

        res_id = f"res-{self.target_id}-{self._step_counter:03d}"
        test_result = self.session.record_test_result(
            result_id=res_id,
            test_id=safe_test.test_id,
            evidence_ref=ev.evidence_id,
            status=status,
            summary=summary,
        )

        # 7. Evaluate result with planner and deduce conclusion
        eval_outcome = self.planner.evaluate_result(
            session=self.session,
            safe_test=safe_test,
            test_result=test_result,
            evidence_payload=execution_result,
        )

        concl_id = f"concl-{self.target_id}-{self._step_counter:03d}"
        conclusion = self.session.add_conclusion(
            conclusion_id=concl_id,
            hypothesis_id=active_hyp.hypothesis_id,
            result_refs=[test_result.result_id],
            status=eval_outcome["conclusion_status"],
            rationale=eval_outcome["rationale"],
        )

        # 8. Record any newly discovered facts as observations
        new_obs_list = []
        for i, obs_info in enumerate(eval_outcome.get("new_observations", []), start=1):
            obs_id = f"obs-{self.target_id}-{self._step_counter:03d}-{i}"
            new_obs = self.session.add_observation(
                observation_id=obs_id,
                evidence_ref=ev.evidence_id,
                description=obs_info["description"],
                attributes=obs_info.get("attributes", {}),
            )
            new_obs_list.append(new_obs.observation_id)

        # 9. Atomic session persistence
        self.session.save()

        return {
            "step_id": step_id,
            "hypothesis_id": active_hyp.hypothesis_id,
            "test_id": safe_test.test_id,
            "result_id": test_result.result_id,
            "conclusion_id": conclusion.conclusion_id,
            "conclusion_status": conclusion.status,
            "evidence_ref": ev.evidence_id,
            "new_observations": new_obs_list,
        }

    def run(self, max_steps: int = 10) -> List[Dict[str, Any]]:
        """Execute scientific reconnaissance loop until completion or max_steps."""
        history = []
        for _ in range(max_steps):
            step_record = self.step()
            if not step_record:
                break
            history.append(step_record)
        return history
