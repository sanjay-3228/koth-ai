"""
Final Execution Authorization Gate for koth-agent.

Enforces deterministic multi-stage gating before any action execution:
  1. Policy Authorization: SecurityPolicy.authorize(decision)
  2. Registry Authorization: ActionRegistry.resolve() & config.is_action_allowed()
  3. Task Authorization: validate_task_authorization(task, swarm_client)
  4. FINAL Execution Authorization: Execution-time Phase Fence & Kill Switch
  5. Concrete Execution: action.execute(...)

Guarantees:
  - No AI output can bypass the authorization chain.
  - Phase Fence: Outdated tasks from prior epochs or mismatched phases are rejected at execution time.
  - Kill Switch: Global or local kill switches immediately halt execution.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from agent.actions.base import ActionContext, ActionExecutionRecord, BaseAction
from agent.actions.registry import ActionRegistry, HoldAction
from agent.config import Config, load_config
from agent.gemini_client import Decision
from agent.security.policy import AuthorizationResult, RiskLevel, SecurityPolicy
from agent.swarm.models import Phase, Task, TaskStatus

logger = logging.getLogger("koth.security.execution_gate")


@dataclass
class ExecutionGateResult:
    allowed: bool
    reason: str
    stage: str
    risk_level: RiskLevel = RiskLevel.LOW
    action: Optional[BaseAction] = None
    record: Optional[ActionExecutionRecord] = None


class FinalExecutionGate:
    """
    Central gate keeper validating the entire authorization chain
    before any concrete action can touch the system or network.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        security_policy: Optional[SecurityPolicy] = None,
        action_registry: Optional[ActionRegistry] = None,
    ):
        self.config = config or load_config()
        self.security_policy = security_policy or SecurityPolicy(self.config)
        self.action_registry = action_registry or ActionRegistry()

    def verify_and_authorize(
        self,
        decision: Decision,
        context: ActionContext,
        task: Optional[Task] = None,
        swarm_client: Optional[Any] = None,
    ) -> ExecutionGateResult:
        """
        Verify every stage of the authorization chain:
          policy authorization -> registry authorization -> task authorization -> FINAL execution authorization
        """
        # ======================================================================
        # STAGE 1: Policy Authorization
        # ======================================================================
        policy_res: AuthorizationResult = self.security_policy.authorize(decision)
        if not policy_res.allowed:
            logger.warning(
                f"[GATE 1: POLICY REJECTION] Decision {decision.action_type} on {decision.target} rejected: {policy_res.reason}"
            )
            return ExecutionGateResult(
                allowed=False,
                reason=f"Policy authorization rejected: {policy_res.reason}",
                stage="policy_authorization",
                risk_level=policy_res.risk_level,
                action=HoldAction(),
            )

        # ======================================================================
        # STAGE 2: Registry Authorization
        # ======================================================================
        resolved_action = self.action_registry.resolve(
            action_type=decision.action_type,
            target=policy_res.sanitized_target or decision.target,
            details=decision.reasoning,
            fallback_to_hold=False,
            config=self.config,
        )

        action_name = getattr(decision, "action_name", None) or resolved_action.action_name
        if action_name != "hold" and not self.config.is_action_allowed(action_name):
            logger.warning(
                f"[GATE 2: REGISTRY REJECTION] Action '{action_name}' is not in allowed_actions ({self.config.allowed_actions})"
            )
            return ExecutionGateResult(
                allowed=False,
                reason=f"Registry authorization rejected: action '{action_name}' is disallowed",
                stage="registry_authorization",
                risk_level=RiskLevel.CRITICAL,
                action=HoldAction(),
            )

        # ======================================================================
        # STAGE 3: Task Authorization
        # ======================================================================
        if task is not None:
            if task.status == TaskStatus.CANCELLED:
                logger.warning(
                    f"[GATE 3: TASK REJECTION] Task {task.task_id} is CANCELLED"
                )
                return ExecutionGateResult(
                    allowed=False,
                    reason=f"Task authorization rejected: task {task.task_id} has been cancelled",
                    stage="task_authorization",
                    risk_level=RiskLevel.HIGH,
                    action=HoldAction(),
                )

            if swarm_client is not None:
                # Validate lease ownership
                if swarm_client.current_lease and task.lease_id:
                    if swarm_client.current_lease.lease_id != task.lease_id:
                        logger.warning(
                            f"[GATE 3: TASK REJECTION] Lease mismatch: current={swarm_client.current_lease.lease_id} task={task.lease_id}"
                        )
                        return ExecutionGateResult(
                            allowed=False,
                            reason="Task authorization rejected: lease mismatch or lease revoked",
                            stage="task_authorization",
                            risk_level=RiskLevel.HIGH,
                            action=HoldAction(),
                        )

        # ======================================================================
        # STAGE 4: FINAL Execution Authorization (Phase Fence & Kill Switch)
        # ======================================================================
        # 4a. Kill Switch check
        if self.config.kill_switch or (swarm_client and getattr(swarm_client, "kill_switch_active", False)):
            logger.critical("[GATE 4: FINAL GATE REJECTION] Kill switch is active! Execution strictly forbidden.")
            return ExecutionGateResult(
                allowed=False,
                reason="FINAL execution authorization rejected: Kill switch is active",
                stage="final_execution_authorization",
                risk_level=RiskLevel.CRITICAL,
                action=HoldAction(),
            )

        # 4b. Execution-Time Phase Fence
        if swarm_client is not None:
            current_phase_state = swarm_client.current_phase_state
            current_phase = current_phase_state.phase
            current_epoch = current_phase_state.phase_epoch

            # Task epoch / phase fence
            if task is not None:
                if task.phase != current_phase:
                    logger.warning(
                        f"[GATE 4: PHASE FENCE] Task phase '{task.phase.value}' does not match "
                        f"current swarm phase '{current_phase.value}'. Execution aborted."
                    )
                    return ExecutionGateResult(
                        allowed=False,
                        reason=(
                            f"Execution-time phase fence rejected: task phase '{task.phase.value}' "
                            f"does not match current active phase '{current_phase.value}'"
                        ),
                        stage="final_execution_authorization",
                        risk_level=RiskLevel.CRITICAL,
                        action=HoldAction(),
                    )

                if task.phase_epoch != current_epoch:
                    logger.warning(
                        f"[GATE 4: PHASE FENCE] Task epoch {task.phase_epoch} does not match "
                        f"current swarm epoch {current_epoch}. Execution aborted."
                    )
                    return ExecutionGateResult(
                        allowed=False,
                        reason=(
                            f"Execution-time phase fence rejected: task epoch {task.phase_epoch} "
                            f"does not match current active epoch {current_epoch}"
                        ),
                        stage="final_execution_authorization",
                        risk_level=RiskLevel.CRITICAL,
                        action=HoldAction(),
                    )

            # Action type phase fence
            if current_phase == Phase.DEFENSE and decision.action_type in ("attack", "recon"):
                logger.warning(
                    f"[GATE 4: PHASE FENCE] Action '{decision.action_type}' strictly forbidden during DEFENSE phase."
                )
                return ExecutionGateResult(
                    allowed=False,
                    reason=f"Execution-time phase fence rejected: action '{decision.action_type}' forbidden in DEFENSE phase",
                    stage="final_execution_authorization",
                    risk_level=RiskLevel.CRITICAL,
                    action=HoldAction(),
                )

            if current_phase == Phase.ATTACK and decision.action_type in ("defend", "patch"):
                logger.warning(
                    f"[GATE 4: PHASE FENCE] Action '{decision.action_type}' strictly forbidden during ATTACK phase."
                )
                return ExecutionGateResult(
                    allowed=False,
                    reason=f"Execution-time phase fence rejected: action '{decision.action_type}' forbidden in ATTACK phase",
                    stage="final_execution_authorization",
                    risk_level=RiskLevel.CRITICAL,
                    action=HoldAction(),
                )

            if current_phase in (Phase.HOLD, Phase.UNKNOWN) and decision.action_type != "hold":
                logger.warning(
                    f"[GATE 4: PHASE FENCE] Active action '{decision.action_type}' forbidden during HOLD phase."
                )
                return ExecutionGateResult(
                    allowed=False,
                    reason=f"Execution-time phase fence rejected: active actions forbidden in HOLD phase",
                    stage="final_execution_authorization",
                    risk_level=RiskLevel.CRITICAL,
                    action=HoldAction(),
                )

        # All 4 stages successfully passed!
        return ExecutionGateResult(
            allowed=True,
            reason="All 4 authorization gates passed: policy -> registry -> task -> final execution gate",
            stage="execution_ready",
            risk_level=RiskLevel.LOW,
            action=resolved_action,
        )

    def execute_with_gates(
        self,
        decision: Decision,
        context: ActionContext,
        task: Optional[Task] = None,
        swarm_client: Optional[Any] = None,
    ) -> ActionExecutionRecord:
        """
        Run decision through the 4-stage authorization chain and execute ONLY if all gates pass.
        Returns ActionExecutionRecord.
        """
        gate_result = self.verify_and_authorize(
            decision=decision,
            context=context,
            task=task,
            swarm_client=swarm_client,
        )

        target = decision.target
        started_at = time.time()

        if not gate_result.allowed:
            # Execution ABORTED at one of the authorization gates
            rec = ActionExecutionRecord(
                action_type=decision.action_type,
                action_name=getattr(decision, "action_name", "") or decision.action_type,
                target=target,
                model_used=decision.model_used or "execution-gate",
                model_confidence=decision.confidence,
                attempted=False,
                started_at=started_at,
                completed_at=time.time(),
                success=False,
                failure_reason=gate_result.reason,
                empirical_success=False,
                verification_result={"gate_stage": gate_result.stage, "allowed": False},
            )
            rec.build_dry_run_record(authorized=False)
            return rec

        # ======================================================================
        # STAGE 5: Concrete Execution
        # ======================================================================
        action = gate_result.action or HoldAction()
        record = action.execute(
            target=target,
            context=context,
            model_used=decision.model_used,
            model_confidence=decision.confidence,
        )
        return record
