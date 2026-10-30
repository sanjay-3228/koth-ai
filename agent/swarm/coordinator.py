"""
Swarm Coordinator for null_warriors.
Coordinates the 4 worker agents, tracks authoritative phase state, leases, and task assignments.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.heartbeat import HeartbeatMonitor
from agent.swarm.leases import LeaseManager
from agent.swarm.models import (
    AgentHeartbeat,
    AgentRole,
    AgentSession,
    AgentStatus,
    Phase,
    PhaseState,
    Task,
    TaskLease,
    TaskStatus,
)
from agent.swarm.phase_manager import PhaseManager, PhaseProvider, ManualPhaseProvider, SimulatedPhaseProvider
from agent.swarm.shared_state import SharedTeamState
from agent.swarm.task_manager import TaskManager
from agent.db import DatabaseManager
from agent.hill.manager import HillHealth, HillManager, OwnershipStatus
from agent.hill.verifier import HillVerifier, SimulatedHillVerifier
from agent.llm.agent_config import AgentLLMConfig, AgentLLMConfigManager, redact_secrets
from agent.llm.client_factory import AgentLLMClient
from agent.swarm.team_manager import AGENT_HILL_MAPPING, TeamManager
from agent.competition.manager import CompetitionManager
from agent.competition.models import (
    Competition,
    CompetitionHill,
    CompetitionMode,
    CompetitionRules,
    CompetitionStatus,
    CompetitionTeam,
    HillEnvironmentType,
    KothFormat,
    OwnershipState,
    RedVsBlueFormat,
    ScoreCategory,
    TeamSide,
    VerifierType,
)

logger = logging.getLogger("koth.swarm.coordinator")


class SwarmCoordinator:
    """
    Authoritative coordinator for the 4-agent swarm.
    Provides direct in-memory API (for rehearsals/fast tests) and HTTP endpoints (for LAN).
    """

    def __init__(
        self,
        team_id: str = "null_warriors",
        phase_provider: Optional[PhaseProvider] = None,
        lease_ttl: float = 15.0,
        heartbeat_timeout: float = 10.0,
        target_hosts: Optional[List[str]] = None,
        own_hosts: Optional[List[str]] = None,
        auth_token: Optional[str] = None,
        operator_token: Optional[str] = None,
        agent_tokens: Optional[Dict[str, str]] = None,
        session_ttl: Optional[float] = None,
        authorized_agents: Optional[List[str]] = None,
        agent_usernames: Optional[Dict[str, str]] = None,
        admin_username: str = "admin",
        enable_username_login: bool = False,
        db_path: Optional[str] = None,
        db_manager: Optional[DatabaseManager] = None,
        team_manager: Optional[TeamManager] = None,
        hill_manager: Optional[HillManager] = None,
        verifier: Optional[HillVerifier] = None,
        competition_manager: Optional[CompetitionManager] = None,
    ):
        self.team_id = team_id
        self.target_hosts = target_hosts or []
        self.own_hosts = own_hosts or []
        self.auth_token = auth_token
        self.operator_token = operator_token
        self.agent_tokens = agent_tokens or {}
        self.session_ttl = session_ttl if session_ttl is not None else max(heartbeat_timeout * 2.0, 10.0)
        self.coordinator_instance_id = secrets.token_hex(8)
        self.agent_usernames = {str(k): str(v).strip() for k, v in (agent_usernames or {}).items()}
        self.username_to_agent = {v.lower(): k for k, v in self.agent_usernames.items()}
        self.admin_username = str(admin_username).strip() or "admin"
        self.enable_username_login = bool(enable_username_login)
        self.authorized_agents = (
            authorized_agents
            if authorized_agents is not None
            else ["agent-01", "agent-02", "agent-03", "agent-04"]
        )
        self.active_sessions: Dict[str, AgentSession] = {}
        self.agent_to_session: Dict[str, str] = {}
        self._lock = threading.RLock()

        self.db_manager = db_manager or DatabaseManager(db_path=db_path)
        self.team_manager = team_manager or TeamManager(db_path=db_path)
        self.hill_manager = hill_manager or HillManager(db_path=db_path, team_manager=self.team_manager)
        self.verifier = verifier or SimulatedHillVerifier()
        self.llm_config_manager = AgentLLMConfigManager(db_path=db_path or self.db_manager.db_path)
        self.competition_manager = competition_manager or CompetitionManager(db_path=db_path or self.db_manager.db_path)

        self.event_bus = SwarmEventBus()
        self.shared_state = SharedTeamState(team_id=team_id)
        self.lease_manager = LeaseManager(default_ttl=lease_ttl, event_bus=self.event_bus)
        self.heartbeat_monitor = HeartbeatMonitor(
            heartbeat_timeout_seconds=heartbeat_timeout, event_bus=self.event_bus
        )
        self.task_manager = TaskManager(
            lease_manager=self.lease_manager,
            shared_state=self.shared_state,
            event_bus=self.event_bus,
        )

        self.phase_provider = phase_provider or ManualPhaseProvider(
            initial_phase=Phase.HOLD, initial_round=1
        )
        self.phase_manager = PhaseManager(
            provider=self.phase_provider,
            event_bus=self.event_bus,
            on_phase_change=self._handle_phase_transition,
        )

        # Wire event bus to notifications persistence
        self.event_bus.subscribe_all(self._on_swarm_event_notification)

        # Restore persistent emergency stop state
        estop = self.db_manager.get_emergency_stop()
        self.kill_switch_active = bool(estop.get("is_active", False))
        if self.kill_switch_active:
            logger.critical(
                f"[SECURITY ALERT] Swarm Coordinator booted with PERSISTENT EMERGENCY STOP ACTIVE "
                f"(triggered by {estop.get('triggered_by')}: {estop.get('reason')})"
            )
        self._running = False
        self._reaper_thread: Optional[threading.Thread] = None

    def _handle_phase_transition(self, old_state: PhaseState, new_state: PhaseState) -> None:
        """
        Five-step transition sequence:
        1. Epoch incremented and event published by phase_manager.
        2. Invalidate all active leases from old phase.
        3. Cancel in-flight tasks from old phase.
        4. Populate initial tasks for new phase if ATTACK or DEFENSE.
        5. Ready for agent task requests.
        """
        logger.warning(
            f"[TRANSITION] Switching from {old_state.phase.value} to {new_state.phase.value} (epoch {new_state.phase_epoch})"
        )
        with self._lock:
            # Release all existing leases
            self.lease_manager.release_all_for_phase()

            # Cancel old phase tasks
            self.task_manager.cancel_tasks_for_phase(old_state.phase)

            # Populate tasks for the new phase
            if new_state.phase in (Phase.ATTACK, Phase.DEFENSE):
                self.task_manager.populate_phase_tasks(
                    phase=new_state.phase,
                    target_hosts=self.target_hosts,
                    own_hosts=self.own_hosts,
                    phase_epoch=new_state.phase_epoch,
                )

    def trigger_kill_switch(self, triggered_by: str, reason: str = "Operator manual kill") -> None:
        with self._lock:
            self.kill_switch_active = True
            logger.critical(f"KILL SWITCH TRIGGERED by {triggered_by}: {reason}")
            self.db_manager.set_emergency_stop(active=True, actor=triggered_by, reason=reason)
            self.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.KILL_SWITCH_TRIGGERED,
                    source_agent_id=triggered_by,
                    data={"reason": reason, "timestamp": time.time()},
                )
            )
            # Invalidate all leases immediately
            self.lease_manager.release_all_for_phase()

    def reset_kill_switch(self, reset_by: str) -> None:
        with self._lock:
            self.kill_switch_active = False
            logger.warning(f"KILL SWITCH RESET by {reset_by}")
            self.db_manager.set_emergency_stop(active=False, actor=reset_by, reason="Operator manual reset")
            self.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.KILL_SWITCH_RESET,
                    source_agent_id=reset_by,
                    data={"action": "kill_switch_reset", "timestamp": time.time()},
                )
            )
            self.lease_manager.release_all_for_phase()

    def get_phase(self) -> PhaseState:
        if self.kill_switch_active:
            return PhaseState(
                phase=Phase.HOLD,
                round_id=0,
                phase_epoch=999999,
                ttl_seconds=0.0,
                source="kill_switch",
            )
        state, _ = self.phase_manager.poll()
        return state

    def record_heartbeat(self, heartbeat: AgentHeartbeat) -> Dict[str, Any]:
        """Record heartbeat from an agent and return current phase acknowledgment."""
        self.heartbeat_monitor.record_heartbeat(heartbeat)
        current_phase = self.get_phase()
        return {
            "ack": True,
            "phase": current_phase.to_dict(),
            "kill_switch": self.kill_switch_active,
        }

    def request_task(
        self, agent_id: str, phase: Phase, phase_epoch: int
    ) -> Dict[str, Any]:
        """Distribute next eligible task to requesting agent with an exclusive lease."""
        if self.kill_switch_active:
            return {"task": None, "lease": None, "reason": "kill_switch_active"}

        current_phase = self.get_phase()
        if current_phase.phase != phase or current_phase.phase_epoch != phase_epoch:
            return {
                "task": None,
                "lease": None,
                "reason": "phase_epoch_mismatch",
                "current_phase": current_phase.to_dict(),
            }

        task, lease = self.task_manager.request_next_task(agent_id, phase, phase_epoch)
        return {
            "task": task.to_dict() if task else None,
            "lease": lease.to_dict() if lease else None,
            "reason": "ok" if task else "no_tasks_available",
        }

    def claim_task(
        self, task_id: str, agent_id: str, phase: Phase, phase_epoch: int
    ) -> Dict[str, Any]:
        """Claim a specific task by task_id with mutual-exclusion checks."""
        if self.kill_switch_active:
            return {"task": None, "lease": None, "reason": "kill_switch_active"}

        current_phase = self.get_phase()
        if current_phase.phase != phase or current_phase.phase_epoch != phase_epoch:
            return {
                "task": None,
                "lease": None,
                "reason": "phase_epoch_mismatch",
                "current_phase": current_phase.to_dict(),
            }

        task, lease = self.task_manager.claim_task(task_id, agent_id, phase, phase_epoch)
        return {
            "task": task.to_dict() if task else None,
            "lease": lease.to_dict() if lease else None,
            "reason": "ok" if task else "claim_rejected",
        }

    def advance_phase(self, phase: Phase, round_id: Optional[int] = None) -> PhaseState:
        """Advance phase on the underlying provider or force transition."""
        if hasattr(self.phase_provider, "set_phase"):
            self.phase_provider.set_phase(phase, round_id=round_id)
        self.phase_manager.poll()
        return self.get_phase()

    def renew_lease(self, lease_id: str, agent_id: str) -> bool:
        if self.kill_switch_active:
            return False
        return self.lease_manager.renew_lease(lease_id, agent_id)

    def complete_task(
        self, task_id: str, agent_id: str, result: Optional[Dict[str, Any]] = None
    ) -> bool:
        return self.task_manager.complete_task(task_id, agent_id, result)

    def fail_task(
        self, task_id: str, agent_id: str, error: str, retryable: bool = True
    ) -> bool:
        return self.task_manager.fail_task(task_id, agent_id, error, retryable)

    def tick_maintenance(self, now: Optional[float] = None) -> None:
        """Periodic maintenance tick: checks dead agents, reaps abandoned leases."""
        with self._lock:
            # 1. Detect dead agents
            dead_agents = self.heartbeat_monitor.check_agent_health(now=now)
            for dead_id in dead_agents:
                self.task_manager.reset_tasks_for_agent(dead_id)
                self.lease_manager.release_all_for_agent(dead_id)

            # 2. Reap expired leases and reset tasks to pending
            self.task_manager.reap_abandoned_tasks(now=now)

            # 3. Poll phase provider
            self.phase_manager.poll()

            # 4. Periodic Hill Verification
            for hill_id in (1, 2, 3, 4):
                try:
                    hstate = self.hill_manager.get_hill(hill_id)
                    if hstate:
                        own_st, h_st, det = self.verifier.verify(hill_id, hstate)
                        self.hill_manager.update_ownership_status(hill_id, own_st, details=det)
                        self.hill_manager.update_health(hill_id, h_st, latency_ms=det.get("latency_ms", 0.0))
                except Exception as ex:
                    logger.debug(f"Hill verification tick error for hill {hill_id}: {ex}")

    def start_background_maintenance(self, interval_seconds: float = 2.0) -> None:
        if self._running:
            return
        self._running = True

        def _run():
            while self._running:
                try:
                    self.tick_maintenance()
                except Exception as e:
                    logger.error(f"Error in coordinator maintenance loop: {e}", exc_info=True)
                time.sleep(interval_seconds)

        self._reaper_thread = threading.Thread(
            target=_run, name="coordinator-maintenance", daemon=True
        )
        self._reaper_thread.start()

    def stop_background_maintenance(self) -> None:
        self._running = False
        if self._reaper_thread and self._reaper_thread.is_alive():
            self._reaper_thread.join(timeout=2.0)

    def get_active_session(self, session_id: str) -> Optional[AgentSession]:
        """Retrieve an active non-expired, non-revoked session."""
        with self._lock:
            session = self.active_sessions.get(session_id)
            if session and session.is_active():
                return session
            return None

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revoke an active session."""
        with self._lock:
            session = self.active_sessions.get(session_id)
            if session:
                session.revoked = True
                if self.agent_to_session.get(session.agent_id) == session_id:
                    del self.agent_to_session[session.agent_id]
                return True
            return False

    def issue_username_session(self, username: str) -> Optional[Dict[str, Any]]:
        """Issue a rehearsal/admin session from a configured username.

        Username-only login is intentionally opt-in and intended for local rehearsal.
        Production/LAN deployments should keep token authentication enabled.
        """
        if not self.enable_username_login:
            return None
        clean = str(username or "").strip()
        if not clean:
            return None
        if clean.lower() == self.admin_username.lower():
            agent_id = "operator"
            role = AgentRole.OPERATOR
        else:
            agent_id = self.username_to_agent.get(clean.lower())
            if not agent_id or agent_id not in self.authorized_agents:
                return None
            role = AgentRole.WORKER

        with self._lock:
            if role == AgentRole.WORKER:
                existing_id = self.agent_to_session.get(agent_id)
                if existing_id and existing_id in self.active_sessions:
                    existing = self.active_sessions[existing_id]
                    if existing.is_active() and self.heartbeat_monitor.is_agent_alive(agent_id):
                        return {"error": "already_logged_in", "agent_id": agent_id}
                    existing.revoked = True
                    self.active_sessions.pop(existing_id, None)
                    self.agent_to_session.pop(agent_id, None)
            session_id = secrets.token_hex(24)
            session = AgentSession(
                session_id=session_id,
                agent_id=agent_id,
                role=role,
                created_at=time.time(),
                last_heartbeat=time.time(),
                ttl=self.session_ttl,
            )
            self.active_sessions[session_id] = session
            if role == AgentRole.WORKER:
                self.agent_to_session[agent_id] = session_id
            return {
                "logged_in": True,
                "username": clean,
                "agent_id": agent_id,
                "role": role.value,
                "session_token": session_id,
                "coordinator_instance_id": self.coordinator_instance_id,
            }

    def verify_agent_credential(self, agent_id: str, credential: Optional[str]) -> bool:
        """
        Authoritatively verify that the provided credential maps to the specified agent_id.
        Rejects mismatched credentials (e.g. credential for agent-02 supplied with agent_id agent-03).
        """
        if not self.auth_token and not self.agent_tokens and not self.operator_token:
            return True

        if not credential:
            return False

        # 1. Authoritative check: Per-agent unique tokens (Preferred Model)
        if self.agent_tokens:
            expected = self.agent_tokens.get(agent_id)
            if expected and hmac.compare_digest(expected, credential):
                return True

            # Reject explicitly if credential matches another agent's token
            for other_id, other_token in self.agent_tokens.items():
                if other_id != agent_id and hmac.compare_digest(other_token, credential):
                    logger.warning(
                        f"[SECURITY] Agent impersonation rejected: credential for '{other_id}' "
                        f"presented for agent_id '{agent_id}'"
                    )
                    return False
            return False

        # 2. Cryptographic HMAC-SHA256 derivation from team secret (Legacy fallback)
        if self.auth_token:
            expected_hmac = hmac.new(
                self.auth_token.encode("utf-8"),
                agent_id.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if hmac.compare_digest(expected_hmac, credential):
                return True

            # Reject if credential matches another authorized agent's HMAC:
            for other_id in (self.authorized_agents or []):
                if other_id != agent_id:
                    other_hmac = hmac.new(
                        self.auth_token.encode("utf-8"),
                        other_id.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    if hmac.compare_digest(other_hmac, credential):
                        logger.warning(
                            f"[SECURITY] Agent impersonation rejected: credential for '{other_id}' "
                            f"presented for agent_id '{agent_id}'"
                        )
                        return False

            # Fallback: exact match with team auth_token only if no operator_token configured
            if not self.operator_token and hmac.compare_digest(self.auth_token, credential):
                return True

        return False

    def _on_swarm_event_notification(self, event: SwarmEvent) -> None:
        """Route event bus events to persistent notification store with anti-duplication."""
        try:
            etype = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
            if etype == "AGENT_HEARTBEAT":
                return  # Do not spam notifications with periodic heartbeats

            category = "AGENTS"
            severity = "INFO"
            title = etype.replace("_", " ").title()
            hill_id = event.data.get("hill_id")
            agent_id = event.agent_id or event.source_agent_id
            description = f"Event {etype}"

            if etype in ("HILL_CAPTURED", "HILL_LOST", "HILL_RECAPTURED"):
                category = "HILLS"
                severity = "SUCCESS" if etype in ("HILL_CAPTURED", "HILL_RECAPTURED") else "CRITICAL"
                title = f"Hill {hill_id} {etype.replace('_', ' ').title()}" if hill_id else etype.replace('_', ' ').title()
                team = event.data.get("team_id", event.team_id)
                description = f"Hill {hill_id} {etype.lower().replace('_', ' ')} by {agent_id or team}."
            elif etype in ("VERIFICATION_SUCCESS", "VERIFICATION_FAILED"):
                category = "HILLS"
                severity = "SUCCESS" if etype == "VERIFICATION_SUCCESS" else "WARNING"
                title = f"Hill {hill_id} Verification {'Passed' if etype == 'VERIFICATION_SUCCESS' else 'Failed'}"
                description = f"Integrity check {'succeeded' if etype == 'VERIFICATION_SUCCESS' else 'failed'} for Hill {hill_id}."
            elif etype in ("TASK_ASSIGNED", "TASK_STARTED", "TASK_COMPLETED", "TASK_FAILED", "TASK_REASSIGNED", "TASK_CANCELLED"):
                category = "TASKS"
                if etype == "TASK_COMPLETED":
                    severity = "SUCCESS"
                elif etype == "TASK_FAILED":
                    severity = "WARNING"
                else:
                    severity = "INFO"
                tid = event.task_id or event.data.get("task_id", "")
                title = f"Task {etype.replace('TASK_', '').title()}"
                description = f"Task '{tid}' {etype.lower().replace('task_', '').replace('_', ' ')} by {agent_id or 'coordinator'}."
                if etype == "TASK_REASSIGNED":
                    prev = event.data.get("previous_agent_id", "previous agent")
                    nxt = event.data.get("new_agent_id", "new agent")
                    description = f"Task '{tid}' reassigned from {prev} to {nxt}."
            elif etype in ("AGENT_JOINED", "AGENT_RECONNECTED", "AGENT_DROPPED"):
                category = "AGENTS"
                severity = "CRITICAL" if etype == "AGENT_DROPPED" else ("SUCCESS" if etype == "AGENT_RECONNECTED" else "INFO")
                title = f"Agent {agent_id} {etype.replace('AGENT_', '').title()}"
                description = f"Agent {agent_id} is now {etype.lower().replace('agent_', '').replace('_', ' ')}."
            elif etype in ("ACTION_BLOCKED", "SECURITY_ALERT", "KILL_SWITCH_TRIGGERED", "KILL_SWITCH_RESET"):
                category = "SECURITY"
                severity = "CRITICAL"
                title = f"Security: {etype.replace('_', ' ').title()}"
                reason = event.data.get("reason", "Security policy enforcement")
                description = f"Action blocked or alert triggered: {reason}"
            elif etype == "COORDINATION_REQUEST":
                category = "COORDINATION"
                severity = "INFO"
                title = "Swarm Coordination Update"
                description = event.data.get("description", "Leader decomposed objectives for the swarm.")
            elif etype == "AGENT_ERROR":
                category = "AGENTS"
                severity = "ERROR"
                title = f"Agent Error: {agent_id}"
                description = event.data.get("error", "An agent error occurred.")

            import uuid
            event_id = f"evt-{uuid.uuid4().hex[:12]}"
            self.db_manager.record_notification(
                event_id=event_id,
                event_type=etype,
                category=category,
                severity=severity,
                agent_id=agent_id,
                hill_id=hill_id,
                team_id=event.team_id,
                competition_id=event.data.get("competition_id"),
                title=title,
                description=description,
                details=event.data,
                timestamp=event.timestamp,
            )
        except Exception as e:
            logger.error(f"Failed to record notification from swarm event: {e}")

    def get_swarm_status(self) -> Dict[str, Any]:
        """Return comprehensive status for dashboard and CLI monitoring."""
        with self._lock:
            phase_state = self.get_phase()
            heartbeats = self.heartbeat_monitor.get_all_heartbeats()
            active_leases = self.lease_manager.get_active_leases()
            all_tasks = self.task_manager.get_all_tasks()
            now = time.time()

            agent_states = {}
            for aid in self.authorized_agents:
                hb = heartbeats.get(aid)
                last_time = self.heartbeat_monitor._last_seen.get(aid)
                alive = self.heartbeat_monitor.is_agent_alive(aid, now=now)
                hb_data = hb.to_dict() if hb else None
                current_task_id = hb.current_task_id if hb else None
                current_target = hb.current_target if hb else None
                task = self.task_manager.get_task(current_task_id) if current_task_id else None

                # Calculate crisp connection state: ONLINE, BUSY, IDLE, STALE, OFFLINE
                if not alive or not last_time:
                    conn_state = "OFFLINE"
                else:
                    age = now - last_time
                    if age > 5.0:
                        conn_state = "STALE"
                    elif task and task.status in (TaskStatus.LEASED, TaskStatus.RUNNING):
                        conn_state = "BUSY"
                    else:
                        conn_state = "IDLE"

                # Real metrics from heartbeat metadata (None if not provided - NO FABRICATION)
                meta = hb.metadata if hb else {}
                tel = meta.get("telemetry") if isinstance(meta.get("telemetry"), dict) else {}
                cpu_pct = meta.get("cpu_percent") or tel.get("cpu_percent")
                mem_pct = meta.get("memory_percent") or tel.get("memory_percent")
                mem_mb = meta.get("memory_mb") or tel.get("memory_used_mb")
                telemetry_dict = tel if tel else {"cpu_percent": cpu_pct, "memory_percent": mem_pct, "memory_mb": mem_mb}

                # LLM config status
                llm_cfg = self.llm_config_manager.get_config(aid)
                if isinstance(llm_cfg, dict):
                    provider = llm_cfg.get("provider", "none")
                    model_id = llm_cfg.get("model_id", "")
                    enabled = bool(llm_cfg.get("enabled", False))
                    connection_status = llm_cfg.get("connection_status", "UNCONFIGURED")
                elif llm_cfg is not None:
                    provider = getattr(llm_cfg, "provider", "none")
                    model_id = getattr(llm_cfg, "model_id", "")
                    enabled = bool(getattr(llm_cfg, "enabled", False))
                    connection_status = getattr(llm_cfg, "connection_status", "UNCONFIGURED")
                else:
                    provider = "none"
                    model_id = ""
                    enabled = False
                    connection_status = "UNCONFIGURED"

                llm_summary = {
                    "provider": provider,
                    "model_id": model_id,
                    "enabled": enabled,
                    "connection_status": connection_status,
                }

                # Task counts for this agent
                agent_tasks = [t for t in all_tasks if t.assigned_agent_id == aid]
                completed_count = len([t for t in agent_tasks if t.status == TaskStatus.COMPLETED])
                failed_count = len([t for t in agent_tasks if t.status == TaskStatus.FAILED])
                pending_count = len([t for t in agent_tasks if t.status in (TaskStatus.PENDING, TaskStatus.LEASED, TaskStatus.RUNNING)])

                assigned_hill = AGENT_HILL_MAPPING.get(aid, 1)

                agent_states[aid] = {
                    "agent_id": aid,
                    "username": self.agent_usernames.get(aid, aid),
                    "alive": alive,
                    "role": "LEADER" if aid == "agent-01" else "SPECIALIST",
                    "status": (hb.status.value if hb else (AgentStatus.DISCONNECTED.value if not alive else AgentStatus.READY.value)),
                    "connection_state": conn_state,
                    "phase": (hb.current_phase.value if hb else phase_state.phase.value),
                    "phase_epoch": (hb.phase_epoch if hb else phase_state.phase_epoch),
                    "current_task_id": current_task_id,
                    "current_target": current_target,
                    "current_task_type": task.task_type.value if task else None,
                    "task_status": task.status.value if task else None,
                    "task_progress": getattr(task, "progress", 0) if task else 0,
                    "task_description": getattr(task, "description", "") if task else "",
                    "assigned_hill": assigned_hill,
                    "scope": f"Hill {assigned_hill} Target Scope",
                    "cpu_percent": cpu_pct,
                    "memory_percent": mem_pct,
                    "memory_mb": mem_mb,
                    "telemetry": telemetry_dict,
                    "last_heartbeat": last_time,
                    "heartbeat_age_seconds": round(now - last_time, 1) if last_time else None,
                    "llm_status": llm_summary,
                    "task_counts": {
                        "completed": completed_count,
                        "failed": failed_count,
                        "pending": pending_count,
                        "total": len(agent_tasks),
                    },
                    "heartbeat": hb_data,
                }

            return {
                "team_id": self.team_id,
                "authorized_agents": list(self.authorized_agents),
                "kill_switch": self.kill_switch_active,
                "phase": phase_state.to_dict(),
                "agents": agent_states,
                "active_leases_count": len(active_leases),
                "active_leases": [l.to_dict() for l in active_leases],
                "task_counts": {
                    "total": len(all_tasks),
                    "pending": len([t for t in all_tasks if t.status == TaskStatus.PENDING]),
                    "leased": len([t for t in all_tasks if t.status == TaskStatus.LEASED]),
                    "completed": len([t for t in all_tasks if t.status == TaskStatus.COMPLETED]),
                    "failed": len([t for t in all_tasks if t.status == TaskStatus.FAILED]),
                    "cancelled": len([t for t in all_tasks if t.status == TaskStatus.CANCELLED]),
                },
                "shared_state": self.shared_state.get_snapshot(),
            }


def create_coordinator_blueprint(coordinator: SwarmCoordinator):
    """Factory for Flask Blueprint to expose REST API for physical LAN operation."""
    from flask import Blueprint, g, jsonify, request

    bp = Blueprint("swarm_coordinator", __name__)

    @bp.before_request
    def check_swarm_auth():
        # Handle CORS preflight
        if request.method == "OPTIONS":
            return jsonify({}), 200

        # Unprotected endpoints (health check, network info, and team registration/login)
        if request.path in (
            "/healthz",
            "/api/swarm/healthz",
            "/api/swarm/network-info",
            "/api/team/register",
            "/api/team/register-four",
            "/api/team/create",
            "/api/team/login",
            "/api/team/join",
        ) or request.endpoint in (
            "swarm_coordinator.healthz_endpoint",
            "swarm_coordinator.root_endpoint",
            "swarm_coordinator.network_info_endpoint",
            "swarm_coordinator.register_endpoint",
            "swarm_coordinator.login_endpoint",
            "swarm_coordinator.team_create_endpoint",
            "swarm_coordinator.team_register_endpoint",
            "swarm_coordinator.team_join_endpoint",
            "swarm_coordinator.team_login_endpoint",
        ):
            return None

        # Extract token from header
        token = (
            request.headers.get("X-Operator-Token")
            or request.headers.get("X-Session-Token")
            or request.headers.get("X-Swarm-Token")
            or request.headers.get("X-Agent-Credential")
        )
        if not token:
            auth_hdr = request.headers.get("Authorization", "")
            if auth_hdr.startswith("Bearer "):
                token = auth_hdr[7:].strip()

        # Public competition read & join endpoints when no token is supplied
        is_public_comp_read = (
            request.path == "/api/competitions"
            or (request.path.startswith("/api/competition") and (request.method == "GET" or request.path.endswith("/join")))
            or request.endpoint == "swarm_coordinator.list_competitions_endpoint"
        )
        if not token and is_public_comp_read:
            return None

        # 1. Authoritative Session & Credential Verification (when token is provided)
        if token:
            # Check Team Member Session Token (stored in SQLite auth_sessions)
            member = coordinator.team_manager.verify_session(token)
            if member:
                g.team_member = member
                g.authenticated_role = AgentRole.OPERATOR if member.get("role") == "LEADER" else AgentRole.WORKER
                g.authenticated_agent_id = member.get("agent_id")
                g.authenticated_username = member.get("username")
                g.member_hill_id = member.get("hill_id")
                g.session = coordinator.get_active_session(token)
                return None

            # Check Active In-Memory Session Token (coordinator.active_sessions)
            session = coordinator.get_active_session(token)
            if session:
                session.last_heartbeat = time.time()
                g.session = session
                g.authenticated_role = session.role
                g.authenticated_agent_id = session.agent_id
                g.authenticated_username = getattr(session, "username", None) or session.agent_id
                return None

            # Check Operator Token
            if coordinator.operator_token and hmac.compare_digest(token, coordinator.operator_token):
                g.authenticated_role = AgentRole.OPERATOR
                g.authenticated_agent_id = "operator"
                g.authenticated_username = "operator"
                g.session = None
                return None

            # Check provisioned Agent Tokens
            if coordinator.agent_tokens:
                for aid, atok in coordinator.agent_tokens.items():
                    if hmac.compare_digest(token, atok):
                        g.authenticated_role = AgentRole.WORKER
                        g.authenticated_agent_id = aid
                        g.authenticated_username = aid
                        g.session = None
                        return None

            # Check legacy team token
            if coordinator.auth_token:
                if coordinator.authorized_agents:
                    for aid in coordinator.authorized_agents:
                        expected_hmac = hmac.new(
                            coordinator.auth_token.encode("utf-8"),
                            aid.encode("utf-8"),
                            hashlib.sha256,
                        ).hexdigest()
                        if hmac.compare_digest(token, expected_hmac):
                            g.authenticated_role = AgentRole.WORKER
                            g.authenticated_agent_id = aid
                            g.authenticated_username = aid
                            g.session = None
                            return None

                if not coordinator.operator_token and hmac.compare_digest(token, coordinator.auth_token):
                    g.authenticated_role = AgentRole.OPERATOR
                    g.authenticated_agent_id = "operator"
                    g.authenticated_username = "operator"
                    g.session = None
                    return None

            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid, expired, or revoked session token",
            }), 401

        # 2. No token provided
        # Protected agent LLM endpoints strictly require an authenticated session token
        if request.path.startswith("/api/agent/"):
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication required: missing session token or agent credential",
            }), 401

        # If coordinator has no auth required at all (mock/in-memory test mode for general swarm endpoints)
        if not coordinator.auth_token and not coordinator.operator_token and not coordinator.agent_tokens:
            g.authenticated_role = AgentRole.OPERATOR
            g.authenticated_agent_id = "operator"
            g.authenticated_username = "operator"
            g.session = None
            return None

        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required: missing session token or operator token",
        }), 401

    @bp.route("/api/swarm/network-info", methods=["GET"])
    def network_info_endpoint():
        """Expose central server LAN IP addresses, hostname, service port, and reachable status."""
        import socket
        hostname = socket.gethostname()
        primary_ip = "127.0.0.1"
        lan_ips = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        try:
            addrs = socket.getaddrinfo(hostname, None)
            for item in addrs:
                ip = item[4][0]
                if ":" not in ip and not ip.startswith("127.") and ip not in lan_ips:
                    lan_ips.append(ip)
        except Exception:
            pass

        if primary_ip not in lan_ips and not primary_ip.startswith("127."):
            lan_ips.insert(0, primary_ip)
        if not lan_ips:
            lan_ips = [primary_ip]

        scheme = "https" if getattr(coordinator, "use_tls", False) else "http"
        port = getattr(coordinator, "port", 5000) or 5000

        status = coordinator.get_swarm_status()
        agents_data = status.get("agents") or {}
        connected_count = len([a for a in agents_data.values() if a.get("alive")])

        return jsonify({
            "hostname": hostname,
            "primary_lan_ip": primary_ip,
            "all_lan_ips": lan_ips,
            "port": port,
            "scheme": scheme,
            "api_url": f"{scheme}://{primary_ip}:{port}",
            "tls_enabled": getattr(coordinator, "use_tls", False),
            "service_status": "ok",
            "reachable": True,
            "connected_agents_count": connected_count,
            "total_agents": 4,
            "team_id": coordinator.team_id,
        })

    @bp.route("/api/swarm/login", methods=["POST"])
    def login_endpoint():
        data = request.get_json(force=True) or {}
        if not coordinator.enable_username_login:
            return jsonify({"error": "Forbidden", "message": "Username login is disabled; use provisioned agent credentials"}), 403
        result = coordinator.issue_username_session(data.get("username", ""))
        if not result:
            return jsonify({"error": "Unauthorized", "message": "Unknown username"}), 401
        if result.get("error") == "already_logged_in":
            return jsonify({"error": "Conflict", "message": f"Agent '{result['agent_id']}' is already logged in"}), 409
        return jsonify(result)

    @bp.route("/api/swarm/register", methods=["POST"])
    def register_endpoint():
        data = request.get_json(force=True) or {}
        agent_id = data.get("agent_id")
        team_id = data.get("team_id", coordinator.team_id)
        role_str = data.get("role", "WORKER").upper()

        if not agent_id:
            return jsonify({
                "error": "Bad Request",
                "message": "Missing required agent_id",
            }), 400

        # Registration Validation 1: TEAM_ID must match
        if team_id != coordinator.team_id:
            logger.warning(
                f"Registration rejected for agent '{agent_id}': team_id mismatch "
                f"('{team_id}' != '{coordinator.team_id}')"
            )
            return jsonify({
                "error": "Forbidden",
                "message": f"Team ID mismatch: expected '{coordinator.team_id}', got '{team_id}'",
            }), 403

        # Registration Validation 2: Unknown agents must be rejected
        if coordinator.authorized_agents and agent_id not in coordinator.authorized_agents:
            logger.warning(
                f"Registration rejected: agent_id '{agent_id}' not in authorized roster "
                f"{coordinator.authorized_agents}"
            )
            return jsonify({
                "error": "Forbidden",
                "message": f"Agent ID '{agent_id}' is not in the authorized roster",
            }), 403


        # Registration Validation 3: provisioned credential OR team-issued session OR username session
        session_token = request.headers.get("X-Session-Token") or data.get("session_token")
        member_session = coordinator.team_manager.verify_session(session_token) if session_token else None
        login_session = coordinator.get_active_session(session_token) if session_token else None

        if member_session:
            if member_session.get("agent_id") != agent_id:
                return jsonify({"error": "Forbidden", "message": f"Session belongs to '{member_session.get('agent_id')}', not '{agent_id}'"}), 403
            if member_session.get("team_id") != coordinator.team_id:
                return jsonify({"error": "Forbidden", "message": "Team ID mismatch"}), 403
            session_id = session_token
            # Register in active sessions if not already present
            with coordinator._lock:
                role = AgentRole.OPERATOR if member_session.get("role") == "LEADER" else AgentRole.WORKER
                if session_id not in coordinator.active_sessions:
                    coordinator.active_sessions[session_id] = AgentSession(
                        session_id=session_id,
                        agent_id=agent_id,
                        role=role,
                        created_at=time.time(),
                        last_heartbeat=time.time(),
                        ttl=coordinator.session_ttl,
                    )
        elif login_session:
            if login_session.role != AgentRole.WORKER or login_session.agent_id != agent_id:
                return jsonify({"error": "Forbidden", "message": "Session does not belong to this agent"}), 403
            session_id = login_session.session_id
        else:
            cred = (
                request.headers.get("X-Swarm-Token")
                or request.headers.get("X-Agent-Credential")
                or data.get("credential")
                or data.get("token")
            )
            if not cred:
                auth_hdr = request.headers.get("Authorization", "")
                if auth_hdr.startswith("Bearer "):
                    cred = auth_hdr[7:].strip()

            if not coordinator.verify_agent_credential(agent_id, cred):
                logger.warning(
                    f"[SECURITY ALERT] Registration rejected for agent '{agent_id}': invalid credential or agent mismatch"
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Invalid credential for agent ID '{agent_id}'",
                }), 403

            # Registration Validation 4: Duplicate active registration prevention & safe reconnect
            with coordinator._lock:
                existing_session_id = coordinator.agent_to_session.get(agent_id)
                if existing_session_id and existing_session_id in coordinator.active_sessions:
                    existing_sess = coordinator.active_sessions[existing_session_id]
                    is_alive = coordinator.heartbeat_monitor.is_agent_alive(agent_id)
                    reconnect_requested = bool(data.get("reconnect") or data.get("force_reconnect"))
                    if existing_sess.is_active() and is_alive and not reconnect_requested:
                        logger.warning(
                            f"Registration rejected for agent '{agent_id}': duplicate active session {existing_session_id}"
                        )
                        return jsonify({
                            "error": "Conflict",
                            "message": f"Duplicate active registration: agent '{agent_id}' already has an active session. Pass 'reconnect': true to recover session.",
                        }), 409
                    existing_sess.revoked = True
                    del coordinator.active_sessions[existing_session_id]
                    if agent_id in coordinator.agent_to_session:
                        del coordinator.agent_to_session[agent_id]

                session_id = secrets.token_hex(24)
                role = AgentRole.WORKER
                new_session = AgentSession(
                    session_id=session_id,
                    agent_id=agent_id,
                    role=role,
                    created_at=time.time(),
                    last_heartbeat=time.time(),
                    ttl=coordinator.session_ttl,
                )
                coordinator.active_sessions[session_id] = new_session
                coordinator.agent_to_session[agent_id] = session_id
                logger.info(f"Registered agent '{agent_id}' with new session {session_id[:8]}... (role={role.value})")

        role = AgentRole.WORKER
        with coordinator._lock:
            session = coordinator.active_sessions.get(session_id)
            if session:
                session.last_heartbeat = time.time()
            coordinator.agent_to_session[agent_id] = session_id
        logger.info(f"Registered agent '{agent_id}' with session {session_id[:8]}... (role={role.value})")

        # Initial heartbeat
        hb = AgentHeartbeat(
            agent_id=agent_id,
            team_id=team_id,
            status=AgentStatus.READY,
            current_phase=coordinator.get_phase().phase,
            phase_epoch=coordinator.get_phase().phase_epoch,
            timestamp=time.time(),
            metadata={"role": role.value},
        )
        coordinator.record_heartbeat(hb)
        return jsonify({
            "registered": True,
            "agent_id": agent_id,
            "team_id": coordinator.team_id,
            "session_token": session_id,
            "coordinator_instance_id": coordinator.coordinator_instance_id,
            "phase": coordinator.get_phase().to_dict(),
        })

    @bp.route("/api/swarm/session", methods=["GET"])
    def session_endpoint():
        return jsonify({
            "role": g.get("authenticated_role", AgentRole.OPERATOR).value,
            "agent_id": g.get("authenticated_agent_id", "operator"),
            "username": g.get("authenticated_username") or coordinator.agent_usernames.get(g.get("authenticated_agent_id"), coordinator.admin_username),
        })

    @bp.route("/api/swarm/phase", methods=["GET"])
    def get_phase_endpoint():
        return jsonify(coordinator.get_phase().to_dict())

    @bp.route("/api/swarm/phase/advance", methods=["POST"])
    def phase_advance_endpoint():
        if g.get("authenticated_role") != AgentRole.OPERATOR:
            return jsonify({
                "error": "Forbidden",
                "message": "Operator privileges required to advance phase",
            }), 403
        data = request.get_json(force=True) or {}
        raw_phase = data.get("phase", "HOLD").upper()
        round_id = data.get("round_id")
        phase = Phase(raw_phase)
        state = coordinator.advance_phase(phase, round_id=round_id)
        return jsonify(state.to_dict())

    @bp.route("/api/swarm/heartbeat", methods=["POST"])
    def heartbeat_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            if data.get("agent_id") and data["agent_id"] != g.get("authenticated_agent_id"):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Agent ID mismatch with session: authenticated as '{g.get('authenticated_agent_id')}'",
                }), 403
            data["agent_id"] = g.get("authenticated_agent_id")
        data.setdefault("team_id", coordinator.team_id)
        if "telemetry" in data:
            data.setdefault("metadata", {})["telemetry"] = data["telemetry"]
        hb = AgentHeartbeat.from_dict(data)
        res = coordinator.record_heartbeat(hb)
        return jsonify(res)

    @bp.route("/api/swarm/task/request", methods=["POST"])
    @bp.route("/api/swarm/tasks/request", methods=["POST"])
    def task_request_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            agent_id = g.get("authenticated_agent_id")
        else:
            agent_id = data["agent_id"]
        phase = Phase(data["phase"])
        phase_epoch = int(data["phase_epoch"])
        res = coordinator.request_task(agent_id, phase, phase_epoch)
        return jsonify(res)

    @bp.route("/api/swarm/task/claim", methods=["POST"])
    @bp.route("/api/swarm/tasks/claim", methods=["POST"])
    def task_claim_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            agent_id = g.get("authenticated_agent_id")
        else:
            agent_id = data["agent_id"]
        phase = Phase(data["phase"])
        phase_epoch = int(data["phase_epoch"])
        task_id = data.get("task_id")
        if task_id:
            res = coordinator.claim_task(task_id, agent_id, phase, phase_epoch)
        else:
            res = coordinator.request_task(agent_id, phase, phase_epoch)
        return jsonify(res)

    @bp.route("/api/swarm/task/renew", methods=["POST"])
    @bp.route("/api/swarm/leases/renew", methods=["POST"])
    def task_renew_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            if data.get("agent_id") and data["agent_id"] != g.get("authenticated_agent_id"):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Agent ID mismatch with session: authenticated as '{g.get('authenticated_agent_id')}'",
                }), 403
            agent_id = g.get("authenticated_agent_id")
        else:
            agent_id = data["agent_id"]
        success = coordinator.renew_lease(data["lease_id"], agent_id)
        return jsonify({"success": success})

    @bp.route("/api/swarm/task/complete", methods=["POST"])
    @bp.route("/api/swarm/tasks/complete", methods=["POST"])
    def task_complete_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            if data.get("agent_id") and data["agent_id"] != g.get("authenticated_agent_id"):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Agent ID mismatch with session: authenticated as '{g.get('authenticated_agent_id')}'",
                }), 403
            agent_id = g.get("authenticated_agent_id")
        else:
            agent_id = data["agent_id"]
        success = coordinator.complete_task(
            data["task_id"], agent_id, data.get("result")
        )
        if not success:
            return jsonify({
                "success": False,
                "error": "Task completion rejected: lease invalid, expired, or assigned to another agent",
            }), 409
        return jsonify({"success": True})

    @bp.route("/api/swarm/task/fail", methods=["POST"])
    def task_fail_endpoint():
        data = request.get_json(force=True)
        if g.get("authenticated_role") == AgentRole.WORKER:
            if data.get("agent_id") and data["agent_id"] != g.get("authenticated_agent_id"):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Agent ID mismatch with session: authenticated as '{g.get('authenticated_agent_id')}'",
                }), 403
            agent_id = g.get("authenticated_agent_id")
        else:
            agent_id = data["agent_id"]
        success = coordinator.fail_task(
            data["task_id"],
            agent_id,
            data.get("error", "unknown"),
            data.get("retryable", True),
        )
        return jsonify({"success": success})

    @bp.route("/api/swarm/shared-state", methods=["GET", "POST"])
    def shared_state_endpoint():
        if request.method == "GET":
            return jsonify(coordinator.shared_state.get_snapshot())

        data = request.get_json(force=True) or {}
        auth_agent = g.get("authenticated_agent_id")
        is_worker = g.get("authenticated_role") == AgentRole.WORKER

        try:
            if "scan" in data:
                s = data["scan"]
                coordinator.shared_state.record_host_scan(
                    s["host"], s["ports"], os_hint=s.get("os"), metadata=s.get("metadata")
                )
            if "compromise" in data:
                c = data["compromise"]
                if is_worker and c.get("agent_id") and c["agent_id"] != auth_agent:
                    return jsonify({
                        "error": "Forbidden",
                        "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit compromise for '{c.get('agent_id')}'",
                    }), 403
                target_agent = auth_agent if is_worker else c.get("agent_id", "operator")
                coordinator.shared_state.record_compromise(
                    c["host"], target_agent, details=c.get("details")
                )
            if "patch" in data:
                p = data["patch"]
                if is_worker and p.get("agent_id") and p["agent_id"] != auth_agent:
                    return jsonify({
                        "error": "Forbidden",
                        "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit patch for '{p.get('agent_id')}'",
                    }), 403
                target_agent = auth_agent if is_worker else p.get("agent_id", "operator")
                coordinator.shared_state.record_patch(
                    p["service_or_host"], target_agent, details=p.get("details")
                )
            if "flag" in data:
                f = data["flag"]
                if is_worker and f.get("agent_id") and f["agent_id"] != auth_agent:
                    return jsonify({
                        "error": "Forbidden",
                        "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit flag for '{f.get('agent_id')}'",
                    }), 403
                target_agent = auth_agent if is_worker else f.get("agent_id", "operator")
                coordinator.shared_state.record_flag(
                    flag_hash=f["flag_hash"], agent_id=target_agent, round_id=int(f.get("round_id", 1))
                )
            if "metadata" in data:
                for k, v in data["metadata"].items():
                    coordinator.shared_state.set_metadata(k, v)
            return jsonify({"success": True, "updated_at": coordinator.shared_state._updated_at})
        except ValueError as ve:
            return jsonify({"success": False, "error": str(ve)}), 400

    @bp.route("/api/swarm/state/compromised", methods=["POST"])
    def state_compromised_endpoint():
        data = request.get_json(force=True) or {}
        auth_agent = g.get("authenticated_agent_id")
        is_worker = g.get("authenticated_role") == AgentRole.WORKER
        if is_worker and data.get("agent_id") and data["agent_id"] != auth_agent:
            return jsonify({
                "error": "Forbidden",
                "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit for '{data.get('agent_id')}'",
            }), 403
        target_agent = auth_agent if is_worker else data.get("agent_id", "operator")
        coordinator.shared_state.record_compromise(
            data["host"], target_agent, details=data.get("details")
        )
        return jsonify({"success": True})

    @bp.route("/api/swarm/state/patches", methods=["POST"])
    def state_patches_endpoint():
        data = request.get_json(force=True) or {}
        auth_agent = g.get("authenticated_agent_id")
        is_worker = g.get("authenticated_role") == AgentRole.WORKER
        if is_worker and data.get("agent_id") and data["agent_id"] != auth_agent:
            return jsonify({
                "error": "Forbidden",
                "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit for '{data.get('agent_id')}'",
            }), 403
        target_agent = auth_agent if is_worker else data.get("agent_id", "operator")
        coordinator.shared_state.record_patch(
            data.get("service_or_host") or data.get("host"), target_agent, details=data.get("details")
        )
        return jsonify({"success": True})

    @bp.route("/api/swarm/state/flags", methods=["POST"])
    def state_flags_endpoint():
        data = request.get_json(force=True) or {}
        auth_agent = g.get("authenticated_agent_id")
        is_worker = g.get("authenticated_role") == AgentRole.WORKER
        if is_worker and data.get("agent_id") and data["agent_id"] != auth_agent:
            return jsonify({
                "error": "Forbidden",
                "message": f"Unauthorized shared-state impersonation: authenticated as '{auth_agent}', cannot submit for '{data.get('agent_id')}'",
            }), 403
        target_agent = auth_agent if is_worker else data.get("agent_id", "operator")
        coordinator.shared_state.record_flag(
            flag_hash=data["flag_hash"], agent_id=target_agent, round_id=int(data.get("round_id", 1))
        )
        return jsonify({"success": True})

    @bp.route("/api/swarm/tasks", methods=["GET"])
    def tasks_endpoint():
        tasks = coordinator.task_manager.get_all_tasks()
        return jsonify({"tasks": [t.to_dict() for t in tasks]})

    @bp.route("/api/swarm/status", methods=["GET"])
    def status_endpoint():
        return jsonify(coordinator.get_swarm_status())

    @bp.route("/api/swarm/kill-switch", methods=["POST"])
    def kill_switch_endpoint():
        if g.get("authenticated_role") != AgentRole.OPERATOR:
            return jsonify({
                "error": "Forbidden",
                "message": "Operator privileges required to trigger kill switch",
            }), 403
        data = request.get_json(force=True) or {}
        coordinator.trigger_kill_switch(
            triggered_by=data.get("agent_id", "operator"),
            reason=data.get("reason", "Operator REST trigger"),
        )
        return jsonify({"status": "KILL_SWITCH_ACTIVE"})

    @bp.route("/api/swarm/kill-switch/reset", methods=["POST"])
    def kill_switch_reset_endpoint():
        if g.get("authenticated_role") != AgentRole.OPERATOR:
            return jsonify({
                "error": "Forbidden",
                "message": "Operator/Leader privileges required to reset kill switch",
            }), 403
        data = request.get_json(force=True) or {}
        reset_by = data.get("agent_id") or g.get("authenticated_agent_id", "operator")
        coordinator.reset_kill_switch(reset_by=reset_by)
        return jsonify({"status": "KILL_SWITCH_RESET", "active": False})

    @bp.route("/api/swarm/audit-log", methods=["GET"])
    def audit_log_endpoint():
        limit = min(int(request.args.get("limit", 50)), 200)
        events = coordinator.db_manager.get_audit_events(limit=limit)
        return jsonify({"events": events, "count": len(events)})

    # =========================================================================
    # Participant Features: Agent Monitoring, Event Feed & Swarm Coordination
    # =========================================================================

    @bp.route("/api/swarm/agent/<agent_id>/monitoring", methods=["GET"])
    def agent_monitoring_detail_endpoint(agent_id: str):
        # RBAC: Worker can inspect their own agent; Leader / Operator can inspect any agent
        caller_role = g.get("authenticated_role")
        caller_agent_id = g.get("authenticated_agent_id")
        if caller_role == AgentRole.WORKER and caller_agent_id != agent_id:
            return jsonify({
                "error": "Forbidden",
                "message": f"Agent '{caller_agent_id}' cannot view monitoring details for '{agent_id}'",
            }), 403

        status = coordinator.get_swarm_status()
        agent_info = status.get("agents", {}).get(agent_id)
        if not agent_info:
            return jsonify({"error": "NotFound", "message": f"Agent '{agent_id}' not found"}), 404

        all_tasks = coordinator.task_manager.get_all_tasks()
        agent_tasks = [t.to_dict() for t in all_tasks if t.assigned_agent_id == agent_id]

        recent_actions = coordinator.db_manager.get_recent_actions(limit=25)
        agent_actions = [a for a in recent_actions if a.get("target") == agent_id or a.get("details", {}).get("agent_id") == agent_id]
        if not agent_actions:
            agent_actions = recent_actions[:10]

        recent_notifications = coordinator.db_manager.get_notifications(limit=30)
        agent_notifs = [n for n in recent_notifications if n.get("agent_id") == agent_id]

        return jsonify({
            "agent_id": agent_id,
            "status": agent_info,
            "task_history": agent_tasks,
            "execution_logs": agent_actions,
            "recent_events": agent_notifs,
        })

    @bp.route("/api/swarm/notifications", methods=["GET"])
    def notifications_endpoint():
        category = request.args.get("category")
        limit = min(int(request.args.get("limit", 50)), 200)
        since_ts = float(request.args.get("since_ts")) if request.args.get("since_ts") else None
        team_id = request.args.get("team_id") or coordinator.team_id
        competition_id = request.args.get("competition_id")

        notifs = coordinator.db_manager.get_notifications(
            team_id=team_id,
            competition_id=competition_id,
            category=category,
            since_ts=since_ts,
            limit=limit,
        )
        return jsonify({"notifications": notifs, "count": len(notifs)})

    @bp.route("/api/swarm/notifications/emit", methods=["POST"])
    def emit_notification_endpoint():
        data = request.get_json(force=True) or {}
        event_type = data.get("event_type", "INFO")
        category = data.get("category", "COORDINATION")
        severity = data.get("severity", "INFO")
        description = data.get("description", "")
        title = data.get("title", "")
        agent_id = data.get("agent_id") or g.get("authenticated_agent_id")
        hill_id = data.get("hill_id")
        team_id = data.get("team_id") or coordinator.team_id
        details = data.get("details", {})

        eid = coordinator.db_manager.record_notification(
            event_type=event_type,
            category=category,
            severity=severity,
            description=description,
            title=title,
            agent_id=agent_id,
            hill_id=hill_id,
            team_id=team_id,
            details=details,
        )
        return jsonify({"success": True, "event_id": eid})

    @bp.route("/api/swarm/coordination/objective", methods=["POST"])
    def coordination_objective_endpoint():
        caller_role = g.get("authenticated_role")
        caller_agent_id = g.get("authenticated_agent_id")
        if caller_role != AgentRole.OPERATOR and caller_agent_id != "agent-01":
            return jsonify({
                "error": "Forbidden",
                "message": "Only team leader (agent-01) or operator can decompose objectives",
            }), 403

        data = request.get_json(force=True) or {}
        objective = data.get("objective", "").strip()
        if not objective:
            return jsonify({"error": "Missing objective text"}), 400

        phase_str = data.get("phase", coordinator.get_phase().phase.value)
        phase = Phase(phase_str) if phase_str in Phase._value2member_map_ else Phase.ATTACK
        target_hosts = data.get("target_hosts") or coordinator.target_hosts
        hills = data.get("hills") or [1, 2, 3, 4]
        epoch = coordinator.get_phase().phase_epoch

        created_tasks = coordinator.task_manager.break_down_objective(
            objective_text=objective,
            leader_agent_id=caller_agent_id or "agent-01",
            phase=phase,
            target_hosts=target_hosts,
            hills=hills,
            phase_epoch=epoch,
        )

        coordinator.db_manager.record_coordination_message(
            from_agent_id=caller_agent_id or "agent-01",
            to_agent_id="ALL",
            message_type="OBJECTIVE",
            content=f"Decomposed objective: {objective}",
            details={"task_count": len(created_tasks), "tasks": [t.task_id for t in created_tasks]},
            team_id=coordinator.team_id,
        )

        coordinator.event_bus.publish(
            SwarmEvent(
                event_type=EventType.COORDINATION_REQUEST,
                source_agent_id=caller_agent_id or "agent-01",
                data={
                    "description": f"Leader decomposed objective into {len(created_tasks)} subtasks: {objective[:50]}",
                    "task_count": len(created_tasks),
                },
            )
        )

        return jsonify({
            "success": True,
            "objective": objective,
            "tasks_created": len(created_tasks),
            "tasks": [t.to_dict() for t in created_tasks],
        })

    @bp.route("/api/swarm/coordination/message", methods=["POST"])
    @bp.route("/api/coordination/message", methods=["POST"])
    @bp.route("/api/coordination/messages", methods=["POST"])
    def post_coordination_message_endpoint():
        data = request.get_json(force=True) or {}
        auth_aid = g.get("authenticated_agent_id")
        provided_aid = data.get("from_agent_id")

        if auth_aid and provided_aid and provided_aid != auth_aid and auth_aid != "operator":
            return jsonify({
                "error": "Forbidden",
                "message": f"Sender impersonation rejected: authenticated session is bound to '{auth_aid}', cannot send as '{provided_aid}'",
            }), 403

        caller_agent_id = auth_aid or provided_aid or "agent-01"
        to_agent_id = data.get("to_agent_id", "ALL")
        msg_type = data.get("message_type", "STATUS_UPDATE")
        content = data.get("content", "").strip()
        if not content:
            return jsonify({"error": "Message content cannot be empty"}), 400

        hill_id = data.get("hill_id")
        task_id = data.get("task_id")
        team_id = data.get("team_id") or coordinator.team_id
        comp_id = data.get("competition_id")
        details = data.get("details", {})

        mid = coordinator.db_manager.record_coordination_message(
            from_agent_id=caller_agent_id,
            to_agent_id=to_agent_id,
            message_type=msg_type,
            content=content,
            hill_id=hill_id,
            task_id=task_id,
            team_id=team_id,
            competition_id=comp_id,
            details=details,
        )

        if msg_type in ("BLOCKER_REPORT", "ASSISTANCE_REQUEST"):
            coordinator.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.COORDINATION_REQUEST,
                    source_agent_id=caller_agent_id,
                    data={
                        "message_type": msg_type,
                        "description": f"[{msg_type}] Agent {caller_agent_id}: {content[:60]}",
                        "hill_id": hill_id,
                        "task_id": task_id,
                    },
                )
            )

        return jsonify({"success": True, "message_id": mid})

    @bp.route("/api/swarm/coordination/messages", methods=["GET"])
    @bp.route("/api/coordination/messages", methods=["GET"])
    def get_coordination_messages_endpoint():
        limit = min(int(request.args.get("limit", 50)), 200)
        since_ts = float(request.args.get("since_ts")) if request.args.get("since_ts") else None
        team_id = request.args.get("team_id") or coordinator.team_id
        comp_id = request.args.get("competition_id")
        agent_id = request.args.get("agent_id")

        msgs = coordinator.db_manager.get_coordination_messages(
            team_id=team_id,
            competition_id=comp_id,
            agent_id=agent_id,
            since_ts=since_ts,
            limit=limit,
        )
        return jsonify({"messages": msgs, "count": len(msgs)})

    @bp.route("/api/swarm/coordination/reassign", methods=["POST"])
    def coordination_reassign_endpoint():
        caller_role = g.get("authenticated_role")
        caller_agent_id = g.get("authenticated_agent_id") or "agent-01"
        if caller_role != AgentRole.OPERATOR and caller_agent_id != "agent-01":
            return jsonify({
                "error": "Forbidden",
                "message": "Only team leader (agent-01) or operator can reassign tasks",
            }), 403

        data = request.get_json(force=True) or {}
        task_id = data.get("task_id")
        new_agent_id = data.get("new_agent_id")
        reason = data.get("reason", "Leader reassignment")
        if not task_id or not new_agent_id:
            return jsonify({"error": "Missing task_id or new_agent_id"}), 400

        success, msg = coordinator.task_manager.reassign_task(
            task_id=task_id,
            new_agent_id=new_agent_id,
            caller_agent_id=caller_agent_id,
            reason=reason,
        )
        if not success:
            return jsonify({"success": False, "message": msg}), 400
        return jsonify({"success": True, "message": msg})

    @bp.route("/api/swarm/coordination/summary", methods=["GET"])
    def coordination_summary_endpoint():
        tasks = coordinator.task_manager.get_all_tasks()
        shared = coordinator.shared_state.get_snapshot()
        messages = coordinator.db_manager.get_coordination_messages(limit=20)
        blockers = [m for m in messages if m.get("message_type") in ("BLOCKER_REPORT", "ASSISTANCE_REQUEST")]

        agent_tasks = {}
        for aid in coordinator.authorized_agents:
            agent_tasks[aid] = [t.to_dict() for t in tasks if t.assigned_agent_id == aid]

        return jsonify({
            "leader": "agent-01",
            "active_tasks_count": len([t for t in tasks if t.status in (TaskStatus.PENDING, TaskStatus.LEASED, TaskStatus.RUNNING)]),
            "completed_tasks_count": len([t for t in tasks if t.status == TaskStatus.COMPLETED]),
            "failed_tasks_count": len([t for t in tasks if t.status == TaskStatus.FAILED]),
            "tasks": [t.to_dict() for t in tasks],
            "agent_assignments": agent_tasks,
            "blockers": blockers,
            "shared_findings": {
                "discovered_hosts": shared.get("discovered_hosts", {}),
                "compromised_targets": shared.get("compromised_targets", {}),
                "patched_services": shared.get("patched_services", {}),
                "captured_flags_count": len(shared.get("captured_flags", [])),
            },
        })

    # =========================================================================
    # Team Management Routes (PBKDF2 Authentication & 4-Agent Portals)
    # =========================================================================
    @bp.route("/api/team/register", methods=["POST"])
    @bp.route("/api/team/register-four", methods=["POST"])
    def team_register_endpoint():
        data = request.get_json(force=True) or {}
        try:
            result = coordinator.team_manager.register_four_member_team(data)
            coordinator.db_manager.record_audit_event(
                event_type="TEAM_REGISTERED_4_MEMBER",
                actor=result["leader"]["username"],
                target=result["team_id"],
                details={"team_name": result["team_name"], "members_count": len(result["members"])},
            )
            with coordinator._lock:
                leader_token = result["session_token"]
                new_sess = AgentSession(
                    session_id=leader_token,
                    agent_id="agent-01",
                    role=AgentRole.OPERATOR,
                    created_at=time.time(),
                    last_heartbeat=time.time(),
                    ttl=coordinator.session_ttl,
                )
                coordinator.active_sessions[leader_token] = new_sess
                coordinator.agent_to_session["agent-01"] = leader_token

            return jsonify({"success": True, **result})
        except KeyError as ke:
            return jsonify({"error": "Bad Request", "message": f"Missing required field: {ke}"}), 400
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/team/create", methods=["POST"])
    def team_create_endpoint():
        data = request.get_json(force=True) or {}
        try:
            if "leader" in data and ("teammate_1" in data or "teammates" in data or "members" in data):
                result = coordinator.team_manager.register_four_member_team(data)
                coordinator.db_manager.record_audit_event(
                    event_type="TEAM_REGISTERED_4_MEMBER",
                    actor=result["leader"]["username"],
                    target=result["team_id"],
                    details={"team_name": result["team_name"]},
                )
                with coordinator._lock:
                    leader_token = result["session_token"]
                    new_sess = AgentSession(
                        session_id=leader_token,
                        agent_id="agent-01",
                        role=AgentRole.OPERATOR,
                        created_at=time.time(),
                        last_heartbeat=time.time(),
                        ttl=coordinator.session_ttl,
                    )
                    coordinator.active_sessions[leader_token] = new_sess
                    coordinator.agent_to_session["agent-01"] = leader_token
                return jsonify({"success": True, "team": result, **result})

            team = coordinator.team_manager.create_team(
                team_id=data.get("team_id", coordinator.team_id),
                team_name=data.get("team_name", data.get("team_id", coordinator.team_id)),
                leader_username=data["leader_username"],
                leader_password=data["leader_password"],
                full_name=data.get("full_name", ""),
                description=data.get("description", ""),
                competition_id=data.get("competition_id", ""),
                teammates=data.get("teammates"),
            )
            coordinator.db_manager.record_audit_event(
                event_type="TEAM_CREATED",
                actor=data["leader_username"],
                target=team["team_id"],
                details={"team_name": team["team_name"]},
            )
            return jsonify({"success": True, "team": team})
        except KeyError as ke:
            return jsonify({"error": "Bad Request", "message": f"Missing required field: {ke}"}), 400
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/team/complete-registration", methods=["POST"])
    def team_complete_registration_endpoint():
        caller_agent = g.get("authenticated_agent_id")
        if caller_agent != "agent-01":
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: only the Team Leader (Agent 01) can complete team registration.",
            }), 403

        data = request.get_json(force=True) or {}
        team_id = data.get("team_id")
        if not team_id:
            if hasattr(g, "team_member") and g.team_member:
                team_id = g.team_member.get("team_id")
            else:
                team_id = coordinator.team_id

        teammates = data.get("teammates") or []

        token = (
            request.headers.get("X-Session-Token")
            or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        )

        try:
            result = coordinator.team_manager.complete_team_registration(
                team_id=team_id,
                leader_session_token=token,
                teammates=teammates,
            )
            coordinator.db_manager.record_audit_event(
                event_type="TEAM_REGISTRATION_COMPLETED",
                actor=g.get("authenticated_username", "agent-01"),
                target=team_id,
                details={"team_id": team_id},
            )
            return jsonify(result)
        except PermissionError as pe:
            return jsonify({"error": "Forbidden", "message": str(pe)}), 403
        except (ValueError, KeyError) as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/team/management", methods=["GET"])
    def team_management_endpoint():
        caller_agent = g.get("authenticated_agent_id")
        if caller_agent != "agent-01":
            return jsonify({
                "error": "Forbidden",
                "message": "Access denied: Team management view is restricted to the Team Leader (Agent 01).",
            }), 403

        team_id = request.args.get("team_id")
        if not team_id:
            if hasattr(g, "team_member") and g.team_member:
                team_id = g.team_member.get("team_id")
            else:
                team_id = coordinator.team_id

        try:
            view = coordinator.team_manager.get_team_management_view(
                team_id=team_id,
                caller_agent_id=caller_agent,
            )
            return jsonify(view)
        except PermissionError as pe:
            return jsonify({"error": "Forbidden", "message": str(pe)}), 403
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/team/join", methods=["POST"])
    def team_join_endpoint():
        data = request.get_json(force=True) or {}
        try:
            member = coordinator.team_manager.join_team(
                team_id=data.get("team_id", coordinator.team_id),
                username=data["username"],
                password=data["password"],
            )
            coordinator.db_manager.record_audit_event(
                event_type="TEAM_MEMBER_JOINED",
                actor=data["username"],
                target=member["agent_id"],
                details={"team_id": member["team_id"], "hill_id": member["hill_id"]},
            )
            return jsonify({"success": True, "member": member})
        except KeyError as ke:
            return jsonify({"error": "Bad Request", "message": f"Missing required field: {ke}"}), 400
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/team/login", methods=["POST"])
    def team_login_endpoint():
        data = request.get_json(force=True) or {}
        session_info = coordinator.team_manager.login(
            username=data.get("username", ""),
            password=data.get("password", ""),
        )
        if not session_info:
            return jsonify({"error": "Unauthorized", "message": "Invalid username or password"}), 401

        with coordinator._lock:
            role = AgentRole.OPERATOR if session_info["role"] == "LEADER" else AgentRole.WORKER
            new_sess = AgentSession(
                session_id=session_info["session_token"],
                agent_id=session_info["agent_id"],
                role=role,
                created_at=time.time(),
                last_heartbeat=time.time(),
                ttl=coordinator.session_ttl,
            )
            coordinator.active_sessions[session_info["session_token"]] = new_sess
            coordinator.agent_to_session[session_info["agent_id"]] = session_info["session_token"]

        coordinator.db_manager.record_audit_event(
            event_type="MEMBER_LOGIN",
            actor=session_info["username"],
            target=session_info["agent_id"],
            details={"role": session_info["role"], "hill_id": session_info["hill_id"]},
        )
        return jsonify({
            "logged_in": True,
            **session_info,
            "coordinator_instance_id": coordinator.coordinator_instance_id,
        })

    @bp.route("/api/team/logout", methods=["POST"])
    def team_logout_endpoint():
        token = (
            request.headers.get("X-Session-Token")
            or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        )
        if token:
            coordinator.team_manager.revoke_session(token)
            coordinator.revoke_session(token)
        return jsonify({"success": True})

    @bp.route("/api/team/members", methods=["GET"])
    def team_members_endpoint():
        team_id = request.args.get("team_id", coordinator.team_id)
        members = coordinator.team_manager.list_team_members(team_id)
        return jsonify({"team_id": team_id, "members": members})

    # =========================================================================
    # Hill Portals & Configuration Routes
    # =========================================================================
    @bp.route("/api/hills", methods=["GET"])
    def hills_endpoint():
        member_role = "LEADER" if g.get("authenticated_role") == AgentRole.OPERATOR else "TEAMMATE"
        assigned_hill = g.get("member_hill_id")
        if member_role == "LEADER":
            hills = coordinator.hill_manager.get_all_hills_leader_view(member_role=member_role)
            return jsonify({"hills": hills, "role": "LEADER"})
        else:
            hills = []
            for h_id in (1, 2, 3, 4):
                try:
                    view = coordinator.hill_manager.get_hill_view(
                        hill_id=h_id,
                        member_assigned_hill=assigned_hill,
                        member_role=member_role,
                    )
                    hills.append(view)
                except PermissionError:
                    h_obj = coordinator.hill_manager.get_hill(h_id)
                    if h_obj:
                        hills.append({
                            "hill_id": h_id,
                            "name": h_obj.name,
                            "ownership_status": h_obj.ownership_status.value,
                            "health_status": h_obj.health_status.value,
                            "assigned_agent_id": h_obj.assigned_agent_id,
                            "accessible": False,
                        })
            return jsonify({"hills": hills, "role": "TEAMMATE", "assigned_hill": assigned_hill})

    @bp.route("/api/hill/<int:hill_id>", methods=["GET"])
    def hill_detail_endpoint(hill_id: int):
        member_role = "LEADER" if g.get("authenticated_role") == AgentRole.OPERATOR else "TEAMMATE"
        assigned_hill = g.get("member_hill_id")
        try:
            view = coordinator.hill_manager.get_hill_view(
                hill_id=hill_id,
                member_assigned_hill=assigned_hill,
                member_role=member_role,
            )
            return jsonify(view)
        except PermissionError as pe:
            return jsonify({"error": "Forbidden", "message": str(pe)}), 403

    @bp.route("/api/hill/<int:hill_id>/config", methods=["POST"])
    def hill_config_endpoint(hill_id: int):
        data = request.get_json(force=True) or {}
        member_role = "LEADER" if g.get("authenticated_role") == AgentRole.OPERATOR else "TEAMMATE"
        assigned_hill = g.get("member_hill_id")
        actor = g.get("authenticated_agent_id", "operator")

        try:
            updated = coordinator.hill_manager.configure_hill(
                hill_id=hill_id,
                service_name=data.get("service_name"),
                target_host=data.get("target_host"),
                target_port=int(data.get("target_port")) if data.get("target_port") else None,
                defense_endpoint=data.get("defense_endpoint"),
                configured_by=actor,
                member_role=member_role,
                member_assigned_hill=assigned_hill,
            )
            coordinator.db_manager.record_audit_event(
                event_type="HILL_CONFIGURED",
                actor=actor,
                target=f"hill-{hill_id}",
                details={"hill_id": hill_id, "service_name": updated.service_name, "target_host": updated.target_host},
            )
            return jsonify(updated.to_safe_dict() if hasattr(updated, "to_safe_dict") else updated.to_dict())
        except PermissionError as pe:
            return jsonify({"error": "Forbidden", "message": str(pe)}), 403
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/hill/<int:hill_id>/flag", methods=["POST"])
    def hill_flag_endpoint(hill_id: int):
        data = request.get_json(force=True) or {}
        flag = data.get("flag", "")
        if not flag:
            return jsonify({"error": "Bad Request", "message": "Missing required flag"}), 400

        member_role = "LEADER" if g.get("authenticated_role") == AgentRole.OPERATOR else "TEAMMATE"
        assigned_hill = g.get("member_hill_id")
        actor = g.get("authenticated_agent_id", "operator")

        try:
            flag_hash = coordinator.hill_manager.set_hill_flag(
                hill_id=hill_id,
                flag_plaintext=flag,
                configured_by=actor,
                member_role=member_role,
                member_assigned_hill=assigned_hill,
            )
            coordinator.db_manager.record_audit_event(
                event_type="HILL_FLAG_SET",
                actor=actor,
                target=f"hill-{hill_id}",
                details={"hill_id": hill_id, "flag_hash": flag_hash},
            )
            return jsonify({"success": True, "hill_id": hill_id, "flag_hash": flag_hash})
        except PermissionError as pe:
            return jsonify({"error": "Forbidden", "message": str(pe)}), 403

    @bp.route("/api/hill/<int:hill_id>/verify", methods=["POST"])
    def hill_verify_endpoint(hill_id: int):
        member_role = "LEADER" if g.get("authenticated_role") == AgentRole.OPERATOR else "TEAMMATE"
        assigned_hill = g.get("member_hill_id")
        if member_role != "LEADER" and assigned_hill != hill_id:
            return jsonify({"error": "Forbidden", "message": "Cannot verify other hills"}), 403

        hstate = coordinator.hill_manager.get_hill(hill_id)
        if not hstate:
            return jsonify({"error": "Not Found", "message": f"Hill {hill_id} not found"}), 404

        own_st, h_st, det = coordinator.verifier.verify(hill_id, hstate)
        coordinator.hill_manager.update_ownership_status(hill_id, own_st, details=det)
        coordinator.hill_manager.update_health(hill_id, h_st, latency_ms=det.get("latency_ms", 0.0))

        is_verified = (own_st == OwnershipStatus.OWNED or h_st == HillHealth.HEALTHY)
        coordinator.event_bus.publish(
            SwarmEvent(
                event_type=EventType.VERIFICATION_SUCCESS if is_verified else EventType.VERIFICATION_FAILED,
                source_agent_id=g.get("authenticated_agent_id"),
                data={
                    "hill_id": hill_id,
                    "ownership_status": own_st.value,
                    "health_status": h_st.value,
                    "details": det,
                },
            )
        )

        return jsonify({
            "hill_id": hill_id,
            "ownership_status": own_st.value,
            "health_status": h_st.value,
            "details": det,
        })

    @bp.route("/api/agent/<agent_id>/llm", methods=["GET"])
    def get_agent_llm_config_endpoint(agent_id: str):
        caller = g.get("authenticated_agent_id")
        # Strict isolation: One agent must never read another agent's LLM configuration
        if not caller or caller != agent_id:
            return jsonify({
                "error": "Forbidden",
                "message": f"Access denied: agent '{caller}' cannot access LLM configuration for '{agent_id}'",
            }), 403

        cfg = coordinator.llm_config_manager.get_config(agent_id, mask_secrets=True)
        return jsonify(cfg)

    @bp.route("/api/agent/<agent_id>/llm", methods=["POST"])
    def set_agent_llm_config_endpoint(agent_id: str):
        caller = g.get("authenticated_agent_id")
        # Strict isolation: One agent must never overwrite another agent's LLM configuration
        if not caller or caller != agent_id:
            return jsonify({
                "error": "Forbidden",
                "message": f"Access denied: agent '{caller}' cannot update LLM configuration for '{agent_id}'",
            }), 403

        data = request.get_json(force=True) or {}
        provider = data.get("provider", "none")
        endpoint = data.get("endpoint", "")
        model_id = data.get("model_id", "")
        api_key = data.get("api_key")
        enabled = bool(data.get("enabled", False))

        try:
            saved = coordinator.llm_config_manager.set_config(
                agent_id=agent_id,
                provider=provider,
                endpoint=endpoint,
                model_id=model_id,
                api_key=api_key,
                enabled=enabled,
            )
            coordinator.db_manager.record_audit_event(
                event_type="LLM_CONFIG_UPDATED",
                actor=g.get("authenticated_username") or caller,
                target=agent_id,
                details={
                    "agent_id": agent_id,
                    "provider": provider,
                    "model_id": model_id,
                    "enabled": enabled,
                    "endpoint": endpoint,
                },
            )
            return jsonify(saved)
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

    @bp.route("/api/agent/<agent_id>/llm/test", methods=["POST"])
    def test_agent_llm_connection_endpoint(agent_id: str):
        caller = g.get("authenticated_agent_id")
        if not caller or caller != agent_id:
            return jsonify({
                "error": "Forbidden",
                "message": f"Access denied: agent '{caller}' cannot test LLM configuration for '{agent_id}'",
            }), 403

        data = request.get_json(force=True) or {}
        # Allow testing unsaved overrides or stored config
        raw_cfg = coordinator.llm_config_manager.get_raw_config(agent_id)
        if not raw_cfg:
            raw_cfg = AgentLLMConfig(agent_id=agent_id)

        provider = data.get("provider", raw_cfg.provider)
        endpoint = data.get("endpoint", raw_cfg.endpoint)
        model_id = data.get("model_id", raw_cfg.model_id)
        api_key = data.get("api_key")
        if api_key is None or "..." in api_key or api_key == "***":
            api_key = raw_cfg.api_key
        enabled = bool(data.get("enabled", raw_cfg.enabled))

        test_cfg = AgentLLMConfig(
            agent_id=agent_id,
            provider=provider,
            endpoint=endpoint,
            model_id=model_id,
            api_key=api_key or "",
            enabled=enabled,
        )

        client = AgentLLMClient(test_cfg, timeout_seconds=6.0)
        success, message, latency_ms = client.test_connection()

        new_status = "CONNECTED" if success else "FAILED"
        if not enabled:
            new_status = "DISABLED"
        coordinator.llm_config_manager.update_connection_status(
            agent_id=agent_id,
            status=new_status,
            error_message="" if success else message,
        )

        coordinator.db_manager.record_audit_event(
            event_type="LLM_CONNECTION_TESTED",
            actor=g.get("authenticated_username") or caller,
            target=agent_id,
            details={
                "agent_id": agent_id,
                "provider": provider,
                "model_id": model_id,
                "success": success,
                "status": new_status,
                "latency_ms": latency_ms,
            },
        )

        return jsonify({
            "success": success,
            "status": new_status,
            "message": message,
            "latency_ms": latency_ms,
        })

    @bp.route("/api/swarm/shutdown", methods=["POST"])
    def shutdown_endpoint():
        if g.get("authenticated_role") != AgentRole.OPERATOR:
            return jsonify({
                "error": "Forbidden",
                "message": "Operator privileges required to shutdown coordinator",
            }), 403
        coordinator.stop_background_maintenance()
        return jsonify({"status": "SHUTDOWN_INITIATED"})

    # --------------------------------------------------------------------------
    # COMPETITION & MULTI-MODE PLATFORM ENDPOINTS (KOTH & RED VS BLUE)
    # --------------------------------------------------------------------------

    @bp.route("/api/competitions", methods=["GET"])
    def list_competitions_endpoint():
        comps = coordinator.competition_manager.list_competitions()
        return jsonify({"competitions": comps})

    @bp.route("/api/competitions", methods=["POST"])
    def create_competition_endpoint():
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"error": "Missing competition name"}), 400

        mode = data.get("mode", "KOTH").upper()
        comp_format = data.get("format", "SINGLE_HILL").upper()
        description = data.get("description", "").strip()
        duration_minutes = int(data.get("duration_minutes", 60))
        rules = data.get("rules", {})
        creator = g.get("authenticated_username") or "admin"
        cid = data.get("competition_id")

        comp = coordinator.competition_manager.create_competition(
            name=name,
            mode=mode,
            format=comp_format,
            description=description,
            duration_minutes=duration_minutes,
            rules=rules,
            created_by=creator,
            competition_id=cid,
        )

        # Enroll initial teams if provided
        teams_payload = data.get("teams", [])
        for t in teams_payload:
            t_id = t.get("team_id") or t.get("name", "").lower().replace(" ", "_")
            t_name = t.get("name") or t.get("team_name") or t_id
            t_side = t.get("side", "NEUTRAL").upper()
            coordinator.competition_manager.enroll_team(
                competition_id=comp.competition_id,
                team_id=t_id,
                team_name=t_name,
                side=t_side,
            )

        # Provision hills if provided
        hills_payload = data.get("hills", [])
        for h in hills_payload:
            hid = int(h.get("hill_id", 1))
            hname = h.get("name", f"Hill {hid}")
            env_type = h.get("environment_type", "LINUX").upper()
            thost = h.get("target_host", "127.0.0.1")
            tport = int(h.get("target_port", 80))
            sname = h.get("service_name", "service")
            pts_interval = int(h.get("points_per_interval", 10))
            cap_pts = int(h.get("capture_points", 100))
            flag = h.get("flag") or h.get("flag_token")
            vtype = h.get("verifier_type", "SIMULATED").upper()
            vend = h.get("verifier_endpoint", "")
            init_owner = h.get("initial_owner_team_id")
            init_side = h.get("initial_owner_side")

            coordinator.competition_manager.add_hill(
                competition_id=comp.competition_id,
                hill_id=hid,
                name=hname,
                environment_type=env_type,
                target_host=thost,
                target_port=tport,
                service_name=sname,
                initial_owner_team_id=init_owner,
                initial_owner_side=init_side,
                points_per_interval=pts_interval,
                capture_points=cap_pts,
                flag=flag,
                verifier_type=vtype,
                verifier_endpoint=vend,
            )

        return jsonify({
            "success": True,
            "competition": comp.to_dict(),
            "message": f"Competition '{comp.name}' created successfully.",
        }), 201

    @bp.route("/api/competition/<competition_id>", methods=["GET"])
    def get_competition_endpoint(competition_id):
        comp = coordinator.competition_manager.get_competition(competition_id)
        if not comp:
            return jsonify({"error": "Competition not found"}), 404
        return jsonify({"competition": comp.to_dict()})

    @bp.route("/api/competition/<competition_id>/start", methods=["POST"])
    def start_competition_endpoint(competition_id):
        ok = coordinator.competition_manager.start_competition(competition_id)
        if not ok:
            return jsonify({"error": "Failed to start competition"}), 400
        return jsonify({"success": True, "message": f"Competition {competition_id} is now ACTIVE."})

    @bp.route("/api/competition/<competition_id>/pause", methods=["POST"])
    def pause_competition_endpoint(competition_id):
        ok = coordinator.competition_manager.pause_competition(competition_id)
        if not ok:
            return jsonify({"error": "Failed to pause competition"}), 400
        return jsonify({"success": True, "message": f"Competition {competition_id} is PAUSED."})

    @bp.route("/api/competition/<competition_id>/complete", methods=["POST"])
    def complete_competition_endpoint(competition_id):
        ok = coordinator.competition_manager.complete_competition(competition_id)
        if not ok:
            return jsonify({"error": "Failed to complete competition"}), 400
        return jsonify({"success": True, "message": f"Competition {competition_id} marked COMPLETED."})

    @bp.route("/api/competition/<competition_id>/tick", methods=["POST"])
    def competition_tick_endpoint(competition_id):
        result = coordinator.competition_manager.process_tick(competition_id)
        return jsonify(result)

    @bp.route("/api/competition/<competition_id>/teams", methods=["GET"])
    def get_competition_teams_endpoint(competition_id):
        teams = coordinator.competition_manager.get_competition_teams(competition_id)
        return jsonify({"teams": [t.to_dict() for t in teams]})

    @bp.route("/api/competition/<competition_id>/teams/enroll", methods=["POST"])
    @bp.route("/api/competition/<competition_id>/join", methods=["POST"])
    def enroll_competition_team_endpoint(competition_id):
        data = request.get_json(silent=True) or {}
        team_id = data.get("team_id")
        if not team_id and g.get("team_member"):
            team_id = g.team_member.get("team_id")
        team_name = data.get("team_name") or team_id
        side = data.get("side", "NEUTRAL")
        if not team_id:
            return jsonify({"error": "Missing team_id"}), 400
        ok = coordinator.competition_manager.enroll_team(
            competition_id=competition_id,
            team_id=team_id,
            team_name=team_name,
            side=side,
        )
        return jsonify({"success": ok, "message": f"Team {team_id} joined competition on side {side}."})

    @bp.route("/api/competition/<competition_id>/access", methods=["GET"])
    def verify_competition_access_endpoint(competition_id):
        caller_team_id = None
        if g.get("team_member"):
            caller_team_id = g.team_member.get("team_id")
        else:
            caller_team_id = request.args.get("team_id")

        if not caller_team_id:
            return jsonify({"authorized": False, "error": "No authenticated team identity provided"}), 401

        authorized, reason, data = coordinator.competition_manager.verify_competition_access(
            competition_id=competition_id,
            team_id=caller_team_id,
        )
        if not authorized:
            return jsonify({"authorized": False, "error": reason}), 403

        return jsonify({
            "authorized": True,
            "team_id": caller_team_id,
            "data": data,
        })

    @bp.route("/api/competition/<competition_id>/hills", methods=["GET"])
    def get_competition_hills_endpoint(competition_id):
        hills = coordinator.competition_manager.get_competition_hills(competition_id)
        viewer_team_id = None
        viewer_side = None
        if g.get("team_member"):
            viewer_team_id = g.team_member.get("team_id")
            team_obj = coordinator.competition_manager.get_team(competition_id, viewer_team_id)
            if team_obj:
                viewer_side = team_obj.side

        safe_hills = [h.to_safe_dict(viewer_team_id=viewer_team_id, viewer_side=viewer_side) for h in hills]
        return jsonify({"hills": safe_hills})

    @bp.route("/api/competition/<competition_id>/hill/<int:hill_id>/notes", methods=["POST"])
    def update_hill_notes_endpoint(competition_id, hill_id):
        data = request.get_json(silent=True) or {}
        notes = data.get("notes", "")
        caller_team_id = None
        if g.get("team_member"):
            caller_team_id = g.team_member.get("team_id")
        else:
            caller_team_id = data.get("team_id")

        if not caller_team_id:
            return jsonify({"error": "Team identification required"}), 400

        ok = coordinator.competition_manager.update_hill_defense_notes(
            competition_id=competition_id,
            hill_id=hill_id,
            team_id=caller_team_id,
            notes=notes,
        )
        if not ok:
            return jsonify({"error": "Cannot update notes: you do not currently hold this hill"}), 403
        return jsonify({"success": True, "message": "Defense notes updated."})

    @bp.route("/api/competition/<competition_id>/capture", methods=["POST"])
    def submit_competition_capture_endpoint(competition_id):
        data = request.get_json(silent=True) or {}
        hill_id = data.get("hill_id")
        flag = data.get("flag") or data.get("flag_token")
        if hill_id is None or not flag:
            return jsonify({"error": "Missing hill_id or flag token"}), 400

        caller_team_id = None
        caller_agent_id = None
        if g.get("team_member"):
            caller_team_id = g.team_member.get("team_id")
            caller_agent_id = g.team_member.get("agent_id")
        else:
            caller_team_id = data.get("team_id") or "null_warriors"
            caller_agent_id = data.get("agent_id") or g.get("authenticated_agent_id") or "agent-01"

        success, msg, submission = coordinator.competition_manager.submit_capture(
            competition_id=competition_id,
            hill_id=int(hill_id),
            team_id=caller_team_id,
            agent_id=caller_agent_id,
            flag=str(flag),
        )

        coordinator.db_manager.record_audit_event(
            event_type="COMPETITION_CAPTURE_ATTEMPT",
            actor=g.get("authenticated_username") or caller_agent_id,
            target=f"hill-{hill_id}",
            details={"competition_id": competition_id, "success": success, "message": msg},
        )

        if not success:
            return jsonify({"success": False, "message": msg}), 400

        etype = EventType.HILL_RECAPTURED if "recapture" in msg.lower() else EventType.HILL_CAPTURED
        coordinator.event_bus.publish(
            SwarmEvent(
                event_type=etype,
                source_agent_id=caller_agent_id,
                team_id=caller_team_id,
                data={
                    "hill_id": int(hill_id),
                    "competition_id": competition_id,
                    "team_id": caller_team_id,
                    "agent_id": caller_agent_id,
                    "message": msg,
                },
            )
        )

        return jsonify({
            "success": True,
            "message": msg,
            "submission": submission.to_dict() if submission else None,
        })

    @bp.route("/api/competition/<competition_id>/defense", methods=["POST"])
    def submit_competition_defense_endpoint(competition_id):
        data = request.get_json(silent=True) or {}
        hill_id = data.get("hill_id")
        patch_summary = data.get("patch_summary", "Service patched and verified")
        service_status = data.get("service_status", "HEALTHY")
        if hill_id is None:
            return jsonify({"error": "Missing hill_id"}), 400

        caller_team_id = None
        caller_agent_id = None
        if g.get("team_member"):
            caller_team_id = g.team_member.get("team_id")
            caller_agent_id = g.team_member.get("agent_id")
        else:
            caller_team_id = data.get("team_id") or "null_warriors"
            caller_agent_id = data.get("agent_id") or g.get("authenticated_agent_id") or "agent-02"

        success, msg, submission = coordinator.competition_manager.submit_defense(
            competition_id=competition_id,
            hill_id=int(hill_id),
            team_id=caller_team_id,
            agent_id=caller_agent_id,
            patch_summary=patch_summary,
            service_status=service_status,
        )

        coordinator.db_manager.record_audit_event(
            event_type="COMPETITION_DEFENSE_SUBMISSION",
            actor=g.get("authenticated_username") or caller_agent_id,
            target=f"hill-{hill_id}",
            details={"competition_id": competition_id, "success": success, "message": msg},
        )

        if not success:
            coordinator.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.VERIFICATION_FAILED,
                    source_agent_id=caller_agent_id,
                    team_id=caller_team_id,
                    data={
                        "hill_id": int(hill_id),
                        "competition_id": competition_id,
                        "team_id": caller_team_id,
                        "agent_id": caller_agent_id,
                        "error": msg,
                    },
                )
            )
            return jsonify({"success": False, "message": msg}), 400

        coordinator.event_bus.publish(
            SwarmEvent(
                event_type=EventType.VERIFICATION_SUCCESS,
                source_agent_id=caller_agent_id,
                team_id=caller_team_id,
                data={
                    "hill_id": int(hill_id),
                    "competition_id": competition_id,
                    "team_id": caller_team_id,
                    "agent_id": caller_agent_id,
                    "patch_summary": patch_summary,
                    "service_status": service_status,
                },
            )
        )

        return jsonify({
            "success": True,
            "message": msg,
            "submission": submission.to_dict() if submission else None,
        })

    @bp.route("/api/competition/<competition_id>/leaderboard", methods=["GET"])
    def get_competition_leaderboard_endpoint(competition_id):
        board = coordinator.competition_manager.get_leaderboard(competition_id)
        return jsonify(board)

    @bp.route("/api/competition/<competition_id>/history", methods=["GET"])
    def get_competition_history_endpoint(competition_id):
        hill_id = request.args.get("hill_id", type=int)
        history = coordinator.competition_manager.get_ownership_history(competition_id, hill_id=hill_id)
        return jsonify({"history": history})

    return bp
