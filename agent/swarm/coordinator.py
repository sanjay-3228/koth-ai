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

        self.kill_switch_active = False
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
                )

    def trigger_kill_switch(self, triggered_by: str, reason: str = "Operator manual kill") -> None:
        with self._lock:
            self.kill_switch_active = True
            logger.critical(f"KILL SWITCH TRIGGERED by {triggered_by}: {reason}")
            self.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.KILL_SWITCH_TRIGGERED,
                    source_agent_id=triggered_by,
                    data={"reason": reason, "timestamp": time.time()},
                )
            )
            # Invalidate all leases immediately
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

    def get_swarm_status(self) -> Dict[str, Any]:
        """Return comprehensive status for dashboard and CLI monitoring."""
        with self._lock:
            phase_state = self.get_phase()
            heartbeats = self.heartbeat_monitor.get_all_heartbeats()
            active_leases = self.lease_manager.get_active_leases()
            all_tasks = self.task_manager.get_all_tasks()

            agent_states = {}
            for aid in self.authorized_agents:
                hb = heartbeats.get(aid)
                alive = self.heartbeat_monitor.is_agent_alive(aid)
                hb_data = hb.to_dict() if hb else None
                current_task_id = hb.current_task_id if hb else None
                current_target = hb.current_target if hb else None
                task = self.task_manager.get_task(current_task_id) if current_task_id else None
                agent_states[aid] = {
                    "username": self.agent_usernames.get(aid, aid),
                    "alive": alive,
                    "status": (hb.status.value if hb else (AgentStatus.DISCONNECTED.value if not alive else AgentStatus.READY.value)),
                    "phase": (hb.current_phase.value if hb else phase_state.phase.value),
                    "phase_epoch": (hb.phase_epoch if hb else phase_state.phase_epoch),
                    "current_task_id": current_task_id,
                    "current_target": current_target,
                    "current_task_type": task.task_type.value if task else None,
                    "task_status": task.status.value if task else None,
                    "last_heartbeat": self.heartbeat_monitor._last_seen.get(aid),
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
        # Unprotected endpoints (health check)
        if request.path in ("/healthz", "/api/swarm/healthz") or request.endpoint in (
            "swarm_coordinator.healthz_endpoint",
            "swarm_coordinator.root_endpoint",
        ):
            return None

        # Registration endpoint handles its own per-agent credential verification
        if request.endpoint in ("swarm_coordinator.register_endpoint", "swarm_coordinator.login_endpoint"):
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

        # If coordinator has no auth required at all (mock/in-memory test mode)
        if not coordinator.auth_token and not coordinator.operator_token and not coordinator.agent_tokens:
            g.authenticated_role = AgentRole.OPERATOR
            g.authenticated_agent_id = "operator"
            g.session = None
            return None

        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication required: missing session token or operator token",
            }), 401

        # Check if Operator Token
        if coordinator.operator_token and hmac.compare_digest(token, coordinator.operator_token):
            g.authenticated_role = AgentRole.OPERATOR
            g.authenticated_agent_id = "operator"
            g.session = None
            return None

        # Check if active Session Token
        session = coordinator.get_active_session(token)
        if session:
            session.last_heartbeat = time.time()
            g.authenticated_role = session.role
            g.authenticated_agent_id = session.agent_id
            g.session = session
            return None

        # Check legacy team token without operator token configured (treat as operator)
        if coordinator.auth_token and not coordinator.operator_token and hmac.compare_digest(token, coordinator.auth_token):
            g.authenticated_role = AgentRole.OPERATOR
            g.authenticated_agent_id = "operator"
            g.session = None
            return None

        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid, expired, or revoked session token",
        }), 401

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


        # Registration Validation 3: provisioned credential OR username-issued session
        session_token = request.headers.get("X-Session-Token") or data.get("session_token")
        login_session = coordinator.get_active_session(session_token) if session_token else None
        if login_session:
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

            # Registration Validation 4: Duplicate active registration prevention
            with coordinator._lock:
                existing_session_id = coordinator.agent_to_session.get(agent_id)
                if existing_session_id and existing_session_id in coordinator.active_sessions:
                    existing_sess = coordinator.active_sessions[existing_session_id]
                    is_alive = coordinator.heartbeat_monitor.is_agent_alive(agent_id)
                    if existing_sess.is_active() and is_alive:
                        logger.warning(
                            f"Registration rejected for agent '{agent_id}': duplicate active session {existing_session_id}"
                        )
                        return jsonify({
                            "error": "Conflict",
                            "message": f"Duplicate active registration: agent '{agent_id}' already has an active session",
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
            "username": coordinator.agent_usernames.get(g.get("authenticated_agent_id"), coordinator.admin_username),
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
        return jsonify({"success": success})

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

    @bp.route("/api/swarm/shutdown", methods=["POST"])
    def shutdown_endpoint():
        if g.get("authenticated_role") != AgentRole.OPERATOR:
            return jsonify({
                "error": "Forbidden",
                "message": "Operator privileges required to shutdown coordinator",
            }), 403
        coordinator.stop_background_maintenance()
        return jsonify({"status": "SHUTDOWN_INITIATED"})

    return bp
