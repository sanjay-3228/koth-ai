"""
Swarm Client running on each worker agent (agent-01 through agent-04).
Supports both in-memory direct transport (rehearsal/fast integration) and HTTP REST (physical LAN).
Handles coordinator disconnect by entering SAFE_DEGRADED mode.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

from agent.config import config
from agent.swarm.models import (
    AgentHeartbeat,
    AgentStatus,
    Phase,
    PhaseState,
    Task,
    TaskLease,
)

logger = logging.getLogger("koth.swarm.client")


class SwarmClient:
    """
    Client interface for an individual koth-agent instance to communicate with the swarm coordinator.
    """

    def __init__(
        self,
        agent_id: str,
        team_id: str = "null_warriors",
        coordinator: Optional[Any] = None,
        coordinator_url: Optional[str] = None,
        heartbeat_interval: float = 3.0,
        request_timeout: float = 3.0,
        auth_token: Optional[str] = None,
        agent_credential: Optional[str] = None,
        ca_cert: Optional[str] = None,
        use_tls: Optional[bool] = None,
        username: Optional[str] = None,
    ):
        self.agent_id = agent_id
        self.username = username
        self.team_id = team_id
        self.coordinator = coordinator  # SwarmCoordinator direct ref if in-process
        self.coordinator_url = coordinator_url.rstrip("/") if coordinator_url else None
        self.heartbeat_interval = heartbeat_interval
        self.request_timeout = request_timeout
        self.auth_token = auth_token if auth_token is not None else getattr(config, "swarm_auth_token", "")
        if use_tls is not None:
            self.use_tls = use_tls
        elif self.coordinator_url and self.coordinator_url.startswith("https://"):
            self.use_tls = True
        else:
            self.use_tls = getattr(config, "use_tls", False)

        # Insecure downgrade guard: If use_tls is enabled, coordinator_url must NOT be cleartext http://
        if self.coordinator_url and self.use_tls and self.coordinator_url.startswith("http://"):
            raise ValueError("Insecure HTTP transport rejected: TLS is required (no silent downgrade)")

        # Authenticated agent credential
        self.ca_cert: Optional[str] = ca_cert if ca_cert is not None else getattr(config, "ca_cert", None)
        if agent_credential is not None:
            self.agent_credential = agent_credential
        else:
            agent_tok = getattr(config, "agent_token", None)
            if agent_tok:
                self.agent_credential = agent_tok
            elif self.auth_token:
                self.agent_credential = hmac.new(
                    self.auth_token.encode("utf-8"),
                    self.agent_id.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
            else:
                self.agent_credential = ""

        self.session_token: Optional[str] = None
        self.coordinator_instance_id: Optional[str] = None

        self._lock = threading.RLock()
        self.status = AgentStatus.STARTING
        self.current_phase_state = PhaseState(
            phase=Phase.UNKNOWN, round_id=0, phase_epoch=0, source="client_init"
        )
        self.current_task: Optional[Task] = None
        self.current_lease: Optional[TaskLease] = None
        self.consecutive_failed_syncs = 0
        self.kill_switch_active = False

        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.session_token:
            headers["X-Session-Token"] = self.session_token
            headers["Authorization"] = f"Bearer {self.session_token}"
        elif self.agent_credential:
            headers["X-Agent-Credential"] = self.agent_credential
            headers["Authorization"] = f"Bearer {self.agent_credential}"
        elif self.auth_token:
            headers["X-Swarm-Token"] = self.auth_token
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _verify_setting(self) -> Any:
        if self.coordinator_url and self.coordinator_url.startswith("https://"):
            if self.ca_cert:
                return self.ca_cert
            # Strictly enforce certificate validation using system CA store.
            # Disabling certificate verification (verify=False) is strictly forbidden.
            return True
        return None

    def _handle_unauthorized(self) -> None:
        with self._lock:
            logger.warning(
                f"[{self.agent_id}] Session invalidated (401 Unauthorized). "
                "Reverting to SAFE_DEGRADED / HOLD."
            )
            self.session_token = None
            self.current_task = None
            self.current_lease = None
            self.status = AgentStatus.SAFE_DEGRADED
            self.current_phase_state = PhaseState(
                phase=Phase.HOLD,
                round_id=self.current_phase_state.round_id,
                phase_epoch=self.current_phase_state.phase_epoch,
                ttl_seconds=0.0,
                source="session_invalidation",
            )

    @property
    def current_phase(self) -> Phase:
        with self._lock:
            # If coordinator failed repeatedly or phase is expired -> HOLD
            if self.consecutive_failed_syncs >= 3 or self.current_phase_state.is_expired():
                return Phase.HOLD
            return self.current_phase_state.phase

    def login_with_username(self) -> bool:
        """Authenticate with the coordinator using a roster username in rehearsal mode."""
        if not self.username or not self.coordinator_url:
            return False
        try:
            import requests
            resp = requests.post(
                f"{self.coordinator_url}/api/swarm/login",
                json={"username": self.username},
                timeout=self.request_timeout,
                verify=self._verify_setting(),
            )
            if resp.status_code != 200:
                logger.warning(f"[{self.username}] Username login rejected ({resp.status_code}): {resp.text}")
                return False
            data = resp.json()
            if data.get("role") != "WORKER":
                logger.warning(f"[{self.username}] Username is not a worker account")
                return False
            self.agent_id = data["agent_id"]
            self.session_token = data.get("session_token")
            self.coordinator_instance_id = data.get("coordinator_instance_id")
            if data.get("phase"):
                self.current_phase_state = PhaseState.from_dict(data["phase"])
            logger.info(f"[{self.username}] Logged in as {self.agent_id}")
            return True
        except Exception as e:
            logger.error(f"[{self.username}] Username login failed: {e}")
            return False

    def register(self, role: str = "WORKER") -> bool:
        """Explicitly register worker with coordinator."""
        payload = {
            "agent_id": self.agent_id,
            "team_id": self.team_id,
            "role": role,
            "credential": self.agent_credential,
            "session_token": self.session_token,
        }
        try:
            if self.coordinator:
                hb = AgentHeartbeat(
                    agent_id=self.agent_id,
                    team_id=self.team_id,
                    status=AgentStatus.READY,
                    current_phase=self.coordinator.get_phase().phase,
                    phase_epoch=self.coordinator.get_phase().phase_epoch,
                    metadata={"role": role},
                )
                self.coordinator.record_heartbeat(hb)
                self.status = AgentStatus.READY
                return True
            elif self.coordinator_url:
                import requests

                resp = requests.post(
                    f"{self.coordinator_url}/api/swarm/register",
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self.session_token = data.get("session_token")
                    self.coordinator_instance_id = data.get("coordinator_instance_id")
                    if "phase" in data:
                        with self._lock:
                            self.current_phase_state = PhaseState.from_dict(data["phase"])
                    self.status = AgentStatus.READY
                    logger.info(f"[{self.agent_id}] Registered with coordinator {self.coordinator_url}")
                    return True
                else:
                    logger.warning(
                        f"[{self.agent_id}] Registration rejected ({resp.status_code}): {resp.text}"
                    )
                    return False
            return False
        except Exception as e:
            logger.error(f"[{self.agent_id}] Registration failed: {e}")
            return False

    def sync_phase(self) -> PhaseState:
        """Fetch authoritative phase from coordinator with fail-safe HOLD fallback."""
        try:
            if self.coordinator:
                state = self.coordinator.get_phase()
            elif self.coordinator_url:
                import requests

                resp = requests.get(
                    f"{self.coordinator_url}/api/swarm/phase",
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if resp.status_code == 401:
                    self._handle_unauthorized()
                    raise RuntimeError(f"HTTP error {resp.status_code} fetching phase: session unauthorized")
                elif resp.status_code == 200:
                    state = PhaseState.from_dict(resp.json())
                else:
                    raise RuntimeError(f"HTTP error {resp.status_code} fetching phase")
            else:
                raise ValueError("No coordinator or coordinator_url configured")

            with self._lock:
                old_phase = self.current_phase_state.phase
                old_epoch = self.current_phase_state.phase_epoch
                self.consecutive_failed_syncs = 0
                if self.status == AgentStatus.SAFE_DEGRADED:
                    self.status = AgentStatus.READY

                # Stale phase check: if TTL is expired, fallback to HOLD
                if state.is_expired():
                    logger.warning(
                        f"[{self.agent_id}] phase state expired (ttl={state.ttl_seconds}s). Fallback to HOLD."
                    )
                    state.phase = Phase.HOLD

                self.current_phase_state = state

                if old_phase != state.phase or old_epoch != state.phase_epoch:
                    logger.info(f"[{self.agent_id}] phase={state.phase.value} epoch={state.phase_epoch}")
                    # Release in-flight task on phase shift
                    if old_phase != state.phase and self.current_task:
                        logger.info(
                            f"[{self.agent_id}] Phase changed from {old_phase.value} to {state.phase.value}. "
                            f"Dropping in-flight task {self.current_task.task_id}"
                        )
                        self.current_task = None
                        self.current_lease = None

                return state

        except Exception as e:
            with self._lock:
                self.consecutive_failed_syncs += 1
                logger.warning(
                    f"Agent {self.agent_id} failed to sync phase ({self.consecutive_failed_syncs} consecutive): {e}"
                )
                if self.consecutive_failed_syncs >= 3:
                    if self.status != AgentStatus.SAFE_DEGRADED:
                        logger.error(
                            f"Coordinator unavailable. Agent {self.agent_id} falling back to SAFE_DEGRADED (HOLD mode)."
                        )
                    self.status = AgentStatus.SAFE_DEGRADED
                    self.current_phase_state = PhaseState(
                        phase=Phase.HOLD,
                        round_id=self.current_phase_state.round_id,
                        phase_epoch=self.current_phase_state.phase_epoch,
                        ttl_seconds=0.0,
                        source="safe_degraded_fallback",
                    )
                    logger.info(f"[{self.agent_id}] phase=HOLD epoch={self.current_phase_state.phase_epoch}")
            return self.current_phase_state

    def send_heartbeat(self) -> bool:
        """Send agent heartbeat beacon to coordinator."""
        with self._lock:
            task_id = self.current_task.task_id if self.current_task else None
            target = self.current_task.target_host if self.current_task else None
            hb = AgentHeartbeat(
                agent_id=self.agent_id,
                team_id=self.team_id,
                status=self.status,
                current_phase=self.current_phase_state.phase,
                phase_epoch=self.current_phase_state.phase_epoch,
                current_task_id=task_id,
                current_target=target,
                timestamp=time.time(),
            )

        try:
            if self.coordinator:
                resp = self.coordinator.record_heartbeat(hb)
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/heartbeat",
                    json=hb.to_dict(),
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return False
                elif r.status_code == 200:
                    resp = r.json()
                else:
                    return False
            else:
                return False

            if resp.get("kill_switch"):
                self.kill_switch_active = True
                self.status = AgentStatus.SAFE_HOLD

            if "phase" in resp:
                new_state = PhaseState.from_dict(resp["phase"])
                with self._lock:
                    self.current_phase_state = new_state
            return True

        except Exception as e:
            logger.debug(f"Heartbeat send failed for {self.agent_id}: {e}")
            return False

    def request_task(self) -> Tuple[Optional[Task], Optional[TaskLease]]:
        """Request next eligible task for the current phase from coordinator."""
        if self.kill_switch_active or self.status == AgentStatus.SAFE_DEGRADED:
            return None, None

        phase_state = self.sync_phase()
        if phase_state.phase in (Phase.HOLD, Phase.UNKNOWN):
            return None, None

        payload = {
            "agent_id": self.agent_id,
            "phase": phase_state.phase.value,
            "phase_epoch": phase_state.phase_epoch,
        }

        try:
            if self.coordinator:
                resp = self.coordinator.request_task(
                    self.agent_id, phase_state.phase, phase_state.phase_epoch
                )
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/task/request",
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return None, None
                resp = r.json() if r.status_code == 200 else {}
            else:
                return None, None

            task_dict = resp.get("task")
            lease_dict = resp.get("lease")
            if task_dict and lease_dict:
                task = Task.from_dict(task_dict)
                lease = TaskLease.from_dict(lease_dict)
                with self._lock:
                    self.current_task = task
                    self.current_lease = lease
                    self.status = AgentStatus.RUNNING
                return task, lease
            return None, None

        except Exception as e:
            logger.error(f"Error requesting task from coordinator: {e}")
            return None, None

    def claim_task(self, task_id: str) -> Tuple[Optional[Task], Optional[TaskLease]]:
        """Claim a specific task by task_id with mutual exclusion."""
        if self.kill_switch_active or self.status == AgentStatus.SAFE_DEGRADED:
            return None, None

        phase_state = self.sync_phase()
        if phase_state.phase in (Phase.HOLD, Phase.UNKNOWN):
            return None, None

        payload = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "phase": phase_state.phase.value,
            "phase_epoch": phase_state.phase_epoch,
        }

        try:
            if self.coordinator:
                resp = self.coordinator.claim_task(
                    task_id, self.agent_id, phase_state.phase, phase_state.phase_epoch
                )
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/task/claim",
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return None, None
                resp = r.json() if r.status_code == 200 else {}
            else:
                return None, None

            task_dict = resp.get("task")
            lease_dict = resp.get("lease")
            if task_dict and lease_dict:
                task = Task.from_dict(task_dict)
                lease = TaskLease.from_dict(lease_dict)
                with self._lock:
                    self.current_task = task
                    self.current_lease = lease
                    self.status = AgentStatus.RUNNING
                return task, lease
            return None, None

        except Exception as e:
            logger.error(f"Error claiming task {task_id} from coordinator: {e}")
            return None, None

    def renew_lease(self) -> bool:
        with self._lock:
            if not self.current_lease:
                return False
            lid = self.current_lease.lease_id

        try:
            if self.coordinator:
                return self.coordinator.renew_lease(lid, self.agent_id)
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/task/renew",
                    json={"lease_id": lid, "agent_id": self.agent_id},
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return False
                return bool(r.status_code == 200 and r.json().get("success"))
            return False
        except Exception:
            return False

    def complete_task(self, result: Optional[Dict[str, Any]] = None) -> bool:
        with self._lock:
            if not self.current_task:
                return False
            tid = self.current_task.task_id

        try:
            if self.coordinator:
                res = self.coordinator.complete_task(tid, self.agent_id, result)
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/task/complete",
                    json={"task_id": tid, "agent_id": self.agent_id, "result": result},
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return False
                res = bool(r.status_code == 200 and r.json().get("success"))
            else:
                res = False

            with self._lock:
                if res:
                    self.current_task = None
                    self.current_lease = None
                    self.status = AgentStatus.READY
            return res
        except Exception as e:
            logger.error(f"Error completing task {tid}: {e}")
            return False

    def fail_task(self, error: str, retryable: bool = True) -> bool:
        with self._lock:
            if not self.current_task:
                return False
            tid = self.current_task.task_id

        try:
            if self.coordinator:
                res = self.coordinator.fail_task(tid, self.agent_id, error, retryable)
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/task/fail",
                    json={
                        "task_id": tid,
                        "agent_id": self.agent_id,
                        "error": error,
                        "retryable": retryable,
                    },
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return False
                res = bool(r.status_code == 200 and r.json().get("success"))
            else:
                res = False

            with self._lock:
                self.current_task = None
                self.current_lease = None
                self.status = AgentStatus.READY
            return res
        except Exception as e:
            logger.error(f"Error failing task {tid}: {e}")
            return False

    def release_current_work(self) -> None:
        """Drop current work locally without marking completed (e.g. on phase shift)."""
        with self._lock:
            self.current_task = None
            self.current_lease = None
            if self.status == AgentStatus.RUNNING:
                self.status = AgentStatus.READY

    def start_heartbeat_loop(self) -> None:
        if self._running:
            return
        self._running = True

        def _loop():
            while self._running:
                try:
                    self.send_heartbeat()
                except Exception as e:
                    logger.debug(f"Heartbeat loop error: {e}")
                time.sleep(self.heartbeat_interval)

        self._heartbeat_thread = threading.Thread(
            target=_loop, name=f"hb-client-{self.agent_id}", daemon=True
        )
        self._heartbeat_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=2.0)
        self.status = AgentStatus.STOPPED

    def update_shared_state(self, payload: Dict[str, Any]) -> bool:
        """Post shared telemetry/intelligence update to coordinator."""
        # Enforce authenticated agent identity on outgoing mutations
        if "compromise" in payload and isinstance(payload["compromise"], dict):
            payload["compromise"]["agent_id"] = self.agent_id
        if "patch" in payload and isinstance(payload["patch"], dict):
            payload["patch"]["agent_id"] = self.agent_id
        if "flag" in payload and isinstance(payload["flag"], dict):
            payload["flag"]["agent_id"] = self.agent_id

        try:
            if self.coordinator:
                if "scan" in payload:
                    s = payload["scan"]
                    self.coordinator.shared_state.record_host_scan(
                        s["host"], s["ports"], os_hint=s.get("os"), metadata=s.get("metadata")
                    )
                if "compromise" in payload:
                    c = payload["compromise"]
                    self.coordinator.shared_state.record_compromise(
                        c["host"], self.agent_id, details=c.get("details")
                    )
                if "patch" in payload:
                    p = payload["patch"]
                    self.coordinator.shared_state.record_patch(
                        p["service_or_host"], self.agent_id, details=p.get("details")
                    )
                if "flag" in payload:
                    f = payload["flag"]
                    self.coordinator.shared_state.record_flag(
                        flag_hash=f["flag_hash"],
                        agent_id=self.agent_id,
                        round_id=int(f.get("round_id", 1)),
                    )
                if "metadata" in payload:
                    for k, v in payload["metadata"].items():
                        self.coordinator.shared_state.set_metadata(k, v)
                return True
            elif self.coordinator_url:
                import requests

                r = requests.post(
                    f"{self.coordinator_url}/api/swarm/shared-state",
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return False
                return bool(r.status_code == 200 and r.json().get("success"))
            return False
        except Exception as e:
            logger.error(f"Error updating shared state: {e}")
            return False

    def get_shared_state(self) -> Optional[Dict[str, Any]]:
        """Fetch current shared intelligence snapshot from coordinator."""
        try:
            if self.coordinator:
                return self.coordinator.shared_state.get_snapshot()
            elif self.coordinator_url:
                import requests

                r = requests.get(
                    f"{self.coordinator_url}/api/swarm/shared-state",
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return None
                return r.json() if r.status_code == 200 else None
            return None
        except Exception as e:
            logger.error(f"Error getting shared state: {e}")
            return None

    def get_coordinator_status(self) -> Optional[Dict[str, Any]]:
        """Fetch overall swarm status from coordinator."""
        try:
            if self.coordinator:
                return self.coordinator.get_swarm_status()
            elif self.coordinator_url:
                import requests

                r = requests.get(
                    f"{self.coordinator_url}/api/swarm/status",
                    headers=self._get_headers(),
                    timeout=self.request_timeout,
                    verify=self._verify_setting(),
                )
                if r.status_code == 401:
                    self._handle_unauthorized()
                    return None
                return r.json() if r.status_code == 200 else None
            return None
        except Exception as e:
            logger.error(f"Error getting coordinator status: {e}")
            return None
