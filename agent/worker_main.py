"""
KOTH Swarm — Distributed Remote Agent Worker
Standalone client application for remote agent PCs in a 5-PC LAN deployment.

Roles:
  - PC 1: Agent 01 — Leader/Coordinator
  - PC 2: Agent 02 — Specialist (Recon)
  - PC 3: Agent 03 — Specialist (Exploit)
  - PC 4: Agent 04 — Specialist (Defense)

Features:
  - Independent identity and authentication credential.
  - Zero direct database access: communicates strictly via authenticated REST APIs.
  - Real CPU and memory telemetry via heartbeats.
  - Interactive enrollment wizard or automated command-line arguments.
  - Reconnects automatically after temporary network failures or server restarts.
  - Fail-safe SAFE_DEGRADED (HOLD) mode when disconnected.
  - Coordination findings exchange with leader and specialists.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import platform
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

# Try importing psutil for real telemetry; fallback to standard metrics if unavailable
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("koth.agent_worker")

AGENT_ROLES = {
    "agent-01": {"title": "Leader / Swarm Coordinator", "hill": 1, "role": "LEADER"},
    "agent-02": {"title": "Reconnaissance Specialist", "hill": 2, "role": "MEMBER"},
    "agent-03": {"title": "Exploitation Specialist", "hill": 3, "role": "MEMBER"},
    "agent-04": {"title": "Defense & Hardening Specialist", "hill": 4, "role": "MEMBER"},
}

CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "KOTH Agent Worker"
CONFIG_FILE = CONFIG_DIR / "agent_config.json"


def get_system_telemetry() -> Dict[str, Any]:
    """Collect real system telemetry (CPU, RAM, OS info)."""
    cpu_percent = 0.0
    mem_percent = 0.0
    mem_used_mb = 0.0

    if HAS_PSUTIL:
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            mem_used_mb = round(mem.used / (1024 * 1024), 1)
        except Exception:
            pass

    return {
        "cpu_percent": cpu_percent,
        "memory_percent": mem_percent,
        "memory_used_mb": mem_used_mb,
        "platform": platform.platform(),
        "hostname": platform.node(),
    }


class RemoteAgentWorker:
    def __init__(
        self,
        coordinator_url: str,
        agent_id: str,
        team_id: str = "null_warriors",
        session_token: Optional[str] = None,
        agent_token: Optional[str] = None,
        ca_cert: Optional[str] = None,
        poll_interval: float = 1.0,
        heartbeat_interval: float = 3.0,
    ):
        self.coordinator_url = coordinator_url.rstrip("/")
        self.agent_id = agent_id
        self.team_id = team_id
        self.session_token = session_token
        self.agent_token = agent_token
        self.ca_cert = ca_cert
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval

        self.assigned_hill = AGENT_ROLES.get(agent_id, {}).get("hill", 1)
        self.role_title = AGENT_ROLES.get(agent_id, {}).get("title", "Specialist")

        self.status = "STARTING"
        self.current_phase = "HOLD"
        self.phase_epoch = 0
        self.round_id = 0
        self.current_task: Optional[Dict[str, Any]] = None
        self.current_lease: Optional[Dict[str, Any]] = None
        self.coordinator_instance_id: Optional[str] = None

        self.last_heartbeat_time = 0.0
        self.last_latency_ms = 0.0
        self.completed_tasks_count = 0
        self.failed_tasks_count = 0
        self.consecutive_connection_failures = 0

        self._running = False
        self._stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

    def _verify_setting(self) -> Any:
        if self.coordinator_url.startswith("https://"):
            if self.ca_cert and os.path.exists(self.ca_cert):
                return self.ca_cert
            return True
        return None

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.session_token:
            headers["X-Session-Token"] = self.session_token
            headers["Authorization"] = f"Bearer {self.session_token}"
        elif self.agent_token:
            headers["X-Agent-Credential"] = self.agent_token
            headers["Authorization"] = f"Bearer {self.agent_token}"
        return headers

    def test_connection(self) -> Tuple[bool, str]:
        """Test health endpoint of central coordinator."""
        try:
            t0 = time.time()
            resp = requests.get(
                f"{self.coordinator_url}/healthz",
                timeout=3.0,
                verify=self._verify_setting(),
            )
            self.last_latency_ms = round((time.time() - t0) * 1000, 1)
            if resp.status_code == 200:
                data = resp.json()
                self.coordinator_instance_id = data.get("coordinator_instance_id")
                return True, f"Reachable ({self.last_latency_ms}ms) — Team: {data.get('team_id')}, Phase: {data.get('phase')}"
            return False, f"Server returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Connection failed: {e}"

    def enroll_with_member_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        """Enroll agent via team member login."""
        try:
            url = f"{self.coordinator_url}/api/team/login"
            resp = requests.post(
                url,
                json={"username": username, "password": password, "team_id": self.team_id},
                timeout=5.0,
                verify=self._verify_setting(),
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("logged_in"):
                    self.session_token = data.get("session_token")
                    returned_agent_id = data.get("agent_id")
                    if returned_agent_id and returned_agent_id != self.agent_id:
                        logger.warning(
                            f"Account {username} is assigned to '{returned_agent_id}', updating agent ID from '{self.agent_id}'"
                        )
                        self.agent_id = returned_agent_id
                        self.assigned_hill = data.get("hill_id", data.get("assigned_hill", 1))
                    self.coordinator_instance_id = data.get("coordinator_instance_id")
                    return True, f"Successfully authenticated as {username} ({self.agent_id})"
                return False, data.get("message", "Authentication rejected")
            return False, f"Login failed (HTTP {resp.status_code}): {resp.text}"
        except Exception as e:
            return False, f"Enrollment error: {e}"

    def register(self, reconnect: bool = True) -> bool:
        """Register or re-register with authoritative coordinator server."""
        payload = {
            "agent_id": self.agent_id,
            "team_id": self.team_id,
            "role": "WORKER",
            "session_token": self.session_token,
            "credential": self.agent_token,
            "token": self.agent_token,
            "reconnect": reconnect,
        }
        try:
            resp = requests.post(
                f"{self.coordinator_url}/api/swarm/register",
                json=payload,
                headers=self._get_headers(),
                timeout=4.0,
                verify=self._verify_setting(),
            )
            if resp.status_code == 200:
                data = resp.json()
                if not self.session_token:
                    self.session_token = data.get("session_token")
                self.coordinator_instance_id = data.get("coordinator_instance_id")
                if "phase" in data:
                    phase_dict = data["phase"]
                    self.current_phase = phase_dict.get("phase", "HOLD")
                    self.phase_epoch = phase_dict.get("phase_epoch", 0)
                    self.round_id = phase_dict.get("round_id", 0)
                self.status = "READY"
                self.consecutive_connection_failures = 0
                logger.info(
                    f"[{self.agent_id}] Registered with central coordinator {self.coordinator_url} (Phase: {self.current_phase})"
                )
                return True
            else:
                logger.warning(f"[{self.agent_id}] Registration rejected ({resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            logger.error(f"[{self.agent_id}] Registration failed: {e}")
            return False

    def sync_phase(self) -> Tuple[str, int, int]:
        """Fetch authoritative phase from coordinator with fail-safe HOLD fallback."""
        try:
            resp = requests.get(
                f"{self.coordinator_url}/api/swarm/phase",
                headers=self._get_headers(),
                timeout=3.0,
                verify=self._verify_setting(),
            )
            if resp.status_code == 200:
                data = resp.json()
                self.consecutive_connection_failures = 0
                old_phase = self.current_phase
                self.current_phase = data.get("phase", "HOLD")
                self.phase_epoch = data.get("phase_epoch", 0)
                self.round_id = data.get("round_id", 0)

                if old_phase != self.current_phase:
                    logger.info(
                        f"[{self.agent_id}] Phase transition: {old_phase} -> {self.current_phase} (Epoch {self.phase_epoch})"
                    )
                    # Release in-flight task on phase change
                    if self.current_task:
                        logger.info(f"[{self.agent_id}] Phase shifted; dropping in-flight task {self.current_task.get('task_id')}")
                        self.current_task = None
                        self.current_lease = None
                return self.current_phase, self.phase_epoch, self.round_id
            elif resp.status_code == 401:
                logger.warning(f"[{self.agent_id}] Session invalidated (401); re-registering...")
                self.register(reconnect=True)
                return "HOLD", self.phase_epoch, self.round_id
            else:
                raise RuntimeError(f"HTTP error {resp.status_code}")
        except Exception as e:
            self.consecutive_connection_failures += 1
            if self.consecutive_connection_failures >= 3:
                if self.status != "SAFE_DEGRADED":
                    logger.error(f"[{self.agent_id}] Central coordinator unreachable. Entering SAFE_DEGRADED (HOLD).")
                self.status = "SAFE_DEGRADED"
                self.current_phase = "HOLD"
            return self.current_phase, self.phase_epoch, self.round_id

    def send_heartbeat(self) -> bool:
        """Send live heartbeat and system telemetry beacon."""
        telemetry = get_system_telemetry()
        task_id = self.current_task.get("task_id") if self.current_task else None
        target = self.current_task.get("target_host") if self.current_task else None

        payload = {
            "agent_id": self.agent_id,
            "team_id": self.team_id,
            "status": self.status,
            "current_phase": self.current_phase,
            "phase_epoch": self.phase_epoch,
            "current_task_id": task_id,
            "current_target": target,
            "timestamp": time.time(),
            "cpu_percent": telemetry["cpu_percent"],
            "memory_percent": telemetry["memory_percent"],
            "assigned_hill": self.assigned_hill,
            "telemetry": telemetry,
        }

        try:
            t0 = time.time()
            resp = requests.post(
                f"{self.coordinator_url}/api/swarm/heartbeat",
                json=payload,
                headers=self._get_headers(),
                timeout=2.5,
                verify=self._verify_setting(),
            )
            self.last_latency_ms = round((time.time() - t0) * 1000, 1)
            self.last_heartbeat_time = time.time()

            if resp.status_code == 200:
                data = resp.json()
                if data.get("kill_switch"):
                    if self.status != "SAFE_HOLD":
                        logger.warning(f"[{self.agent_id}] EMERGENCY KILL SWITCH BROADCAST RECEIVED FROM LEADER.")
                    self.status = "SAFE_HOLD"
                    self.current_task = None
                    self.current_lease = None
                return True
            elif resp.status_code == 401:
                self.register(reconnect=True)
                return False
            return False
        except Exception:
            return False

    def request_task(self) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Request next eligible task for this agent's assigned hill and role."""
        if self.status in ("SAFE_DEGRADED", "SAFE_HOLD") or self.current_phase in ("HOLD", "UNKNOWN"):
            return None, None

        payload = {
            "agent_id": self.agent_id,
            "phase": self.current_phase,
            "phase_epoch": self.phase_epoch,
            "assigned_hill": self.assigned_hill,
        }

        try:
            resp = requests.post(
                f"{self.coordinator_url}/api/swarm/task/request",
                json=payload,
                headers=self._get_headers(),
                timeout=3.0,
                verify=self._verify_setting(),
            )
            if resp.status_code == 200:
                data = resp.json()
                task = data.get("task")
                lease = data.get("lease")
                if task and lease:
                    self.current_task = task
                    self.current_lease = lease
                    self.status = "BUSY"
                    logger.info(
                        f"[{self.agent_id}] Leased Task {task.get('task_id')} "
                        f"({task.get('task_type')}) on Hill {task.get('hill_id', self.assigned_hill)}: "
                        f"Target {task.get('target_host')}"
                    )
                    return task, lease
            elif resp.status_code == 401:
                self.register(reconnect=True)
            return None, None
        except Exception as e:
            logger.debug(f"[{self.agent_id}] Task request failed: {e}")
            return None, None

    def execute_and_report_task(self, task: Dict[str, Any], lease: Dict[str, Any]):
        """Execute the authorized task and report outcome to coordinator."""
        task_id = task.get("task_id")
        task_type = task.get("task_type", "GENERIC_TASK")
        target_host = task.get("target_host", "10.254.254.10")
        hill_id = task.get("hill_id", self.assigned_hill)

        logger.info(f"[{self.agent_id}] Executing {task_type} for Hill {hill_id} ({target_host})...")
        time.sleep(1.0)  # Simulated execution cycle

        # Formulate execution findings
        execution_success = True
        findings = {
            "agent_id": self.agent_id,
            "hill_id": hill_id,
            "target_host": target_host,
            "task_type": task_type,
            "status": "COMPLETED",
            "timestamp": time.time(),
            "details": f"Executed authorized operation {task_type} on Hill {hill_id}",
        }

        # Complete task on coordinator
        complete_payload = {
            "task_id": task_id,
            "agent_id": self.agent_id,
            "lease_id": lease.get("lease_id"),
            "result": findings,
        }

        try:
            resp = requests.post(
                f"{self.coordinator_url}/api/swarm/task/complete",
                json=complete_payload,
                headers=self._get_headers(),
                timeout=3.0,
                verify=self._verify_setting(),
            )
            if resp.status_code == 200:
                self.completed_tasks_count += 1
                logger.info(f"[{self.agent_id}] Task {task_id} successfully reported complete.")
            else:
                self.failed_tasks_count += 1
                logger.warning(f"[{self.agent_id}] Task complete report returned HTTP {resp.status_code}")
        except Exception as e:
            self.failed_tasks_count += 1
            logger.error(f"[{self.agent_id}] Failed to report task completion: {e}")

        # Post coordination update
        self.send_coordination_finding(
            message=f"Agent {self.agent_id} completed {task_type} on Hill {hill_id} ({target_host})"
        )

        self.current_task = None
        self.current_lease = None
        self.status = "READY"

    def send_coordination_finding(self, message: str):
        """Send a coordination message/finding to the swarm."""
        payload = {
            "sender_id": self.agent_id,
            "team_id": self.team_id,
            "message_type": "FINDING",
            "content": message,
            "hill_id": self.assigned_hill,
            "timestamp": time.time(),
        }
        try:
            requests.post(
                f"{self.coordinator_url}/api/coordination/messages",
                json=payload,
                headers=self._get_headers(),
                timeout=2.0,
                verify=self._verify_setting(),
            )
        except Exception:
            pass

    def start_heartbeat_thread(self):
        """Run continuous heartbeat thread."""
        def _loop():
            while not self._stop_event.is_set():
                self.send_heartbeat()
                self._stop_event.wait(self.heartbeat_interval)

        self._heartbeat_thread = threading.Thread(target=_loop, daemon=True, name="HeartbeatThread")
        self._heartbeat_thread.start()

    def run(self):
        """Main autonomous worker execution loop."""
        self._running = True
        logger.info(f"Starting KOTH Swarm Remote Worker [{self.agent_id}] ({self.role_title})")
        logger.info(f"Connecting to Central Coordinator: {self.coordinator_url}")

        # Step 1: Initial registration
        connected = False
        while not self._stop_event.is_set() and not connected:
            ok, msg = self.test_connection()
            if ok:
                if self.register(reconnect=True):
                    connected = True
                    break
            logger.info(f"Waiting for central coordinator at {self.coordinator_url}... ({msg})")
            self._stop_event.wait(2.0)

        self.start_heartbeat_thread()
        print_banner(self)

        # Step 2: Main worker cycle
        while not self._stop_event.is_set():
            try:
                phase, epoch, rnd = self.sync_phase()

                if self.status == "SAFE_DEGRADED":
                    # Attempt reconnection
                    logger.debug(f"[{self.agent_id}] Reconnecting to coordinator...")
                    if self.register(reconnect=True):
                        self.status = "READY"
                    self._stop_event.wait(2.0)
                    continue

                if phase in ("ATTACK", "DEFENSE") and self.status != "SAFE_HOLD":
                    task, lease = self.request_task()
                    if task and lease:
                        self.execute_and_report_task(task, lease)

                self._stop_event.wait(self.poll_interval)
            except Exception as e:
                logger.error(f"Worker loop error: {e}")
                self._stop_event.wait(2.0)

        logger.info(f"[{self.agent_id}] Worker loop exited.")

    def stop(self):
        """Gracefully stop worker."""
        logger.info(f"[{self.agent_id}] Shutting down worker...")
        self._stop_event.set()
        self.status = "OFFLINE"
        try:
            self.send_heartbeat()
        except Exception:
            pass


def print_banner(worker: RemoteAgentWorker):
    """Print status console banner."""
    print("\n" + "=" * 78)
    print(f"  KOTH COMMAND — DISTRIBUTED AGENT WORKER")
    print(f"  Agent ID:       {worker.agent_id} ({worker.role_title})")
    print(f"  Assigned Hill:  Hill {worker.assigned_hill}")
    print(f"  Central Server: {worker.coordinator_url}")
    print(f"  Latency:        {worker.last_latency_ms} ms")
    print(f"  Status:         ONLINE / {worker.status}")
    print(f"  Swarm Phase:    {worker.current_phase} (Epoch {worker.phase_epoch}, Round {worker.round_id})")
    print("=" * 78 + "\n")


def interactive_enrollment() -> Dict[str, Any]:
    """Interactive CLI enrollment wizard for remote agent PCs."""
    print("\n" + "=" * 70)
    print("  KOTH COMMAND — AGENT WORKER ENROLLMENT WIZARD")
    print("  Configure this Windows PC to connect to the Central Coordinator")
    print("=" * 70 + "\n")

    # Load previous config if available
    prev_config = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                prev_config = json.load(f)
        except Exception:
            pass

    default_url = prev_config.get("coordinator_url", "http://192.168.1.50:5000")
    print(f"1. Central Server Connection")
    coord_url = input(f"   Enter Central Server URL [{default_url}]: ").strip() or default_url

    print(f"\n2. Select Agent Seat for this PC:")
    print("   1) agent-01 — Team Leader / Swarm Coordinator (Hill 1)")
    print("   2) agent-02 — Reconnaissance Specialist (Hill 2)")
    print("   3) agent-03 — Exploitation Specialist (Hill 3)")
    print("   4) agent-04 — Defense & Hardening Specialist (Hill 4)")
    default_seat = prev_config.get("agent_id", "agent-02")
    seat_choice = input(f"   Select seat (1-4 or agent-0X) [{default_seat}]: ").strip() or default_seat

    seat_map = {"1": "agent-01", "2": "agent-02", "3": "agent-03", "4": "agent-04"}
    agent_id = seat_map.get(seat_choice, seat_choice)
    if agent_id not in AGENT_ROLES:
        agent_id = "agent-02"

    print(f"\n3. Authentication Method:")
    print("   A) Team Member Login (Username & Password)")
    print("   B) Provisioned Agent Secret Token")
    auth_choice = input("   Choose authentication method (A/B) [A]: ").strip().upper() or "A"

    session_token = None
    agent_token = None
    team_id = prev_config.get("team_id", "null_warriors")

    if auth_choice == "B":
        agent_token = input("   Enter provisioned Agent Secret Token: ").strip()
    else:
        team_id = input(f"   Team Name/ID [{team_id}]: ").strip() or team_id
        username = input("   Username: ").strip()
        password = getpass.getpass("   Password: ")

        print("\nTesting enrollment against central coordinator...")
        worker = RemoteAgentWorker(coordinator_url=coord_url, agent_id=agent_id, team_id=team_id)
        ok, msg = worker.enroll_with_member_credentials(username=username, password=password)
        if not ok:
            print(f"\n[ERROR] Enrollment failed: {msg}")
            sys.exit(1)
        print(f"[SUCCESS] {msg}")
        session_token = worker.session_token
        agent_id = worker.agent_id

    ca_cert = None
    if coord_url.startswith("https://"):
        ca_cert = input("   Path to CA Certificate (leave blank for system trust store): ").strip() or None

    config_data = {
        "coordinator_url": coord_url,
        "agent_id": agent_id,
        "team_id": team_id,
        "session_token": session_token,
        "agent_token": agent_token,
        "ca_cert": ca_cert,
    }

    # Save configuration
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=2)
    print(f"\nConfiguration saved to: {CONFIG_FILE}\n")

    return config_data


def main():
    parser = argparse.ArgumentParser(description="KOTH Command — Remote Agent Worker")
    parser.add_argument("--coordinator-url", help="Central coordinator URL (e.g. http://192.168.1.50:5000)")
    parser.add_argument("--agent-id", choices=["agent-01", "agent-02", "agent-03", "agent-04"], help="Agent seat ID")
    parser.add_argument("--team-id", default="null_warriors", help="Team ID")
    parser.add_argument("--token", help="Independent agent secret token or session token")
    parser.add_argument("--username", help="Username for member login")
    parser.add_argument("--password", help="Password for member login")
    parser.add_argument("--ca-cert", help="Path to CA certificate for TLS verification")
    parser.add_argument("--enroll", action="store_true", help="Run interactive enrollment wizard")
    parser.add_argument("--config", help="Path to agent configuration file")
    args = parser.parse_args()

    # Determine configuration
    config_data = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r") as f:
            config_data = json.load(f)
    elif CONFIG_FILE.exists() and not (args.coordinator_url or args.enroll):
        try:
            with open(CONFIG_FILE, "r") as f:
                config_data = json.load(f)
        except Exception:
            pass

    if args.enroll or (not args.coordinator_url and not config_data.get("coordinator_url")):
        config_data = interactive_enrollment()

    coord_url = args.coordinator_url or config_data.get("coordinator_url", "http://127.0.0.1:5000")
    agent_id = args.agent_id or config_data.get("agent_id", "agent-02")
    team_id = args.team_id or config_data.get("team_id", "null_warriors")
    token = args.token or config_data.get("agent_token") or config_data.get("session_token")
    ca_cert = args.ca_cert or config_data.get("ca_cert")

    worker = RemoteAgentWorker(
        coordinator_url=coord_url,
        agent_id=agent_id,
        team_id=team_id,
        agent_token=token if not config_data.get("session_token") else None,
        session_token=config_data.get("session_token"),
        ca_cert=ca_cert,
    )

    if args.username and args.password:
        ok, msg = worker.enroll_with_member_credentials(args.username, args.password)
        if not ok:
            logger.error(f"Authentication failed: {msg}")
            sys.exit(1)

    def _sig_handler(sig, frame):
        logger.info("Received termination signal.")
        worker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        worker.run()
    except KeyboardInterrupt:
        worker.stop()


if __name__ == "__main__":
    main()

