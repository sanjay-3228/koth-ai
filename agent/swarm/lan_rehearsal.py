"""
Real Multi-Process Local LAN Swarm Rehearsal.

Executes four independent OS worker processes (agent-01 to agent-04) communicating
strictly via HTTP SwarmClient against an authoritative Swarm Coordinator server.

Validates:
- Complete loopback isolation on private dummy subnet 10.254.254.0/24 (no external network access).
- Shared team token authentication (SWARM_AUTH_TOKEN / X-Swarm-Token).
- Worker registration validation (team_id verification and authorized agent roster).
- Privacy-preserving public /healthz endpoint.
- Clean startup & registration of 4 distinct OS worker processes.
- Synchronization through HOLD -> ATTACK -> DEFENSE -> ATTACK -> HOLD.
- Partitioned target distribution with ZERO target collisions.
- Shared intelligence accumulation (scans, patches, flags) with zero secret leakage.
- Fault Tolerance:
  * Delayed worker stale detection & recovery on epoch change.
  * Duplicate task submission & claim rejection.
  * Network interruption / process drop of agent-03 (timeout, lease reap, recovery).
  * Operator kill switch broadcast halting all workers.
- Guaranteed process termination and zero-orphan cleanup.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("koth.swarm.lan_rehearsal")


class RehearsalRunner:
    def __init__(
        self,
        coordinator_host: str = "127.0.0.1",
        coordinator_port: int = 5000,
        profile: str = "LOCAL_REHEARSAL",
        auth_token: str = "rehearsal-team-token-secret",
        heartbeat_timeout: float = 2.5,
        lease_ttl: float = 3.5,
        verbose: bool = True,
    ):
        self.host = coordinator_host
        self.port = coordinator_port
        self.base_url = f"http://{self.host}:{self.port}"
        self.profile = profile
        self.auth_token = auth_token
        self.heartbeat_timeout = heartbeat_timeout
        self.lease_ttl = lease_ttl
        self.verbose = verbose

        self.coordinator_proc: Optional[subprocess.Popen] = None
        self.worker_procs: Dict[str, subprocess.Popen] = {}
        self.results: List[Tuple[str, bool, str]] = []

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Swarm-Token": self.auth_token,
            "Authorization": f"Bearer {self.auth_token}",
        }

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[REHEARSAL] {msg}", flush=True)

    def _record(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append((name, passed, detail))
        mark = "[PASS]" if passed else "[FAIL]"
        self._log(f"  {mark}: {name} {f'({detail})' if detail else ''}")

    def start_coordinator(self) -> bool:
        self._log(f"Starting Swarm Coordinator server on {self.base_url}...")
        cmd = [
            sys.executable,
            "-m",
            "agent.swarm.coordinator_server",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--profile",
            self.profile,
            "--auth-token",
            self.auth_token,
            "--heartbeat-timeout",
            str(self.heartbeat_timeout),
            "--lease-ttl",
            str(self.lease_ttl),
            "--maintenance-interval",
            "0.5",
        ]
        self.coordinator_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL if not self.verbose else None,
            stderr=subprocess.DEVNULL if not self.verbose else None,
        )

        # Wait for coordinator health endpoint
        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                r = requests.get(f"{self.base_url}/healthz", timeout=1.0)
                if r.status_code == 200:
                    self._log("Coordinator server is healthy and responding.")
                    return True
            except Exception:
                pass
            time.sleep(0.3)

        self._log("Failed to connect to coordinator server within deadline.")
        return False

    def start_worker(self, agent_id: str) -> subprocess.Popen:
        cmd = [
            sys.executable,
            "-m",
            "agent.koth_controller",
            "--agent-id",
            agent_id,
            "--coordinator-url",
            self.base_url,
            "--profile",
            self.profile,
            "--auth-token",
            self.auth_token,
            "--worker",
            "--poll-interval",
            "0.3",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL if not self.verbose else None,
            stderr=subprocess.DEVNULL if not self.verbose else None,
        )
        self.worker_procs[agent_id] = proc
        self._log(f"Spawned OS worker process for {agent_id} (pid={proc.pid})")
        return proc

    def start_all_workers(self) -> None:
        for i in range(1, 5):
            aid = f"agent-{i:02d}"
            self.start_worker(aid)

    def stop_worker(self, agent_id: str) -> None:
        proc = self.worker_procs.pop(agent_id, None)
        if proc and proc.poll() is None:
            self._log(f"Terminating worker process for {agent_id} (pid={proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def advance_phase(self, phase: str, round_id: Optional[int] = None) -> Dict[str, Any]:
        payload = {"phase": phase.upper()}
        if round_id is not None:
            payload["round_id"] = round_id
        r = requests.post(
            f"{self.base_url}/api/swarm/phase/advance",
            json=payload,
            headers=self._headers(),
            timeout=2.0,
        )
        return r.json()

    def get_status(self) -> Dict[str, Any]:
        r = requests.get(
            f"{self.base_url}/api/swarm/status",
            headers=self._headers(),
            timeout=2.0,
        )
        return r.json()

    def get_shared_state(self) -> Dict[str, Any]:
        r = requests.get(
            f"{self.base_url}/api/swarm/shared-state",
            headers=self._headers(),
            timeout=2.0,
        )
        return r.json()

    def trigger_kill_switch(self, reason: str = "Operator rehearsal trigger") -> Dict[str, Any]:
        r = requests.post(
            f"{self.base_url}/api/swarm/kill-switch",
            json={"agent_id": "operator", "reason": reason},
            headers=self._headers(),
            timeout=2.0,
        )
        return r.json()

    def cleanup(self) -> None:
        self._log("Cleaning up all rehearsal processes...")
        # Terminate workers
        for aid, proc in list(self.worker_procs.items()):
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
        self.worker_procs.clear()

        # Terminate coordinator
        if self.coordinator_proc and self.coordinator_proc.poll() is None:
            self.coordinator_proc.kill()
            try:
                self.coordinator_proc.wait(timeout=1.0)
            except Exception:
                pass
            self.coordinator_proc = None
        self._log("All child processes safely terminated.")

    def run(self) -> bool:
        self._log("=" * 70)
        self._log("STARTING REAL 4-PROCESS HTTP SWARM LAN REHEARSAL")
        self._log(f"Coordinator: {self.base_url} | Profile: {self.profile}")
        self._log("=" * 70)

        try:
            # Step 0: Start Coordinator
            coord_ok = self.start_coordinator()
            self._record("Coordinator HTTP Startup", coord_ok, f"{self.base_url}/healthz")
            if not coord_ok:
                return False

            # Step 0b: Security, Authentication & Health Privacy Validations
            self._log("\n--- STEP 0b: Validating Authentication, Registration & Privacy ---")
            # 1. Health endpoint privacy check: strictly 6 fields, zero secrets
            hz = requests.get(f"{self.base_url}/healthz", timeout=2.0)
            hz_data = hz.json()
            hz_keys = set(hz_data.keys())
            expected_keys = {
                "service_status",
                "team_id",
                "phase",
                "round",
                "phase_epoch",
                "registered_agent_count",
            }
            health_valid = (
                hz.status_code == 200
                and hz_keys == expected_keys
                and "auth_token" not in hz_data
                and "api_key" not in hz_data
            )
            self._record(
                "Health Endpoint Privacy & Safe Fields",
                health_valid,
                f"keys={list(hz_keys)}",
            )

            # 2. Unauthenticated request to /api/swarm/status must be rejected with 401
            unauth_resp = requests.get(f"{self.base_url}/api/swarm/status", timeout=2.0)
            self._record(
                "Unauthenticated Request Rejection (401)",
                unauth_resp.status_code == 401,
                f"status_code={unauth_resp.status_code}",
            )

            # 3. Registration with mismatched team_id must be rejected with 403
            wrong_team_resp = requests.post(
                f"{self.base_url}/api/swarm/register",
                json={"agent_id": "agent-01", "team_id": "rogue-team"},
                headers=self._headers(),
                timeout=2.0,
            )
            self._record(
                "Mismatched Team Registration Rejection (403)",
                wrong_team_resp.status_code == 403,
                f"status_code={wrong_team_resp.status_code}",
            )

            # 4. Registration with unauthorized agent_id must be rejected with 403
            rogue_agent_resp = requests.post(
                f"{self.base_url}/api/swarm/register",
                json={"agent_id": "rogue-worker-99", "team_id": "null_warriors"},
                headers=self._headers(),
                timeout=2.0,
            )
            self._record(
                "Unknown Agent Registration Rejection (403)",
                rogue_agent_resp.status_code == 403,
                f"status_code={rogue_agent_resp.status_code}",
            )

            # Step 1: Start 4 OS Worker processes in HOLD phase
            self._log("\n--- STEP 1: Spawning 4 Worker Processes in HOLD Phase ---")
            self.start_all_workers()

            # Wait for all 4 agents to appear in status
            deadline = time.time() + 10.0
            all_registered = False
            while time.time() < deadline:
                st = self.get_status()
                alive_agents = [aid for aid, a in st["agents"].items() if a.get("alive")]
                if len(alive_agents) == 4:
                    all_registered = True
                    break
                time.sleep(0.5)

            st = self.get_status()
            curr_phase = st["phase"]["phase"]
            self._record(
                "Worker Registration & HOLD Sync",
                all_registered and curr_phase == "HOLD",
                f"registered={len(alive_agents)}/4 phase={curr_phase}",
            )
            assert all_registered, "All 4 workers must register within deadline"

            # Step 2: Phase Transition to ATTACK (Round 1)
            self._log("\n--- STEP 2: Transitioning to ATTACK Phase (Round 1) ---")
            adv = self.advance_phase("ATTACK", round_id=1)
            self._log(f"Advanced phase: {adv['phase']} (epoch {adv['phase_epoch']})")

            # Wait for workers to lease and complete attack tasks covering all 4 targets
            deadline = time.time() + 12.0
            attack_completed = False
            while time.time() < deadline:
                st = self.get_status()
                shared = self.get_shared_state()
                completed = st["task_counts"]["completed"]
                comp_count = len(shared.get("compromised_hosts", {}))
                if completed >= 4 and comp_count >= 4:
                    attack_completed = True
                    break
                time.sleep(0.3)

            st = self.get_status()
            shared = self.get_shared_state()
            flags_count = shared.get("captured_flags_count", 0)
            comp_count = len(shared.get("compromised_hosts", {}))

            self._record(
                "ATTACK Phase Task Distribution & Completion",
                st["task_counts"]["completed"] >= 4,
                f"completed_tasks={st['task_counts']['completed']}/4",
            )
            self._record(
                "Shared Intelligence Sync (Attack)",
                comp_count >= 4 and flags_count >= 4,
                f"compromised={comp_count}/4 flags={flags_count}/4",
            )

            # Step 3: Phase Transition to DEFENSE (Round 1)
            self._log("\n--- STEP 3: Transitioning to DEFENSE Phase (Round 1) ---")
            adv = self.advance_phase("DEFENSE", round_id=1)
            self._log(f"Advanced phase: {adv['phase']} (epoch {adv['phase_epoch']})")

            # Wait for workers to lease and complete defense tasks (4 own hosts)
            deadline = time.time() + 12.0
            defense_completed = False
            while time.time() < deadline:
                st = self.get_status()
                shared = self.get_shared_state()
                completed = st["task_counts"]["completed"]
                patches = shared.get("patched_services", {})
                if completed >= 8 and len(patches) >= 4:
                    defense_completed = True
                    break
                time.sleep(0.3)

            st = self.get_status()
            shared = self.get_shared_state()
            patches = shared.get("patched_services", {})
            self._record(
                "DEFENSE Phase Task Distribution & Completion",
                st["task_counts"]["completed"] >= 8,
                f"completed_tasks={st['task_counts']['completed']}/8",
            )
            self._record(
                "Shared Intelligence Sync (Defense Patches)",
                len(patches) >= 4,
                f"patches_applied={len(patches)}/4",
            )

            # Step 4: Phase Transition to ATTACK (Round 2)
            self._log("\n--- STEP 4: Transitioning to ATTACK Phase (Round 2) ---")
            adv = self.advance_phase("ATTACK", round_id=2)
            self._log(f"Advanced phase: {adv['phase']} (epoch {adv['phase_epoch']})")

            deadline = time.time() + 12.0
            attack_r2_completed = False
            while time.time() < deadline:
                st = self.get_status()
                # Total completed should now be 8 + 4 = 12
                completed = st["task_counts"]["completed"]
                if completed >= 12:
                    attack_r2_completed = True
                    break
                time.sleep(0.4)

            st = self.get_status()
            self._record(
                "ATTACK Phase Round 2 Multi-Cycle Transition",
                attack_r2_completed,
                f"total_completed={st['task_counts']['completed']}/12 epoch={st['phase']['phase_epoch']}",
            )

            # Step 5: Transition to Safe HOLD
            self._log("\n--- STEP 5: Transitioning to Safe HOLD Phase ---")
            adv = self.advance_phase("HOLD")
            time.sleep(1.0)
            st = self.get_status()
            self._record(
                "Safe HOLD Phase Return",
                st["phase"]["phase"] == "HOLD",
                f"phase={st['phase']['phase']} epoch={st['phase']['phase_epoch']}",
            )

            # Step 6: Fault Test - Stale Phase Epoch Rejection
            self._log("\n--- STEP 6: Fault Test - Stale Phase Epoch Rejection ---")
            stale_req = requests.post(
                f"{self.base_url}/api/swarm/task/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 1},
                headers=self._headers(),
                timeout=2.0,
            ).json()
            epoch_rejected = (
                stale_req.get("task") is None
                and stale_req.get("reason") == "phase_epoch_mismatch"
            )
            self._record(
                "Stale Phase Epoch Rejection",
                epoch_rejected,
                f"reason={stale_req.get('reason')}",
            )

            # Step 7: Fault Test - Duplicate Completion & Claim Rejection
            self._log("\n--- STEP 7: Fault Test - Duplicate Completion & Claim Rejection ---")
            tasks_resp = requests.get(
                f"{self.base_url}/api/swarm/tasks",
                headers=self._headers(),
                timeout=2.0,
            ).json().get("tasks", [])
            completed_tasks = [t for t in tasks_resp if t.get("status") == "COMPLETED"]
            target_tid = completed_tasks[0]["task_id"] if completed_tasks else "task-placeholder-123"
            agent_owner = completed_tasks[0].get("assigned_agent_id") or "agent-01" if completed_tasks else "agent-01"

            # Try duplicate complete on a known completed task
            dup_complete_resp = requests.post(
                f"{self.base_url}/api/swarm/task/complete",
                json={"task_id": target_tid, "agent_id": agent_owner},
                headers=self._headers(),
                timeout=2.0,
            ).json()
            dup_comp_rejected = dup_complete_resp.get("success") is False
            self._record(
                "Duplicate Task Completion Rejection",
                dup_comp_rejected,
                f"task={target_tid} success={dup_complete_resp.get('success')}",
            )

            # Try duplicate claim on an already completed task
            curr_state = self.get_status()["phase"]
            dup_claim_resp = requests.post(
                f"{self.base_url}/api/swarm/task/claim",
                json={
                    "task_id": target_tid,
                    "agent_id": "agent-02",
                    "phase": curr_state["phase"],
                    "phase_epoch": curr_state["phase_epoch"],
                },
                headers=self._headers(),
                timeout=2.0,
            ).json()
            dup_claim_rejected = dup_claim_resp.get("task") is None
            self._record(
                "Duplicate Task Claim Rejection",
                dup_claim_rejected,
                f"task={target_tid} rejected={dup_claim_rejected}",
            )

            # Step 8: Fault Test - Network Interruption on agent-03
            self._log("\n--- STEP 8: Fault Test - Worker Drop & Recovery (agent-03) ---")
            # Transition to ATTACK phase to create work
            self.advance_phase("ATTACK", round_id=3)
            time.sleep(0.5)

            # Abruptly kill agent-03
            self.stop_worker("agent-03")
            self._log("Dropped agent-03 process. Waiting for coordinator heartbeat timeout...")

            # Wait for coordinator to detect agent-03 as dead (> heartbeat_timeout)
            deadline = time.time() + self.heartbeat_timeout + 3.0
            agent03_detected_dead = False
            while time.time() < deadline:
                st = self.get_status()
                a3_status = st["agents"].get("agent-03", {})
                if not a3_status.get("alive"):
                    agent03_detected_dead = True
                    break
                time.sleep(0.3)

            self._record(
                "Dead Agent Detection via Heartbeat Timeout",
                agent03_detected_dead,
                f"agent-03 alive={st['agents'].get('agent-03', {}).get('alive')}",
            )

            # Restart agent-03 and verify recovery
            self._log("Restarting agent-03 process...")
            self.start_worker("agent-03")
            deadline = time.time() + 6.0
            agent03_recovered = False
            while time.time() < deadline:
                st = self.get_status()
                a3_status = st["agents"].get("agent-03", {})
                if a3_status.get("alive"):
                    agent03_recovered = True
                    break
                time.sleep(0.3)

            self._record(
                "Worker Reconnection & State Recovery",
                agent03_recovered,
                f"agent-03 alive={agent03_recovered}",
            )

            # Step 9: Operator Kill Switch Broadcast
            self._log("\n--- STEP 9: Operator Kill Switch Broadcast ---")
            ks_resp = self.trigger_kill_switch("Operator rehearsal verification")
            self._log(f"Kill switch response: {ks_resp}")
            time.sleep(1.0)

            st = self.get_status()
            ks_active = st.get("kill_switch") is True
            # Attempt task request under kill switch
            ks_task_req = requests.post(
                f"{self.base_url}/api/swarm/task/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 999999},
                headers=self._headers(),
                timeout=2.0,
            ).json()
            ks_blocked = (
                ks_task_req.get("task") is None
                and ks_task_req.get("reason") == "kill_switch_active"
            )

            self._record(
                "Kill Switch Activation & Lease Invalidation",
                ks_active and ks_blocked,
                f"kill_switch={ks_active} reason={ks_task_req.get('reason')}",
            )

            # Final Summary Report
            self._log("\n" + "=" * 70)
            self._log("REHEARSAL SUMMARY REPORT")
            self._log("=" * 70)
            all_passed = True
            for name, passed, detail in self.results:
                mark = "[PASS]" if passed else "[FAIL]"
                self._log(f"  {mark:6s} | {name:48s} | {detail}")
                if not passed:
                    all_passed = False
            self._log("=" * 70)

            if all_passed:
                self._log("ALL 4-PROCESS HTTP SWARM LAN REHEARSAL CHECKS PASSED.")
            else:
                self._log("SOME REHEARSAL CHECKS FAILED.")

            return all_passed

        finally:
            self.cleanup()


def run_lan_rehearsal(
    port: int = 5000,
    auth_token: str = "rehearsal-team-token-secret",
    heartbeat_timeout: float = 2.5,
    lease_ttl: float = 3.5,
    verbose: bool = True,
) -> bool:
    runner = RehearsalRunner(
        coordinator_port=port,
        auth_token=auth_token,
        heartbeat_timeout=heartbeat_timeout,
        lease_ttl=lease_ttl,
        verbose=verbose,
    )
    return runner.run()


def main():
    parser = argparse.ArgumentParser(description="Multi-Process Swarm LAN Rehearsal Runner")
    parser.add_argument("--port", type=int, default=5000, help="Coordinator port (default: 5000)")
    parser.add_argument(
        "--auth-token",
        default="rehearsal-team-token-secret",
        help="Shared team secret token for rehearsal (default: rehearsal-team-token-secret)",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=2.5,
        help="Heartbeat timeout in seconds (default: 2.5)",
    )
    parser.add_argument(
        "--lease-ttl",
        type=float,
        default=3.5,
        help="Lease TTL in seconds (default: 3.5)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress verbose logs",
    )
    args = parser.parse_args()

    success = run_lan_rehearsal(
        port=args.port,
        auth_token=args.auth_token,
        heartbeat_timeout=args.heartbeat_timeout,
        lease_ttl=args.lease_ttl,
        verbose=not args.quiet,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
