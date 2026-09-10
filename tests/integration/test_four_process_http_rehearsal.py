"""
Integration Test Suite for 4-Process HTTP Swarm LAN Rehearsal.

Spawns four independent OS worker processes communicating strictly over loopback HTTP
with a SwarmCoordinator server.
Verifies phase synchronization, target partitioning, fault tolerance,
stale epoch detection, duplicate submission rejection, network interruption,
and emergency kill switch.
"""

import socket
import time
import pytest

from agent.swarm.lan_rehearsal import RehearsalRunner, run_lan_rehearsal


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestFourProcessHttpRehearsal:
    """Integration tests running real OS processes communicating via HTTP."""

    def test_full_lan_rehearsal_sequence(self):
        """
        Execute complete multi-process LAN rehearsal:
        HOLD -> ATTACK -> DEFENSE -> ATTACK -> HOLD + all 4 fault tests.
        """
        port = find_free_port()
        runner = RehearsalRunner(
            coordinator_port=port,
            heartbeat_timeout=2.5,
            lease_ttl=3.5,
            verbose=True,
        )
        try:
            success = runner.run()
            assert success is True, f"Rehearsal failed. Results: {runner.results}"

            # Verify every individual step passed
            for name, passed, detail in runner.results:
                assert passed is True, f"Step '{name}' failed: {detail}"

        finally:
            runner.cleanup()

    def test_stale_epoch_and_duplicate_safety(self):
        """
        Verify coordinator rejects task requests with stale epochs and
        rejects duplicate completions / claims over HTTP.
        """
        import requests

        port = find_free_port()
        runner = RehearsalRunner(
            coordinator_port=port,
            heartbeat_timeout=2.5,
            lease_ttl=3.5,
            verbose=False,
        )
        try:
            assert runner.start_coordinator() is True
            base = f"http://127.0.0.1:{port}"
            hdrs = runner._headers()

            # Advance to ATTACK epoch 1
            r = requests.post(f"{base}/api/swarm/phase/advance", json={"phase": "ATTACK", "round_id": 1}, headers=hdrs)
            assert r.status_code == 200
            epoch_1 = r.json()["phase_epoch"]

            # Advance to ATTACK epoch 2
            r = requests.post(f"{base}/api/swarm/phase/advance", json={"phase": "ATTACK", "round_id": 2}, headers=hdrs)
            assert r.status_code == 200
            epoch_2 = r.json()["phase_epoch"]
            assert epoch_2 > epoch_1

            # Agent attempts to request task with stale epoch_1
            req_stale = requests.post(
                f"{base}/api/swarm/task/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": epoch_1},
                headers=hdrs,
            ).json()
            assert req_stale.get("task") is None
            assert req_stale.get("reason") == "phase_epoch_mismatch"

            # Valid request with epoch_2 succeeds
            req_valid = requests.post(
                f"{base}/api/swarm/task/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": epoch_2},
                headers=hdrs,
            ).json()
            assert req_valid.get("task") is not None
            task_id = req_valid["task"]["task_id"]

            # Complete task
            comp = requests.post(
                f"{base}/api/swarm/task/complete",
                json={"task_id": task_id, "agent_id": "agent-01", "result": {"scanned": True}},
                headers=hdrs,
            ).json()
            assert comp.get("success") is True

            # Duplicate completion attempt must be rejected
            dup_comp = requests.post(
                f"{base}/api/swarm/task/complete",
                json={"task_id": task_id, "agent_id": "agent-01"},
                headers=hdrs,
            ).json()
            assert dup_comp.get("success") is False

            # Duplicate claim attempt on completed task must be rejected
            dup_claim = requests.post(
                f"{base}/api/swarm/task/claim",
                json={"task_id": task_id, "agent_id": "agent-02", "phase": "ATTACK", "phase_epoch": epoch_2},
                headers=hdrs,
            ).json()
            assert dup_claim.get("task") is None

        finally:
            runner.cleanup()

    def test_kill_switch_over_http(self):
        """Verify operator kill switch immediately halts task leases and puts system in SAFE_HOLD."""
        import requests

        port = find_free_port()
        runner = RehearsalRunner(
            coordinator_port=port,
            heartbeat_timeout=2.5,
            lease_ttl=3.5,
            verbose=False,
        )
        try:
            assert runner.start_coordinator() is True
            base = f"http://127.0.0.1:{port}"
            hdrs = runner._headers()

            # Advance to ATTACK
            requests.post(f"{base}/api/swarm/phase/advance", json={"phase": "ATTACK", "round_id": 1}, headers=hdrs)

            # Trigger kill switch
            ks = requests.post(
                f"{base}/api/swarm/kill-switch",
                json={"agent_id": "operator", "reason": "Emergency halt test"},
                headers=hdrs,
            ).json()
            assert ks.get("status") == "KILL_SWITCH_ACTIVE"

            # Status confirms kill switch is active and phase is HOLD
            st = requests.get(f"{base}/api/swarm/status", headers=hdrs).json()
            assert st.get("kill_switch") is True
            assert st["phase"]["phase"] == "HOLD"

            # All task requests blocked
            req = requests.post(
                f"{base}/api/swarm/task/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 1},
                headers=hdrs,
            ).json()
            assert req.get("task") is None
            assert req.get("reason") == "kill_switch_active"

        finally:
            runner.cleanup()

