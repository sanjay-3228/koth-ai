"""
4-Agent Swarm Rehearsal for PwnGrounds Competition.
Simulates null_warriors running 4 synchronized agents across ATTACK, DEFENSE, and HOLD phases,
verifying mutual exclusion, failure recovery, safe degradation, and kill switch.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import Dict, List

from agent.swarm.client import SwarmClient
from agent.swarm.coordinator import SwarmCoordinator
from agent.swarm.models import AgentStatus, Phase, TaskStatus
from agent.swarm.phase_manager import SimulatedPhaseProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("koth.swarm.rehearsal")


def run_swarm_rehearsal() -> bool:
    print("=" * 70)
    print("PWNGROUNDS 4-AGENT SWARM REHEARSAL: NULL_WARRIORS")
    print("=" * 70)

    target_hosts = ["10.10.10.11", "10.10.10.12", "10.10.10.13", "10.10.10.14"]
    own_hosts = ["10.10.10.101", "10.10.10.102", "10.10.10.103", "10.10.10.104"]

    phase_provider = SimulatedPhaseProvider(initial_phase=Phase.HOLD, initial_round=1)
    coordinator = SwarmCoordinator(
        team_id="null_warriors",
        phase_provider=phase_provider,
        lease_ttl=3.0,
        heartbeat_timeout=2.0,
        target_hosts=target_hosts,
        own_hosts=own_hosts,
    )

    agents = {
        f"agent-{i:02d}": SwarmClient(
            agent_id=f"agent-{i:02d}",
            team_id="null_warriors",
            coordinator=coordinator,
        )
        for i in range(1, 5)
    }

    print("\n[STEP 1] Starting 4 agents in initial HOLD phase...")
    for aid, client in agents.items():
        client.sync_phase()
        client.send_heartbeat()
        assert client.current_phase == Phase.HOLD, f"{aid} must be in HOLD"
    print("  -> All 4 agents synchronized in HOLD mode.")

    print("\n[STEP 2] Transitioning to ATTACK Phase (Round 1)...")
    phase_provider.set_phase(Phase.ATTACK, round_id=1)
    coordinator.tick_maintenance()

    for aid, client in agents.items():
        client.sync_phase()
        client.send_heartbeat()
        assert client.current_phase == Phase.ATTACK, f"{aid} must be in ATTACK"
    print("  -> All 4 agents transitioned to ATTACK phase.")

    print("\n[STEP 3] Distributing partitioned attack tasks across agents...")
    assigned_targets: Dict[str, str] = {}
    for aid, client in agents.items():
        task, lease = client.request_task()
        assert task is not None, f"{aid} should receive an attack task"
        assert lease is not None, f"{aid} should receive an exclusive lease"
        assert task.target_host in target_hosts, f"Target {task.target_host} not in authorized list"
        assert task.target_host not in assigned_targets.values(), (
            f"COLLISION: Target {task.target_host} assigned multiple times!"
        )
        assigned_targets[aid] = task.target_host
        print(f"  -> {aid} leased task {task.task_id} for target {task.target_host}")

    assert len(set(assigned_targets.values())) == 4, "Must partition all 4 distinct targets"
    print("  -> Verified: Zero target collisions across 4 agents.")

    print("\n[STEP 4] Completing attack tasks and updating shared state...")
    for aid, client in agents.items():
        target = assigned_targets[aid]
        scan_result = {
            "open_ports": [22, 80],
            "os": "linux",
            "compromised": True,
            "flag_captured": f"flag_{aid}_{target}",
            "round_id": 1,
        }
        success = client.complete_task(result=scan_result)
        assert success, f"{aid} complete_task failed"
        client.send_heartbeat()

    snapshot = coordinator.shared_state.get_snapshot()
    assert len(snapshot["host_discoveries"]) == 4, "Must have 4 host discoveries"
    assert len(snapshot["compromised_hosts"]) == 4, "Must have 4 compromised hosts"
    assert snapshot["captured_flags_count"] == 4, "Must have 4 captured flags recorded"
    print(f"  -> Shared state updated: {snapshot['captured_flags_count']} flags recorded.")

    print("\n[STEP 5] Transitioning to DEFENSE Phase (Round 1)...")
    phase_provider.set_phase(Phase.DEFENSE, round_id=1)
    coordinator.tick_maintenance()

    for aid, client in agents.items():
        client.release_current_work()
        client.sync_phase()
        client.send_heartbeat()
        assert client.current_phase == Phase.DEFENSE, f"{aid} must be in DEFENSE"
    print("  -> All 4 agents transitioned to DEFENSE phase.")

    print("\n[STEP 6] Requesting defense tasks for own hosts...")
    defense_targets: Dict[str, str] = {}
    for aid, client in agents.items():
        task, lease = client.request_task()
        assert task is not None, f"{aid} should receive defense task"
        assert task.target_host in own_hosts, f"Target {task.target_host} not in own hosts"
        defense_targets[aid] = task.target_host
        print(f"  -> {aid} leased defense task {task.task_id} for host {task.target_host}")

    print("\n[STEP 7] Simulating Agent-03 drop / failure recovery...")
    dead_agent = "agent-03"
    dead_target = defense_targets[dead_agent]
    print(f"  -> Simulating {dead_agent} stopping heartbeats on target {dead_target}...")

    # Advance time past heartbeat_timeout (2s) and lease_ttl (3s)
    future_time = time.time() + 4.0
    coordinator.heartbeat_monitor.check_agent_health(now=future_time)
    reaped = coordinator.task_manager.reap_abandoned_tasks()
    print(f"  -> Coordinator reaped {reaped} abandoned task(s).")

    # Complete work for agent-01, then agent-01 takes over the abandoned task
    agents["agent-01"].complete_task(result={"patched": True})
    new_task, new_lease = agents["agent-01"].request_task()
    assert new_task is not None, "Agent-01 should pick up available defense task"
    print(f"  -> Recovery verified: agent-01 acquired task {new_task.task_id} (target {new_task.target_host})")

    print("\n[STEP 8] Simulating Coordinator Unreachable (SAFE_DEGRADED fallback)...")
    degraded_agent = agents["agent-04"]
    # Disconnect coordinator reference
    degraded_agent.coordinator = None
    degraded_agent.coordinator_url = "http://127.0.0.1:59999"  # Unreachable port
    for _ in range(3):
        degraded_agent.sync_phase()

    assert degraded_agent.status == AgentStatus.SAFE_DEGRADED, "Agent must enter SAFE_DEGRADED"
    assert degraded_agent.current_phase == Phase.HOLD, "Agent must fallback to HOLD mode"
    print(f"  -> Safe degradation verified: {degraded_agent.agent_id} in {degraded_agent.status.value} (HOLD).")

    print("\n[STEP 9] Triggering Emergency Kill Switch...")
    coordinator.trigger_kill_switch(triggered_by="operator", reason="Rehearsal kill switch test")
    status = coordinator.get_swarm_status()
    assert status["kill_switch"] is True, "Kill switch must be active"
    assert len(status["active_leases"]) == 0, "All leases must be revoked on kill switch"
    print("  -> Kill switch verified: All leases revoked, emergency HOLD active.")

    print("\n" + "=" * 70)
    print("REHEARSAL SUCCESSFUL: ALL 9 VERIFICATION PHASES PASSED!")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_swarm_rehearsal()
    sys.exit(0 if success else 1)
