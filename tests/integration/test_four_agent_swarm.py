"""
Comprehensive 24-Step Integration Test Suite for the 4-Agent Swarm Architecture.
Tests 4 identical worker agents (agent-01 to agent-04) under null_warriors for PwnGrounds.
Verifies phase synchronization, target partitioning, failure recovery, safe degradation,
kill switch, and strict security policy enforcement.
"""

from __future__ import annotations

import time
import pytest

from agent.config import Config
from agent.gemini_client import Decision
from agent.security.policy import RiskLevel, SecurityPolicy
from agent.swarm import (
    AgentHeartbeat,
    AgentStatus,
    Phase,
    PhaseState,
    SimulatedPhaseProvider,
    SwarmClient,
    SwarmCoordinator,
    TaskStatus,
    TaskType,
)


@pytest.fixture
def target_hosts():
    return ["10.10.10.11", "10.10.10.12", "10.10.10.13", "10.10.10.14"]


@pytest.fixture
def own_hosts():
    return ["10.10.10.101", "10.10.10.102", "10.10.10.103", "10.10.10.104"]


@pytest.fixture
def swarm_setup(target_hosts, own_hosts):
    phase_provider = SimulatedPhaseProvider(initial_phase=Phase.HOLD, initial_round=1, ttl_seconds=20.0)
    coordinator = SwarmCoordinator(
        team_id="null_warriors",
        phase_provider=phase_provider,
        lease_ttl=4.0,
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
    return {
        "coordinator": coordinator,
        "phase_provider": phase_provider,
        "agents": agents,
        "target_hosts": target_hosts,
        "own_hosts": own_hosts,
    }


def test_24_step_four_agent_swarm_lifecycle(swarm_setup):
    """
    24-Step complete swarm verification covering every requirement.
    """
    coordinator: SwarmCoordinator = swarm_setup["coordinator"]
    phase_provider: SimulatedPhaseProvider = swarm_setup["phase_provider"]
    agents = swarm_setup["agents"]
    target_hosts = swarm_setup["target_hosts"]
    own_hosts = swarm_setup["own_hosts"]

    # STEP 1: Initialize SwarmCoordinator
    assert coordinator.team_id == "null_warriors"
    assert len(coordinator.target_hosts) == 4
    assert len(coordinator.own_hosts) == 4

    # STEP 2: Instantiate 4 agents
    assert len(agents) == 4
    assert set(agents.keys()) == {"agent-01", "agent-02", "agent-03", "agent-04"}

    # STEP 3: Connect and report initial status READY
    for aid, client in agents.items():
        client.status = AgentStatus.READY
        success = client.send_heartbeat()
        assert success is True
    active_ids = coordinator.heartbeat_monitor.get_active_agent_ids()
    assert len(active_ids) == 4

    # STEP 4: Phase manager starts in HOLD; all 4 agents synchronize to HOLD
    initial_phase = coordinator.get_phase()
    assert initial_phase.phase == Phase.HOLD
    for client in agents.values():
        state = client.sync_phase()
        assert state.phase == Phase.HOLD
        assert client.current_phase == Phase.HOLD

    # STEP 5: Transition to ATTACK phase (Round 1)
    phase_provider.set_phase(Phase.ATTACK, round_id=1)
    coordinator.tick_maintenance()
    assert coordinator.get_phase().phase == Phase.ATTACK
    assert coordinator.get_phase().phase_epoch == 2

    # STEP 6: All 4 agents synchronize to Phase.ATTACK
    for client in agents.values():
        state = client.sync_phase()
        assert state.phase == Phase.ATTACK
        assert client.current_phase == Phase.ATTACK

    # STEPS 7-10: Agents 01-04 request tasks -> leased Targets 1 to 4
    assigned_targets = {}
    assigned_tasks = {}
    for aid in ["agent-01", "agent-02", "agent-03", "agent-04"]:
        client = agents[aid]
        task, lease = client.request_task()
        assert task is not None, f"{aid} must receive a task"
        assert lease is not None, f"{aid} must receive a lease"
        assert task.phase == Phase.ATTACK
        assert task.target_host in target_hosts
        assigned_targets[aid] = task.target_host
        assigned_tasks[aid] = task

    # STEP 11: Mutual exclusion: Zero target collisions across the 4 agents
    unique_targets = set(assigned_targets.values())
    assert len(unique_targets) == 4, "Every agent must be assigned a unique target host"
    assert unique_targets == set(target_hosts)

    # STEP 12: LeaseManager rejects duplicate request for an already leased target
    conflict_lease = coordinator.lease_manager.acquire_lease(
        task_id="conflict-task",
        agent_id="rogue-agent",
        phase=Phase.ATTACK,
        phase_epoch=2,
        target_host=assigned_targets["agent-01"],
    )
    assert conflict_lease is None, "Should not grant lease on busy target host"

    # STEP 13: Agents renew their leases successfully
    for aid, client in agents.items():
        renewed = client.renew_lease()
        assert renewed is True, f"{aid} should successfully renew its lease"

    # STEP 14: Agents complete attack tasks and record results
    for aid, client in agents.items():
        host = assigned_targets[aid]
        scan_result = {
            "open_ports": [22, 80, 443],
            "os": "linux",
            "compromised": True,
            "flag_captured": f"FLAG_{aid}_{host}",
            "round_id": 1,
        }
        completed = client.complete_task(result=scan_result)
        assert completed is True, f"{aid} complete_task failed"

    # STEP 15: Verify SharedTeamState discoveries and captured flags (no credentials)
    snapshot = coordinator.shared_state.get_snapshot()
    assert len(snapshot["host_discoveries"]) == 4
    for host in target_hosts:
        assert host in snapshot["host_discoveries"]
        assert snapshot["host_discoveries"][host]["ports"] == [22, 80, 443]
    assert len(snapshot["compromised_hosts"]) == 4
    assert snapshot["captured_flags_count"] == 4

    # STEP 16: Transition to DEFENSE phase (Round 1)
    phase_provider.set_phase(Phase.DEFENSE, round_id=1)
    coordinator.tick_maintenance()
    assert coordinator.get_phase().phase == Phase.DEFENSE
    assert coordinator.get_phase().phase_epoch == 3

    # STEP 17: Old attack tasks cancelled and leases released
    old_tasks = [t for t in coordinator.task_manager.get_all_tasks() if t.phase == Phase.ATTACK]
    for t in old_tasks:
        assert t.status in (TaskStatus.COMPLETED, TaskStatus.CANCELLED)
    assert len(coordinator.lease_manager.get_active_leases()) == 0

    # STEP 18: All 4 agents synchronize to Phase.DEFENSE
    for client in agents.values():
        client.release_current_work()
        state = client.sync_phase()
        assert state.phase == Phase.DEFENSE
        assert client.current_phase == Phase.DEFENSE

    # STEP 19: Agents request defense tasks for own hosts
    defense_targets = {}
    defense_tasks = {}
    for aid in ["agent-01", "agent-02", "agent-03", "agent-04"]:
        client = agents[aid]
        task, lease = client.request_task()
        assert task is not None
        assert lease is not None
        assert task.phase == Phase.DEFENSE
        assert task.target_host in own_hosts
        defense_targets[aid] = task.target_host
        defense_tasks[aid] = task

    assert len(set(defense_targets.values())) == 4, "Zero target collisions on defended hosts"

    # STEP 20: Agents complete defense tasks
    for aid in ["agent-01", "agent-02", "agent-04"]:
        client = agents[aid]
        completed = client.complete_task(result={"patched": True, "service": "sshd"})
        assert completed is True

    # STEP 21: Agent failure recovery: agent-03 disconnects
    # Advance time past lease_ttl (4.0s) and heartbeat_timeout (2.0s)
    future_time = time.time() + 6.0
    coordinator.tick_maintenance(now=future_time)
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-03", now=future_time) is False

    # Verify agent-03's abandoned task was reset to PENDING and unassigned
    abandoned_task = coordinator.task_manager.get_task(defense_tasks["agent-03"].task_id)
    assert abandoned_task.status == TaskStatus.PENDING
    assert abandoned_task.assigned_agent_id is None
    assert abandoned_task.lease_id is None

    # Agent-01 acquires next available defense task
    next_task, next_lease = agents["agent-01"].request_task()
    assert next_task is not None
    assert next_lease is not None
    assert next_task.target_host in own_hosts

    # STEP 22: Coordinator Disappearance -> Agents enter SAFE_DEGRADED (HOLD)
    broken_agent = agents["agent-04"]
    broken_agent.coordinator = None
    broken_agent.coordinator_url = "http://127.0.0.1:59998"
    for _ in range(3):
        broken_agent.sync_phase()

    assert broken_agent.status == AgentStatus.SAFE_DEGRADED
    assert broken_agent.current_phase == Phase.HOLD

    # STEP 23: Kill switch activation
    coordinator.trigger_kill_switch(triggered_by="operator", reason="24-step integration kill switch test")
    assert coordinator.kill_switch_active is True
    assert len(coordinator.lease_manager.get_active_leases()) == 0
    assert coordinator.get_phase().phase == Phase.HOLD

    # Attempting to request a task after kill switch returns None
    no_task, no_lease = agents["agent-01"].request_task()
    assert no_task is None
    assert no_lease is None

    # STEP 24: Security Policy compliance checks
    cfg = Config(
        target_hosts=target_hosts,
        own_services=[f"{h}:22:sshd" for h in own_hosts],
        protected_hosts=own_hosts,
        allowed_ports=[21, 22, 80, 443],
    )
    policy = SecurityPolicy(cfg)

    # Policy Check A: Attacking own infrastructure rejected
    res_own = policy.authorize(
        Decision(action_type="attack", target="10.10.10.101:22", priority="high", reasoning="test")
    )
    assert res_own.allowed is False
    assert "own/protected" in res_own.reason or "Forbidden" in res_own.reason

    # Policy Check B: Attacking organizer port 9999 rejected
    res_9999 = policy.authorize(
        Decision(action_type="attack", target="10.10.10.11:9999", priority="high", reasoning="test")
    )
    assert res_9999.allowed is False
    assert "9999" in res_9999.reason

    # Policy Check C: Attacking unconfigured external host rejected
    res_ext = policy.authorize(
        Decision(action_type="attack", target="8.8.8.8:80", priority="high", reasoning="test")
    )
    assert res_ext.allowed is False
    assert "TARGET_HOSTS" in res_ext.reason

    # Policy Check D: Defending valid own service permitted
    res_def = policy.authorize(
        Decision(action_type="defend", target="10.10.10.101:22", priority="high", reasoning="test")
    )
    assert res_def.allowed is True

    # Policy Check E: Attacking valid authorized target on allowed port permitted
    res_atk = policy.authorize(
        Decision(action_type="attack", target="10.10.10.11:80", priority="high", reasoning="test")
    )
    assert res_atk.allowed is True


def test_shared_team_state_credential_safety():
    """Verify that attempting to store sensitive credentials in SharedTeamState raises ValueError."""
    from agent.swarm.shared_state import SharedTeamState

    state = SharedTeamState(team_id="null_warriors")
    state.set_metadata("round_objective", "scan and patch")
    assert state.get_metadata("round_objective") == "scan and patch"

    with pytest.raises(ValueError, match="Security violation"):
        state.set_metadata("root_password", "P@ssw0rd123!")

    with pytest.raises(ValueError, match="Security violation"):
        state.set_metadata("stolen_private_key", "-----BEGIN RSA PRIVATE KEY-----")


def test_phase_state_ttl_expiration_fallback():
    """Verify that expired phase states fall back to Phase.HOLD."""
    state = PhaseState(
        phase=Phase.ATTACK,
        round_id=1,
        phase_epoch=1,
        timestamp=time.time() - 100.0,
        ttl_seconds=10.0,
    )
    assert state.is_expired() is True

    provider = SimulatedPhaseProvider(initial_phase=Phase.ATTACK, initial_round=1, ttl_seconds=1.0)
    from agent.swarm.phase_manager import PhaseManager

    pm = PhaseManager(provider=provider)
    assert pm.current_phase == Phase.ATTACK

    # Force expiration
    pm._current_state.timestamp = time.time() - 10.0
    assert pm.current_phase == Phase.HOLD
