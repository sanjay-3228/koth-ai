"""
Tests for Phase 6: Worker Execution Gating, Hill Task Assignment, and Authorization.
"""
import pytest
import time
from agent.actions.base import ActionContext
from agent.actions.registry import ActionRegistry
from agent.config import Config
from agent.gemini_client import Decision
from agent.security.execution_gate import FinalExecutionGate
from agent.security.policy import SecurityPolicy
from agent.swarm.models import Phase, PhaseState, Task, TaskLease, TaskStatus, TaskType


class FakeSwarmClient:
    def __init__(self, agent_id="agent-01", current_phase=Phase.ATTACK, epoch=1, kill_switch=False):
        self.agent_id = agent_id
        self.team_id = "test_team"
        self.current_phase = current_phase
        self.phase_epoch = epoch
        self.current_phase_state = PhaseState(
            phase=current_phase,
            round_id=1,
            phase_epoch=epoch,
            timestamp=time.time(),
        )
        self.kill_switch_active = kill_switch
        self.current_lease = None
        self.current_task = None


@pytest.fixture
def execution_gate():
    cfg = Config(
        target_hosts=["10.254.254.11", "10.254.254.12", "10.254.254.13", "10.254.254.14"],
        allowed_actions=["nmap_scan", "audit_local_services", "patch_vulnerability"],
    )
    policy = SecurityPolicy(cfg)
    registry = ActionRegistry()
    return FinalExecutionGate(config=cfg, security_policy=policy, action_registry=registry)


@pytest.fixture
def action_context():
    return ActionContext(agent_id="agent-01", team_id="test_team", dry_run=True)


def test_gate3_rejects_missing_task_in_active_phase(execution_gate, action_context):
    client = FakeSwarmClient(agent_id="agent-01", current_phase=Phase.ATTACK, epoch=1)
    decision = Decision(
        action_type="recon",
        target="10.254.254.11",
        priority="HIGH",
        confidence=1.0,
        reasoning="Test recon",
    )
    decision.action_name = "nmap_scan"

    # In ATTACK phase with no authorized task, Gate 3 MUST reject
    res = execution_gate.verify_and_authorize(
        decision=decision,
        context=action_context,
        task=None,
        swarm_client=client,
    )
    assert res.allowed is False
    assert res.stage == "task_authorization"
    assert "missing authorized task" in res.reason


def test_gate3_rejects_wrong_agent_assignment(execution_gate, action_context):
    client = FakeSwarmClient(agent_id="agent-01", current_phase=Phase.ATTACK, epoch=1)
    task = Task(
        task_id="task-123",
        task_type=TaskType.ATTACK_SCAN,
        phase=Phase.ATTACK,
        phase_epoch=1,
        target_host="10.254.254.11",
        assigned_agent_id="agent-02", # Assigned to agent-02, but executed by agent-01!
        lease_id="lease-123",
        hill_id=1,
    )
    decision = Decision(
        action_type="recon",
        target="10.254.254.11",
        priority="HIGH",
        confidence=1.0,
        reasoning="Test recon",
    )
    decision.action_name = "nmap_scan"

    res = execution_gate.verify_and_authorize(
        decision=decision,
        context=action_context,
        task=task,
        swarm_client=client,
    )
    assert res.allowed is False
    assert res.stage == "task_authorization"
    assert "different agent" in res.reason


def test_gate3_rejects_hill_isolation_violation(execution_gate, action_context):
    # agent-02 is mapped to Hill 2. If given a task for Hill 3, reject!
    client = FakeSwarmClient(agent_id="agent-02", current_phase=Phase.ATTACK, epoch=1)
    lease = TaskLease(
        lease_id="lease-abc",
        task_id="task-hill3",
        agent_id="agent-02",
        phase=Phase.ATTACK,
        phase_epoch=1,
        target_host="10.254.254.13",
    )
    client.current_lease = lease
    task = Task(
        task_id="task-hill3",
        task_type=TaskType.ATTACK_SCAN,
        phase=Phase.ATTACK,
        phase_epoch=1,
        target_host="10.254.254.13",
        assigned_agent_id="agent-02",
        lease_id="lease-abc",
        hill_id=3, # Violates Hill 2 assignment!
    )
    decision = Decision(
        action_type="recon",
        target="10.254.254.13",
        priority="HIGH",
        confidence=1.0,
        reasoning="Test recon",
    )
    decision.action_name = "nmap_scan"

    res = execution_gate.verify_and_authorize(
        decision=decision,
        context=action_context,
        task=task,
        swarm_client=client,
    )
    assert res.allowed is False
    assert res.stage == "task_authorization"
    assert "hill assignment mismatch" in res.reason


def test_gate4_rejects_stale_epoch(execution_gate, action_context):
    client = FakeSwarmClient(agent_id="agent-01", current_phase=Phase.ATTACK, epoch=5)
    lease = TaskLease(
        lease_id="lease-stale",
        task_id="task-old",
        agent_id="agent-01",
        phase=Phase.ATTACK,
        phase_epoch=4,
        target_host="10.254.254.11",
    )
    client.current_lease = lease
    task = Task(
        task_id="task-old",
        task_type=TaskType.ATTACK_SCAN,
        phase=Phase.ATTACK,
        phase_epoch=4, # Epoch 4 != Swarm Epoch 5
        target_host="10.254.254.11",
        assigned_agent_id="agent-01",
        lease_id="lease-stale",
        hill_id=1,
    )
    decision = Decision(
        action_type="recon",
        target="10.254.254.11",
        priority="HIGH",
        confidence=1.0,
        reasoning="Test recon",
    )
    decision.action_name = "nmap_scan"

    res = execution_gate.verify_and_authorize(
        decision=decision,
        context=action_context,
        task=task,
        swarm_client=client,
    )
    assert res.allowed is False
    assert res.stage == "final_execution_authorization"
    assert "epoch" in res.reason.lower()


def test_gate4_rejects_on_emergency_stop(execution_gate, action_context):
    client = FakeSwarmClient(agent_id="agent-01", current_phase=Phase.ATTACK, epoch=1, kill_switch=True)
    decision = Decision(
        action_type="recon",
        target="10.254.254.11",
        priority="HIGH",
        confidence=1.0,
        reasoning="Test recon",
    )
    decision.action_name = "nmap_scan"

    res = execution_gate.verify_and_authorize(
        decision=decision,
        context=action_context,
        task=None,
        swarm_client=client,
    )
    assert res.allowed is False
    assert "Kill switch is active" in res.reason
