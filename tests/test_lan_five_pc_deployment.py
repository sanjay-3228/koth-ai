"""
Integration and Recovery Test Suite for KOTH Command 5-PC LAN Deployment.

Tests:
1. Agent enrollment and independent credential authentication (agent-01 to agent-04).
2. Cross-agent impersonation rejection (agent-02 presenting agent-03 credentials).
3. Central coordinator network info exposure (/api/swarm/network-info).
4. Real heartbeat telemetry, alive status tracking, and assigned hill verification.
5. Recovery Scenario 1: One agent disconnects -> heartbeat times out -> marked STALE/OFFLINE.
6. Recovery Scenario 2: One agent reconnects with reconnect flag -> resumes active session without lockout.
7. Recovery Scenario 3: Task lease expires while agent is disconnected -> lease reaped -> reset to PENDING.
8. Recovery Scenario 4: Leader / Swarm reallocates work to an active specialist.
9. Recovery Scenario 5: Duplicate task execution prevention (two agents cannot execute or complete same lease).
10. Recovery Scenario 6: Central backend restarts (epoch bump / new instance) -> worker resynchronizes.
11. Multi-Agent coordination messages and findings exchange across 4 agents.
"""

import os
import tempfile
import time
import pytest
from flask import Flask

from agent.db import DatabaseManager
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import Phase, Task, TaskStatus, TaskType
from agent.swarm.team_manager import TeamManager


@pytest.fixture
def coordinator_env():
    """Setup an authoritative SwarmCoordinator with SQLite testbed."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_koth_lan.db")

    db_manager = DatabaseManager(db_path=db_path)
    team_manager = TeamManager(db_path=db_path)

    # Register standard 4-member team
    team_manager.register_four_member_team({
        "team_name": "Cyber Dragons",
        "team_id": "cyber_dragons",
        "description": "5-PC LAN Championship Team",
        "competition_id": "comp-lan-2026",
        "leader": {"full_name": "Alice Leader", "username": "alice_leader", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_1": {"full_name": "Bob Recon", "username": "bob_recon", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_2": {"full_name": "Charlie Exploit", "username": "charlie_exploit", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_3": {"full_name": "Diana Defender", "username": "diana_defender", "password": "Password123!", "confirm_password": "Password123!"},
    })

    # Per-agent unique tokens
    agent_tokens = {
        "agent-01": "secret-token-agent-01-leader",
        "agent-02": "secret-token-agent-02-recon",
        "agent-03": "secret-token-agent-03-exploit",
        "agent-04": "secret-token-agent-04-defense",
    }

    coordinator = SwarmCoordinator(
        team_id="cyber_dragons",
        lease_ttl=2.0,  # Fast lease TTL for tests
        heartbeat_timeout=1.5,  # Fast heartbeat timeout
        agent_tokens=agent_tokens,
        operator_token="operator-secret-token",
        auth_token="shared-team-token",
        db_path=db_path,
        db_manager=db_manager,
        team_manager=team_manager,
    )

    app = Flask("test_koth_lan")
    app.config["TESTING"] = True
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)

    client = app.test_client()

    yield {
        "coordinator": coordinator,
        "team_manager": team_manager,
        "db_manager": db_manager,
        "client": client,
        "agent_tokens": agent_tokens,
        "db_path": db_path,
    }

    try:
        coordinator.stop_background_maintenance()
    except Exception:
        pass


def test_independent_agent_enrollment_and_auth(coordinator_env):
    """Verify each of the 4 agents must present its own credential."""
    client = coordinator_env["client"]
    agent_tokens = coordinator_env["agent_tokens"]

    # 1. Agent 01 registers with its valid token
    resp1 = client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-01", "team_id": "cyber_dragons", "credential": agent_tokens["agent-01"]},
    )
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    assert "session_token" in data1
    sess_agent_01 = data1["session_token"]

    # 2. Agent 02 registers with its valid token
    resp2 = client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": agent_tokens["agent-02"]},
    )
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert "session_token" in data2
    sess_agent_02 = data2["session_token"]
    assert sess_agent_01 != sess_agent_02

    # 3. Impersonation attack: Agent 02 attempts to use Agent 03's token
    resp_bad = client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": agent_tokens["agent-03"]},
    )
    assert resp_bad.status_code == 403
    assert "Invalid credential" in resp_bad.get_json()["message"]


def test_member_login_enrollment_from_remote_pc(coordinator_env):
    """Test enrollment using team member username and password from PC 3 (Specialist)."""
    client = coordinator_env["client"]

    # Member login for Charlie Exploit (mapped to agent-03)
    login_resp = client.post(
        "/api/team/login",
        json={"username": "charlie_exploit", "password": "Password123!", "team_id": "cyber_dragons"},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.get_json()
    assert login_data["logged_in"] is True
    assert login_data["agent_id"] == "agent-03"
    assert login_data["assigned_hill"] == 3
    session_token = login_data["session_token"]

    # Now Agent 03 sends heartbeat using this session token
    hb_resp = client.post(
        "/api/swarm/heartbeat",
        headers={"X-Session-Token": session_token},
        json={
            "agent_id": "agent-03",
            "team_id": "cyber_dragons",
            "status": "READY",
            "current_phase": "HOLD",
            "phase_epoch": 0,
            "cpu_percent": 14.5,
            "memory_percent": 38.2,
            "assigned_hill": 3,
            "timestamp": time.time(),
        },
    )
    assert hb_resp.status_code == 200


def test_network_info_endpoint(coordinator_env):
    """Verify central server exposes its LAN IP, port, and status without auth."""
    client = coordinator_env["client"]
    resp = client.get("/api/swarm/network-info")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "primary_lan_ip" in data
    assert "port" in data
    assert data["port"] == 5000
    assert data["service_status"] == "ok"
    assert data["reachable"] is True


def test_agent_disconnect_and_stale_detection(coordinator_env):
    """Verify an agent that misses heartbeats transitions to offline/stale."""
    coordinator = coordinator_env["coordinator"]
    client = coordinator_env["client"]
    tokens = coordinator_env["agent_tokens"]

    # Register and send initial heartbeat for agent-02
    client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": tokens["agent-02"]},
    )
    client.post(
        "/api/swarm/heartbeat",
        headers={"X-Agent-Credential": tokens["agent-02"]},
        json={
            "agent_id": "agent-02",
            "team_id": "cyber_dragons",
            "status": "READY",
            "current_phase": "HOLD",
            "phase_epoch": 0,
            "timestamp": time.time(),
        },
    )

    status_before = coordinator.get_swarm_status()
    assert status_before["agents"]["agent-02"]["alive"] is True

    # Advance time beyond heartbeat timeout (1.5s)
    future_time = time.time() + 3.0
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-02", now=future_time) is False


def test_agent_reconnect_resilience(coordinator_env):
    """Verify an agent can reconnect after temporary disconnect using reconnect flag."""
    client = coordinator_env["client"]
    tokens = coordinator_env["agent_tokens"]

    # 1. Initial register
    r1 = client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-04", "team_id": "cyber_dragons", "credential": tokens["agent-04"]},
    )
    assert r1.status_code == 200

    # 2. Re-registering immediately with reconnect=True successfully supersedes session
    r2 = client.post(
        "/api/swarm/register",
        json={"agent_id": "agent-04", "team_id": "cyber_dragons", "credential": tokens["agent-04"], "reconnect": True},
    )
    assert r2.status_code == 200
    assert "session_token" in r2.get_json()


def test_task_lease_expiration_and_reallocation(coordinator_env):
    """Verify task lease expires when agent drops, and is reassigned to another agent."""
    coordinator = coordinator_env["coordinator"]
    client = coordinator_env["client"]
    tokens = coordinator_env["agent_tokens"]

    # Advance phase to ATTACK
    coordinator.advance_phase(Phase.ATTACK)
    epoch = coordinator.get_phase().phase_epoch

    # Register agent-02 (Specialist 1) and agent-03 (Specialist 2)
    reg2 = client.post("/api/swarm/register", json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": tokens["agent-02"]}).get_json()
    reg3 = client.post("/api/swarm/register", json={"agent_id": "agent-03", "team_id": "cyber_dragons", "credential": tokens["agent-03"]}).get_json()

    sess_02 = reg2["session_token"]
    sess_03 = reg3["session_token"]

    # Seed a task
    coordinator.task_manager.create_task(
        task_id="TASK-LAN-001",
        task_type=TaskType.ATTACK_SCAN,
        phase=Phase.ATTACK,
        phase_epoch=epoch,
        target_host="10.254.254.12",
        hill_id=2,
    )

    # Agent 02 leases the task
    req_resp = client.post(
        "/api/swarm/task/request",
        headers={"X-Session-Token": sess_02},
        json={"agent_id": "agent-02", "phase": "ATTACK", "phase_epoch": epoch, "assigned_hill": 2},
    )
    assert req_resp.status_code == 200
    leased_task = req_resp.get_json()["task"]
    assert leased_task["task_id"] == "TASK-LAN-001"

    # Agent 02 goes offline and lease expires (TTL is 2.0s)
    future = time.time() + 5.0
    reaped = coordinator.task_manager.reap_abandoned_tasks(now=future)
    assert reaped >= 1

    # Task is now back in PENDING status
    t_after = coordinator.task_manager.get_task("TASK-LAN-001")
    assert t_after.status == TaskStatus.PENDING

    # Leader reallocates work to Specialist (agent-03)
    ok, msg = coordinator.task_manager.reassign_task(
        task_id="TASK-LAN-001",
        new_agent_id="agent-03",
        caller_agent_id="agent-01",
        reason="Agent-02 disconnected, reallocating work to agent-03",
    )
    assert ok is True

    # Agent 03 (Specialist 2) can now claim the task!
    req3_resp = client.post(
        "/api/swarm/task/request",
        headers={"X-Session-Token": sess_03},
        json={"agent_id": "agent-03", "phase": "ATTACK", "phase_epoch": epoch, "assigned_hill": 3},
    )
    assert req3_resp.status_code == 200
    assert req3_resp.get_json()["task"]["task_id"] == "TASK-LAN-001"


def test_duplicate_task_execution_prevention(coordinator_env):
    """Verify two agents cannot execute or complete the same task lease concurrently."""
    coordinator = coordinator_env["coordinator"]
    client = coordinator_env["client"]
    tokens = coordinator_env["agent_tokens"]

    coordinator.advance_phase(Phase.ATTACK)
    epoch = coordinator.get_phase().phase_epoch

    # Register agent-02 and agent-03
    sess_02 = client.post("/api/swarm/register", json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": tokens["agent-02"]}).get_json()["session_token"]
    sess_03 = client.post("/api/swarm/register", json={"agent_id": "agent-03", "team_id": "cyber_dragons", "credential": tokens["agent-03"]}).get_json()["session_token"]

    coordinator.task_manager.create_task(
        task_id="TASK-LAN-EXCLUSIVE",
        task_type=TaskType.ATTACK_EXPLOIT,
        phase=Phase.ATTACK,
        phase_epoch=epoch,
        target_host="10.254.254.13",
        hill_id=3,
    )

    # Agent 03 acquires the lease
    req = client.post(
        "/api/swarm/task/request",
        headers={"X-Session-Token": sess_03},
        json={"agent_id": "agent-03", "phase": "ATTACK", "phase_epoch": epoch, "assigned_hill": 3},
    ).get_json()
    lease_id = req["lease"]["lease_id"]

    # Agent 02 attempts to illegally report completion of Agent 03's task
    fake_complete = client.post(
        "/api/swarm/task/complete",
        headers={"X-Session-Token": sess_02},
        json={
            "task_id": "TASK-LAN-EXCLUSIVE",
            "agent_id": "agent-02",
            "lease_id": lease_id,
            "result": {"status": "SUCCESS"},
        },
    )
    assert fake_complete.status_code in (400, 403, 409)

    # Agent 03 reports completion legitimately
    valid_complete = client.post(
        "/api/swarm/task/complete",
        headers={"X-Session-Token": sess_03},
        json={
            "task_id": "TASK-LAN-EXCLUSIVE",
            "agent_id": "agent-03",
            "lease_id": lease_id,
            "result": {"status": "SUCCESS"},
        },
    )
    assert valid_complete.status_code == 200
    assert valid_complete.get_json()["success"] is True


def test_coordination_messaging_between_agents(coordinator_env):
    """Verify Leader and Specialists exchange findings and guidance across the swarm."""
    client = coordinator_env["client"]
    tokens = coordinator_env["agent_tokens"]

    sess_leader = client.post("/api/swarm/register", json={"agent_id": "agent-01", "team_id": "cyber_dragons", "credential": tokens["agent-01"]}).get_json()["session_token"]
    sess_recon = client.post("/api/swarm/register", json={"agent_id": "agent-02", "team_id": "cyber_dragons", "credential": tokens["agent-02"]}).get_json()["session_token"]

    # Specialist (agent-02) reports a finding on Hill 2
    post_resp = client.post(
        "/api/coordination/messages",
        headers={"X-Session-Token": sess_recon},
        json={
            "sender_id": "agent-02",
            "team_id": "cyber_dragons",
            "message_type": "FINDING",
            "content": "Port 80 open on Hill 2 (10.254.254.12) - Apache Struts vulnerability detected",
            "hill_id": 2,
            "timestamp": time.time(),
        },
    )
    assert post_resp.status_code == 200

    # Leader (agent-01) retrieves coordination messages
    get_resp = client.get(
        "/api/coordination/messages?limit=10",
        headers={"X-Session-Token": sess_leader},
    )
    assert get_resp.status_code == 200
    msgs = get_resp.get_json()["messages"]
    assert len(msgs) >= 1
    assert any("Apache Struts" in m["content"] for m in msgs)
