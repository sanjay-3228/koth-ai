"""
Comprehensive Automated Verification for Participant-Focused Features:
1. Real-Time Agent Monitoring (telemetry, heartbeat health, LLM status, RBAC inspection).
2. Notifications and Event Feed (persistence, anti-duplication, category filtering, team isolation).
3. Multi-Agent Coordination (objective decomposition, task dependencies, duplicate detection, reassignment).
"""

import time
import pytest
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import (
    AgentHeartbeat,
    AgentRole,
    AgentStatus,
    Phase,
    Task,
    TaskStatus,
    TaskType,
)
from agent.swarm.events import EventType, SwarmEvent
from agent.db import DatabaseManager
from agent.swarm.team_manager import TeamManager


@pytest.fixture
def coordinator_env(tmp_path):
    db_path = str(tmp_path / "participant_test.db")
    db_mgr = DatabaseManager(db_path=db_path)
    team_mgr = TeamManager(db_path=db_path)

    coord = SwarmCoordinator(
        team_id="test_team",
        db_path=db_path,
        db_manager=db_mgr,
        team_manager=team_mgr,
        target_hosts=["10.0.1.10", "10.0.2.20"],
        own_hosts=["192.168.1.10", "192.168.1.20"],
    )

    # Register sample team
    payload = {
        "team_name": "Test Swarm",
        "team_id": "test_team",
        "description": "Test Swarm Team",
        "leader": {"full_name": "Alice Leader", "username": "alice", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_1": {"full_name": "Bob Specialist", "username": "bob", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_2": {"full_name": "Charlie Specialist", "username": "charlie", "password": "Password123!", "confirm_password": "Password123!"},
        "teammate_3": {"full_name": "Diana Specialist", "username": "diana", "password": "Password123!", "confirm_password": "Password123!"},
    }
    team_mgr.register_four_member_team(payload)

    import flask
    app = flask.Flask(__name__)
    app.config["TESTING"] = True
    bp = create_coordinator_blueprint(coord)
    app.register_blueprint(bp)
    client = app.test_client()

    # Login alice (leader -> agent-01) and bob (teammate -> agent-02)
    alice_login = client.post("/api/team/login", json={"username": "alice", "password": "Password123!"}).get_json()
    bob_login = client.post("/api/team/login", json={"username": "bob", "password": "Password123!"}).get_json()

    return {
        "coord": coord,
        "client": client,
        "db": db_mgr,
        "alice_token": alice_login["session_token"],
        "bob_token": bob_login["session_token"],
    }


class TestRealTimeAgentMonitoring:
    """Verifies agent connection states, telemetry masking, LLM configuration, and inspection RBAC."""

    def test_telemetry_metrics_zero_fabrication(self, coordinator_env):
        coord = coordinator_env["coord"]
        now = time.time()

        # agent-01 sends telemetry with CPU & memory
        hb1 = AgentHeartbeat(
            agent_id="agent-01",
            team_id="test_team",
            status=AgentStatus.RUNNING,
            current_phase=Phase.ATTACK,
            phase_epoch=1,
            timestamp=now,
            metadata={"cpu_percent": 34.5, "memory_mb": 512.0},
        )
        coord.heartbeat_monitor.record_heartbeat(hb1)

        # agent-02 sends telemetry WITHOUT CPU & memory
        hb2 = AgentHeartbeat(
            agent_id="agent-02",
            team_id="test_team",
            status=AgentStatus.READY,
            current_phase=Phase.ATTACK,
            phase_epoch=1,
            timestamp=now,
            metadata={},
        )
        coord.heartbeat_monitor.record_heartbeat(hb2)

        status = coord.get_swarm_status()
        ag1 = status["agents"]["agent-01"]
        ag2 = status["agents"]["agent-02"]

        # Real telemetry present
        assert ag1["cpu_percent"] == 34.5
        assert ag1["memory_mb"] == 512.0

        # Telemetry absent: MUST be None, NO fabrication!
        assert ag2["cpu_percent"] is None
        assert ag2["memory_mb"] is None

    def test_connection_states_online_busy_idle_stale_offline(self, coordinator_env):
        coord = coordinator_env["coord"]
        now = time.time()

        # 1. agent-01: Heartbeat sent just now, active lease/task -> BUSY
        t1 = coord.task_manager.create_task(
            task_type=TaskType.ATTACK_SCAN,
            phase=Phase.ATTACK,
            target_host="10.0.1.10",
        )
        task, lease = coord.task_manager.claim_task(t1.task_id, "agent-01", Phase.ATTACK, 1)
        hb1 = AgentHeartbeat(
            agent_id="agent-01",
            team_id="test_team",
            status=AgentStatus.RUNNING,
            current_phase=Phase.ATTACK,
            phase_epoch=1,
            current_task_id=t1.task_id,
            timestamp=now,
        )
        coord.heartbeat_monitor.record_heartbeat(hb1)

        # 2. agent-02: Heartbeat sent just now, no active task -> IDLE
        hb2 = AgentHeartbeat(
            agent_id="agent-02",
            team_id="test_team",
            status=AgentStatus.READY,
            current_phase=Phase.ATTACK,
            phase_epoch=1,
            timestamp=now,
        )
        coord.heartbeat_monitor.record_heartbeat(hb2)

        # 3. agent-03: Missed recent heartbeat (6 seconds ago) -> STALE
        hb3 = AgentHeartbeat(
            agent_id="agent-03",
            team_id="test_team",
            status=AgentStatus.READY,
            current_phase=Phase.ATTACK,
            phase_epoch=1,
            timestamp=now - 6.0,
        )
        coord.heartbeat_monitor.record_heartbeat(hb3)
        coord.heartbeat_monitor._last_seen["agent-03"] = now - 6.0

        # 4. agent-04: Never checked in or timed out (>15s) -> OFFLINE
        coord.heartbeat_monitor._last_seen.pop("agent-04", None)

        status = coord.get_swarm_status()
        assert status["agents"]["agent-01"]["connection_state"] == "BUSY"
        assert status["agents"]["agent-02"]["connection_state"] == "IDLE"
        assert status["agents"]["agent-03"]["connection_state"] == "STALE"
        assert status["agents"]["agent-04"]["connection_state"] == "OFFLINE"

    def test_agent_monitoring_detail_rbac(self, coordinator_env):
        client = coordinator_env["client"]
        alice_token = coordinator_env["alice_token"]  # Leader (agent-01)
        bob_token = coordinator_env["bob_token"]      # Specialist (agent-02)

        # Leader can view any agent
        res1 = client.get(
            "/api/swarm/agent/agent-02/monitoring",
            headers={"X-Session-Token": alice_token},
        )
        assert res1.status_code == 200
        data1 = res1.get_json()
        assert data1["agent_id"] == "agent-02"
        assert "status" in data1
        assert "task_history" in data1
        assert "execution_logs" in data1

        # Bob can view his own agent
        res2 = client.get(
            "/api/swarm/agent/agent-02/monitoring",
            headers={"X-Session-Token": bob_token},
        )
        assert res2.status_code == 200

        # Bob CANNOT inspect another agent (agent-03)
        res3 = client.get(
            "/api/swarm/agent/agent-03/monitoring",
            headers={"X-Session-Token": bob_token},
        )
        assert res3.status_code == 403


class TestNotificationsAndEventFeed:
    """Verifies persistent event feed, anti-duplication, and category filters."""

    def test_notification_persistence_and_anti_duplication(self, coordinator_env):
        db = coordinator_env["db"]

        # Insert notification
        eid1 = db.record_notification(
            event_id="evt-uniq-101",
            event_type="HILL_CAPTURED",
            category="HILLS",
            severity="SUCCESS",
            description="Hill 1 captured by agent-01",
            agent_id="agent-01",
            hill_id=1,
            team_id="test_team",
        )
        assert eid1 == "evt-uniq-101"

        # Duplicate insert with identical event_id must be ignored
        eid2 = db.record_notification(
            event_id="evt-uniq-101",
            event_type="HILL_CAPTURED",
            category="HILLS",
            severity="SUCCESS",
            description="Duplicate attempt",
            agent_id="agent-01",
            hill_id=1,
            team_id="test_team",
        )
        assert eid2 == "evt-uniq-101"

        notifs = db.get_notifications(team_id="test_team")
        matching = [n for n in notifs if n["event_id"] == "evt-uniq-101"]
        assert len(matching) == 1
        assert matching[0]["description"] == "Hill 1 captured by agent-01"

    def test_notification_category_filtering_and_rest_endpoint(self, coordinator_env):
        client = coordinator_env["client"]
        alice_token = coordinator_env["alice_token"]
        db = coordinator_env["db"]

        # Seed notifications in different categories
        db.record_notification(
            event_type="HILL_CAPTURED", category="HILLS", severity="SUCCESS",
            description="Hill 2 captured", team_id="test_team"
        )
        db.record_notification(
            event_type="TASK_COMPLETED", category="TASKS", severity="SUCCESS",
            description="Task completed", team_id="test_team"
        )
        db.record_notification(
            event_type="ACTION_BLOCKED", category="SECURITY", severity="CRITICAL",
            description="Unauthorized port blocked", team_id="test_team"
        )

        # Query all
        res_all = client.get("/api/swarm/notifications", headers={"X-Session-Token": alice_token})
        assert res_all.status_code == 200
        all_items = res_all.get_json()["notifications"]
        assert len(all_items) >= 3

        # Query category HILLS
        res_hills = client.get("/api/swarm/notifications?category=HILLS", headers={"X-Session-Token": alice_token})
        assert res_hills.status_code == 200
        hills_items = res_hills.get_json()["notifications"]
        assert all(n["category"] == "HILLS" for n in hills_items)

        # Query category SECURITY
        res_sec = client.get("/api/swarm/notifications?category=SECURITY", headers={"X-Session-Token": alice_token})
        assert res_sec.status_code == 200
        sec_items = res_sec.get_json()["notifications"]
        assert all(n["category"] == "SECURITY" for n in sec_items)


class TestMultiAgentCoordination:
    """Verifies objective breakdown, prerequisite dependencies, duplicate detection, and task reassignment."""

    def test_objective_decomposition_and_dependencies(self, coordinator_env):
        coord = coordinator_env["coord"]
        task_mgr = coord.task_manager

        # Leader breaks down competition objective
        tasks = task_mgr.break_down_objective(
            objective_text="Compromise Hill 2 and audit web services",
            leader_agent_id="agent-01",
            phase=Phase.ATTACK,
            target_hosts=["10.0.2.20"],
            hills=[2],
        )

        assert len(tasks) == 2
        recon_task = tasks[0]
        exploit_task = tasks[1]

        # Recon task has no dependencies
        assert recon_task.dependencies == []
        assert recon_task.task_type == TaskType.ATTACK_SCAN

        # Exploit task depends on Recon task!
        assert recon_task.task_id in exploit_task.dependencies
        assert exploit_task.task_type == TaskType.ATTACK_EXPLOIT

        # Attempt to claim exploit_task BEFORE recon_task is completed: MUST FAIL
        claimed_task, lease = task_mgr.claim_task(exploit_task.task_id, "agent-02", Phase.ATTACK, 1)
        assert claimed_task is None
        assert lease is None

        # Now claim and complete recon_task
        c_recon, l_recon = task_mgr.claim_task(recon_task.task_id, "agent-02", Phase.ATTACK, 1)
        assert c_recon is not None
        ok = task_mgr.complete_task(recon_task.task_id, "agent-02", {"open_ports": [80, 443]})
        assert ok is True

        # Now exploit_task can be claimed because its prerequisite dependency is completed!
        c_exploit, l_exploit = task_mgr.claim_task(exploit_task.task_id, "agent-02", Phase.ATTACK, 1)
        assert c_exploit is not None
        assert l_exploit is not None

    def test_duplicate_work_detection(self, coordinator_env):
        coord = coordinator_env["coord"]
        task_mgr = coord.task_manager

        # Create active task on 10.0.1.10 nmap_scan
        t1 = task_mgr.create_task(
            task_type=TaskType.ATTACK_SCAN,
            phase=Phase.ATTACK,
            target_host="10.0.1.10",
            action_name="nmap_scan",
        )
        assert t1 is not None

        # Duplicate check should detect existing active task
        is_dup = task_mgr.detect_duplicate_work(
            target_host="10.0.1.10",
            action_name="nmap_scan",
            phase=Phase.ATTACK,
        )
        assert is_dup is True

        # Different target should not be considered duplicate
        assert task_mgr.detect_duplicate_work("10.0.9.99", "nmap_scan", Phase.ATTACK) is False

    def test_task_reassignment_on_agent_failure(self, coordinator_env):
        coord = coordinator_env["coord"]
        task_mgr = coord.task_manager

        t = task_mgr.create_task(
            task_type=TaskType.DEFENSE_PATCH,
            phase=Phase.DEFENSE,
            target_host="192.168.1.10",
            hill_id=2,
        )
        c, lease = task_mgr.claim_task(t.task_id, "agent-02", Phase.DEFENSE, 1)
        assert t.assigned_agent_id == "agent-02"

        # Specialist (bob) fails or disconnects; Leader reassigns task to agent-03
        ok, msg = task_mgr.reassign_task(
            task_id=t.task_id,
            new_agent_id="agent-03",
            caller_agent_id="agent-01",
            reason="agent-02 disconnected, reassigning to Charlie",
        )
        assert ok is True
        assert t.assigned_agent_id == "agent-03"
        assert t.lease_id is None
        assert t.status == TaskStatus.PENDING

        # Specialist cannot reassign tasks (unauthorized)
        fail_ok, _ = task_mgr.reassign_task(
            task_id=t.task_id,
            new_agent_id="agent-04",
            caller_agent_id="agent-02",
        )
        assert fail_ok is False

    def test_coordination_messages_and_blockers_api(self, coordinator_env):
        client = coordinator_env["client"]
        alice_token = coordinator_env["alice_token"]
        bob_token = coordinator_env["bob_token"]

        # Bob posts a blocker report
        post_res = client.post(
            "/api/swarm/coordination/message",
            headers={"X-Session-Token": bob_token},
            json={
                "message_type": "BLOCKER_REPORT",
                "content": "Port 443 blocked by WAF, need firewall assistance",
                "hill_id": 2,
            },
        )
        assert post_res.status_code == 200
        assert post_res.get_json()["success"] is True

        # Fetch messages
        get_res = client.get(
            "/api/swarm/coordination/messages",
            headers={"X-Session-Token": alice_token},
        )
        assert get_res.status_code == 200
        msgs = get_res.get_json()["messages"]
        assert len(msgs) >= 1
        assert msgs[0]["message_type"] == "BLOCKER_REPORT"

        # Check summary endpoint
        sum_res = client.get(
            "/api/swarm/coordination/summary",
            headers={"X-Session-Token": alice_token},
        )
        assert sum_res.status_code == 200
        summary = sum_res.get_json()
        assert summary["leader"] == "agent-01"
        assert len(summary["blockers"]) >= 1
