"""
Comprehensive Architecture Verification Suite: Full Desktop Client Architecture
Simulates a Central Server + 4 Independent Participant Desktop PC Clients over LAN.

Verifies:
  1. Authoritative SQLite persistence strictly on the Central Server.
  2. 4-member squad registration with distinct user accounts.
  3. 4 independent participant client logins (Leader + 3 Teammates).
  4. Server-authoritative session binding and rejection of agent identity impersonation.
  5. Role-based authorization gates (Leader-only phase advance vs Member restrictions).
  6. Shared live competition state synchronization across all 4 desktop sessions.
  7. Local agent worker runtime simulation (independent heartbeats & telemetry).
  8. Cross-client multi-agent coordination messaging & event feed synchronization.
  9. Client network disconnection and graceful reconnection resilience.
 10. Central coordinator restart recovery with persistent session resumption.
"""

import json
import os
import shutil
import tempfile
import time
import pytest
from flask import Flask

from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import AgentRole, Phase
from agent.swarm.team_manager import TeamManager


@pytest.fixture
def test_environment():
    """Setup an isolated temporary environment simulating the Central Server."""
    temp_dir = tempfile.mkdtemp(prefix="koth_full_desktop_test_")
    db_path = os.path.join(temp_dir, "central_koth_swarm.db")

    # Initialize authoritative Central Coordinator
    coordinator = SwarmCoordinator(
        db_path=db_path,
        team_id="cyber_guardians",
        session_ttl=3600.0,
        lease_ttl=15.0,
    )

    app = Flask(__name__)
    app.config["TESTING"] = True
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)
    client = app.test_client()

    yield {
        "temp_dir": temp_dir,
        "db_path": db_path,
        "coordinator": coordinator,
        "app": app,
        "client": client,
    }

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_01_central_server_persistence_and_no_client_db(test_environment):
    """Verify that authoritative state is stored on the central server SQLite database."""
    import sqlite3
    db_path = test_environment["db_path"]
    coordinator = test_environment["coordinator"]

    assert os.path.exists(db_path), "Central authoritative SQLite database must exist on Central PC"
    assert coordinator.db_manager is not None
    # Verify WAL mode is configured
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        assert mode.upper() == "WAL", f"Central DB must use WAL mode, got {mode}"


def test_02_four_member_squad_registration_and_distinct_logins(test_environment):
    """
    Test registration of a full 4-member squad and independent logins for:
    - Leader (Agent 01, Hill 1)
    - Teammate 1 (Agent 02, Hill 2)
    - Teammate 2 (Agent 03, Hill 3)
    - Teammate 3 (Agent 04, Hill 4)
    """
    client = test_environment["client"]

    # 1. Register 4-member team
    reg_payload = {
        "team_name": "Cyber Guardians",
        "team_id": "cyber_guardians",
        "leader": {
            "full_name": "Alice Leader",
            "username": "alice_leader",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_1": {
            "full_name": "Bob Recon",
            "username": "bob_recon",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_2": {
            "full_name": "Charlie Exploit",
            "username": "charlie_exploit",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_3": {
            "full_name": "Diana Defender",
            "username": "diana_defense",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    }

    reg_resp = client.post("/api/team/register-four", json=reg_payload)
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.get_json()}"
    reg_data = reg_resp.get_json()
    assert reg_data["success"] is True

    # 2. Login from 4 separate desktop client instances
    client_credentials = [
        ("alice_leader", "Password123!", "agent-01", 1, "LEADER"),
        ("bob_recon", "Password123!", "agent-02", 2, "MEMBER"),
        ("charlie_exploit", "Password123!", "agent-03", 3, "MEMBER"),
        ("diana_defense", "Password123!", "agent-04", 4, "MEMBER"),
    ]

    sessions = {}
    for username, pwd, expected_agent, expected_hill, expected_role in client_credentials:
        login_resp = client.post("/api/team/login", json={"username": username, "password": pwd})
        assert login_resp.status_code == 200, f"Login failed for {username}"
        ldata = login_resp.get_json()

        assert ldata["logged_in"] is True
        assert ldata["agent_id"] == expected_agent, f"Wrong agent_id for {username}"
        assert ldata["assigned_hill"] == expected_hill, f"Wrong assigned_hill for {username}"
        assert ldata["role"] == expected_role, f"Wrong role for {username}"
        assert len(ldata["session_token"]) > 32, "Cryptographically secure token required"

        sessions[username] = ldata

    # Verify all session tokens are unique
    all_tokens = [s["session_token"] for s in sessions.values()]
    assert len(set(all_tokens)) == 4, "Every client must receive an independent unique session token"


def test_03_impersonation_rejection_across_participants(test_environment):
    """
    Verify that an authenticated participant client cannot impersonate another agent identity:
    - Teammate 1 (bob_recon / agent-02) cannot send heartbeats or coordination messages claiming to be agent-01.
    """
    client = test_environment["client"]

    # Register & Login
    _register_standard_squad(client)
    bob_login = client.post("/api/team/login", json={"username": "bob_recon", "password": "Password123!"}).get_json()
    bob_token = bob_login["session_token"]

    bob_headers = {
        "Content-Type": "application/json",
        "X-Session-Token": bob_token,
    }

    # 1. Impersonation attempt via heartbeat
    impersonate_hb = client.post(
        "/api/swarm/heartbeat",
        headers=bob_headers,
        json={"agent_id": "agent-01"},  # Bob claims to be agent-01!
    )
    assert impersonate_hb.status_code == 403, "Heartbeat impersonation must be rejected with 403 Forbidden"
    assert "Agent ID mismatch" in impersonate_hb.get_json()["message"]

    # 2. Impersonation attempt via coordination message
    impersonate_msg = client.post(
        "/api/coordination/message",
        headers=bob_headers,
        json={
            "from_agent_id": "agent-01",  # Bob claims to be leader!
            "to_agent_id": "ALL",
            "message_type": "TACTICAL_DIRECTIVE",
            "content": "Fake directive from unauthorized teammate",
        },
    )
    assert impersonate_msg.status_code == 403, "Coordination message impersonation must be rejected with 403 Forbidden"
    assert "Sender impersonation rejected" in impersonate_msg.get_json()["message"]


def test_04_role_based_leader_gates(test_environment):
    """
    Verify that leader-only operations are strictly enforced by the backend:
    - Teammate (role=MEMBER) cannot advance swarm phase.
    - Team Leader (role=LEADER) can advance swarm phase.
    """
    client = test_environment["client"]
    _register_standard_squad(client)

    alice_token = client.post("/api/team/login", json={"username": "alice_leader", "password": "Password123!"}).get_json()["session_token"]
    bob_token = client.post("/api/team/login", json={"username": "bob_recon", "password": "Password123!"}).get_json()["session_token"]

    # 1. Teammate attempts phase advance
    tm_advance = client.post(
        "/api/swarm/phase/advance",
        headers={"X-Session-Token": bob_token},
        json={"phase": "ATTACK"},
    )
    assert tm_advance.status_code == 403, "Teammate must be forbidden from advancing phase"
    assert "Operator privileges required" in tm_advance.get_json()["message"]

    # 2. Leader advances phase
    leader_advance = client.post(
        "/api/swarm/phase/advance",
        headers={"X-Session-Token": alice_token},
        json={"phase": "ATTACK"},
    )
    assert leader_advance.status_code == 200, f"Leader must be able to advance phase: {leader_advance.get_json()}"
    assert leader_advance.get_json()["phase"] == "ATTACK"


def test_05_shared_workspace_synchronization_across_four_clients(test_environment):
    """
    Verify that all 4 connected participant desktop clients see the exact same
    synchronized competition state, swarm phase, epoch, and hill configurations.
    """
    client = test_environment["client"]
    _register_standard_squad(client)

    tokens = {}
    for un, aid in [("alice_leader", "agent-01"), ("bob_recon", "agent-02"), ("charlie_exploit", "agent-03"), ("diana_defense", "agent-04")]:
        tokens[aid] = client.post("/api/team/login", json={"username": un, "password": "Password123!"}).get_json()["session_token"]

    # Leader advances phase to DEFENSE
    client.post(
        "/api/swarm/phase/advance",
        headers={"X-Session-Token": tokens["agent-01"]},
        json={"phase": "DEFENSE"},
    )

    # All 4 clients poll swarm status independently
    for aid, tok in tokens.items():
        resp = client.get("/api/swarm/status", headers={"X-Session-Token": tok})
        assert resp.status_code == 200, f"Client {aid} status polling failed"
        data = resp.json
        assert data["phase"]["phase"] == "DEFENSE", f"Client {aid} saw desynchronized phase"
        assert data["phase"]["phase_epoch"] >= 1, f"Client {aid} saw desynchronized epoch"


def test_06_local_agent_worker_heartbeats_and_telemetry(test_environment):
    """
    Simulate the 4 local agent workers running on the 4 participant PCs:
    - Each sends authentic heartbeats and CPU/RAM telemetry for its assigned agent ID.
    - Central server tracks all 4 agents as online and registers their metrics.
    """
    client = test_environment["client"]
    coordinator = test_environment["coordinator"]
    _register_standard_squad(client)

    agent_metrics = {
        "agent-01": {"cpu_percent": 14.5, "memory_percent": 42.1},
        "agent-02": {"cpu_percent": 28.2, "memory_percent": 55.4},
        "agent-03": {"cpu_percent": 8.0, "memory_percent": 35.8},
        "agent-04": {"cpu_percent": 19.3, "memory_percent": 49.0},
    }

    tokens = {}
    for un, aid in [("alice_leader", "agent-01"), ("bob_recon", "agent-02"), ("charlie_exploit", "agent-03"), ("diana_defense", "agent-04")]:
        tokens[aid] = client.post("/api/team/login", json={"username": un, "password": "Password123!"}).get_json()["session_token"]

    # Transmit heartbeats with metrics from each worker
    for aid, metrics in agent_metrics.items():
        hb_resp = client.post(
            "/api/swarm/heartbeat",
            headers={"X-Session-Token": tokens[aid]},
            json={
                "agent_id": aid,
                "team_id": "cyber_guardians",
                "telemetry": metrics,
            },
        )
        assert hb_resp.status_code == 200, f"Heartbeat failed for {aid}: {hb_resp.get_json()}"

    # Verify in central coordinator status
    status_resp = client.get("/api/swarm/status", headers={"X-Session-Token": tokens["agent-01"]})
    agents = status_resp.get_json()["agents"]

    for aid, expected_metrics in agent_metrics.items():
        assert aid in agents, f"{aid} missing from swarm agents"
        assert agents[aid]["alive"] is True, f"{aid} should be alive"
        assert agents[aid]["telemetry"]["cpu_percent"] == expected_metrics["cpu_percent"]
        assert agents[aid]["telemetry"]["memory_percent"] == expected_metrics["memory_percent"]


def test_07_cross_client_coordination_messaging(test_environment):
    """
    Verify bidirectional coordination messaging across participant desktop clients:
    - Teammate 1 (agent-02) posts a finding message.
    - All 4 clients can query and read the message.
    """
    client = test_environment["client"]
    _register_standard_squad(client)

    alice_token = client.post("/api/team/login", json={"username": "alice_leader", "password": "Password123!"}).get_json()["session_token"]
    bob_token = client.post("/api/team/login", json={"username": "bob_recon", "password": "Password123!"}).get_json()["session_token"]
    charlie_token = client.post("/api/team/login", json={"username": "charlie_exploit", "password": "Password123!"}).get_json()["session_token"]

    # Bob sends a coordination finding
    post_resp = client.post(
        "/api/coordination/message",
        headers={"X-Session-Token": bob_token},
        json={
            "from_agent_id": "agent-02",
            "to_agent_id": "ALL",
            "message_type": "FINDING_DISCOVERED",
            "content": "Port 8080 exposed with default admin credentials on Hill 2",
            "hill_id": 2,
        },
    )
    assert post_resp.status_code == 200
    mid = post_resp.get_json()["message_id"]

    # Charlie (on PC 3) retrieves messages
    c_resp = client.get("/api/coordination/messages", headers={"X-Session-Token": charlie_token})
    assert c_resp.status_code == 200
    messages = c_resp.get_json()["messages"]
    found = [m for m in messages if m.get("message_id") == mid or m.get("id") == mid]
    assert len(found) == 1, "Charlie must see Bob's message"
    assert found[0]["from_agent_id"] == "agent-02"
    assert "default admin credentials" in found[0]["content"]

    # Alice (on PC 1) also retrieves messages
    a_resp = client.get("/api/coordination/messages", headers={"X-Session-Token": alice_token})
    assert any(m.get("message_id") == mid or m.get("id") == mid for m in a_resp.get_json()["messages"]), "Alice must see Bob's message"


def test_08_client_disconnection_and_reconnection_resilience(test_environment):
    """
    Verify system resilience when an agent worker disconnects and subsequently reconnects:
    - Agent 03 halts heartbeats -> detected as stale / offline after threshold.
    - Other agents remain unaffected.
    - Agent 03 resumes heartbeats -> seamlessly returns to alive/online status.
    """
    client = test_environment["client"]
    coordinator = test_environment["coordinator"]
    _register_standard_squad(client)

    tokens = {}
    for un, aid in [("alice_leader", "agent-01"), ("bob_recon", "agent-02"), ("charlie_exploit", "agent-03"), ("diana_defense", "agent-04")]:
        tokens[aid] = client.post("/api/team/login", json={"username": un, "password": "Password123!"}).get_json()["session_token"]

    # All 4 agents send heartbeat at t0
    t0 = time.time()
    for aid, tok in tokens.items():
        client.post(
            "/api/swarm/heartbeat",
            headers={"X-Session-Token": tok},
            json={"agent_id": aid, "team_id": "cyber_guardians"},
        )

    # Simulate 35 seconds passing: Agent 03 does NOT send heartbeat; agents 01, 02, 04 do send heartbeat
    t_future = t0 + 35.0
    for aid in ["agent-01", "agent-02", "agent-04"]:
        coordinator.heartbeat_monitor._last_seen[aid] = t_future

    # Check alive status: agent-03 must be stale/offline (>30s)
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-03", now=t_future) is False, "Agent 03 should be offline"
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-01", now=t_future) is True, "Agent 01 should remain online"
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-02", now=t_future) is True, "Agent 02 should remain online"
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-04", now=t_future) is True, "Agent 04 should remain online"

    # Agent 03 reconnects and sends a new heartbeat
    t_reconnect = t_future + 5.0
    coordinator.heartbeat_monitor._last_seen["agent-03"] = t_reconnect
    assert coordinator.heartbeat_monitor.is_agent_alive("agent-03", now=t_reconnect) is True, "Agent 03 must return to alive"


def test_09_coordinator_restart_resilience_with_persistent_sqlite(test_environment):
    """
    Verify server restart recovery:
    - Sessions and team records remain intact in persistent SQLite DB.
    - After coordinator reboots, participant clients resume active queries without re-registering.
    """
    db_path = test_environment["db_path"]
    client = test_environment["client"]
    _register_standard_squad(client)

    alice_login = client.post("/api/team/login", json={"username": "alice_leader", "password": "Password123!"}).get_json()
    alice_token = alice_login["session_token"]

    # Simulate coordinator crash / restart
    restarted_coord = SwarmCoordinator(
        db_path=db_path,
        team_id="cyber_guardians",
        session_ttl=3600.0,
    )
    new_app = Flask(__name__)
    new_app.config["TESTING"] = True
    new_app.register_blueprint(create_coordinator_blueprint(restarted_coord))
    new_client = new_app.test_client()

    # Reconnected client queries status using persisted session token
    status_resp = new_client.get("/api/swarm/status", headers={"X-Session-Token": alice_token})
    assert status_resp.status_code == 200, "Persisted session token must remain valid after coordinator restart"
    assert status_resp.get_json()["team_id"] == "cyber_guardians"


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

def _register_standard_squad(client):
    """Register standard 4-member squad for testing."""
    return client.post("/api/team/register-four", json={
        "team_name": "Cyber Guardians",
        "team_id": "cyber_guardians",
        "leader": {
            "full_name": "Alice Leader",
            "username": "alice_leader",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_1": {
            "full_name": "Bob Recon",
            "username": "bob_recon",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_2": {
            "full_name": "Charlie Exploit",
            "username": "charlie_exploit",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_3": {
            "full_name": "Diana Defender",
            "username": "diana_defense",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    })
