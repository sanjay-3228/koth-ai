"""
Tests for Phase 3: Team and Member Management with PBKDF2 Password Hashing,
Atomic 4-Member Registration, Strict RBAC Isolation, and Migration Handling.

Covers all 12 requirements:
1. Complete four-member team registration succeeds.
2. Missing teammate details rejection.
3. Duplicate username within team registration rejection.
4. Duplicate username against existing registered team rejection.
5. Password confirmation mismatch rejection.
6. Password hashing verified: PBKDF2 with unique salt, not plaintext.
7. Atomic transaction: failure on member 4 rolls back all records (zero left in DB).
8. Individual member login succeeds for all four members.
9. Correct agent assignment: Leader -> agent-01, TM1 -> agent-02, TM2 -> agent-03, TM3 -> agent-04.
10. Correct hill isolation: TM1 cannot configure Hill 1, 3, or 4.
11. Team management permissions: Leader gets 200 with all 4 members; Teammates get 403.
12. Existing database migration & incomplete team handling: legacy teams marked INCOMPLETE, leader can complete onboarding, no fake accounts.
"""
import os
import sqlite3
import tempfile
import pytest
from flask import Flask

from agent.swarm.team_manager import TeamManager, verify_password, hash_password
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import AgentRole


@pytest.fixture
def temp_team_mgr():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_team.db")
        mgr = TeamManager(db_path=db_path)
        yield mgr


@pytest.fixture
def coordinator_app():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_coord.db")
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            auth_token="test-team-secret-1234",
            operator_token="test-operator-secret-1234",
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("test_coord_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        yield coord, app


def sample_four_member_payload(team_id="cyber_dragons", team_name="Cyber Dragons"):
    return {
        "team_id": team_id,
        "team_name": team_name,
        "description": "Red Team Defense Swarm",
        "competition_id": "DEFCON-2026",
        "leader": {
            "full_name": "Alice Leader",
            "username": f"{team_id}_alice",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_1": {
            "full_name": "Bob Defender",
            "username": f"{team_id}_bob",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_2": {
            "full_name": "Charlie Sentry",
            "username": f"{team_id}_charlie",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        "teammate_3": {
            "full_name": "Diana Recon",
            "username": f"{team_id}_diana",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    }


# =============================================================================
# 1. Complete Four-Member Team Registration
# =============================================================================
def test_complete_four_member_team_registration(temp_team_mgr):
    payload = sample_four_member_payload()
    result = temp_team_mgr.register_four_member_team(payload)

    assert result["success"] is True
    assert result["team_id"] == "cyber_dragons"
    assert result["team_name"] == "Cyber Dragons"
    assert result["registration_status"] == "COMPLETE"
    assert len(result["members"]) == 4

    # Verify session token for the leader
    assert "session_token" in result
    assert result["agent_id"] == "agent-01"
    assert result["assigned_hill"] == 1

    # Verify database state
    with temp_team_mgr._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM team_members WHERE team_id = 'cyber_dragons'")
        assert cur.fetchone()["cnt"] == 4

        cur.execute("SELECT COUNT(*) as cnt FROM hill_configs WHERE team_id = 'cyber_dragons'")
        assert cur.fetchone()["cnt"] == 4


# =============================================================================
# 2. Missing Teammate Details Rejection
# =============================================================================
def test_missing_teammate_details_rejection(temp_team_mgr):
    # Only leader provided
    payload_incomplete = {
        "team_name": "Incomplete Team",
        "leader": {
            "full_name": "Alice Leader",
            "username": "incomp_alice",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    }
    with pytest.raises(ValueError, match="All four team members.*are mandatory"):
        temp_team_mgr.register_four_member_team(payload_incomplete)

    # Empty full_name for teammate 2
    payload_empty_name = sample_four_member_payload("empty_name_team", "Empty Name Team")
    payload_empty_name["teammate_2"]["full_name"] = "  "
    with pytest.raises(ValueError, match="Full name is required for Teammate 2"):
        temp_team_mgr.register_four_member_team(payload_empty_name)

    # Empty username for teammate 3
    payload_empty_user = sample_four_member_payload("empty_user_team", "Empty User Team")
    payload_empty_user["teammate_3"]["username"] = ""
    with pytest.raises(ValueError, match="Username for Teammate 3 must be between 3 and 30 characters"):
        temp_team_mgr.register_four_member_team(payload_empty_user)


# =============================================================================
# 3. Duplicate Username Within Team Registration Rejection
# =============================================================================
def test_duplicate_username_within_team_rejected(temp_team_mgr):
    payload = sample_four_member_payload("dup_internal", "Duplicate Internal Team")
    # Teammate 1 copies leader username
    payload["teammate_1"]["username"] = payload["leader"]["username"]

    with pytest.raises(ValueError, match="Duplicate username.*within team registration"):
        temp_team_mgr.register_four_member_team(payload)


# =============================================================================
# 4. Duplicate Username Against Existing Registered Team Rejection
# =============================================================================
def test_duplicate_username_against_existing_team_rejected(temp_team_mgr):
    team1 = sample_four_member_payload("team_one", "Team One")
    temp_team_mgr.register_four_member_team(team1)

    # Team 2 attempts to use Team 1's leader username for Teammate 2
    team2 = sample_four_member_payload("team_two", "Team Two")
    team2["teammate_2"]["username"] = team1["leader"]["username"]

    with pytest.raises(ValueError, match="already registered"):
        temp_team_mgr.register_four_member_team(team2)


# =============================================================================
# 5. Password Confirmation Mismatch Rejection
# =============================================================================
def test_password_confirmation_mismatch_rejected(temp_team_mgr):
    payload = sample_four_member_payload("mismatch_team", "Mismatch Team")
    payload["teammate_3"]["confirm_password"] = "DifferentPassword123!"

    with pytest.raises(ValueError, match="Password confirmation does not match for Teammate 3"):
        temp_team_mgr.register_four_member_team(payload)


# =============================================================================
# 6. Password Hashing Verified: PBKDF2 with Unique Salt, Not Plaintext
# =============================================================================
def test_password_hashing_pbkdf2_unique_salts(temp_team_mgr):
    payload = sample_four_member_payload("hash_verify_team", "Hash Verify Team")
    temp_team_mgr.register_four_member_team(payload)

    with temp_team_mgr._get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT username, password_hash, salt FROM team_members WHERE team_id = 'hash_verify_team'"
        )
        rows = cur.fetchall()

    assert len(rows) == 4
    salts = set()
    for row in rows:
        u = row["username"]
        ph = row["password_hash"]
        salt = row["salt"]

        # Plaintext password is never stored
        assert ph != "Password123!"
        assert salt != "Password123!"

        # PBKDF2-HMAC-SHA256 hex digest length is 64 chars
        assert len(ph) == 64
        # 16-byte random salt in hex is 32 chars
        assert len(salt) == 32

        # Verify password verifies correctly against stored hash and salt
        assert verify_password("Password123!", ph, salt) is True
        assert verify_password("WrongPassword123!", ph, salt) is False

        # Verify each user has a unique random salt
        assert salt not in salts
        salts.add(salt)


# =============================================================================
# 7. Atomic Transaction: Rollback on Failure (Zero Records Remain)
# =============================================================================
def test_atomic_transaction_rollback_on_failure(temp_team_mgr):
    payload = sample_four_member_payload("atomic_team", "Atomic Team")
    # Member 4 has password mismatch
    payload["teammate_3"]["confirm_password"] = "WillFailConfirmation"

    with pytest.raises(ValueError, match="Password confirmation does not match"):
        temp_team_mgr.register_four_member_team(payload)

    # Verify zero records exist in teams, team_members, or hill_configs
    with temp_team_mgr._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM teams WHERE team_id = 'atomic_team'")
        assert cur.fetchone()["cnt"] == 0

        cur.execute("SELECT COUNT(*) as cnt FROM team_members WHERE team_id = 'atomic_team'")
        assert cur.fetchone()["cnt"] == 0

        cur.execute("SELECT COUNT(*) as cnt FROM hill_configs WHERE team_id = 'atomic_team'")
        assert cur.fetchone()["cnt"] == 0


# =============================================================================
# 8. Individual Member Login Succeeds for All Four Members
# =============================================================================
def test_individual_member_login_all_four_members(temp_team_mgr):
    payload = sample_four_member_payload("login_team", "Login Team")
    temp_team_mgr.register_four_member_team(payload)

    usernames = [
        ("login_team_alice", "agent-01", "LEADER", 1),
        ("login_team_bob", "agent-02", "MEMBER", 2),
        ("login_team_charlie", "agent-03", "MEMBER", 3),
        ("login_team_diana", "agent-04", "MEMBER", 4),
    ]

    for un, expected_aid, expected_role, expected_hill in usernames:
        login_res = temp_team_mgr.login(un, "Password123!")
        assert login_res is not None, f"Login failed for {un}"
        assert login_res["username"] == un
        assert login_res["agent_id"] == expected_aid
        assert login_res["role"] == expected_role
        assert login_res["assigned_hill"] == expected_hill
        assert login_res["team_name"] == "Login Team"
        assert "session_token" in login_res

        # Verify session token
        sess = temp_team_mgr.verify_session(login_res["session_token"])
        assert sess is not None
        assert sess["agent_id"] == expected_aid


# =============================================================================
# 9. Correct Agent Assignment
# =============================================================================
def test_correct_agent_assignment_mapping(temp_team_mgr):
    payload = sample_four_member_payload("assign_team", "Assign Team")
    res = temp_team_mgr.register_four_member_team(payload)

    expected = {
        "assign_team_alice": ("agent-01", 1, "LEADER"),
        "assign_team_bob": ("agent-02", 2, "MEMBER"),
        "assign_team_charlie": ("agent-03", 3, "MEMBER"),
        "assign_team_diana": ("agent-04", 4, "MEMBER"),
    }

    for m in res["members"]:
        un = m["username"]
        assert un in expected
        exp_aid, exp_hill, exp_role = expected[un]
        assert m["agent_id"] == exp_aid
        assert m["assigned_hill"] == exp_hill
        assert m["role"] == exp_role


# =============================================================================
# 10. Correct Hill Isolation: Teammate 1 Cannot Configure Hill 1, 3, or 4
# =============================================================================
def test_hill_isolation_via_api(coordinator_app):
    coord, app = coordinator_app
    client = app.test_client()

    payload = sample_four_member_payload("iso_team", "Isolation Team")
    coord.team_manager.register_four_member_team(payload)

    # Login as Teammate 1 (agent-02, Hill 2)
    login_bob = coord.team_manager.login("iso_team_bob", "Password123!")
    token_bob = login_bob["session_token"]
    headers_bob = {"X-Session-Token": token_bob}

    # TM1 can configure Hill 2
    res_h2 = client.post(
        "/api/hill/2/config",
        headers=headers_bob,
        json={"service_name": "http-service-2", "target_host": "10.0.0.22", "target_port": 8080},
    )
    assert res_h2.status_code == 200

    # TM1 attempting to configure Hill 1 is 403 Forbidden
    res_h1 = client.post(
        "/api/hill/1/config",
        headers=headers_bob,
        json={"service_name": "malicious", "target_host": "10.0.0.1"},
    )
    assert res_h1.status_code == 403
    assert "Forbidden" in res_h1.get_json()["error"]

    # TM1 attempting to configure Hill 3 is 403 Forbidden
    res_h3 = client.post(
        "/api/hill/3/config",
        headers=headers_bob,
        json={"service_name": "malicious", "target_host": "10.0.0.3"},
    )
    assert res_h3.status_code == 403

    # TM1 attempting to configure Hill 4 is 403 Forbidden
    res_h4 = client.post(
        "/api/hill/4/config",
        headers=headers_bob,
        json={"service_name": "malicious", "target_host": "10.0.0.4"},
    )
    assert res_h4.status_code == 403


# =============================================================================
# 11. Team Management Permissions: Leader Gets 200; Teammates Get 403
# =============================================================================
def test_team_management_permissions_via_api(coordinator_app):
    coord, app = coordinator_app
    client = app.test_client()

    payload = sample_four_member_payload("mgmt_perm_team", "Mgmt Perm Team")
    # Register via API endpoint
    reg_res = client.post("/api/team/register", json=payload)
    assert reg_res.status_code == 200
    token_leader = reg_res.get_json()["session_token"]

    # Leader requests team management view: 200 OK
    res_leader = client.get(
        "/api/team/management?team_id=mgmt_perm_team",
        headers={"X-Session-Token": token_leader},
    )
    assert res_leader.status_code == 200
    mgmt_data = res_leader.get_json()
    assert mgmt_data["team_id"] == "mgmt_perm_team"
    assert mgmt_data["team_name"] == "Mgmt Perm Team"
    assert mgmt_data["registration_status"] == "COMPLETE"
    assert len(mgmt_data["members"]) == 4

    # Crucial security check: passwords and password hashes are NEVER exposed
    for m in mgmt_data["members"]:
        assert "password" not in m
        assert "password_hash" not in m
        assert "salt" not in m

    # Teammate 1 (agent-02) logs in and attempts team management view: 403 Forbidden
    login_tm1 = client.post(
        "/api/team/login",
        json={"username": "mgmt_perm_team_bob", "password": "Password123!"},
    )
    assert login_tm1.status_code == 200
    token_tm1 = login_tm1.get_json()["session_token"]

    res_tm1 = client.get(
        "/api/team/management?team_id=mgmt_perm_team",
        headers={"X-Session-Token": token_tm1},
    )
    assert res_tm1.status_code == 403
    assert "restricted to the Team Leader" in res_tm1.get_json()["message"]


# =============================================================================
# 12. Existing Database Migration & Incomplete Team Handling
# =============================================================================
def test_existing_database_migration_and_incomplete_onboarding():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "legacy_koth.db")

        # 1. Create legacy database with original schema (missing description, competition_id, etc.)
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE teams (
                    team_id TEXT PRIMARY KEY,
                    team_name TEXT NOT NULL,
                    leader_username TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE team_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    assigned_hill INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(team_id, username),
                    UNIQUE(team_id, agent_id),
                    FOREIGN KEY(team_id) REFERENCES teams(team_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE auth_sessions (
                    session_token TEXT PRIMARY KEY,
                    team_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    assigned_hill INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER DEFAULT 0
                )
                """
            )
            pwd_hash, salt = hash_password("LegacyLeader123!")
            cur.execute(
                "INSERT INTO teams (team_id, team_name, leader_username, created_at) VALUES ('legacy_team', 'Legacy Team', 'alice_legacy', 1700000000.0)"
            )
            cur.execute(
                """
                INSERT INTO team_members (team_id, username, password_hash, salt, role, agent_id, assigned_hill, created_at)
                VALUES ('legacy_team', 'alice_legacy', ?, ?, 'LEADER', 'agent-01', 1, 1700000000.0)
                """,
                (pwd_hash, salt),
            )
            conn.commit()

        # 2. Initialize TeamManager pointing to the legacy database -> triggers safe migrations
        mgr = TeamManager(db_path=db_path)

        # Verify migration marked the legacy single-member team as INCOMPLETE
        with mgr._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT registration_status FROM teams WHERE team_id = 'legacy_team'")
            row = cur.fetchone()
            assert row["registration_status"] == "INCOMPLETE"

            # Verify NO fake accounts were created: only 1 member exists
            cur.execute("SELECT COUNT(*) as cnt FROM team_members WHERE team_id = 'legacy_team'")
            assert cur.fetchone()["cnt"] == 1

        # 3. Leader logs in and completes onboarding for the 3 missing teammates
        login_res = mgr.login("alice_legacy", "LegacyLeader123!")
        assert login_res is not None
        assert login_res["registration_status"] == "INCOMPLETE"
        leader_token = login_res["session_token"]

        missing_teammates = [
            {"full_name": "New Bob", "username": "legacy_bob", "password": "Password123!", "confirm_password": "Password123!"},
            {"full_name": "New Charlie", "username": "legacy_charlie", "password": "Password123!", "confirm_password": "Password123!"},
            {"full_name": "New Diana", "username": "legacy_diana", "password": "Password123!", "confirm_password": "Password123!"},
        ]

        comp_res = mgr.complete_team_registration(
            team_id="legacy_team",
            leader_session_token=leader_token,
            teammates=missing_teammates,
        )
        assert comp_res["success"] is True
        assert comp_res["registration_status"] == "COMPLETE"

        # Verify all 4 members now exist in DB and can log in
        with mgr._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM team_members WHERE team_id = 'legacy_team'")
            assert cur.fetchone()["cnt"] == 4

            cur.execute("SELECT registration_status FROM teams WHERE team_id = 'legacy_team'")
            assert cur.fetchone()["registration_status"] == "COMPLETE"

        # Teammate 1 can now log in
        tm1_login = mgr.login("legacy_bob", "Password123!")
        assert tm1_login is not None
        assert tm1_login["agent_id"] == "agent-02"
        assert tm1_login["assigned_hill"] == 2
        assert tm1_login["registration_status"] == "COMPLETE"


# =============================================================================
# Legacy Baseline Tests (Preserved)
# =============================================================================
def test_create_team_success(temp_team_mgr):
    team = temp_team_mgr.create_team(
        team_id="cyber_dragons_legacy",
        team_name="Cyber Dragons Legacy",
        leader_username="alice_leg",
        leader_password="test-leader-password-123",
    )
    assert team["team_id"] == "cyber_dragons_legacy"
    assert team["team_name"] == "Cyber Dragons Legacy"
    assert team["leader_username"] == "alice_leg"

    members = temp_team_mgr.list_team_members("cyber_dragons_legacy")
    assert len(members) == 1
    leader = members[0]
    assert leader["username"] == "alice_leg"
    assert leader["role"] == "LEADER"
    assert leader["agent_id"] == "agent-01"
    assert leader["hill_id"] == 1


def test_create_duplicate_team_fails(temp_team_mgr):
    temp_team_mgr.create_team("alpha", "Alpha", "alice_alpha", "test_pass123")
    with pytest.raises(ValueError, match="already exists"):
        temp_team_mgr.create_team("alpha", "Alpha 2", "bob_alpha", "test_pass456")


def test_join_team_up_to_four_members(temp_team_mgr):
    temp_team_mgr.create_team("team_x", "Team X", "leader_user", "test_pass_leader")

    m2 = temp_team_mgr.join_team("team_x", "teammate_1", "test_pass_tm1")
    assert m2["agent_id"] == "agent-02"
    assert m2["hill_id"] == 2
    assert m2["role"] == "TEAMMATE"

    m3 = temp_team_mgr.join_team("team_x", "teammate_2", "test_pass_tm2")
    assert m3["agent_id"] == "agent-03"
    assert m3["hill_id"] == 3
    assert m3["role"] == "TEAMMATE"

    m4 = temp_team_mgr.join_team("team_x", "teammate_3", "test_pass_tm3")
    assert m4["agent_id"] == "agent-04"
    assert m4["hill_id"] == 4
    assert m4["role"] == "TEAMMATE"

    with pytest.raises(ValueError, match="Team 'team_x' is full"):
        temp_team_mgr.join_team("team_x", "teammate_4", "test_pass_tm4")


def test_login_and_session_verification(temp_team_mgr):
    temp_team_mgr.create_team("cyber_unit", "Cyber Unit", "commander", "test_ComplexPass!99")

    bad_login = temp_team_mgr.login("commander", "test_WrongPassword")
    assert bad_login is None

    login_info = temp_team_mgr.login("commander", "test_ComplexPass!99")
    assert login_info is not None
    assert login_info["username"] == "commander"
    assert login_info["role"] == "LEADER"
    assert login_info["agent_id"] == "agent-01"
    assert "session_token" in login_info

    session_data = temp_team_mgr.verify_session(login_info["session_token"])
    assert session_data is not None
    assert session_data["username"] == "commander"
    assert session_data["agent_id"] == "agent-01"

    revoked = temp_team_mgr.revoke_session(login_info["session_token"])
    assert revoked is True
    assert temp_team_mgr.verify_session(login_info["session_token"]) is None
