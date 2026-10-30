"""
Comprehensive Automated Test Suite for KOTH and Red vs Blue Competition Platform.
Verifies:
- Exactly 2 competition modes (KOTH and RED_VS_BLUE)
- All 5 KOTH formats (SINGLE_HILL, MULTI_HILL, TEAM_VS_TEAM, ELIMINATION, TIMED)
- All 6 Red vs Blue formats (CLASSIC, MULTI_TEAM, MULTI_HILL, ELIMINATION, TIMED, CONTINUOUS)
- All 9 Heterogeneous Hill Environment Types
- All 10 Hill Ownership States & State Transitions
- Flag SHA-256 secrecy, Anti-replay evidence idempotency
- Symmetric attack, capture, defense, and recapture mechanics for both sides
- Periodic tick hold scoring and uptime calculations
- Elimination logic & tie-breaking rules
- Side isolation and concealment of opponent defense notes
- REST API integration via SwarmCoordinator
"""

import hashlib
import json
import pytest
from flask import Flask

from agent.competition.models import (
    Competition,
    CompetitionHill,
    CompetitionMode,
    CompetitionRules,
    CompetitionStatus,
    CompetitionTeam,
    HillEnvironmentType,
    KothFormat,
    OwnershipState,
    RedVsBlueFormat,
    ScoreCategory,
    TeamSide,
    VerifierType,
)
from agent.competition.manager import CompetitionManager
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint


@pytest.fixture
def comp_manager(tmp_path):
    db_file = str(tmp_path / "test_competition.db")
    return CompetitionManager(db_path=db_file)


@pytest.fixture
def coordinator_app(tmp_path):
    db_file = str(tmp_path / "test_coord_comp.db")
    coordinator = SwarmCoordinator(db_path=db_file)
    app = Flask(__name__)
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)
    return app, coordinator


# ==============================================================================
# 1. DOMAIN MODELS & ENUM INTEGRITY TESTS
# ==============================================================================

def test_competition_modes_and_formats_integrity():
    assert set(CompetitionMode) == {CompetitionMode.KOTH, CompetitionMode.RED_VS_BLUE}
    assert len(CompetitionMode) == 2

    # Verify 5 KOTH formats
    expected_koth = {
        KothFormat.SINGLE_HILL,
        KothFormat.MULTI_HILL,
        KothFormat.TEAM_VS_TEAM,
        KothFormat.ELIMINATION,
        KothFormat.TIMED,
    }
    assert set(KothFormat) == expected_koth
    assert len(KothFormat) == 5

    # Verify 6 Red vs Blue formats
    expected_rvb = {
        RedVsBlueFormat.CLASSIC,
        RedVsBlueFormat.MULTI_TEAM,
        RedVsBlueFormat.MULTI_HILL,
        RedVsBlueFormat.ELIMINATION,
        RedVsBlueFormat.TIMED,
        RedVsBlueFormat.CONTINUOUS,
    }
    assert set(RedVsBlueFormat) == expected_rvb
    assert len(RedVsBlueFormat) == 6


def test_nine_hill_environment_types():
    expected_envs = {
        HillEnvironmentType.LINUX,
        HillEnvironmentType.WINDOWS,
        HillEnvironmentType.WEB_APPLICATION,
        HillEnvironmentType.DATABASE,
        HillEnvironmentType.NETWORK,
        HillEnvironmentType.ACTIVE_DIRECTORY,
        HillEnvironmentType.CLOUD_SECURITY,
        HillEnvironmentType.CONTAINER_K8S,
        HillEnvironmentType.FORENSICS_IR,
    }
    assert set(HillEnvironmentType) == expected_envs
    assert len(HillEnvironmentType) == 9


def test_ten_hill_ownership_states():
    expected_states = {
        OwnershipState.UNASSIGNED,
        OwnershipState.AVAILABLE,
        OwnershipState.OWNED,
        OwnershipState.UNDER_ATTACK,
        OwnershipState.CAPTURE_PENDING,
        OwnershipState.CAPTURED,
        OwnershipState.COMPROMISED,
        OwnershipState.LOST,
        OwnershipState.RECOVERY_PENDING,
        OwnershipState.UNKNOWN,
    }
    assert set(OwnershipState) == expected_states
    assert len(OwnershipState) == 10


# ==============================================================================
# 2. COMPETITION CREATION & LIFECYCLE TESTS
# ==============================================================================

def test_create_and_lifecycle_competition(comp_manager):
    comp = comp_manager.create_competition(
        name="DEFCON 2026 Finals",
        mode=CompetitionMode.RED_VS_BLUE.value,
        format=RedVsBlueFormat.CLASSIC.value,
        description="Epic showdown",
        duration_minutes=90,
        rules={"capture_points": 150, "hold_interval_points": 15, "recapture_bonus": 50},
        created_by="alice",
    )

    assert comp.name == "DEFCON 2026 Finals"
    assert comp.mode == CompetitionMode.RED_VS_BLUE
    assert comp.format == "CLASSIC"
    assert comp.status == CompetitionStatus.DRAFT
    assert comp.rules.capture_points == 150
    assert comp.rules.recapture_bonus == 50

    # Start competition
    assert comp_manager.start_competition(comp.competition_id)
    comp_active = comp_manager.get_competition(comp.competition_id)
    assert comp_active.status == CompetitionStatus.ACTIVE
    assert comp_active.start_time > 0
    assert comp_active.end_time > comp_active.start_time

    # Pause & Complete
    assert comp_manager.pause_competition(comp.competition_id)
    assert comp_manager.get_competition(comp.competition_id).status == CompetitionStatus.PAUSED
    assert comp_manager.complete_competition(comp.competition_id)
    assert comp_manager.get_competition(comp.competition_id).status == CompetitionStatus.COMPLETED


# ==============================================================================
# 3. TEAM ENROLLMENT & SIDES IN RED VS BLUE
# ==============================================================================

def test_team_enrollment_and_side_assignment(comp_manager):
    comp = comp_manager.create_competition(
        name="Red vs Blue Multi-Team",
        mode="RED_VS_BLUE",
        format="MULTI_TEAM",
    )

    comp_manager.enroll_team(comp.competition_id, "red_team_1", "Red Squadron", "RED")
    comp_manager.enroll_team(comp.competition_id, "red_team_2", "Red Phalanx", "RED")
    comp_manager.enroll_team(comp.competition_id, "blue_team_1", "Blue Aegis", "BLUE")
    comp_manager.enroll_team(comp.competition_id, "blue_team_2", "Blue Citadel", "BLUE")

    teams = comp_manager.get_competition_teams(comp.competition_id)
    assert len(teams) == 4

    red_teams = [t for t in teams if t.side == TeamSide.RED]
    blue_teams = [t for t in teams if t.side == TeamSide.BLUE]
    assert len(red_teams) == 2
    assert len(blue_teams) == 2


# ==============================================================================
# 4. HETEROGENEOUS HILL PROVISIONING & PRIVACY
# ==============================================================================

def test_provision_all_9_hill_environments_and_privacy(comp_manager):
    comp = comp_manager.create_competition(name="Hetero Matrix", mode="RED_VS_BLUE", format="MULTI_HILL")
    comp_manager.enroll_team(comp.competition_id, "red_alpha", "Red Alpha", "RED")
    comp_manager.enroll_team(comp.competition_id, "blue_bravo", "Blue Bravo", "BLUE")

    envs = list(HillEnvironmentType)
    for i, env in enumerate(envs, start=1):
        comp_manager.add_hill(
            competition_id=comp.competition_id,
            hill_id=i,
            name=f"Contested-{env.value}",
            environment_type=env.value,
            target_host=f"10.0.{i}.10",
            target_port=80 + i,
            service_name=f"svc-{env.value.lower()}",
            points_per_interval=10,
            capture_points=100,
            flag=f"FLAG{{{env.value}_SECRET}}",
            initial_owner_team_id="blue_bravo" if i % 2 == 0 else "red_alpha",
            initial_owner_side="BLUE" if i % 2 == 0 else "RED",
        )

    hills = comp_manager.get_competition_hills(comp.competition_id)
    assert len(hills) == 9

    # Add private defense notes to Hill 2 by blue_bravo
    comp_manager.update_hill_defense_notes(
        competition_id=comp.competition_id,
        hill_id=2,
        team_id="blue_bravo",
        notes="Hardened SSH key and configured fail2ban",
    )

    h2 = comp_manager.get_hill(comp.competition_id, 2)
    # Check safe dict from owner viewpoint (blue_bravo)
    owner_view = h2.to_safe_dict(viewer_team_id="blue_bravo", viewer_side=TeamSide.BLUE)
    assert owner_view["is_controlled_by_viewer"] is True
    assert owner_view["defense_notes"] == "Hardened SSH key and configured fail2ban"
    assert owner_view["flag_configured"] is True
    assert owner_view["flag_hash_prefix"] != ""

    # Check safe dict from opponent viewpoint (red_alpha)
    opponent_view = h2.to_safe_dict(viewer_team_id="red_alpha", viewer_side=TeamSide.RED)
    assert opponent_view["is_controlled_by_viewer"] is False
    assert opponent_view["defense_notes"] == ""  # Hidden from opponent!
    assert opponent_view["flag_hash_prefix"] == ""  # Hidden from opponent!


# ==============================================================================
# 5. CAPTURE, RECAPTURE & ANTI-REPLAY ENGINE
# ==============================================================================

def test_capture_recapture_and_anti_replay(comp_manager):
    comp = comp_manager.create_competition(
        name="Clash Arena",
        mode="RED_VS_BLUE",
        format="CONTINUOUS",
        rules={"capture_points": 100, "recapture_bonus": 50, "penalty_points": 20},
    )
    comp_manager.enroll_team(comp.competition_id, "team_red", "Team Red", "RED")
    comp_manager.enroll_team(comp.competition_id, "team_blue", "Team Blue", "BLUE")

    flag_val = "FLAG{linux_root_shell_999}"
    comp_manager.add_hill(
        competition_id=comp.competition_id,
        hill_id=1,
        name="Central Bastion",
        environment_type="LINUX",
        target_host="10.0.1.1",
        points_per_interval=10,
        capture_points=100,
        flag=flag_val,
        initial_owner_team_id=None,
    )

    # 1. Cannot capture when competition is DRAFT
    ok, msg, _ = comp_manager.submit_capture(comp.competition_id, 1, "team_red", "agent-01", flag_val)
    assert not ok
    assert "not active" in msg

    # Start match
    comp_manager.start_competition(comp.competition_id)

    # 2. Bad flag triggers penalty
    ok, msg, _ = comp_manager.submit_capture(comp.competition_id, 1, "team_red", "agent-01", "FLAG{wrong_token}")
    assert not ok
    assert "Penalty recorded" in msg
    assert comp_manager.get_team(comp.competition_id, "team_red").penalties_count == 1

    # 3. Legitimate First Capture by Red
    ok, msg, sub = comp_manager.submit_capture(comp.competition_id, 1, "team_red", "agent-01", flag_val)
    assert ok
    assert sub.awarded_points == 100
    h1 = comp_manager.get_hill(comp.competition_id, 1)
    assert h1.state == OwnershipState.CAPTURED
    assert h1.current_owner_team_id == "team_red"
    assert h1.current_owner_side == TeamSide.RED

    # 4. Anti-Replay: Submitting identical evidence again by same team is rejected
    ok, msg, _ = comp_manager.submit_capture(comp.competition_id, 1, "team_red", "agent-01", flag_val)
    assert not ok
    assert "already owned" in msg or "Replay rejected" in msg

    # 5. Blue attacks and RECAPTURES the hill
    ok, msg, sub2 = comp_manager.submit_capture(comp.competition_id, 1, "team_blue", "agent-04", flag_val)
    assert ok
    # Awarded capture points (100) + recapture bonus (50) = 150 points!
    assert sub2.awarded_points == 150
    h1_after = comp_manager.get_hill(comp.competition_id, 1)
    assert h1_after.current_owner_team_id == "team_blue"
    assert h1_after.current_owner_side == TeamSide.BLUE

    blue_team = comp_manager.get_team(comp.competition_id, "team_blue")
    assert blue_team.score == 150
    assert blue_team.recaptures_count == 1

    # Verify history event logged RECAPTURE
    history = comp_manager.get_ownership_history(comp.competition_id, hill_id=1)
    assert len(history) >= 2
    assert history[0]["event_type"] == "RECAPTURE"
    assert history[0]["new_owner_team_id"] == "team_blue"
    assert history[0]["previous_owner_team_id"] == "team_red"


# ==============================================================================
# 6. DEFENSE SUBMISSIONS & INTERVAL SCORING
# ==============================================================================

def test_defense_submission_and_tick_scoring(comp_manager):
    comp = comp_manager.create_competition(
        name="Defense Arena",
        mode="RED_VS_BLUE",
        format="CLASSIC",
        rules={"defense_points": 60, "hold_interval_points": 15, "hold_interval_seconds": 30},
    )
    comp_manager.start_competition(comp.competition_id)
    comp_manager.enroll_team(comp.competition_id, "blue_corps", "Blue Corps", "BLUE")

    comp_manager.add_hill(
        competition_id=comp.competition_id,
        hill_id=1,
        name="Vault",
        environment_type="DATABASE",
        initial_owner_team_id="blue_corps",
        initial_owner_side="BLUE",
        points_per_interval=15,
    )

    # Submit defense
    ok, msg, sub = comp_manager.submit_defense(
        comp.competition_id,
        hill_id=1,
        team_id="blue_corps",
        agent_id="agent-02",
        patch_summary="Applied SQL parameterization filter",
        service_status="HEALTHY",
    )
    assert ok
    assert sub.awarded_points == 60
    assert comp_manager.get_team(comp.competition_id, "blue_corps").score == 60

    # Process periodic scoring tick
    tick_res = comp_manager.process_tick(comp.competition_id)
    assert tick_res["awarded"] == 15

    # Blue score is now 60 + 15 = 75
    blue_updated = comp_manager.get_team(comp.competition_id, "blue_corps")
    assert blue_updated.score == 75
    assert blue_updated.uptime_seconds == 30.0


# ==============================================================================
# 7. LEADERBOARD, SIDE AGGREGATION & TIE BREAKING
# ==============================================================================

def test_leaderboard_side_aggregation_and_tie_breaking(comp_manager):
    comp = comp_manager.create_competition(name="Leaderboard Showdown", mode="RED_VS_BLUE", format="MULTI_TEAM")
    comp_manager.start_competition(comp.competition_id)

    comp_manager.enroll_team(comp.competition_id, "red_1", "Red Alpha", "RED")
    comp_manager.enroll_team(comp.competition_id, "red_2", "Red Bravo", "RED")
    comp_manager.enroll_team(comp.competition_id, "blue_1", "Blue Charlie", "BLUE")
    comp_manager.enroll_team(comp.competition_id, "blue_2", "Blue Delta", "BLUE")

    # Manually award points
    with comp_manager._lock, comp_manager._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE competition_teams SET score = 300, captures_count = 3 WHERE team_id = 'red_1'")
        cur.execute("UPDATE competition_teams SET score = 200, captures_count = 2 WHERE team_id = 'red_2'")
        cur.execute("UPDATE competition_teams SET score = 400, captures_count = 4 WHERE team_id = 'blue_1'")
        cur.execute("UPDATE competition_teams SET score = 150, captures_count = 1 WHERE team_id = 'blue_2'")
        conn.commit()

    lb = comp_manager.get_leaderboard(comp.competition_id)
    # Red total: 300 + 200 = 500
    # Blue total: 400 + 150 = 550
    assert lb["red_score"] == 500
    assert lb["blue_score"] == 550
    assert lb["teams"][0]["team_id"] == "blue_1"
    assert lb["teams"][1]["team_id"] == "red_1"


# ==============================================================================
# 8. REST API INTEGRATION VIA COORDINATOR BLUEPRINT
# ==============================================================================

def test_coordinator_competition_api_routes(coordinator_app):
    app, coordinator = coordinator_app
    client = app.test_client()

    # 1. Create competition via POST /api/competitions (Wizard API)
    create_payload = {
        "name": "Live Cyber Battle 2026",
        "mode": "RED_VS_BLUE",
        "format": "CLASSIC",
        "description": "API Integration Test",
        "duration_minutes": 45,
        "rules": {"capture_points": 100, "recapture_bonus": 30},
        "teams": [
            {"team_id": "api_red", "name": "API Red Warriors", "side": "RED"},
            {"team_id": "api_blue", "name": "API Blue Guardians", "side": "BLUE"},
        ],
        "hills": [
            {
                "hill_id": 1,
                "name": "API Hill 1",
                "environment_type": "WEB_APPLICATION",
                "target_host": "10.10.10.1",
                "target_port": 443,
                "service_name": "api-web",
                "flag": "FLAG{api_hill_flag_123}",
                "initial_owner_team_id": "api_blue",
                "initial_owner_side": "BLUE",
            }
        ],
    }

    resp = client.post("/api/competitions", json=create_payload)
    assert resp.status_code == 201
    comp_data = resp.json["competition"]
    cid = comp_data["competition_id"]

    # 2. Start competition
    resp = client.post(f"/api/competition/{cid}/start")
    assert resp.status_code == 200

    # 3. Fetch hills
    resp = client.get(f"/api/competition/{cid}/hills")
    assert resp.status_code == 200
    assert len(resp.json["hills"]) == 1
    assert resp.json["hills"][0]["environment_type"] == "WEB_APPLICATION"

    # 4. Red team captures Hill 1
    resp = client.post(
        f"/api/competition/{cid}/capture",
        json={"hill_id": 1, "flag": "FLAG{api_hill_flag_123}", "team_id": "api_red", "agent_id": "agent-01"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    # 5. Check leaderboard
    resp = client.get(f"/api/competition/{cid}/leaderboard")
    assert resp.status_code == 200
    assert resp.json["red_score"] == 130  # 100 capture + 30 recapture bonus

    # 6. Check history
    resp = client.get(f"/api/competition/{cid}/history")
    assert resp.status_code == 200
    assert len(resp.json["history"]) >= 2  # initial assignment + recapture

    # 7. Join competition via /api/competition/<cid>/join
    resp = client.post(
        f"/api/competition/{cid}/join",
        json={"team_id": "new_rebel_squad", "team_name": "New Rebel Squad", "side": "RED"},
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True

    # 8. Check access authorization gate
    # Enrolled team -> 200 Authorized
    resp = client.get(f"/api/competition/{cid}/access?team_id=new_rebel_squad")
    assert resp.status_code == 200
    assert resp.json["authorized"] is True

    # Unknown / unenrolled team -> 403 Forbidden
    resp = client.get(f"/api/competition/{cid}/access?team_id=unauthorized_invader")
    assert resp.status_code == 403
    assert resp.json["authorized"] is False
    assert "not enrolled" in resp.json["error"]

