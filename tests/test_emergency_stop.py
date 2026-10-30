"""
Tests for Phase 8: Authenticated Emergency Stop and Persistent State Recovery.
"""
import pytest
import tempfile
import os
from agent.db import DatabaseManager
from agent.swarm.coordinator import SwarmCoordinator
from agent.swarm.models import Phase


@pytest.fixture
def temp_coordinator():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_estop.db")
        db_mgr = DatabaseManager(db_path=db_path)
        coord = SwarmCoordinator(
            team_id="test_team",
            db_path=db_path,
            db_manager=db_mgr,
            operator_token="test-operator-secret",
        )
        yield {
            "coord": coord,
            "db_path": db_path,
            "db_mgr": db_mgr,
        }


def test_emergency_stop_persists_across_restart(temp_coordinator):
    coord = temp_coordinator["coord"]
    db_path = temp_coordinator["db_path"]
    db_mgr = temp_coordinator["db_mgr"]

    # 1. Initially emergency stop is false
    assert coord.kill_switch_active is False

    # 2. Operator triggers emergency stop
    coord.trigger_kill_switch(triggered_by="operator-alice", reason="Manual operator drill")
    assert coord.kill_switch_active is True

    # Check persistence in database
    estop_row = db_mgr.get_emergency_stop()
    assert estop_row["is_active"] is True
    assert estop_row["triggered_by"] == "operator-alice"
    assert estop_row["reason"] == "Manual operator drill"

    # 3. Simulate coordinator restart by instantiating a new SwarmCoordinator with the same DB
    restarted_coord = SwarmCoordinator(
        team_id="test_team",
        db_path=db_path,
        operator_token="test-operator-secret",
    )
    # MUST boot with emergency stop active from persistent state
    assert restarted_coord.kill_switch_active is True

    # Phase request while emergency stop is active must return HOLD with source kill_switch
    phase = restarted_coord.get_phase()
    assert phase.phase == Phase.HOLD
    assert phase.source == "kill_switch"

    # Task request must be rejected
    res = restarted_coord.request_task("agent-01", Phase.ATTACK, 1)
    assert res["reason"] == "kill_switch_active"

    # 4. Operator resets emergency stop
    restarted_coord.reset_kill_switch(reset_by="operator-alice")
    assert restarted_coord.kill_switch_active is False

    # Database updated
    estop_reset = db_mgr.get_emergency_stop()
    assert estop_reset["is_active"] is False

    # Restart again: boots normal
    restarted_coord_2 = SwarmCoordinator(
        team_id="test_team",
        db_path=db_path,
        operator_token="test-operator-secret",
    )
    assert restarted_coord_2.kill_switch_active is False


def test_audit_log_redaction(temp_coordinator):
    db_mgr = temp_coordinator["db_mgr"]

    # Log an event containing secret keys, passwords, and tokens
    db_mgr.record_audit_event(
        event_type="TEST_EVENT",
        actor="operator",
        target="hill-1",
        details={
            "user_password": "super-secret-password-123",
            "session_token": "secret-token-xyz",
            "api_key": "nvidia-key-9999",
            "flag": "PWN{flag_token_123}",
            "harmless_param": "scan_port_80",
        },
    )

    events = db_mgr.get_audit_events(limit=5)
    assert len(events) >= 1
    ev = events[0]
    details = ev["details"]

    # Sensitive parameters MUST be [REDACTED]
    assert details["user_password"] == "[REDACTED]"
    assert details["session_token"] == "[REDACTED]"
    assert details["api_key"] == "[REDACTED]"
    assert details["flag"] == "[REDACTED]"

    # Non-sensitive parameters preserved
    assert details["harmless_param"] == "scan_port_80"
