"""
Tests for Phase 4 & Phase 7:
- Isolated 4-hill portals & backend RBAC
- Flag secrecy (SHA-256 hashed, never echoed)
- Competition ownership states (UNVERIFIED, SUBMITTED, OWNED, LOST, UNKNOWN)
- SimulatedHillVerifier
"""
import pytest
import tempfile
import os
import hashlib
from agent.swarm.team_manager import TeamManager
from agent.hill.manager import HillManager, OwnershipStatus, HillHealth
from agent.hill.verifier import SimulatedHillVerifier


@pytest.fixture
def temp_hill_setup():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_hill.db")
        team_mgr = TeamManager(db_path=db_path)
        hill_mgr = HillManager(db_path=db_path, team_manager=team_mgr)
        verifier = SimulatedHillVerifier()

        # Create 4-agent team
        team_mgr.create_team("delta_force", "Delta Force", "leader_bob", "pass123")
        team_mgr.join_team("delta_force", "tm1_charlie", "pass123") # agent-02 -> hill 2
        team_mgr.join_team("delta_force", "tm2_dave", "pass123")    # agent-03 -> hill 3
        team_mgr.join_team("delta_force", "tm3_eve", "pass123")     # agent-04 -> hill 4

        yield {
            "team_mgr": team_mgr,
            "hill_mgr": hill_mgr,
            "verifier": verifier,
        }


def test_hill_portal_isolation(temp_hill_setup):
    hill_mgr = temp_hill_setup["hill_mgr"]

    # 1. Teammate 1 (agent-02, hill 2) configuring Hill 2 succeeds
    updated = hill_mgr.configure_hill(
        hill_id=2,
        service_name="web-portal",
        target_host="10.254.254.12",
        target_port=8080,
        configured_by="agent-02",
        member_role="TEAMMATE",
        member_assigned_hill=2,
    )
    assert updated.service_name == "web-portal"
    assert updated.target_host == "10.254.254.12"
    assert updated.target_port == 8080

    # 2. Teammate 1 attempting to configure Hill 1 or Hill 3 must be rejected with PermissionError
    with pytest.raises(PermissionError, match=r"(Access denied|Permission denied)"):
        hill_mgr.configure_hill(
            hill_id=3,
            service_name="tampered-service",
            configured_by="agent-02",
            member_role="TEAMMATE",
            member_assigned_hill=2,
        )

    # 3. Teammate 1 attempting to view Hill 3 secret details must be rejected
    with pytest.raises(PermissionError, match=r"(Access denied|Permission denied)"):
        hill_mgr.get_hill_view(hill_id=3, member_assigned_hill=2, member_role="TEAMMATE")

    # 4. Team Leader can view all hills
    leader_view = hill_mgr.get_all_hills_leader_view(member_role="LEADER")
    assert len(leader_view) == 4


def test_flag_secrecy_and_hashing(temp_hill_setup):
    hill_mgr = temp_hill_setup["hill_mgr"]
    secret_flag = "PWN{koth_super_secret_flag_2026}"
    expected_hash = hashlib.sha256(secret_flag.encode("utf-8")).hexdigest()

    # Teammate 2 sets flag for Hill 3
    flag_hash = hill_mgr.set_hill_flag(
        hill_id=3,
        flag_plaintext=secret_flag,
        configured_by="agent-03",
        member_role="TEAMMATE",
        member_assigned_hill=3,
    )
    assert flag_hash == expected_hash

    # Plaintext flag is NEVER exposed in the hill view
    view = hill_mgr.get_hill_view(hill_id=3, member_assigned_hill=3, member_role="TEAMMATE")
    assert "flag" not in view or view.get("flag") != secret_flag
    assert view["flag_hash"].startswith(expected_hash[:12])
    assert view["flag_configured"] is True


def test_simulated_verifier_state_transitions(temp_hill_setup):
    hill_mgr = temp_hill_setup["hill_mgr"]
    verifier = temp_hill_setup["verifier"]

    # 1. Unconfigured hill starts as UNVERIFIED
    hstate1 = hill_mgr.get_hill(1)
    own_status, health, _ = verifier.verify(1, hstate1)
    assert own_status == OwnershipStatus.UNVERIFIED

    # 2. Configure flag for Hill 1
    secret_flag = "PWN{hill_1_token_xyz}"
    hill_mgr.set_hill_flag(
        hill_id=1,
        flag_plaintext=secret_flag,
        configured_by="agent-01",
        member_role="LEADER",
        member_assigned_hill=1,
    )
    hill_mgr.update_ownership_status(1, OwnershipStatus.SUBMITTED)

    # 3. Verifier checks submitted flag and transitions to OWNED
    hstate1_updated = hill_mgr.get_hill(1)
    own_status, health, _ = verifier.verify(1, hstate1_updated)
    assert own_status == OwnershipStatus.OWNED

    # 4. Submitting invalid flag candidate results in rejected match
    is_match = verifier.submit_flag(
        hill_id=1,
        flag_candidate="PWN{wrong_flag}",
        expected_flag_hash=hstate1_updated.flag_hash,
    )
    assert is_match is False

    # 5. Correct flag candidate succeeds
    is_match_correct = verifier.submit_flag(
        hill_id=1,
        flag_candidate=secret_flag,
        expected_flag_hash=hstate1_updated.flag_hash,
    )
    assert is_match_correct is True
