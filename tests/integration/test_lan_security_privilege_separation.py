"""
Targeted integration tests for LAN security, privilege separation, and session management.

Verifies all 10 required failure/security cases:
1. Worker attempting phase advance -> 403 Forbidden
2. Worker attempting kill switch -> 403 Forbidden
3. Worker attempting shutdown -> 403 Forbidden
4. Credential / agent mismatch -> 403 Forbidden
5. Duplicate active registration -> rejected (409 Conflict)
6. Unauthorized shared-state impersonation -> rejected (403 Forbidden)
7. Disallowed action -> rejected by deterministic policy & action registry
8. Coordinator restart -> HOLD phase & prior session invalidation
9. Stale session token -> 401 Unauthorized
10. Stale lease -> rejected
"""

import hashlib
import hmac
import pytest
from flask import Flask

from agent.actions.registry import ActionRegistry, HoldAction
from agent.config import Config, ConfigProfile, load_config
from agent.gemini_client import Decision
from agent.security.policy import SecurityPolicy
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import AgentRole, Phase


TEAM_SECRET = "lan-team-secret-null-warriors-99"
OPERATOR_SECRET = "lan-operator-secret-root-42"
AUTHORIZED_ROSTER = ["agent-01", "agent-02", "agent-03", "agent-04"]


def _make_agent_credential(agent_id: str, team_secret: str = TEAM_SECRET) -> str:
    """Derive cryptographic per-agent HMAC credential."""
    return hmac.new(
        team_secret.encode("utf-8"),
        agent_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@pytest.fixture
def test_app():
    """Create a Flask test application with coordinator blueprint."""
    coordinator = SwarmCoordinator(
        team_id="null_warriors",
        auth_token=TEAM_SECRET,
        operator_token=OPERATOR_SECRET,
        authorized_agents=AUTHORIZED_ROSTER,
        session_ttl=10.0,
    )
    app = Flask("test_swarm_security")
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)
    return app, coordinator


class TestPrivilegeSeparationAndRBAC:
    """Verifies that workers cannot execute operator-only administrative commands."""

    def test_worker_attempting_phase_advance_returns_403(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        # Register worker agent-01
        cred = _make_agent_credential("agent-01")
        reg_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        assert reg_resp.status_code == 200
        session_token = reg_resp.json["session_token"]

        # Worker attempts to advance phase
        adv_resp = client.post(
            "/api/swarm/phase/advance",
            json={"phase": "ATTACK", "round_id": 1},
            headers={"X-Session-Token": session_token},
        )
        assert adv_resp.status_code == 403
        assert "Forbidden" in adv_resp.json.get("error", "")

        # Operator advances phase successfully
        op_resp = client.post(
            "/api/swarm/phase/advance",
            json={"phase": "ATTACK", "round_id": 1},
            headers={"X-Session-Token": OPERATOR_SECRET},
        )
        assert op_resp.status_code == 200
        assert op_resp.json["phase"] == "ATTACK"

    def test_worker_attempting_kill_switch_returns_403(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        cred = _make_agent_credential("agent-01")
        reg_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        session_token = reg_resp.json["session_token"]

        # Worker attempts kill switch -> 403
        kill_resp = client.post(
            "/api/swarm/kill-switch",
            json={"agent_id": "agent-01", "reason": "Worker rogue attempt"},
            headers={"X-Session-Token": session_token},
        )
        assert kill_resp.status_code == 403
        assert not coordinator.kill_switch_active

        # Operator triggers kill switch -> 200
        op_kill = client.post(
            "/api/swarm/kill-switch",
            json={"reason": "Operator trigger"},
            headers={"X-Session-Token": OPERATOR_SECRET},
        )
        assert op_kill.status_code == 200
        assert coordinator.kill_switch_active

    def test_worker_attempting_shutdown_returns_403(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        cred = _make_agent_credential("agent-01")
        reg_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        session_token = reg_resp.json["session_token"]

        # Worker attempts shutdown -> 403
        shut_resp = client.post(
            "/api/swarm/shutdown",
            headers={"X-Session-Token": session_token},
        )
        assert shut_resp.status_code == 403


class TestAgentIdentityAndSessionIntegrity:
    """Verifies per-agent authentication, duplicate registration prevention, and spoofing defense."""

    def test_credential_agent_mismatch_rejected_403(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        # Compute credential for agent-02
        cred_agent_02 = _make_agent_credential("agent-02")

        # Attempt to register as agent-03 using agent-02's credential
        mismatch_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-03", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred_agent_02},
        )
        assert mismatch_resp.status_code == 403
        assert "Invalid credential" in mismatch_resp.json.get("message", "")

        # Valid registration for agent-02 succeeds
        valid_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-02", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred_agent_02},
        )
        assert valid_resp.status_code == 200
        assert valid_resp.json["registered"] is True

    def test_duplicate_active_registration_rejected_409(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        cred = _make_agent_credential("agent-01")

        # First registration succeeds
        reg1 = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        assert reg1.status_code == 200

        # Immediate duplicate registration attempt while session is active -> 409 Conflict
        reg2 = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        assert reg2.status_code == 409
        assert "Duplicate active registration" in reg2.json.get("message", "")

    def test_unauthorized_shared_state_impersonation_rejected_403(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        # Register agent-01
        cred = _make_agent_credential("agent-01")
        reg = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        session_token = reg.json["session_token"]

        # Worker agent-01 attempts to post a compromise attributing agent-02
        spoofed_payload = {
            "compromise": {
                "host": "10.254.254.11",
                "agent_id": "agent-02",
                "details": "Fake compromise",
            }
        }
        res = client.post(
            "/api/swarm/shared-state",
            json=spoofed_payload,
            headers={"X-Session-Token": session_token},
        )
        assert res.status_code == 403
        assert "impersonation" in res.json.get("message", "").lower()

        # Legitimate update attributing agent-01 succeeds
        legit_payload = {
            "compromise": {
                "host": "10.254.254.11",
                "agent_id": "agent-01",
                "details": "Real compromise",
            }
        }
        res_legit = client.post(
            "/api/swarm/shared-state",
            json=legit_payload,
            headers={"X-Session-Token": session_token},
        )
        assert res_legit.status_code == 200
        assert res_legit.json["success"] is True

    def test_stale_session_token_rejected_401(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        # Make request with an invalid / non-existent session token
        res = client.post(
            "/api/swarm/heartbeat",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Session-Token": "stale-deadbeef-token-1234"},
        )
        assert res.status_code == 401
        assert "Invalid, expired, or revoked" in res.json.get("message", "")

    def test_stale_lease_renewal_rejected(self, test_app):
        app, coordinator = test_app
        client = app.test_client()

        # Register agent-01
        cred = _make_agent_credential("agent-01")
        reg = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        session_token = reg.json["session_token"]

        # Attempt to renew a non-existent / stale lease
        res = client.post(
            "/api/swarm/task/renew",
            json={"lease_id": "lease-stale-9999", "agent_id": "agent-01"},
            headers={"X-Session-Token": session_token},
        )
        assert res.status_code == 200
        assert res.json["success"] is False


class TestCoordinatorLifecycleAndRestart:
    """Verifies restart clean-slate behavior, initial HOLD phase, and prior session invalidation."""

    def test_coordinator_restart_starts_in_hold_and_invalidates_prior_sessions(self):
        # 1. First coordinator instance
        c1 = SwarmCoordinator(
            team_id="null_warriors",
            auth_token=TEAM_SECRET,
            operator_token=OPERATOR_SECRET,
        )
        c1.advance_phase(Phase.ATTACK, round_id=1)
        assert c1.get_phase().phase == Phase.ATTACK

        # Register worker in c1
        app1 = Flask("app1")
        app1.register_blueprint(create_coordinator_blueprint(c1))
        client1 = app1.test_client()
        cred = _make_agent_credential("agent-01")
        reg1 = client1.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": cred},
        )
        session_token = reg1.json["session_token"]

        # 2. Coordinator restarts (clean instance)
        c2 = SwarmCoordinator(
            team_id="null_warriors",
            auth_token=TEAM_SECRET,
            operator_token=OPERATOR_SECRET,
        )

        # A. Restarts strictly in HOLD phase
        assert c2.get_phase().phase == Phase.HOLD
        assert c2.get_phase().phase_epoch == 1
        assert len(c2.lease_manager.get_active_leases()) == 0

        # B. Prior session token presented to new coordinator instance is rejected with 401
        app2 = Flask("app2")
        app2.register_blueprint(create_coordinator_blueprint(c2))
        client2 = app2.test_client()

        stale_call = client2.get(
            "/api/swarm/tasks",
            headers={"X-Session-Token": session_token},
        )
        assert stale_call.status_code == 401


class TestAllowedActionsEnforcement:
    """Verifies that Config.allowed_actions is deterministically enforced."""

    def test_security_policy_rejects_disallowed_action(self):
        cfg = Config(
            target_hosts=["10.254.254.11"],
            allowed_actions=["nmap_scan", "patch_vulnerability", "hold"],
        )
        policy = SecurityPolicy(cfg=cfg)

        # 1. Action explicitly in allowlist passes
        dec_allowed = Decision(
            action_type="recon",
            target="10.254.254.11",
            priority="normal",
            reasoning="Valid allowed scan",
            confidence=0.9,
        )
        setattr(dec_allowed, "action_name", "nmap_scan")
        res_allowed = policy.authorize(dec_allowed)
        assert res_allowed.allowed is True

        # 2. Action outside allowlist is strictly rejected
        dec_disallowed = Decision(
            action_type="attack",
            target="10.254.254.11:80",
            priority="high",
            reasoning="Disallowed dangerous action",
            confidence=0.9,
        )
        setattr(dec_disallowed, "action_name", "drop_all_tables")
        res_disallowed = policy.authorize(dec_disallowed)
        assert res_disallowed.allowed is False
        assert "not in Config.allowed_actions allowlist" in res_disallowed.reason
        assert res_disallowed.safe_decision.action_type == "hold"

    def test_action_registry_rejects_disallowed_action(self, monkeypatch):
        from agent import config as agent_cfg_module

        # Set allowed_actions to only allow hold and restart_service
        monkeypatch.setattr(
            agent_cfg_module.config,
            "allowed_actions",
            ["restart_service", "hold"],
        )

        registry = ActionRegistry()

        # 1. Allowed action resolves normally
        act_allowed = registry.resolve("defend", target="10.0.1.5:80")
        assert act_allowed.action_name == "restart_service"

        # 2. Disallowed action (recon / attack not in allowed_actions) falls back to safe hold
        act_disallowed = registry.resolve("attack", target="10.254.254.11:80")
        assert act_disallowed.action_name == "hold"
        assert isinstance(act_disallowed, HoldAction)

        # 3. get_action returns None for forbidden action
        assert registry.get_action("exploit_plugin") is None
        assert registry.get_action("restart_service") is not None
