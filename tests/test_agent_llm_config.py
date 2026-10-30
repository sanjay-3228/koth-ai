"""
Tests for Independent Per-Agent LLM Configuration Architecture:
- Independent settings for Agent 1, Agent 2, Agent 3, and Agent 4.
- Support for OpenAI, Anthropic, Google Gemini, Custom endpoints, and Local Simulated.
- Configuration isolation and RBAC (Agent A cannot read/overwrite Agent B).
- API key masking, secret redaction, and safe connection testing without secret leakage.
- Deterministic operation without LLM credentials.
- Advisory-only enforcement through 4-stage deterministic execution gates.
"""
import os
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest
from flask import Flask

from agent.llm.agent_config import (
    AgentLLMConfig,
    AgentLLMConfigManager,
    mask_api_key,
    redact_secrets,
    validate_endpoint,
)
from agent.llm.client_factory import AgentLLMClient
from agent.security.execution_gate import FinalExecutionGate
from agent.actions.base import ActionContext
from agent.gemini_client import Decision
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import AgentRole, Phase, Task, TaskType, TaskLease
from agent.config import Config, ConfigProfile, load_config


@pytest.fixture
def temp_llm_mgr():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_llm.db")
        mgr = AgentLLMConfigManager(db_path=db_path)
        yield mgr


@pytest.fixture
def coordinator_with_llm():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_coord_llm.db")
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            auth_token="test-team-secret-1234",
            operator_token="test-operator-secret-1234",
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("test_coord_llm_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        yield coord, app


# ==============================================================================
# 1. Independent Configuration & Isolation Tests
# ==============================================================================

def test_default_unconfigured_state_per_agent(temp_llm_mgr):
    """All 4 agents start in an unconfigured, disabled state."""
    for aid in ("agent-01", "agent-02", "agent-03", "agent-04"):
        cfg = temp_llm_mgr.get_config(aid)
        assert cfg["agent_id"] == aid
        assert cfg["provider"] == "none"
        assert cfg["enabled"] is False
        assert cfg["connection_status"] == "UNCONFIGURED"
        assert cfg["api_key"] == ""


def test_independent_configuration_per_agent(temp_llm_mgr):
    """Each agent can have distinct providers, endpoints, and models without cross-contamination."""
    # Agent 1 -> OpenAI
    c1 = temp_llm_mgr.set_config(
        agent_id="agent-01",
        provider="openai",
        endpoint="https://api.openai.com/v1",
        model_id="gpt-4o-mini",
        api_key="sk-test-openai-key-agent01-12345",
        enabled=True,
    )
    assert c1["provider"] == "openai"
    assert c1["model_id"] == "gpt-4o-mini"
    assert c1["enabled"] is True

    # Agent 2 -> Anthropic
    c2 = temp_llm_mgr.set_config(
        agent_id="agent-02",
        provider="anthropic",
        endpoint="https://api.anthropic.com/v1",
        model_id="claude-3-5-sonnet-20241022",
        api_key="sk-ant-test-anthropic-key-agent02-67890",
        enabled=True,
    )
    assert c2["provider"] == "anthropic"
    assert c2["model_id"] == "claude-3-5-sonnet-20241022"

    # Agent 3 -> Google Gemini
    c3 = temp_llm_mgr.set_config(
        agent_id="agent-03",
        provider="gemini",
        endpoint="https://generativelanguage.googleapis.com/v1beta",
        model_id="gemini-1.5-flash",
        api_key="AIzaSyTestGeminiKeyAgent03_ABCDE12345",
        enabled=True,
    )
    assert c3["provider"] == "gemini"
    assert c3["model_id"] == "gemini-1.5-flash"

    # Agent 4 -> Custom local endpoint
    c4 = temp_llm_mgr.set_config(
        agent_id="agent-04",
        provider="custom",
        endpoint="http://192.168.1.100:11434/v1",
        model_id="llama3:latest",
        api_key="custom-local-key",
        enabled=True,
    )
    assert c4["provider"] == "custom"
    assert c4["endpoint"] == "http://192.168.1.100:11434/v1"

    # Verify Agent 1 was not modified by Agent 2, 3, or 4
    check_c1 = temp_llm_mgr.get_config("agent-01")
    assert check_c1["provider"] == "openai"
    assert check_c1["model_id"] == "gpt-4o-mini"

    # Verify Agent 2 was not modified
    check_c2 = temp_llm_mgr.get_config("agent-02")
    assert check_c2["provider"] == "anthropic"


def test_configuration_isolation_enforced_by_rbac(coordinator_with_llm):
    """Enforce Requirement 6: One agent must NEVER read or overwrite another agent's LLM configuration."""
    coord, app = coordinator_with_llm
    client = app.test_client()

    # Create team session for Agent 1 and Agent 2
    coord.team_manager.create_team(
        team_id="null_warriors",
        team_name="Null Warriors",
        leader_username="leader_alice",
        leader_password="test_leader_pass_123",
    )
    m2 = coord.team_manager.join_team("null_warriors", "teammate_bob", "test_tm_pass_123")

    s1 = coord.team_manager.login("leader_alice", "test_leader_pass_123")["session_token"]
    s2 = coord.team_manager.login("teammate_bob", "test_tm_pass_123")["session_token"]

    # 1. Unauthenticated request -> 401
    unauth = client.get("/api/agent/agent-01/llm")
    assert unauth.status_code == 401

    # 2. Agent 1 can access Agent 1's LLM settings
    r1_own = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": s1})
    assert r1_own.status_code == 200
    assert r1_own.json["agent_id"] == "agent-01"

    # 3. Agent 1 ATTEMPTS to access Agent 2's LLM settings -> 403 Forbidden!
    r1_cross = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": s1})
    assert r1_cross.status_code == 403
    assert "Access denied" in r1_cross.json["message"]

    # 4. Agent 2 can access Agent 2's LLM settings
    r2_own = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": s2})
    assert r2_own.status_code == 200
    assert r2_own.json["agent_id"] == "agent-02"

    # 5. Agent 2 ATTEMPTS to access Agent 1's LLM settings -> 403 Forbidden!
    r2_cross = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": s2})
    assert r2_cross.status_code == 403

    # 6. Agent 2 ATTEMPTS to overwrite Agent 1's LLM settings -> 403 Forbidden!
    r2_overwrite = client.post(
        "/api/agent/agent-01/llm",
        json={"provider": "openai", "model_id": "malicious-model", "enabled": True},
        headers={"X-Session-Token": s2},
    )
    assert r2_overwrite.status_code == 403
    assert "Access denied" in r2_overwrite.json["message"]

    # 7. Agent 1 configures own LLM successfully
    r1_update = client.post(
        "/api/agent/agent-01/llm",
        json={
            "provider": "openai",
            "endpoint": "https://api.openai.com/v1",
            "model_id": "gpt-4o-mini",
            "api_key": "sk-secret-agent-01-key-99999",
            "enabled": True,
        },
        headers={"X-Session-Token": s1},
    )
    assert r1_update.status_code == 200
    assert r1_update.json["provider"] == "openai"


# ==============================================================================
# 2. Secret Masking & Redaction Tests
# ==============================================================================

def test_secret_masking_in_responses(temp_llm_mgr):
    """API keys must be masked in serializations and never exposed in full plaintext."""
    temp_llm_mgr.set_config(
        agent_id="agent-01",
        provider="openai",
        endpoint="https://api.openai.com/v1",
        model_id="gpt-4o-mini",
        api_key="sk-proj-supersecretkey123456789",
        enabled=True,
    )
    cfg = temp_llm_mgr.get_config("agent-01", mask_secrets=True)
    assert "supersecretkey" not in cfg["api_key"]
    assert cfg["api_key"].startswith("sk-...")
    assert cfg["has_api_key"] is True


def test_redact_secrets_utility():
    """Verify that credentials, tokens, private keys, and competition flags are scrubbed."""
    raw = (
        "Error in API request: sk-1234567890abcdef12345678 failed. "
        "Also found flag{competition_flag_secret_123} and "
        "AIzaSyD7-test-gemini-key-12345678901 and flag_agent-01_10.0.1.5_2"
    )
    scrubbed = redact_secrets(raw)
    assert "sk-1234567890" not in scrubbed
    assert "competition_flag_secret" not in scrubbed
    assert "AIzaSy" not in scrubbed
    assert "flag_agent-01" not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_endpoint_validation():
    """Verify endpoint syntax and protocol allowlist."""
    # Valid
    ok, _ = validate_endpoint("https://api.openai.com/v1", "openai")
    assert ok is True

    ok, _ = validate_endpoint("http://192.168.1.50:11434/v1", "custom")
    assert ok is True

    ok, _ = validate_endpoint("", "none")
    assert ok is True

    ok, _ = validate_endpoint("local://simulated", "local_simulated")
    assert ok is True

    # Invalid: unsupported protocol
    bad_proto, msg = validate_endpoint("ftp://example.com/api", "custom")
    assert bad_proto is False
    assert "Unsupported protocol" in msg

    # Invalid: empty when provider is active
    empty, msg = validate_endpoint("", "openai")
    assert empty is False

    # Invalid: injection characters
    bad_chars, msg = validate_endpoint("https://api.com/v1; rm -rf /", "custom")
    assert bad_chars is False
    assert "invalid characters" in msg


# ==============================================================================
# 3. Connection Testing with Safe Probes (No Flag/Secret Leaks)
# ==============================================================================

def test_safe_connection_testing_openai(coordinator_with_llm):
    """Safe connection probe sends minimal 'pong' prompt and verifies 200 OK without secret leaks."""
    coord, app = coordinator_with_llm
    client = app.test_client()

    coord.team_manager.create_team("team_x", "Team X", "alice", "test_pass_alice_123")
    s1 = coord.team_manager.login("alice", "test_pass_alice_123")["session_token"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"choices": [{"message": {"content": "pong"}}]}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = client.post(
            "/api/agent/agent-01/llm/test",
            json={
                "provider": "openai",
                "endpoint": "https://api.openai.com/v1",
                "model_id": "gpt-4o-mini",
                "api_key": "sk-testkey123456789012345678",
                "enabled": True,
            },
            headers={"X-Session-Token": s1},
        )
        assert res.status_code == 200
        assert res.json["success"] is True
        assert res.json["status"] == "CONNECTED"

        # Verify probe payload was strictly minimal and never leaked flags or secrets
        sent_payload = mock_post.call_args[1]["json"]
        assert sent_payload["messages"][0]["content"] == "Respond with 'pong' only."


def test_safe_connection_testing_anthropic(coordinator_with_llm):
    """Test Anthropic probe with x-api-key header."""
    coord, app = coordinator_with_llm
    client = app.test_client()

    coord.team_manager.create_team("team_y", "Team Y", "alice", "test_pass_alice_123")
    s1 = coord.team_manager.login("alice", "test_pass_alice_123")["session_token"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"content": [{"text": "pong"}]}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = client.post(
            "/api/agent/agent-01/llm/test",
            json={
                "provider": "anthropic",
                "endpoint": "https://api.anthropic.com/v1",
                "model_id": "claude-3-5-sonnet-20241022",
                "api_key": "sk-ant-testkey123456789012345678",
                "enabled": True,
            },
            headers={"X-Session-Token": s1},
        )
        assert res.status_code == 200
        assert res.json["success"] is True
        assert res.json["status"] == "CONNECTED"
        assert "x-api-key" in mock_post.call_args[1]["headers"]


def test_safe_connection_testing_gemini(coordinator_with_llm):
    """Test Google Gemini probe with x-goog-api-key header."""
    coord, app = coordinator_with_llm
    client = app.test_client()

    coord.team_manager.create_team("team_z", "Team Z", "alice", "test_pass_alice_123")
    s1 = coord.team_manager.login("alice", "test_pass_alice_123")["session_token"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"candidates": [{"content": {"parts": [{"text": "pong"}]}}]}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = client.post(
            "/api/agent/agent-01/llm/test",
            json={
                "provider": "gemini",
                "endpoint": "https://generativelanguage.googleapis.com/v1beta",
                "model_id": "gemini-1.5-flash",
                "api_key": "AIzaSyTestKey12345678901234567890",
                "enabled": True,
            },
            headers={"X-Session-Token": s1},
        )
        assert res.status_code == 200
        assert res.json["success"] is True
        assert res.json["status"] == "CONNECTED"
        assert "x-goog-api-key" in mock_post.call_args[1]["headers"]


def test_invalid_credentials_handling(coordinator_with_llm):
    """Provider returning 401 Unauthorized marks status FAILED without leaking key in error."""
    coord, app = coordinator_with_llm
    client = app.test_client()

    coord.team_manager.create_team("team_fail", "Team Fail", "alice", "test_pass_alice_123")
    s1 = coord.team_manager.login("alice", "test_pass_alice_123")["session_token"]

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized: invalid api key sk-badkey1234567890"

    with patch("requests.post", return_value=mock_resp):
        res = client.post(
            "/api/agent/agent-01/llm/test",
            json={
                "provider": "openai",
                "endpoint": "https://api.openai.com/v1",
                "model_id": "gpt-4o-mini",
                "api_key": "sk-badkey1234567890",
                "enabled": True,
            },
            headers={"X-Session-Token": s1},
        )
        assert res.status_code == 200
        assert res.json["success"] is False
        assert res.json["status"] == "FAILED"
        assert "sk-badkey1234567890" not in res.json["message"]


def test_unavailable_provider_timeout_handling(coordinator_with_llm):
    """Timeout during probe cleanly marks status FAILED and redacts secrets."""
    import requests
    coord, app = coordinator_with_llm
    client = app.test_client()

    coord.team_manager.create_team("team_timeout", "Team Timeout", "alice", "test_pass_alice_123")
    s1 = coord.team_manager.login("alice", "test_pass_alice_123")["session_token"]

    with patch("requests.post", side_effect=requests.Timeout("Request to endpoint timed out")):
        res = client.post(
            "/api/agent/agent-01/llm/test",
            json={
                "provider": "custom",
                "endpoint": "http://10.99.99.99:8000/v1",
                "model_id": "local-model",
                "api_key": "sk-timeout-key",
                "enabled": True,
            },
            headers={"X-Session-Token": s1},
        )
        assert res.status_code == 200
        assert res.json["success"] is False
        assert res.json["status"] == "FAILED"
        assert "timed out" in res.json["message"].lower()


# ==============================================================================
# 4. Graceful Fallback & Advisory-Only Execution Gates
# ==============================================================================

def test_operation_without_llm_deterministic_fallback():
    """Verify that when an agent's LLM is disabled or unconfigured, query returns None."""
    cfg = AgentLLMConfig(agent_id="agent-02", provider="none", enabled=False)
    client = AgentLLMClient(cfg)
    advisory = client.query_advisory("Telemetry: host 10.254.254.12 is up")
    assert advisory is None


def test_advisory_only_llm_cannot_bypass_execution_gates():
    """Even if an LLM recommendation is generated, the 4-stage execution gates strictly enforce security.
    
    If the LLM suggests attacking an unconfigured or forbidden host, Stage 1 Policy Authorization rejects it.
    """
    cfg = load_config(profile=ConfigProfile.LOCAL_REHEARSAL)
    cfg.allowed_actions = ["recon_scan", "restart_service", "hold"]
    gate = FinalExecutionGate(config=cfg)

    # Malicious or hallucinatory decision from an LLM
    bad_llm_decision = Decision(
        action_type="attack",
        target="10.254.254.101:22",  # Attempting to attack own protected infrastructure!
        priority="HIGH",
        reasoning="LLM hallucinated attacking own server",
        model_used="rogue-llm",
    )
    bad_llm_decision.action_name = "exploit_plugin"

    ctx = ActionContext(config=cfg)
    rec = gate.execute_with_gates(decision=bad_llm_decision, context=ctx)
    assert rec.success is False
    assert rec.attempted is False
    assert "rejected" in rec.failure_reason.lower()


# ==============================================================================
# 5. Identity Decoupling, Session Validation & Cross-Agent RBAC Regressions
# ==============================================================================

def test_all_four_teammates_can_test_own_llm_and_are_denied_others():
    """Verify that all 4 teammates can test their assigned agent's LLM in default mode,
    while cross-agent testing is strictly denied with 403 Forbidden.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "rehearsal_llm.db")
        # Initialize coordinator without pre-shared tokens (exact desktop/rehearsal mode)
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("rehearsal_llm_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        client = app.test_client()

        # Register team and 3 teammates
        coord.team_manager.create_team("null_warriors", "Null Warriors", "alice_lead", "pass_alice_123")
        coord.team_manager.join_team("null_warriors", "bob_tm1", "pass_bob_123")
        coord.team_manager.join_team("null_warriors", "carol_tm2", "pass_carol_123")
        coord.team_manager.join_team("null_warriors", "dave_tm3", "pass_dave_123")

        s1 = coord.team_manager.login("alice_lead", "pass_alice_123")["session_token"]
        s2 = coord.team_manager.login("bob_tm1", "pass_bob_123")["session_token"]
        s3 = coord.team_manager.login("carol_tm2", "pass_carol_123")["session_token"]
        s4 = coord.team_manager.login("dave_tm3", "pass_dave_123")["session_token"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "pong"}}]}

        with patch("requests.post", return_value=mock_resp):
            payload = {
                "provider": "openai",
                "endpoint": "https://api.openai.com/v1",
                "model_id": "gpt-4o-mini",
                "api_key": "sk-probe-key-123456789012345",
                "enabled": True,
            }

            # 1. Each agent tests their own configuration -> MUST SUCCEED (200 OK)
            r1 = client.post("/api/agent/agent-01/llm/test", json=payload, headers={"X-Session-Token": s1})
            assert r1.status_code == 200, f"Leader failed: {r1.json}"
            assert r1.json["success"] is True
            assert r1.json["status"] == "CONNECTED"

            r2 = client.post("/api/agent/agent-02/llm/test", json=payload, headers={"X-Session-Token": s2})
            assert r2.status_code == 200, f"Teammate 1 failed: {r2.json}"
            assert r2.json["success"] is True
            assert r2.json["status"] == "CONNECTED"

            r3 = client.post("/api/agent/agent-03/llm/test", json=payload, headers={"X-Session-Token": s3})
            assert r3.status_code == 200, f"Teammate 2 failed: {r3.json}"
            assert r3.json["success"] is True
            assert r3.json["status"] == "CONNECTED"

            r4 = client.post("/api/agent/agent-04/llm/test", json=payload, headers={"X-Session-Token": s4})
            assert r4.status_code == 200, f"Teammate 3 failed: {r4.json}"
            assert r4.json["success"] is True
            assert r4.json["status"] == "CONNECTED"

            # 2. Strict isolation: Cross-agent tests MUST be denied with 403 Forbidden
            # Leader attempts cross-agent tests
            assert client.post("/api/agent/agent-02/llm/test", json=payload, headers={"X-Session-Token": s1}).status_code == 403
            assert client.post("/api/agent/agent-03/llm/test", json=payload, headers={"X-Session-Token": s1}).status_code == 403
            assert client.post("/api/agent/agent-04/llm/test", json=payload, headers={"X-Session-Token": s1}).status_code == 403

            # Teammate 1 attempts cross-agent tests
            assert client.post("/api/agent/agent-01/llm/test", json=payload, headers={"X-Session-Token": s2}).status_code == 403
            assert client.post("/api/agent/agent-03/llm/test", json=payload, headers={"X-Session-Token": s2}).status_code == 403
            assert client.post("/api/agent/agent-04/llm/test", json=payload, headers={"X-Session-Token": s2}).status_code == 403

            # Teammate 2 attempts cross-agent tests
            assert client.post("/api/agent/agent-01/llm/test", json=payload, headers={"X-Session-Token": s3}).status_code == 403
            assert client.post("/api/agent/agent-02/llm/test", json=payload, headers={"X-Session-Token": s3}).status_code == 403
            assert client.post("/api/agent/agent-04/llm/test", json=payload, headers={"X-Session-Token": s3}).status_code == 403

            # Teammate 3 attempts cross-agent tests
            assert client.post("/api/agent/agent-01/llm/test", json=payload, headers={"X-Session-Token": s4}).status_code == 403
            assert client.post("/api/agent/agent-02/llm/test", json=payload, headers={"X-Session-Token": s4}).status_code == 403
            assert client.post("/api/agent/agent-03/llm/test", json=payload, headers={"X-Session-Token": s4}).status_code == 403


def test_operator_username_does_not_automatically_receive_agent_privileges():
    """Verify that:
    1. An operator token caller has agent_id 'operator' and is denied access to agent-01..04.
    2. An admin username session has agent_id 'operator' and is denied access.
    3. A human user whose username is literally 'operator' who created a team is assigned to
       agent-01 and CAN test agent-01, but is DENIED access to agent-02.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "op_test.db")
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            operator_token="test-system-operator-secret",
            enable_username_login=True,
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("op_test_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        client = app.test_client()

        # Part 1: System Operator Token caller
        res_op = client.get("/api/agent/agent-01/llm", headers={"X-Operator-Token": "test-system-operator-secret"})
        assert res_op.status_code == 403
        assert "Access denied" in res_op.json["message"]

        res_op_test = client.post(
            "/api/agent/agent-01/llm/test",
            json={"provider": "local_simulated"},
            headers={"X-Operator-Token": "test-system-operator-secret"},
        )
        assert res_op_test.status_code == 403
        assert "Access denied" in res_op_test.json["message"]

        # Part 2: Username login as 'admin' -> issues session with agent_id 'operator'
        admin_login = coord.issue_username_session("admin")
        assert admin_login["agent_id"] == "operator"
        admin_token = admin_login["session_token"]

        res_admin = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": admin_token})
        assert res_admin.status_code == 403
        assert "Access denied" in res_admin.json["message"]

        # Part 3: Human user whose username is literally 'operator' creating a team
        coord.team_manager.create_team(
            team_id="null_warriors",
            team_name="Null Warriors",
            leader_username="operator",
            leader_password="password_op_123",
        )
        login_info = coord.team_manager.login("operator", "password_op_123")
        assert login_info["username"] == "operator"
        assert login_info["agent_id"] == "agent-01"
        op_user_token = login_info["session_token"]

        # Human user 'operator' resolved to agent-01 CAN configure & test agent-01
        res_own = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": op_user_token})
        assert res_own.status_code == 200
        assert res_own.json["agent_id"] == "agent-01"

        res_own_test = client.post(
            "/api/agent/agent-01/llm/test",
            json={"provider": "local_simulated", "enabled": True},
            headers={"X-Session-Token": op_user_token},
        )
        assert res_own_test.status_code == 200
        assert res_own_test.json["success"] is True

        # Human user 'operator' is strictly DENIED access to agent-02
        res_cross = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": op_user_token})
        assert res_cross.status_code == 403
        assert "Access denied" in res_cross.json["message"]


def test_invalid_expired_and_revoked_sessions_rejected():
    """Verify that unauthenticated, malformed, expired, and revoked sessions are rejected with 401."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "session_test.db")
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("session_test_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        client = app.test_client()

        # 1. No token at all -> 401
        res_no_tok = client.get("/api/agent/agent-01/llm")
        assert res_no_tok.status_code == 401
        assert "Authentication required" in res_no_tok.json["message"]

        # 2. Bogus random token -> 401
        res_bogus = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": "bogus-random-token-999"})
        assert res_bogus.status_code == 401
        assert "Invalid, expired, or revoked" in res_bogus.json["message"]

        # Create valid session
        coord.team_manager.create_team("null_warriors", "Null Warriors", "lead_user", "pass_lead_123")
        tok_data = coord.team_manager.login("lead_user", "pass_lead_123")
        valid_tok = tok_data["session_token"]

        # Valid token works
        res_ok = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": valid_tok})
        assert res_ok.status_code == 200

        # 3. Revoke session -> must now return 401
        coord.team_manager.revoke_session(valid_tok)
        res_revoked = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": valid_tok})
        assert res_revoked.status_code == 401
        assert "Invalid, expired, or revoked" in res_revoked.json["message"]

        # 4. Expired session -> must return 401
        new_tok = coord.team_manager.login("lead_user", "pass_lead_123")["session_token"]
        # Manually expire in DB
        with coord.team_manager._get_connection() as conn:
            conn.execute("UPDATE auth_sessions SET expires_at = ? WHERE session_token = ?", (time.time() - 3600, new_tok))
            conn.commit()

        res_expired = client.get("/api/agent/agent-01/llm", headers={"X-Session-Token": new_tok})
        assert res_expired.status_code == 401
        assert "Invalid, expired, or revoked" in res_expired.json["message"]


def test_llm_operations_authorization_consistency():
    """Verify consistent RBAC enforcement across all LLM operations:
    - Read configuration
    - Update configuration
    - Test connection
    - Enable / disable provider
    - Read connection status
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "ops_consistency.db")
        coord = SwarmCoordinator(
            team_id="null_warriors",
            db_path=db_path,
            authorized_agents=["agent-01", "agent-02", "agent-03", "agent-04"],
        )
        app = Flask("ops_consistency_app")
        app.register_blueprint(create_coordinator_blueprint(coord))
        client = app.test_client()

        coord.team_manager.create_team("null_warriors", "Null Warriors", "alice_lead", "pass_alice_123")
        coord.team_manager.join_team("null_warriors", "bob_tm1", "pass_bob_123")

        s1 = coord.team_manager.login("alice_lead", "pass_alice_123")["session_token"]
        s2 = coord.team_manager.login("bob_tm1", "pass_bob_123")["session_token"]

        # 1. Read configuration & status: Bob reads agent-02 (200), Alice is denied (403)
        res_read_bob = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": s2})
        assert res_read_bob.status_code == 200
        assert res_read_bob.json["connection_status"] == "UNCONFIGURED"

        res_read_alice = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": s1})
        assert res_read_alice.status_code == 403

        # 2. Update configuration & enable: Bob updates agent-02 (200), Alice is denied (403)
        update_payload = {
            "provider": "local_simulated",
            "endpoint": "local://simulated",
            "model_id": "sim-model",
            "enabled": True,
        }
        res_up_alice = client.post("/api/agent/agent-02/llm", json=update_payload, headers={"X-Session-Token": s1})
        assert res_up_alice.status_code == 403

        res_up_bob = client.post("/api/agent/agent-02/llm", json=update_payload, headers={"X-Session-Token": s2})
        assert res_up_bob.status_code == 200
        assert res_up_bob.json["enabled"] is True

        # 3. Test connection: Bob tests agent-02 (200), Alice is denied (403)
        res_test_alice = client.post("/api/agent/agent-02/llm/test", json={}, headers={"X-Session-Token": s1})
        assert res_test_alice.status_code == 403

        res_test_bob = client.post("/api/agent/agent-02/llm/test", json={}, headers={"X-Session-Token": s2})
        assert res_test_bob.status_code == 200
        assert res_test_bob.json["status"] == "CONNECTED"

        # 4. Read updated connection status
        res_status_bob = client.get("/api/agent/agent-02/llm", headers={"X-Session-Token": s2})
        assert res_status_bob.status_code == 200
        assert res_status_bob.json["connection_status"] == "CONNECTED"

        # 5. Disable provider: Bob disables agent-02 (200), Alice is denied (403)
        disable_payload = {
            "provider": "local_simulated",
            "endpoint": "local://simulated",
            "model_id": "sim-model",
            "enabled": False,
        }
        res_dis_alice = client.post("/api/agent/agent-02/llm", json=disable_payload, headers={"X-Session-Token": s1})
        assert res_dis_alice.status_code == 403

        res_dis_bob = client.post("/api/agent/agent-02/llm", json=disable_payload, headers={"X-Session-Token": s2})
        assert res_dis_bob.status_code == 200
        assert res_dis_bob.json["enabled"] is False


