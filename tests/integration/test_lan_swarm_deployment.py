"""
Integration Test Suite for Private LAN Swarm Deployment & Security Hardening.

Validates:
1. Coordinator host binding safety rules:
   - 0.0.0.0 is strictly rejected.
   - 127.0.0.1 is rejected in LAN_REHEARSAL mode.
   - Private LAN IPs (RFC 1918) are required in LAN_REHEARSAL mode.
   - 127.0.0.1 is default only in LOCAL_REHEARSAL mode.
2. Shared team secret token authentication:
   - Missing token -> 401 Unauthorized.
   - Invalid token -> 401 Unauthorized.
   - Valid token via X-Swarm-Token and Bearer header -> 200 OK.
3. Worker registration validation:
   - TEAM_ID mismatch -> 403 Forbidden.
   - Unknown agent_id not in authorized roster -> 403 Forbidden.
   - Missing agent_id -> 400 Bad Request.
   - Authorized roster (agent-01 to agent-04) -> 200 OK.
4. Privacy-preserving public /healthz endpoint:
   - Accessible without token.
   - Exactly exposes 6 operational fields.
   - Zero credential or API key leakage.
5. Multi-process deployment:
   - Proves 4 independent OS worker processes connect over HTTP, register,
     receive partitioned tasks, update shared state, and stop on kill switch.
   - Rogue unauthenticated process is rejected.
"""

import socket
import subprocess
import sys
import time
from typing import List

import pytest
import requests

from agent.config import ConfigProfile, load_config
from agent.swarm.coordinator_server import validate_binding_host
from agent.swarm.lan_rehearsal import RehearsalRunner


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestLanBindingValidation:
    """Validate coordinator binding host policies."""

    def test_reject_0000_unconditionally(self):
        with pytest.raises(ValueError, match="cannot be automatically exposed to 0.0.0.0"):
            validate_binding_host("0.0.0.0", ConfigProfile.LOCAL_REHEARSAL)

        with pytest.raises(ValueError, match="cannot be automatically exposed to 0.0.0.0"):
            validate_binding_host("0.0.0.0", ConfigProfile.LAN_REHEARSAL)

    def test_local_rehearsal_defaults_to_loopback(self):
        host = validate_binding_host("", ConfigProfile.LOCAL_REHEARSAL)
        assert host == "127.0.0.1"

        host_explicit = validate_binding_host("127.0.0.1", ConfigProfile.LOCAL_REHEARSAL)
        assert host_explicit == "127.0.0.1"

    def test_lan_rehearsal_rejects_loopback(self):
        with pytest.raises(ValueError, match="must NOT be 127.0.0.1"):
            validate_binding_host("127.0.0.1", ConfigProfile.LAN_REHEARSAL)

    def test_lan_rehearsal_rejects_empty_host(self):
        with pytest.raises(ValueError, match="must be explicitly configured"):
            validate_binding_host("", ConfigProfile.LAN_REHEARSAL)

    def test_lan_rehearsal_rejects_public_ips(self):
        with pytest.raises(ValueError, match="must be a valid private LAN IP"):
            validate_binding_host("8.8.8.8", ConfigProfile.LAN_REHEARSAL)

        with pytest.raises(ValueError, match="must be a valid private LAN IP"):
            validate_binding_host("1.1.1.1", ConfigProfile.LAN_REHEARSAL)

    def test_lan_rehearsal_accepts_private_lan_ips(self):
        # RFC 1918 ranges
        assert validate_binding_host("192.168.1.50", ConfigProfile.LAN_REHEARSAL) == "192.168.1.50"
        assert validate_binding_host("10.0.0.25", ConfigProfile.LAN_REHEARSAL) == "10.0.0.25"
        assert validate_binding_host("172.16.5.10", ConfigProfile.LAN_REHEARSAL) == "172.16.5.10"


class TestCoordinatorSecurityAndAuth:
    """Test token authentication, worker registration validation, and health endpoint privacy."""

    @pytest.fixture
    def server(self):
        port = find_free_port()
        auth_token = "secret-test-token-42"
        runner = RehearsalRunner(
            coordinator_port=port,
            auth_token=auth_token,
            heartbeat_timeout=2.0,
            lease_ttl=3.0,
            verbose=False,
        )
        assert runner.start_coordinator() is True
        yield runner, f"http://127.0.0.1:{port}", auth_token
        runner.cleanup()

    def test_unauthenticated_requests_rejected(self, server):
        _, base, _ = server

        # Missing token
        r1 = requests.get(f"{base}/api/swarm/status")
        assert r1.status_code == 401
        assert r1.json().get("error") == "Unauthorized"

        # Invalid token
        r2 = requests.get(f"{base}/api/swarm/status", headers={"X-Swarm-Token": "bad-token"})
        assert r2.status_code == 401

        # Invalid bearer
        r3 = requests.get(f"{base}/api/swarm/status", headers={"Authorization": "Bearer bad-token"})
        assert r3.status_code == 401

    def test_authenticated_requests_accepted(self, server):
        _, base, token = server

        # X-Swarm-Token
        r1 = requests.get(f"{base}/api/swarm/status", headers={"X-Swarm-Token": token})
        assert r1.status_code == 200
        assert "agents" in r1.json()

        # Authorization: Bearer
        r2 = requests.get(f"{base}/api/swarm/status", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200

    def test_worker_registration_validation(self, server):
        _, base, token = server
        hdrs = {"X-Swarm-Token": token}

        # 1. Missing agent_id -> 400 Bad Request
        r_empty = requests.post(f"{base}/api/swarm/register", json={}, headers=hdrs)
        assert r_empty.status_code == 400

        # 2. Mismatched team_id -> 403 Forbidden
        r_team = requests.post(
            f"{base}/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "rival-team"},
            headers=hdrs,
        )
        assert r_team.status_code == 403
        assert "team id mismatch" in r_team.json().get("message", "").lower()


        # 3. Unknown agent_id not in authorized roster -> 403 Forbidden
        r_unknown = requests.post(
            f"{base}/api/swarm/register",
            json={"agent_id": "rogue-agent-x", "team_id": "null_warriors"},
            headers=hdrs,
        )
        assert r_unknown.status_code == 403
        assert "not in the authorized roster" in r_unknown.json().get("message", "").lower()

        # 4. Valid authorized agent registration -> 200 OK
        r_valid = requests.post(
            f"{base}/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers=hdrs,
        )
        assert r_valid.status_code == 200
        assert r_valid.json().get("registered") is True
        assert r_valid.json().get("agent_id") == "agent-01"

    def test_health_endpoint_privacy(self, server):
        _, base, _ = server

        # Health endpoint must be accessible without token
        resp = requests.get(f"{base}/healthz")
        assert resp.status_code == 200
        data = resp.json()

        # Exactly the 6 specified keys
        expected_keys = {
            "service_status",
            "team_id",
            "phase",
            "round",
            "phase_epoch",
            "registered_agent_count",
        }
        assert set(data.keys()) == expected_keys
        assert data["service_status"] == "ok"
        assert data["team_id"] == "null_warriors"

        # Verify absolutely zero secret leakage
        raw_text = resp.text.lower()
        for forbidden in ["token", "secret", "password", "api_key", "nvidia", "gemini"]:
            assert forbidden not in raw_text, f"Secret leakage detected: '{forbidden}' in healthz"


class TestMultiProcessLanDeployment:
    """Proves four separate HTTP worker processes connect and coordinate."""

    def test_four_workers_http_deployment(self):
        port = find_free_port()
        auth_token = "lan-shared-secret-key-99"
        runner = RehearsalRunner(
            coordinator_port=port,
            auth_token=auth_token,
            heartbeat_timeout=2.5,
            lease_ttl=3.5,
            verbose=False,
        )
        try:
            success = runner.run()
            assert success is True, f"LAN deployment rehearsal failed: {runner.results}"

            # Verify all 18 security and operational checks passed
            passed_checks = [name for name, passed, _ in runner.results if passed]
            assert "Coordinator HTTP Startup" in passed_checks
            assert "Health Endpoint Privacy & Safe Fields" in passed_checks
            assert "Unauthenticated Request Rejection (401)" in passed_checks
            assert "Mismatched Team Registration Rejection (403)" in passed_checks
            assert "Unknown Agent Registration Rejection (403)" in passed_checks
            assert "Worker Registration & HOLD Sync" in passed_checks
            assert "ATTACK Phase Task Distribution & Completion" in passed_checks
            assert "DEFENSE Phase Task Distribution & Completion" in passed_checks
            assert "Kill Switch Activation & Lease Invalidation" in passed_checks

        finally:
            runner.cleanup()

    def test_rogue_worker_rejection(self):
        """Verify an unauthorized worker process cannot join the swarm."""
        port = find_free_port()
        auth_token = "lan-secure-token-55"
        runner = RehearsalRunner(
            coordinator_port=port,
            auth_token=auth_token,
            heartbeat_timeout=2.5,
            lease_ttl=3.5,
            verbose=False,
        )
        try:
            assert runner.start_coordinator() is True

            # Attempt to run rogue worker with invalid auth token
            rogue_cmd = [
                sys.executable,
                "-m",
                "agent.koth_controller",
                "--agent-id",
                "agent-01",
                "--coordinator-url",
                runner.base_url,
                "--auth-token",
                "wrong-rogue-token",
                "--profile",
                "LOCAL_REHEARSAL",
                "--worker",
                "--max-cycles",
                "1",
            ]
            res = subprocess.run(rogue_cmd, capture_output=True, text=True, timeout=5)
            # The rogue client receives 401 on register and cannot proceed
            st = runner.get_status()
            agent1_status = st["agents"].get("agent-01", {})
            assert not agent1_status.get("alive"), "Rogue agent with bad token must NOT be alive"

        finally:
            runner.cleanup()
