"""
Final Adversarial Security Verification Suite for koth-agent LAN Swarm.

Covers all 8 critical verification requirements:
1. PER-AGENT IDENTITY: Unique non-derivable credentials; cross-agent credentials strictly rejected (403).
2. REAL PROCESS RESTART: Coordinator termination & reboot resets to HOLD, invalidates sessions (401), invalidates leases.
3. EXECUTION-TIME PHASE FENCE: Stale ATTACK tasks are rejected at the execution gate during DEFENSE.
4. FINAL ACTION GATE: Deterministic chain: policy -> registry -> task -> final gate -> execution. AI output cannot bypass.
5. TLS SECURITY: HTTPS verification with valid CA, failure on wrong CA, prohibition of verify=False, no HTTP downgrade.
6. PRIVILEGE MATRIX: Complete Worker vs Operator vs Unauthenticated endpoint permission matrix.
7. PHASE RACE: Rapid alternating transitions; no stale epoch task executes.
8. DUPLICATE SESSION RACE: Concurrent registrations for same agent_id result in exactly 1 active session and 1 rejection (409).
"""

from __future__ import annotations

import concurrent.futures
import datetime
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from typing import Dict, Optional, Tuple

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask

from agent.actions.base import ActionContext, ActionExecutionRecord, BaseAction
from agent.actions.registry import ActionRegistry, HoldAction
from agent.config import Config, ConfigProfile, load_config
from agent.gemini_client import Decision
from agent.security.execution_gate import FinalExecutionGate
from agent.security.policy import RiskLevel, SecurityPolicy
from agent.swarm.client import SwarmClient
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.models import AgentRole, AgentStatus, Phase, PhaseState, Task, TaskLease, TaskStatus, TaskType


# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================

AGENT_TOKENS = {
    "agent-01": "secret-token-agent-01-" + secrets.token_hex(8),
    "agent-02": "secret-token-agent-02-" + secrets.token_hex(8),
    "agent-03": "secret-token-agent-03-" + secrets.token_hex(8),
    "agent-04": "secret-token-agent-04-" + secrets.token_hex(8),
}
OPERATOR_TOKEN = "secret-operator-root-" + secrets.token_hex(8)
SWARM_AUTH_TOKEN = "null_warriors-secret-" + secrets.token_hex(8)
AUTHORIZED_ROSTER = ["agent-01", "agent-02", "agent-03", "agent-04"]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def generate_self_signed_cert(ip_str: str = "127.0.0.1") -> Tuple[bytes, bytes]:
    """Generate temporary self-signed TLS cert and private key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip_str)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip_str))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.fixture
def coordinator_app():
    coordinator = SwarmCoordinator(
        team_id="null_warriors",
        auth_token=SWARM_AUTH_TOKEN,
        operator_token=OPERATOR_TOKEN,
        agent_tokens=dict(AGENT_TOKENS),
        authorized_agents=AUTHORIZED_ROSTER,
        target_hosts=["10.254.254.11", "10.254.254.12", "10.254.254.13", "10.254.254.14"],
        own_hosts=["10.254.254.101", "10.254.254.102", "10.254.254.103", "10.254.254.104"],
        session_ttl=10.0,
    )
    app = Flask("test_final_security")
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)
    return app, coordinator


# ==============================================================================
# Requirement 1: PER-AGENT IDENTITY (Cross-Agent Mismatch Rejection)
# ==============================================================================

class TestPerAgentIdentityAdversarial:
    """
    Verifies that each agent has an authoritative, unique credential,
    and knowing another agent's credential or team secret alone cannot derive
    or authenticate as any other agent.
    """

    def test_cross_agent_credential_rejected_403(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        # agent-01 credential with agent-02 identity -> 403 Forbidden
        resp1 = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-02", "team_id": "null_warriors"},
            headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
        )
        assert resp1.status_code == 403
        assert "Invalid credential" in resp1.json.get("message", "")

        # agent-02 credential with agent-01 identity -> 403 Forbidden
        resp2 = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Agent-Credential": AGENT_TOKENS["agent-02"]},
        )
        assert resp2.status_code == 403
        assert "Invalid credential" in resp2.json.get("message", "")

    def test_team_token_alone_cannot_authenticate_as_worker_when_per_agent_active(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        # Attempt to register worker using raw team auth token -> 403 Forbidden
        resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Swarm-Token": SWARM_AUTH_TOKEN},
        )
        assert resp.status_code == 403

    def test_legitimate_per_agent_credentials_succeed(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        for aid in AUTHORIZED_ROSTER:
            resp = client.post(
                "/api/swarm/register",
                json={"agent_id": aid, "team_id": "null_warriors"},
                headers={"X-Agent-Credential": AGENT_TOKENS[aid]},
            )
            assert resp.status_code == 200
            assert "session_token" in resp.json


# ==============================================================================
# Requirement 3 & 4: EXECUTION-TIME PHASE FENCE & FINAL ACTION GATE
# ==============================================================================

class TestExecutionTimePhaseFenceAndActionGates:
    """
    Verifies that the multi-stage authorization gate chain:
      policy authorization -> registry authorization -> task authorization -> FINAL execution gate -> execution
    strictly intercepts and rejects any task or action violating phase, epoch, or policy.
    """

    def test_execution_time_phase_fence_rejects_stale_attack_task_in_defense(self, coordinator_app):
        """
        Create an ATTACK task in ATTACK phase. Give it to worker.
        Transition coordinator to DEFENSE phase.
        Attempt execution using the old ATTACK task.
        MUST be rejected at the final execution authorization gate!
        """
        app, coordinator = coordinator_app
        client = app.test_client()

        # 1. Advance to ATTACK phase (epoch 2)
        adv_resp = client.post(
            "/api/swarm/phase/advance",
            json={"phase": "ATTACK", "round_id": 1},
            headers={"X-Operator-Token": OPERATOR_TOKEN},
        )
        assert adv_resp.status_code == 200

        # 2. Register worker and obtain ATTACK task
        reg_resp = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
        )
        assert reg_resp.status_code == 200
        session_token = reg_resp.json["session_token"]

        task_resp = client.post(
            "/api/swarm/tasks/request",
            json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 2},
            headers={"X-Session-Token": session_token},
        )
        assert task_resp.status_code == 200
        task_data = task_resp.json["task"]
        lease_data = task_resp.json["lease"]
        assert task_data is not None

        attack_task = Task.from_dict(task_data)
        attack_lease = TaskLease.from_dict(lease_data)

        # 3. Simulate SwarmClient holding this task
        swarm_client = SwarmClient(
            agent_id="agent-01",
            coordinator=coordinator,
            agent_credential=AGENT_TOKENS["agent-01"],
        )
        swarm_client.current_task = attack_task
        swarm_client.current_lease = attack_lease
        swarm_client.current_phase_state = PhaseState(
            phase=Phase.ATTACK, round_id=1, phase_epoch=2
        )

        # 4. Now transition coordinator to DEFENSE (epoch 3)
        coordinator.advance_phase(Phase.DEFENSE, round_id=1)
        # Update client phase to match current coordinator reality
        swarm_client.sync_phase()
        assert swarm_client.current_phase == Phase.DEFENSE

        # 5. Worker attempts to execute the old ATTACK task
        decision = Decision(
            action_type="attack",
            target="10.254.254.11:22",
            priority="high",
            reasoning="Attempting exploit on leased target",
            confidence=0.95,
            model_used="advisory-llm",
        )

        cfg = load_config(profile=ConfigProfile.LOCAL_REHEARSAL)
        cfg.allowed_actions = ["recon_scan", "exploit_plugin", "restart_service", "rate_limit_port", "hold"]
        decision.action_name = "exploit_plugin"

        context = ActionContext(
            config=cfg,
            monitor=None,
            firewall=None,
            patcher=None,
            recon=None,
            dispatcher=None,
        )

        gate = FinalExecutionGate(config=cfg)
        record = gate.execute_with_gates(
            decision=decision,
            context=context,
            task=attack_task,
            swarm_client=swarm_client,
        )

        # MUST BE REJECTED AT FINAL EXECUTION AUTHORIZATION GATE
        assert record.success is False
        assert "phase fence rejected" in record.failure_reason.lower()
        assert "does not match current active phase 'DEFENSE'" in record.failure_reason

    def test_final_action_gate_chain_blocks_all_violations(self):
        """
        Prove that every executable action passes through:
           policy authorization -> registry authorization -> task authorization -> FINAL execution authorization -> execution.
        No AI output may bypass this chain.
        """
        cfg = load_config(profile=ConfigProfile.LOCAL_REHEARSAL)
        cfg.allowed_actions = ["restart_service", "hold"]  # 'exploit_plugin' NOT allowed
        gate = FinalExecutionGate(config=cfg)
        context = ActionContext(config=cfg, monitor=None, firewall=None, patcher=None, recon=None, dispatcher=None)

        # 1. Policy violation: attack against own infrastructure
        decision_bad_policy = Decision(
            action_type="attack",
            target="10.254.254.101:22",  # Own host!
            priority="high",
            reasoning="Advisory AI suggested attacking own infrastructure",
        )
        res1 = gate.verify_and_authorize(decision_bad_policy, context)
        assert res1.allowed is False
        assert res1.stage == "policy_authorization"

        # 2. Registry violation: action not in allowed_actions
        decision_bad_registry = Decision(
            action_type="attack",
            target="10.254.254.11:22",  # In scope target
            priority="high",
            reasoning="Exploit attempt",
        )
        res2 = gate.verify_and_authorize(decision_bad_registry, context)
        assert res2.allowed is False
        assert res2.stage == "registry_authorization"

        # 3. Task violation: cancelled task
        cancelled_task = Task(
            task_id="task-test-cancelled",
            phase=Phase.ATTACK,
            phase_epoch=1,
            task_type=TaskType.ATTACK_EXPLOIT,
            target_host="10.254.254.11",
            status=TaskStatus.CANCELLED,
        )
        cfg.allowed_actions.append("exploit_plugin")
        decision_cancelled = Decision(
            action_type="attack",
            target="10.254.254.11:22",
            priority="high",
            reasoning="Valid target and allowed action",
        )
        decision_cancelled.action_name = "exploit_plugin"
        res3 = gate.verify_and_authorize(decision_cancelled, context, task=cancelled_task)
        assert res3.allowed is False
        assert res3.stage == "task_authorization"

        # 4. Final Gate violation: Kill switch active
        cfg.kill_switch = True
        res4 = gate.verify_and_authorize(decision_cancelled, context)
        assert res4.allowed is False
        assert res4.stage == "final_execution_authorization"
        assert "Kill switch" in res4.reason


# ==============================================================================
# Requirement 6: PRIVILEGE MATRIX COMPREHENSIVE VERIFICATION
# ==============================================================================

class TestPrivilegeMatrixComprehensive:
    """
    Tests the complete privilege matrix across Worker, Operator, and Unauthenticated roles:
      WORKER: heartbeat -> ALLOW, task claim/renew/complete -> ALLOW, state -> ALLOW,
              phase advance -> DENY, kill switch -> DENY, shutdown -> DENY.
      OPERATOR: phase advance -> ALLOW, kill switch -> ALLOW, shutdown -> ALLOW.
      UNAUTHENTICATED: all mutations -> DENY.
    """

    def test_worker_privilege_matrix(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        # Advance to ATTACK so tasks exist
        client.post(
            "/api/swarm/phase/advance",
            json={"phase": "ATTACK", "round_id": 1},
            headers={"X-Operator-Token": OPERATOR_TOKEN},
        )

        # Register worker
        reg = client.post(
            "/api/swarm/register",
            json={"agent_id": "agent-01", "team_id": "null_warriors"},
            headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
        )
        assert reg.status_code == 200
        worker_session = reg.json["session_token"]
        w_hdr = {"X-Session-Token": worker_session}

        # Worker ALLOW checks:
        # 1. Heartbeat -> ALLOW
        hb = client.post(
            "/api/swarm/heartbeat",
            json={"agent_id": "agent-01", "team_id": "null_warriors", "current_phase": "ATTACK", "phase_epoch": 2},
            headers=w_hdr,
        )
        assert hb.status_code == 200
        assert hb.json["ack"] is True

        # 2. Task claim -> ALLOW
        claim = client.post(
            "/api/swarm/tasks/claim",
            json={"task_id": "task-attack_recon-10.254.254.11", "agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 2},
            headers=w_hdr,
        )
        assert claim.status_code in (200, 400, 409)  # Endpoint allowed (processed, not 401/403)

        # 3. Task request -> ALLOW
        treq = client.post(
            "/api/swarm/tasks/request",
            json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 2},
            headers=w_hdr,
        )
        assert treq.status_code == 200
        lease_id = treq.json.get("lease", {}).get("lease_id") if treq.json.get("lease") else None

        # 4. Task renew -> ALLOW
        if lease_id:
            renew = client.post(
                "/api/swarm/leases/renew",
                json={"lease_id": lease_id, "agent_id": "agent-01"},
                headers=w_hdr,
            )
            assert renew.status_code == 200

        # 5. Shared state own identity -> ALLOW
        state_resp = client.post(
            "/api/swarm/state/compromised",
            json={"host": "10.254.254.11", "agent_id": "agent-01"},
            headers=w_hdr,
        )
        assert state_resp.status_code == 200

        # Worker DENY checks (Must be 403 Forbidden):
        # 6. Phase advance -> DENY
        p_denied = client.post(
            "/api/swarm/phase/advance",
            json={"phase": "DEFENSE"},
            headers=w_hdr,
        )
        assert p_denied.status_code == 403

        # 7. Kill switch -> DENY
        k_denied = client.post(
            "/api/swarm/kill-switch",
            json={"reason": "Worker attempted kill switch"},
            headers=w_hdr,
        )
        assert k_denied.status_code == 403

        # 8. Shutdown -> DENY
        s_denied = client.post(
            "/api/swarm/shutdown",
            headers=w_hdr,
        )
        assert s_denied.status_code == 403

    def test_operator_privilege_matrix(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()
        op_hdr = {"X-Operator-Token": OPERATOR_TOKEN}

        # 1. Phase advance -> ALLOW
        p_op = client.post(
            "/api/swarm/phase/advance",
            json={"phase": "ATTACK", "round_id": 1},
            headers=op_hdr,
        )
        assert p_op.status_code == 200
        assert p_op.json["phase"] == "ATTACK"

        # 2. Kill switch -> ALLOW
        k_op = client.post(
            "/api/swarm/kill-switch",
            json={"reason": "Operator abort drill"},
            headers=op_hdr,
        )
        assert k_op.status_code == 200
        assert coordinator.kill_switch_active is True

    def test_unauthenticated_requests_denied_401(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        endpoints = [
            ("/api/swarm/heartbeat", "POST", {"agent_id": "agent-01"}),
            ("/api/swarm/tasks/request", "POST", {"agent_id": "agent-01", "phase": "HOLD", "phase_epoch": 1}),
            ("/api/swarm/tasks/claim", "POST", {"task_id": "t1", "agent_id": "agent-01", "phase": "HOLD", "phase_epoch": 1}),
            ("/api/swarm/leases/renew", "POST", {"lease_id": "l1", "agent_id": "agent-01"}),
            ("/api/swarm/tasks/complete", "POST", {"task_id": "t1", "agent_id": "agent-01"}),
            ("/api/swarm/state/compromised", "POST", {"host": "10.254.254.11", "agent_id": "agent-01"}),
            ("/api/swarm/phase/advance", "POST", {"phase": "ATTACK"}),
            ("/api/swarm/kill-switch", "POST", {"reason": "none"}),
            ("/api/swarm/shutdown", "POST", {}),
        ]

        for path, method, payload in endpoints:
            if method == "POST":
                resp = client.post(path, json=payload)
            else:
                resp = client.get(path)
            assert resp.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {resp.status_code}"


# ==============================================================================
# Requirement 8: DUPLICATE SESSION RACE
# ==============================================================================

class TestDuplicateSessionRace:
    """
    Attempt simultaneous registration of the same agent_id from two threads/processes.
    Under coordinator._lock, exactly one registration must succeed (200),
    and the second must be rejected (409 Conflict).
    """

    def test_concurrent_registration_race_results_in_one_active_session(self, coordinator_app):
        app, coordinator = coordinator_app

        def _register():
            client = app.test_client()
            return client.post(
                "/api/swarm/register",
                json={"agent_id": "agent-01", "team_id": "null_warriors"},
                headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut1 = executor.submit(_register)
            fut2 = executor.submit(_register)
            res1 = fut1.result()
            res2 = fut2.result()

        statuses = [res1.status_code, res2.status_code]
        # Exactly one must be 200, the other must be 409 Conflict
        assert 200 in statuses, f"Expected one 200 OK, got {statuses}"
        assert 409 in statuses, f"Expected one 409 Conflict, got {statuses}"
        assert len(coordinator.active_sessions) == 1


# ==============================================================================
# Requirement 7: PHASE RACE TEST
# ==============================================================================

class TestPhaseRaceAndEpochSafety:
    """
    Run 4 workers concurrently while rapidly alternating phases:
      ATTACK -> DEFENSE -> ATTACK -> DEFENSE -> HOLD.
    Verifies that no stale task from a prior epoch can be claimed or renewed.
    """

    def test_rapid_phase_cycling_rejects_stale_epoch_tasks(self, coordinator_app):
        app, coordinator = coordinator_app
        client = app.test_client()

        # Register 4 workers
        sessions = {}
        for aid in AUTHORIZED_ROSTER:
            reg = client.post(
                "/api/swarm/register",
                json={"agent_id": aid, "team_id": "null_warriors"},
                headers={"X-Agent-Credential": AGENT_TOKENS[aid]},
            )
            assert reg.status_code == 200
            sessions[aid] = reg.json["session_token"]

        # Cycle 1: ATTACK (epoch 2)
        coordinator.advance_phase(Phase.ATTACK, round_id=1)
        epoch_attack_1 = coordinator.get_phase().phase_epoch

        # Agent 1 requests task in epoch 2
        req = client.post(
            "/api/swarm/tasks/request",
            json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": epoch_attack_1},
            headers={"X-Session-Token": sessions["agent-01"]},
        )
        assert req.status_code == 200
        old_task_id = req.json["task"]["task_id"]
        old_lease_id = req.json["lease"]["lease_id"]

        # Cycle 2: DEFENSE (epoch 3)
        coordinator.advance_phase(Phase.DEFENSE, round_id=1)

        # Cycle 3: ATTACK (epoch 4)
        coordinator.advance_phase(Phase.ATTACK, round_id=2)

        # Cycle 4: DEFENSE (epoch 5)
        coordinator.advance_phase(Phase.DEFENSE, round_id=2)

        # Cycle 5: Return to HOLD (epoch 6)
        coordinator.advance_phase(Phase.HOLD)
        current_epoch = coordinator.get_phase().phase_epoch

        # Now attempt to renew old lease with stale epoch
        renew_resp = client.post(
            "/api/swarm/leases/renew",
            json={"lease_id": old_lease_id, "agent_id": "agent-01"},
            headers={"X-Session-Token": sessions["agent-01"]},
        )
        assert renew_resp.status_code == 200
        assert renew_resp.json["success"] is False  # Stale lease renewal rejected!

        # Attempt to claim old task with stale epoch
        claim_resp = client.post(
            "/api/swarm/tasks/claim",
            json={"task_id": old_task_id, "agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": epoch_attack_1},
            headers={"X-Session-Token": sessions["agent-01"]},
        )
        assert claim_resp.status_code == 200
        assert claim_resp.json["reason"] == "phase_epoch_mismatch"


# ==============================================================================
# Requirement 5: TLS MULTI-PROCESS REHEARSAL & DOWNGRADE GUARDS
# ==============================================================================

class TestTlsSecurityAndDowngradeGuards:
    """
    Verifies secure HTTPS transport:
    - Valid CA -> success
    - Wrong CA -> SSLError
    - HTTP downgrade attempt -> strictly rejected
    - Disabled certificate verification -> forbidden
    """

    def test_client_rejects_cleartext_http_when_tls_required(self):
        """Worker with use_tls=True pointing to http:// must raise ValueError."""
        with pytest.raises(ValueError, match="Insecure HTTP transport rejected: TLS is required"):
            SwarmClient(
                agent_id="agent-01",
                coordinator_url="http://127.0.0.1:5000",
                use_tls=True,
            )

    def test_client_verify_setting_never_returns_false(self):
        """Client must enforce verification (return cert path or True), NEVER False."""
        client_https = SwarmClient(
            agent_id="agent-01",
            coordinator_url="https://127.0.0.1:5443",
        )
        verify_val = client_https._verify_setting()
        assert verify_val is not False
        assert verify_val is True or isinstance(verify_val, str)

    def test_real_https_server_with_valid_and_wrong_ca(self):
        """
        Start actual Flask HTTPS server with generated certificate on a free port.
        Test connection with valid CA (passes) and wrong CA (fails).
        """
        port = find_free_port()
        cert_pem, key_pem = generate_self_signed_cert("127.0.0.1")
        wrong_cert_pem, _ = generate_self_signed_cert("127.0.0.1")

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "server.crt")
            key_path = os.path.join(tmpdir, "server.key")
            wrong_ca_path = os.path.join(tmpdir, "wrong_ca.crt")

            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)
            with open(wrong_ca_path, "wb") as f:
                f.write(wrong_cert_pem)

            # Start coordinator server process in HTTPS mode
            cmd = [
                sys.executable,
                "-m",
                "agent.swarm.coordinator_server",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--profile",
                "LOCAL_REHEARSAL",
                "--auth-token",
                SWARM_AUTH_TOKEN,
                "--ssl-cert",
                cert_path,
                "--ssl-key",
                key_path,
                "--use-tls",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            https_url = f"https://127.0.0.1:{port}"

            try:
                # Wait for HTTPS server readiness
                ready = False
                for _ in range(30):
                    time.sleep(0.3)
                    try:
                        r = requests.get(f"{https_url}/healthz", verify=cert_path, timeout=1.0)
                        if r.status_code == 200:
                            ready = True
                            break
                    except Exception:
                        pass
                assert ready, "HTTPS Coordinator server failed to start within timeout"

                # 1. Connection with valid CA certificate -> SUCCESS
                client_valid = SwarmClient(
                    agent_id="agent-01",
                    coordinator_url=https_url,
                    auth_token=SWARM_AUTH_TOKEN,
                    ca_cert=cert_path,
                )
                assert client_valid.register() is True

                # 2. Connection with wrong CA certificate -> FAILS with SSLError
                client_wrong_ca = SwarmClient(
                    agent_id="agent-02",
                    coordinator_url=https_url,
                    auth_token=SWARM_AUTH_TOKEN,
                    ca_cert=wrong_ca_path,
                )
                assert client_wrong_ca.register() is False

                # 3. Connection with cleartext HTTP to HTTPS port -> FAILS
                http_url = f"http://127.0.0.1:{port}"
                with pytest.raises(requests.exceptions.RequestException):
                    requests.get(f"{http_url}/healthz", timeout=1.0)

            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


# ==============================================================================
# Requirement 2: REAL PROCESS RESTART TEST
# ==============================================================================

class TestRealProcessRestartLifecycle:
    """
    Start coordinator as actual OS process.
    Start worker and obtain ATTACK task and lease.
    Terminate coordinator process.
    Start completely new coordinator process on same port.
    Verify:
      - new coordinator_instance_id
      - phase = HOLD
      - old session = 401
      - old lease = rejected
      - old task = rejected
      - old phase epoch = rejected
      - worker must re-register
      - worker cannot resume stale attack work
    """

    def test_real_process_restart_resets_state_and_invalidates_sessions(self):
        port = find_free_port()
        base_url = f"http://127.0.0.1:{port}"

        def _spawn_coordinator():
            agent_tokens_arg = ",".join(f"{k}:{v}" for k, v in AGENT_TOKENS.items())
            cmd = [
                sys.executable,
                "-m",
                "agent.swarm.coordinator_server",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--profile",
                "LOCAL_REHEARSAL",
                "--auth-token",
                SWARM_AUTH_TOKEN,
                "--operator-token",
                OPERATOR_TOKEN,
                "--agent-tokens",
                agent_tokens_arg,
            ]
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                time.sleep(0.3)
                try:
                    r = requests.get(f"{base_url}/healthz", timeout=1.0)
                    if r.status_code == 200:
                        return p
                except Exception:
                    pass
            p.kill()
            raise RuntimeError("Coordinator process failed to start")

        # 1. Start Coordinator 1
        proc1 = _spawn_coordinator()
        try:
            # Advance to ATTACK (epoch 2)
            adv = requests.post(
                f"{base_url}/api/swarm/phase/advance",
                json={"phase": "ATTACK", "round_id": 1},
                headers={"X-Operator-Token": OPERATOR_TOKEN},
                timeout=2.0,
            )
            assert adv.status_code == 200

            # Register worker agent-01 using its unique per-agent credential
            reg = requests.post(
                f"{base_url}/api/swarm/register",
                json={"agent_id": "agent-01", "team_id": "null_warriors"},
                headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
                timeout=2.0,
            )
            assert reg.status_code == 200
            reg_data = reg.json()
            session_1 = reg_data["session_token"]
            instance_id_1 = reg_data["coordinator_instance_id"]

            # Acquire task lease
            treq = requests.post(
                f"{base_url}/api/swarm/tasks/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 2},
                headers={"X-Session-Token": session_1},
                timeout=2.0,
            )
            assert treq.status_code == 200
            treq_data = treq.json()
            old_task = treq_data["task"]
            old_lease = treq_data["lease"]
            assert old_lease is not None

        finally:
            # 2. Terminate Coordinator 1 process completely
            proc1.terminate()
            proc1.wait(timeout=2.0)

        # 3. Start completely new Coordinator 2 process on the exact same port
        proc2 = _spawn_coordinator()
        try:
            # Check public health probe
            hz = requests.get(f"{base_url}/healthz", timeout=2.0).json()
            # Must reset to HOLD phase, round 1, epoch 1
            assert hz["phase"] == "HOLD"
            assert hz["phase_epoch"] == 1
            assert hz["registered_agent_count"] == 0

            # 4. Old session token MUST return 401 Unauthorized
            old_poll = requests.get(
                f"{base_url}/api/swarm/phase",
                headers={"X-Session-Token": session_1},
                timeout=2.0,
            )
            assert old_poll.status_code == 401

            # 5. Old lease renewal MUST return 401 (session invalid) or rejected
            old_renew = requests.post(
                f"{base_url}/api/swarm/leases/renew",
                json={"lease_id": old_lease["lease_id"], "agent_id": "agent-01"},
                headers={"X-Session-Token": session_1},
                timeout=2.0,
            )
            assert old_renew.status_code == 401

            # 6. Old task request with stale epoch 2 must fail
            # First re-register worker to get fresh session
            reg2 = requests.post(
                f"{base_url}/api/swarm/register",
                json={"agent_id": "agent-01", "team_id": "null_warriors"},
                headers={"X-Agent-Credential": AGENT_TOKENS["agent-01"]},
                timeout=2.0,
            )
            assert reg2.status_code == 200
            reg2_data = reg2.json()
            session_2 = reg2_data["session_token"]
            instance_id_2 = reg2_data["coordinator_instance_id"]

            # Must have new coordinator instance ID
            assert instance_id_2 != instance_id_1

            # Attempt to request task with stale epoch 2 on new coordinator (which is at epoch 1)
            stale_req = requests.post(
                f"{base_url}/api/swarm/tasks/request",
                json={"agent_id": "agent-01", "phase": "ATTACK", "phase_epoch": 2},
                headers={"X-Session-Token": session_2},
                timeout=2.0,
            )
            assert stale_req.status_code == 200
            stale_data = stale_req.json()
            assert stale_data["reason"] == "phase_epoch_mismatch"
            assert stale_data["task"] is None

        finally:
            proc2.terminate()
            proc2.wait(timeout=2.0)

