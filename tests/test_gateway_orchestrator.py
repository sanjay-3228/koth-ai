"""Comprehensive tests for the Controlled Gateway Orchestrator.

Verifies:
1. valid SafeTest reaches the gateway
2. unregistered target is rejected
3. disabled target is rejected
4. unauthorized tool is rejected
5. invalid HTTP method is rejected
6. malicious/path-traversal parameters are rejected
7. arbitrary command payload is rejected
8. AI-supplied arbitrary IP is rejected
9. successful execution produces evidence
10. failed execution produces evidence
11. session receives TestResult
12. failed approach is recorded
13. repeated failed approach is rejected
14. audit logging occurs
15. gateway security controls remain unchanged
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from core.evidence import EvidenceCollector, IntegrityError, SecurityError
from core.schemas import (
    ConclusionStatus,
    Hypothesis,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
)
from core.session import ApproachAlreadyFailedError, Session, SessionManager
from gateway.orchestrator import (
    AISuppliedIPError,
    ArbitraryCommandError,
    DisabledTargetError,
    GatewayOrchestrator,
    GatewayOrchestratorError,
    GatewaySecurityError,
    InvalidMethodError,
    MaliciousParameterError,
    OrchestratedExecutionAdapter,
    OrchestratorValidationError,
    RepeatedFailedApproachError,
    UnauthorizedToolError,
    UnregisteredTargetError,
    execute_safe_test,
)


class TestGatewayOrchestration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.evidence_dir = self.base_dir / "evidence"
        self.sessions_dir = self.base_dir / "sessions"
        self.config_dir = self.base_dir / "config"
        self.targets_dir = self.base_dir / "targets"
        self.logs_dir = self.base_dir / "logs"

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        # Setup targets.yaml
        self.targets_file = self.config_dir / "targets.yaml"
        self.targets_data = {
            "version": 1,
            "network": "koth-lab",
            "targets": [
                {
                    "id": "target-01",
                    "container": "koth-target-01",
                    "protocol": "http",
                    "port": 8080,
                    "enabled": True,
                    "ip": "172.28.0.10",
                },
                {
                    "id": "target-disabled",
                    "container": "koth-target-disabled",
                    "protocol": "http",
                    "port": 8080,
                    "enabled": False,
                    "ip": "172.28.0.20",
                },
            ],
        }
        with open(self.targets_file, "w") as f:
            json.dump(self.targets_data, f)

        # Setup allowlist.yaml
        self.allowlist_file = self.targets_dir / "allowlist.yaml"
        self.allowlist_data = {
            "version": 1,
            "mode": "authorized-lab-only",
            "targets": ["target-01"],
            "blocked_networks": ["127.0.0.0/8", "169.254.0.0/16"],
            "host_access": {"allowed": False},
            "internet_access": {"allowed": False},
        }
        with open(self.allowlist_file, "w") as f:
            json.dump(self.allowlist_data, f)

        # Setup audit log
        self.audit_log_file = self.logs_dir / "gateway.jsonl"

        self.evidence_collector = EvidenceCollector(evidence_dir=self.evidence_dir)

        # Mock executor returning configurable results
        def mock_executor(target, params):
            path = params.get("path", "/")
            if path == "/fail":
                return {
                    "tool": "http_probe",
                    "target": target["id"],
                    "path": path,
                    "method": params.get("method", "GET"),
                    "status_code": 404,
                    "headers": {"Server": "BaseHTTP/0.6"},
                    "body": "Not Found",
                    "success": False,
                }
            return {
                "tool": "http_probe",
                "target": target["id"],
                "path": path,
                "method": params.get("method", "GET"),
                "status_code": 200,
                "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/html"},
                "body": f"Hello from {target['id']}",
                "success": True,
            }

        self.mock_executor = mock_executor
        self.orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.audit_log_file,
            executor_func=self.mock_executor,
        )

    def tearDown(self):
        for p in self.base_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def _create_test_session(self, target_id="target-01"):
        session = Session(
            session_id=f"sess-{target_id}",
            active_target=target_id,
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )
        ev = self.evidence_collector.store_evidence("http_probe", target_id, {"init": 1})
        session.add_observation("obs-init", ev.evidence_id, "Initial observation")
        session.add_hypothesis("hyp-init", ["obs-init"], "Service is accessible")
        return session

    def test_1_valid_safe_test_reaches_gateway(self):
        """Verify valid SafeTest reaches gateway, executes, and returns allowed result."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-01",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Read-only GET to root",
            expected_outcome="HTTP 200",
            parameters={"path": "/", "method": "GET"},
        )

        result = self.orchestrator.execute_safe_test(safe_test, session)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["test_id"], "test-01")
        self.assertEqual(result["status"], TestStatus.SUCCESS.value)
        self.assertEqual(result["target"], "target-01")
        self.assertEqual(result["execution_output"]["status_code"], 200)

    def test_2_unregistered_target_is_rejected(self):
        """Verify gateway independently validates and rejects unregistered targets."""
        session = self._create_test_session("target-01")
        session.active_target = "target-unknown"
        safe_test = SafeTest(
            test_id="test-unreg",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Check unknown",
            expected_outcome="200",
            parameters={"path": "/"},
        )

        with self.assertRaises(UnregisteredTargetError):
            self.orchestrator.execute_safe_test(safe_test, session)

    def test_3_disabled_target_is_rejected(self):
        """Verify gateway rejects disabled targets defined in config."""
        session = self._create_test_session("target-01")
        session.active_target = "target-disabled"
        safe_test = SafeTest(
            test_id="test-disabled",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Check disabled",
            expected_outcome="200",
            parameters={"path": "/"},
        )

        with self.assertRaises(DisabledTargetError):
            self.orchestrator.execute_safe_test(safe_test, session)

    def test_4_unauthorized_tool_is_rejected(self):
        """Verify tools other than http_probe are rejected by gateway policy."""
        session = self._create_test_session("target-01")
        safe_test = SafeTest(
            test_id="test-nmap",
            hypothesis_id="hyp-init",
            tool="nmap_scan",
            safety_justification="Scan ports",
            expected_outcome="Ports",
            parameters={"path": "/"},
        )

        with self.assertRaises(UnauthorizedToolError):
            self.orchestrator.execute_safe_test(safe_test, session)

    def test_5_invalid_http_method_is_rejected(self):
        """Verify non-whitelisted HTTP methods (POST, PUT, DELETE) are rejected."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-post",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Post attempt",
            expected_outcome="200",
            parameters={"path": "/", "method": "POST"},
        )

        with self.assertRaises(InvalidMethodError):
            self.orchestrator.execute_safe_test(safe_test, session)

    def test_6_malicious_path_traversal_parameters_are_rejected(self):
        """Verify path traversal (..) and shell metacharacters in path are rejected."""
        session = self._create_test_session("target-01")
        # Path traversal
        safe_test_trav = SafeTest(
            test_id="test-trav",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Traversal",
            expected_outcome="Error",
            parameters={"path": "/../../etc/passwd"},
        )
        with self.assertRaises(MaliciousParameterError):
            self.orchestrator.execute_safe_test(safe_test_trav, session)

        # Shell injection characters
        safe_test_inject = SafeTest(
            test_id="test-inject",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Inject",
            expected_outcome="Error",
            parameters={"path": "/; id"},
        )
        with self.assertRaises(MaliciousParameterError):
            self.orchestrator.execute_safe_test(safe_test_inject, session)

    def test_7_arbitrary_command_payload_is_rejected(self):
        """Verify arbitrary command payloads and unrecognized parameters are rejected."""
        session = self._create_test_session("target-01")
        safe_test_cmd = SafeTest(
            test_id="test-cmd",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Cmd test",
            expected_outcome="None",
            parameters={"path": "/", "cmd": "whoami"},
        )
        with self.assertRaises(ArbitraryCommandError):
            self.orchestrator.execute_safe_test(safe_test_cmd, session)

        safe_test_extra = SafeTest(
            test_id="test-extra",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Extra test",
            expected_outcome="None",
            parameters={"path": "/", "arbitrary_arg": "value"},
        )
        with self.assertRaises(ArbitraryCommandError):
            self.orchestrator.execute_safe_test(safe_test_extra, session)

    def test_8_ai_supplied_arbitrary_ip_is_rejected(self):
        """Verify AI-supplied IP/host overrides are strictly rejected."""
        session = self._create_test_session("target-01")
        safe_test_ip = SafeTest(
            test_id="test-ai-ip",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="AI supplied IP",
            expected_outcome="None",
            parameters={"path": "/", "ip": "8.8.8.8"},
        )
        with self.assertRaises(AISuppliedIPError):
            self.orchestrator.execute_safe_test(safe_test_ip, session)

        safe_test_host = SafeTest(
            test_id="test-ai-host",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="AI supplied host",
            expected_outcome="None",
            parameters={"path": "/", "host": "evil.com"},
        )
        with self.assertRaises(AISuppliedIPError):
            self.orchestrator.execute_safe_test(safe_test_host, session)

    def test_9_successful_execution_produces_evidence(self):
        """Verify successful execution creates immutable evidence record with matching hash."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-success-ev",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Root probe",
            expected_outcome="200 OK",
            parameters={"path": "/", "method": "GET"},
        )

        result = self.orchestrator.execute_safe_test(safe_test, session)
        evidence_id = result["evidence_id"]
        self.assertEqual(len(evidence_id), 64)

        # Retrieve evidence from EvidenceCollector
        record = self.evidence_collector.get_evidence(evidence_id)
        self.assertEqual(record.evidence_id, evidence_id)
        self.assertEqual(record.source_tool, "http_probe")
        self.assertEqual(record.target, "target-01")
        self.assertEqual(record.payload["status_code"], 200)

        # Check read-only permission (0444)
        raw_file = self.evidence_dir / "raw" / f"{evidence_id}.json"
        self.assertTrue(raw_file.exists())
        self.assertEqual(raw_file.stat().st_mode & 0o777, 0o444)

    def test_10_failed_execution_produces_evidence(self):
        """Verify failed/404 execution still produces an immutable evidence record."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-fail-ev",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Failing probe",
            expected_outcome="404 Not Found",
            parameters={"path": "/fail", "method": "GET"},
        )

        result = self.orchestrator.execute_safe_test(safe_test, session)
        self.assertEqual(result["status"], TestStatus.FAILURE.value)
        evidence_id = result["evidence_id"]

        record = self.evidence_collector.get_evidence(evidence_id)
        self.assertEqual(record.payload["status_code"], 404)
        self.assertFalse(record.payload["success"])

    def test_11_session_receives_test_result(self):
        """Verify session receives and persists the TestResult linked to evidence."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-res-check",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Result check",
            expected_outcome="200",
            parameters={"path": "/"},
        )

        result = self.orchestrator.execute_safe_test(safe_test, session)
        self.assertEqual(len(session.test_results), 1)
        test_res = session.test_results[0]
        self.assertEqual(test_res.test_id, "test-res-check")
        self.assertEqual(test_res.evidence_ref, result["evidence_id"])
        self.assertEqual(test_res.status, TestStatus.SUCCESS.value)

    def test_12_failed_approach_is_recorded(self):
        """Verify failed test is automatically recorded as negative knowledge in session."""
        session = self._create_test_session("target-01")
        safe_test = session.add_safe_test(
            test_id="test-record-fail",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Probe /fail",
            expected_outcome="200",
            parameters={"path": "/fail", "method": "GET"},
        )

        result = self.orchestrator.execute_safe_test(safe_test, session)
        self.assertEqual(result["status"], TestStatus.FAILURE.value)

        self.assertEqual(len(session.failed_approaches), 1)
        fa = session.failed_approaches[0]
        self.assertEqual(fa.tool, "http_probe")
        self.assertEqual(fa.parameters, {"path": "/fail", "method": "GET"})
        self.assertTrue(session.is_approach_failed("http_probe", {"path": "/fail", "method": "GET"}))

    def test_13_repeated_failed_approach_is_rejected(self):
        """Verify orchestrator prevents accidental repeated execution of failed approach."""
        session = self._create_test_session("target-01")
        safe_test1 = session.add_safe_test(
            test_id="test-fail-1",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="First try",
            expected_outcome="200",
            parameters={"path": "/fail", "method": "GET"},
        )
        self.orchestrator.execute_safe_test(safe_test1, session)

        # Attempt to run another safe test with the same tool and parameters
        safe_test2 = SafeTest(
            test_id="test-fail-repeat",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Repeated try",
            expected_outcome="200",
            parameters={"path": "/fail", "method": "GET"},
        )
        with self.assertRaises(RepeatedFailedApproachError):
            self.orchestrator.execute_safe_test(safe_test2, session)

    def test_14_audit_logging_occurs(self):
        """Verify requests, results, and denials are logged to gateway audit log."""
        session = self._create_test_session("target-01")

        # 1. Allowed execution
        safe_test = session.add_safe_test(
            test_id="test-audit-ok",
            hypothesis_id="hyp-init",
            tool="http_probe",
            safety_justification="Audit check",
            expected_outcome="200",
            parameters={"path": "/"},
        )
        self.orchestrator.execute_safe_test(safe_test, session)

        # 2. Denied execution
        bad_test = SafeTest(
            test_id="test-audit-denied",
            hypothesis_id="hyp-init",
            tool="nmap_scan",
            safety_justification="Bad tool",
            expected_outcome="None",
            parameters={"path": "/"},
        )
        try:
            self.orchestrator.execute_safe_test(bad_test, session)
        except UnauthorizedToolError:
            pass

        # Read audit log
        self.assertTrue(self.audit_log_file.exists())
        with open(self.audit_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        events = [entry.get("event") for entry in lines]
        self.assertIn("request", events)
        self.assertIn("result", events)
        self.assertIn("orchestrator_denied", events)

    def test_15_gateway_security_controls_remain_unchanged(self):
        """Verify original gateway policy, allowed programs, and docker executor remain unchanged."""
        base_dir = Path.home() / "koth-ai"
        gateway_file = base_dir / "gateway" / "gateway.py"
        executor_file = base_dir / "gateway" / "docker_executor.py"
        policy_file = base_dir / "gateway" / "policy" / "policy.yaml"

        self.assertTrue(gateway_file.exists())
        self.assertTrue(executor_file.exists())
        self.assertTrue(policy_file.exists())

        # Verify gateway.py ALLOWED_PROGRAMS
        with open(gateway_file, "r", encoding="utf-8") as f:
            gateway_code = f.read()
        self.assertIn('"whoami"', gateway_code)
        self.assertIn('"ls"', gateway_code)
        self.assertIn('ALLOWED_PROGRAMS', gateway_code)
        self.assertIn('"sudo"', gateway_code)

        # Verify docker_executor.py options
        with open(executor_file, "r", encoding="utf-8") as f:
            executor_code = f.read()
        self.assertIn('--read-only', executor_code)
        self.assertIn('--cap-drop=ALL', executor_code)
        self.assertIn('--security-opt=no-new-privileges:true', executor_code)
        self.assertIn('--network=none', executor_code)

        # Verify policy.yaml settings
        with open(policy_file, "r", encoding="utf-8") as f:
            policy_content = f.read()
        self.assertIn('require_allowlisted_target: true', policy_content)
        self.assertIn('allow_host_access: false', policy_content)
        self.assertIn('allow_internet: false', policy_content)
        self.assertIn('allow_socket: false', policy_content)


if __name__ == "__main__":
    unittest.main()
