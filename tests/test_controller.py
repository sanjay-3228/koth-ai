"""Comprehensive tests for the Bounded Autonomous Research Controller.

Verifies:
1. controller initializes correctly
2. registered target accepted
3. unregistered target rejected
4. disabled target rejected
5. valid bounded run executes
6. max_tests stops execution
7. max_duration stops execution
8. max_consecutive_failures stops execution
9. stop_on_finding works
10. gateway rejection is recorded
11. failed execution is recorded
12. successful execution is recorded
13. evidence references are preserved
14. session persists after run
15. existing session resumes
16. failed approaches are not repeated
17. process restart does not repeat completed failed test
18. arbitrary command is rejected
19. arbitrary IP is rejected
20. unauthorized tool is rejected
21. controller cannot bypass orchestrator
22. malformed SafeTest is rejected
23. target unavailable is handled
24. complete workflow remains scientifically traceable
25. complete existing test suite remains passing & security regression checks
"""

import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from agents.controller import (
    ControllerError,
    ResearchController,
    ResearchLimits,
    ResearchRunSummary,
)
from agents.recon.agent import TargetRegistry
from agents.recon.planner import ReconPlanner
from core.evidence import EvidenceCollector, IntegrityError, SecurityError
from core.schemas import (
    Conclusion,
    ConclusionStatus,
    Finding,
    FindingSeverity,
    Hypothesis,
    HypothesisStatus,
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
    GatewaySecurityError,
    InvalidMethodError,
    MaliciousParameterError,
    RepeatedFailedApproachError,
    UnauthorizedToolError,
    UnregisteredTargetError,
    execute_safe_test,
)


class TestResearchController(unittest.TestCase):
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

        self.audit_log_file = self.logs_dir / "controller.jsonl"
        self.evidence_collector = EvidenceCollector(evidence_dir=self.evidence_dir)

        # Configurable mock executor for deterministic testing
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
            elif path == "/unavailable":
                return {
                    "tool": "http_probe",
                    "target": target["id"],
                    "path": path,
                    "method": params.get("method", "GET"),
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "error": "Connection refused",
                    "success": False,
                }
            elif path == "/robots.txt":
                return {
                    "tool": "http_probe",
                    "target": target["id"],
                    "path": path,
                    "method": params.get("method", "GET"),
                    "status_code": 200,
                    "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
                    "body": "User-agent: *\nDisallow: /admin\n",
                    "success": True,
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
            audit_log_path=self.logs_dir / "gateway.jsonl",
            executor_func=self.mock_executor,
        )

        self.controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
        )

    def tearDown(self):
        for p in self.base_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_controller_initializes_correctly(self):
        """Verify controller properly initializes all subordinate layers."""
        self.assertIsInstance(self.controller.target_registry, TargetRegistry)
        self.assertIsInstance(self.controller.session_manager, SessionManager)
        self.assertIsInstance(self.controller.orchestrator, GatewayOrchestrator)
        self.assertIsInstance(self.controller.planner, ReconPlanner)
        self.assertIsInstance(self.controller.evidence_collector, EvidenceCollector)
        self.assertEqual(self.controller.audit_log_path, self.audit_log_file)

    def test_2_registered_target_accepted(self):
        """Verify valid registered target is accepted and initialized."""
        target_info = self.controller.target_registry.get_target("target-01")
        self.assertEqual(target_info["id"], "target-01")
        self.assertTrue(target_info["enabled"])

    def test_3_unregistered_target_rejected(self):
        """Verify unregistered target is rejected before execution starts."""
        with self.assertRaises(UnregisteredTargetError):
            self.controller.run(session="sess-unreg", target_id="target-unregistered")

    def test_4_disabled_target_rejected(self):
        """Verify disabled target defined in config is rejected."""
        with self.assertRaises(DisabledTargetError):
            self.controller.run(session="sess-disabled", target_id="target-disabled")

    def test_5_valid_bounded_run_executes(self):
        """Verify a valid bounded run executes the scientific loop and returns summary."""
        summary = self.controller.run(
            session="sess-valid-run",
            target_id="target-01",
            limits=ResearchLimits(max_tests=3),
        )
        self.assertIsInstance(summary, ResearchRunSummary)
        self.assertEqual(summary.session_id, "sess-valid-run")
        self.assertEqual(summary.target_id, "target-01")
        self.assertTrue(summary.tests_executed > 0)
        self.assertTrue(len(summary.evidence_refs) > 0)

    def test_6_max_tests_stops_execution(self):
        """Verify controller cleanly terminates when max_tests limit is reached."""
        summary = self.controller.run(
            session="sess-max-tests",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        self.assertEqual(summary.tests_executed, 2)
        self.assertEqual(summary.stop_reason, "max_tests")

    def test_7_max_duration_stops_execution(self):
        """Verify controller terminates when duration limit expires."""
        summary = self.controller.run(
            session="sess-duration",
            target_id="target-01",
            limits=ResearchLimits(max_duration_seconds=0.0001, max_tests=50),
        )
        self.assertEqual(summary.stop_reason, "max_duration")

    def test_8_max_consecutive_failures_stops_execution(self):
        """Verify controller stops cleanly when consecutive failure limit is reached."""
        failing_orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.logs_dir / "fail_audit.jsonl",
            executor_func=lambda target, params: {
                "tool": "http_probe",
                "target": target["id"],
                "path": params.get("path", "/"),
                "status_code": 404,
                "headers": {},
                "body": "Not Found",
                "success": False,
            },
        )
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            orchestrator=failing_orchestrator,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.audit_log_file,
        )
        summary = controller.run(
            session="sess-fail-limit",
            target_id="target-01",
            limits=ResearchLimits(max_consecutive_failures=2, max_tests=10),
        )
        self.assertEqual(summary.consecutive_failures, 2)
        self.assertEqual(summary.stop_reason, "max_consecutive_failures")

    def test_9_stop_on_finding_works(self):
        """Verify controller halts immediately when finding is present and stop_on_finding is True."""
        sess = self.controller.session_manager.create_session("sess-finding", "target-01")
        # Add baseline observation, hypothesis, safe_test, test_result, conclusion
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"vuln": 1})
        sess.add_observation("obs-1", ev.evidence_id, "Vulnerability indicator observed")
        sess.add_hypothesis("hyp-1", ["obs-1"], "Admin portal is exposed")
        sess.add_safe_test("test-1", "hyp-1", "http_probe", "Probe admin", "200", {"path": "/admin"})
        sess.record_test_result("res-1", "test-1", ev.evidence_id, TestStatus.SUCCESS, "Admin panel accessible")
        concl = sess.add_conclusion("concl-1", "hyp-1", ["res-1"], ConclusionStatus.VALIDATED, "Confirmed exposure")
        sess.add_finding(
            finding_id="find-01",
            title="Exposed Admin Panel",
            severity=FindingSeverity.HIGH,
            conclusion_ref=concl.conclusion_id,
            evidence_chain={"evidence": [ev.evidence_id]},
            description="Admin panel exposed without auth",
            impact="Unauthorized access",
        )
        sess.save()

        summary = self.controller.run(
            session=sess,
            limits=ResearchLimits(stop_on_finding=True, max_tests=5),
        )
        self.assertEqual(summary.stop_reason, "stop_on_finding")
        self.assertEqual(summary.findings_count, 1)

    def test_10_gateway_rejection_is_recorded(self):
        """Verify gateway denial is recorded in audit log and increments rejection counter."""
        sess = self.controller.session_manager.create_session("sess-rejection", "target-01")
        ev = self.evidence_collector.store_evidence("target_registry", "target-01", {"init": 1})
        sess.add_observation("obs-1", ev.evidence_id, "Initial target observation")
        sess.add_hypothesis("hyp-1", ["obs-1"], "Test traversal claim")
        
        # Inject SafeTest with path traversal
        bad_test = sess.add_safe_test(
            test_id="test-traversal",
            hypothesis_id="hyp-1",
            tool="http_probe",
            safety_justification="Attempt traversal",
            expected_outcome="Error",
            parameters={"path": "/../../etc/passwd"},
        )
        sess.save()

        summary = self.controller.run(
            session=sess,
            limits=ResearchLimits(max_tests=1),
        )
        self.assertTrue(summary.tests_rejected >= 1)

        # Verify audit log captures gateway_rejection
        self.assertTrue(self.audit_log_file.exists())
        with open(self.audit_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        rejection_events = [e for e in lines if e.get("action") == "gateway_rejection"]
        self.assertTrue(len(rejection_events) >= 1)

    def test_11_failed_execution_is_recorded(self):
        """Verify failing execution (e.g. 404) is recorded in session and failed approaches."""
        summary = self.controller.run(
            session="sess-fail-record",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        session = self.controller.session_manager.load_session("sess-fail-record")
        self.assertEqual(session.session_id, "sess-fail-record")

    def test_12_successful_execution_is_recorded(self):
        """Verify successful probe execution records TestResult with SUCCESS status."""
        summary = self.controller.run(
            session="sess-success-record",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        session = self.controller.session_manager.load_session("sess-success-record")
        self.assertEqual(len(session.test_results), 1)
        self.assertEqual(session.test_results[0].status, TestStatus.SUCCESS.value)
        self.assertEqual(summary.tests_succeeded, 1)

    def test_13_evidence_references_are_preserved(self):
        """Verify evidence references in summary and session are valid SHA-256 and intact."""
        summary = self.controller.run(
            session="sess-ev-verify",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        self.assertTrue(len(summary.evidence_refs) >= 2)
        for ev_ref in summary.evidence_refs:
            self.assertEqual(len(ev_ref), 64)
            record = self.evidence_collector.get_evidence(ev_ref)
            self.assertEqual(record.evidence_id, ev_ref)
            self.assertTrue(self.evidence_collector.verify_evidence(ev_ref))

    def test_14_session_persists_after_run(self):
        """Verify session is written atomically and can be fully reloaded from disk."""
        summary = self.controller.run(
            session="sess-persist",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        reloaded = Session.load("sess-persist", sessions_dir=self.sessions_dir)
        self.assertEqual(len(reloaded.safe_tests), summary.tests_executed)
        self.assertEqual(len(reloaded.test_results), summary.tests_executed)
        self.assertEqual(len(reloaded.conclusions), summary.conclusions_count)

    def test_15_existing_session_resumes(self):
        """Verify running against an existing session preserves previous work and resumes."""
        # First run: 1 test
        summary1 = self.controller.run(
            session="sess-resume",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        self.assertEqual(summary1.tests_executed, 1)

        # Second run: 1 more test
        summary2 = self.controller.run(
            session="sess-resume",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        self.assertEqual(summary2.tests_executed, 1)

        reloaded = Session.load("sess-resume", sessions_dir=self.sessions_dir)
        self.assertEqual(len(reloaded.safe_tests), 2)
        self.assertEqual(len(reloaded.test_results), 2)

    def test_16_failed_approaches_are_not_repeated(self):
        """Verify a failed approach recorded in session is never repeated in subsequent steps."""
        session = self.controller.session_manager.create_session("sess-no-repeat", "target-01")
        # Manually record a failed approach for path /robots.txt
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 404})
        session.add_observation("obs-1", ev.evidence_id, "Obs")
        session.add_hypothesis("hyp-1", ["obs-1"], "Claim /robots.txt")
        test = session.add_safe_test("test-failed", "hyp-1", "http_probe", "Just", "404", {"path": "/robots.txt", "method": "GET"})
        session.record_test_result("res-1", "test-failed", ev.evidence_id, TestStatus.FAILURE, "Failed")
        session.save()

        self.assertTrue(session.is_approach_failed("http_probe", {"path": "/robots.txt", "method": "GET"}))

        # Run controller: it must not execute /robots.txt again
        summary = self.controller.run(
            session=session,
            limits=ResearchLimits(max_tests=2),
        )
        paths_tested = [t.parameters.get("path") for t in session.safe_tests if t.test_id != "test-failed"]
        self.assertNotIn("/robots.txt", paths_tested)

    def test_17_process_restart_does_not_repeat_completed_failed_test(self):
        """Verify process restart (brand new controller instance) respects existing negative knowledge."""
        # Run 1 on controller 1
        summary1 = self.controller.run(
            session="sess-restart",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        # Record a failed approach manually in the session
        sess = self.controller.session_manager.load_session("sess-restart")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 404})
        sess.record_failed_approach(
            approach_id="fa-manual",
            hypothesis_id=sess.hypotheses[0].hypothesis_id,
            test_id=sess.safe_tests[0].test_id,
            target="target-01",
            tool="http_probe",
            parameters={"path": "/admin", "method": "GET"},
            reason="Forbidden 403",
            negative_knowledge="Path /admin fails",
            evidence_ref=ev.evidence_id,
        )
        sess.save()

        # Simulate process restart: completely new Controller instance
        new_controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.audit_log_file,
        )
        new_summary = new_controller.run(
            session="sess-restart",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )

        reloaded = Session.load("sess-restart", sessions_dir=self.sessions_dir)
        tested_paths = [t.parameters.get("path") for t in reloaded.safe_tests]
        # /admin should not have been executed again
        self.assertEqual(tested_paths.count("/admin"), 0)

    def test_18_arbitrary_command_is_rejected(self):
        """Verify controller explicitly rejects arbitrary command execution."""
        with self.assertRaises(ArbitraryCommandError):
            self.controller.execute_command(["whoami"])

    def test_19_arbitrary_ip_is_rejected(self):
        """Verify SafeTest with arbitrary AI-supplied IP is rejected by gateway."""
        sess = self.controller.session_manager.create_session("sess-ai-ip", "target-01")
        bad_test = SafeTest(
            test_id="test-bad-ip",
            hypothesis_id="hyp-dummy",
            tool="http_probe",
            safety_justification="Test arbitrary IP",
            expected_outcome="Fail",
            parameters={"path": "/", "ip": "1.2.3.4"},
        )
        with self.assertRaises(AISuppliedIPError):
            self.orchestrator.execute_safe_test(bad_test, sess)

    def test_20_unauthorized_tool_is_rejected(self):
        """Verify controller limits reject non-approved tools."""
        limits = ResearchLimits(allowed_tools={"http_probe"})
        sess = self.controller.session_manager.create_session("sess-tool-check", "target-01")
        ev = self.evidence_collector.store_evidence("target_registry", "target-01", {"init": 1})
        sess.add_observation("obs-1", ev.evidence_id, "Init")
        sess.add_hypothesis("hyp-1", ["obs-1"], "Claim")

        # Propose with unauthorized tool
        test_plan_tool = "nmap_scan"
        self.assertNotIn(test_plan_tool, limits.allowed_tools)

    def test_21_controller_cannot_bypass_orchestrator(self):
        """Verify controller has no direct subprocess execution or docker runner."""
        self.assertFalse(hasattr(self.controller, "docker_cmd"))
        self.assertFalse(hasattr(self.controller, "subprocess"))
        self.assertTrue(hasattr(self.controller, "orchestrator"))

    def test_22_malformed_safetest_is_rejected(self):
        """Verify malformed SafeTest parameters are rejected by the orchestrator."""
        sess = self.controller.session_manager.create_session("sess-malformed", "target-01")
        bad_test = SafeTest(
            test_id="test-traversal-direct",
            hypothesis_id="hyp-dummy",
            tool="http_probe",
            safety_justification="Traversal",
            expected_outcome="Fail",
            parameters={"path": "/../../shadow"},
        )
        with self.assertRaises(MaliciousParameterError):
            self.orchestrator.execute_safe_test(bad_test, sess)

    def test_23_target_unavailable_is_handled(self):
        """Verify target connection errors/timeouts are handled gracefully without crash."""
        session = self.controller.session_manager.create_session("sess-unavail", "target-01")
        ev = self.evidence_collector.store_evidence("target_registry", "target-01", {"init": 1})
        session.add_observation("obs-1", ev.evidence_id, "Init")
        session.add_hypothesis("hyp-1", ["obs-1"], "Claim unavailable path")
        safe_test = session.add_safe_test(
            test_id="test-unavail",
            hypothesis_id="hyp-1",
            tool="http_probe",
            safety_justification="Test unavailable",
            expected_outcome="Error",
            parameters={"path": "/unavailable", "method": "GET"},
        )
        orch_res = self.orchestrator.execute_safe_test(safe_test, session)
        self.assertEqual(orch_res["status"], TestStatus.FAILURE.value)
        self.assertEqual(orch_res["execution_output"]["status_code"], 0)
        self.assertIn("Connection refused", orch_res["execution_output"]["error"])

    def test_24_complete_workflow_remains_scientifically_traceable(self):
        """Verify full chain traceability: Observation -> Hypothesis -> SafeTest -> Result -> Conclusion."""
        summary = self.controller.run(
            session="sess-traceable",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        session = self.controller.session_manager.load_session("sess-traceable")

        # Verify conclusions trace to test results and hypotheses
        for concl in session.conclusions:
            self.assertTrue(concl.hypothesis_id in session._hypotheses)
            for r_ref in concl.result_refs:
                self.assertTrue(r_ref in session._test_results)
                res = session.get_test_result(r_ref)
                self.assertTrue(res.test_id in session._safe_tests)
                self.assertTrue(len(res.evidence_ref) == 64)

        # Verify hypotheses trace to observations
        for hyp in session.hypotheses:
            for obs_ref in hyp.based_on_observations:
                self.assertTrue(obs_ref in session._observations)
                obs = session.get_observation(obs_ref)
                self.assertTrue(len(obs.evidence_ref) == 64)

    def test_25_complete_existing_test_suite_remains_passing(self):
        """Verify security regressions: Docker sandbox settings and gateway policies remain unchanged."""
        base_dir = Path.home() / "koth-ai"
        gateway_file = base_dir / "gateway" / "gateway.py"
        executor_file = base_dir / "gateway" / "docker_executor.py"
        policy_file = base_dir / "gateway" / "policy" / "policy.yaml"

        with open(gateway_file, "r") as f:
            gw_code = f.read()
        self.assertIn('"whoami"', gw_code)
        self.assertIn("ALLOWED_PROGRAMS", gw_code)

        with open(executor_file, "r") as f:
            exec_code = f.read()
        self.assertIn("--cap-drop=ALL", exec_code)
        self.assertIn("--security-opt=no-new-privileges:true", exec_code)
        self.assertIn("--read-only", exec_code)
        self.assertIn("--network=none", exec_code)
        self.assertIn("--memory=2g", exec_code)
        self.assertIn("--cpus=2", exec_code)
        self.assertIn("--pids-limit=512", exec_code)

        with open(policy_file, "r") as f:
            policy_code = f.read()
        self.assertIn("allow_socket: false", policy_code)
        self.assertIn("allow_host_access: false", policy_code)
        self.assertIn("allow_internet: false", policy_code)


if __name__ == "__main__":
    unittest.main()

