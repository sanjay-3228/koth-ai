"""Unit tests for the Reconnaissance Agent and Scientific Loop.

Verifies:
1. target allowlist enforcement
2. HTTP tool registration
3. safe-test generation
4. evidence references
5. hypothesis creation
6. failed-approach avoidance
7. conclusion evidence requirements
8. rejection of unregistered targets
9. rejection of arbitrary commands
10. complete observation -> hypothesis -> test -> result workflow
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from agents.recon import (
    ArbitraryCommandError,
    BaseTool,
    HttpProbeTool,
    MockExecutionAdapter,
    PolicyViolationError,
    ReconAgent,
    ReconError,
    ReconPlanner,
    TargetRegistry,
    ToolError,
    ToolRegistry,
    ToolValidationError,
    UnregisteredTargetError,
)
from core.evidence import EvidenceCollector, IntegrityError, SecurityError
from core.schemas import (
    ConclusionStatus,
    HypothesisStatus,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
)
from core.session import ApproachAlreadyFailedError, Session, SessionManager


class TestReconAgent(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.evidence_dir = self.base_dir / "evidence"
        self.sessions_dir = self.base_dir / "sessions"
        self.config_dir = self.base_dir / "config"
        self.targets_dir = self.base_dir / "targets"

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.targets_dir.mkdir(parents=True, exist_ok=True)

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

        self.mock_adapter = MockExecutionAdapter(
            routes={
                "/": {
                    "status": 200,
                    "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/html"},
                    "body": "Welcome to Target 01 Training Site",
                },
                "/robots.txt": {
                    "status": 200,
                    "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
                    "body": "User-agent: *\nDisallow: /admin\nDisallow: /private\n",
                },
                "/admin": {
                    "status": 200,
                    "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/html"},
                    "body": "Admin Panel Active",
                },
                "/private": {
                    "status": 403,
                    "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
                    "body": "403 Forbidden",
                },
            }
        )

    def tearDown(self):
        for p in self.base_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_target_allowlist_enforcement(self):
        """Verify TargetRegistry only permits enabled targets in authoritative config."""
        registry = TargetRegistry(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
        )

        # target-01 is enabled and valid
        target_01 = registry.get_target("target-01")
        self.assertEqual(target_01["id"], "target-01")
        self.assertEqual(target_01["protocol"], "http")
        self.assertEqual(target_01["port"], 8080)
        self.assertTrue(registry.is_target_allowlisted("target-01"))

        # target-disabled is marked enabled: false
        with self.assertRaises(UnregisteredTargetError):
            registry.get_target("target-disabled")
        self.assertFalse(registry.is_target_allowlisted("target-disabled"))

        # Unlisted target is rejected
        with self.assertRaises(UnregisteredTargetError):
            registry.get_target("target-99")
        self.assertFalse(registry.is_target_allowlisted("target-99"))

    def test_2_http_tool_registration(self):
        """Verify HTTP tool is properly registered and enforces strict parameters."""
        registry = ToolRegistry()
        self.assertTrue(registry.has("http_probe"))
        self.assertIn("http_probe", registry.list_tools())

        tool = registry.get("http_probe")
        self.assertIsInstance(tool, HttpProbeTool)

        # Valid parameters
        tool.validate_parameters({"path": "/", "method": "GET"})
        tool.validate_parameters({"path": "/robots.txt", "method": "HEAD", "headers": {"X-Test": "1"}})

        # Rejection of invalid path
        with self.assertRaises(ToolValidationError):
            tool.validate_parameters({"path": "relative-no-slash"})
        with self.assertRaises(ToolValidationError):
            tool.validate_parameters({"path": "/../etc/passwd"})

        # Rejection of non-GET/HEAD method
        with self.assertRaises(ToolValidationError):
            tool.validate_parameters({"path": "/", "method": "POST"})
        with self.assertRaises(ToolValidationError):
            tool.validate_parameters({"path": "/", "method": "DELETE"})

        # Unknown tool lookup fails
        with self.assertRaises(ToolValidationError):
            registry.get("nmap_scan")

    def test_3_safe_test_generation(self):
        """Verify ReconPlanner produces safe, bounded SafeTest objects with justifications."""
        planner = ReconPlanner()
        session = Session("sess-safe-test", "target-01", sessions_dir=self.sessions_dir)
        ev_collector = EvidenceCollector(evidence_dir=self.evidence_dir)
        ev = ev_collector.store_evidence("target_registry", "target-01", {"info": 1})
        obs = session.add_observation("obs-1", ev.evidence_id, "Target online", attributes={"path": "/"})
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Claim /robots.txt exists")

        test_plan = planner.propose_safe_test(
            session=session,
            hypothesis=hyp,
            target_info={"id": "target-01", "port": 8080},
            target_path="/robots.txt",
        )

        self.assertIsNotNone(test_plan)
        self.assertEqual(test_plan["tool"], "http_probe")
        self.assertEqual(test_plan["parameters"], {"path": "/robots.txt", "method": "GET"})
        self.assertIn("read-only", test_plan["safety_justification"].lower())
        self.assertTrue(len(test_plan["expected_outcome"]) > 0)

        # Verify adding to session creates a valid SafeTest object
        safe_test = session.add_safe_test(
            test_id="test-01",
            hypothesis_id=hyp.hypothesis_id,
            tool=test_plan["tool"],
            safety_justification=test_plan["safety_justification"],
            expected_outcome=test_plan["expected_outcome"],
            parameters=test_plan["parameters"],
        )
        self.assertEqual(safe_test.hypothesis_id, hyp.hypothesis_id)
        self.assertEqual(safe_test.parameters["path"], "/robots.txt")

    def test_4_evidence_references(self):
        """Verify probe outputs are immutably captured and referenced solely by hash."""
        agent = ReconAgent(
            target_id="target-01",
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            execution_adapter=self.mock_adapter,
            session_id="session-ev-test",
        )

        step_result = agent.step()
        self.assertIsNotNone(step_result)

        evidence_ref = step_result["evidence_ref"]
        self.assertEqual(len(evidence_ref), 64)

        # Verify evidence exists in collector and matches hash
        ev_record = agent.evidence_collector.get_evidence(evidence_ref)
        self.assertEqual(ev_record.evidence_id, evidence_ref)
        self.assertEqual(ev_record.source_tool, "http_probe")
        self.assertEqual(ev_record.target, "target-01")
        self.assertEqual(ev_record.payload["path"], "/")
        self.assertEqual(ev_record.payload["status_code"], 200)

        # Verify session only contains hash reference
        sess_dict = agent.session.to_dict()
        test_res_dict = sess_dict["test_results"][0]
        self.assertEqual(test_res_dict["evidence_ref"], evidence_ref)
        self.assertNotIn("Welcome to Target 01", json.dumps(test_res_dict))

    def test_5_hypothesis_creation(self):
        """Verify hypotheses are derived strictly from observations with valid lifecycle."""
        agent = ReconAgent(
            target_id="target-01",
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            execution_adapter=self.mock_adapter,
            session_id="session-hyp-test",
        )

        # Initially, baseline observation exists
        self.assertEqual(len(agent.session.observations), 1)
        self.assertEqual(len(agent.session.hypotheses), 0)

        # Step 1: Formulates initial connectivity hypothesis and tests it
        step1 = agent.step()
        self.assertIsNotNone(step1)
        self.assertEqual(len(agent.session.hypotheses), 1)
        hyp1 = agent.session.get_hypothesis(step1["hypothesis_id"])
        self.assertEqual(hyp1.status, HypothesisStatus.VALIDATED.value)
        self.assertIn("obs-target-01-init", hyp1.based_on_observations)

        # Step 2: Proposes robots.txt hypothesis based on root observation
        step2 = agent.step()
        self.assertIsNotNone(step2)
        self.assertEqual(len(agent.session.hypotheses), 2)
        hyp2 = agent.session.get_hypothesis(step2["hypothesis_id"])
        self.assertEqual(hyp2.status, HypothesisStatus.VALIDATED.value)
        self.assertIn("/robots.txt", hyp2.claim)

    def test_6_failed_approach_avoidance(self):
        """Verify failed tests are recorded as negative knowledge and never repeated."""
        # Set route for /robots.txt to 404
        failing_adapter = MockExecutionAdapter(
            routes={
                "/": {"status": 200, "headers": {}, "body": "OK"},
                "/robots.txt": {"status": 404, "headers": {}, "body": "Not Found"},
            }
        )

        agent = ReconAgent(
            target_id="target-01",
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            execution_adapter=failing_adapter,
            session_id="session-fail-avoid",
        )

        # Step 1: probe root -> OK
        step1 = agent.step()
        self.assertEqual(step1["conclusion_status"], ConclusionStatus.VALIDATED.value)

        # Step 2: probe /robots.txt -> returns 404 -> REFUTED
        step2 = agent.step()
        self.assertEqual(step2["conclusion_status"], ConclusionStatus.REFUTED.value)

        # Verify failed_approaches captured /robots.txt
        self.assertEqual(len(agent.session.failed_approaches), 1)
        fa = agent.session.failed_approaches[0]
        self.assertEqual(fa.parameters["path"], "/robots.txt")
        self.assertTrue(agent.session.is_approach_failed("http_probe", {"path": "/robots.txt", "method": "GET"}))

        # Next step: planner must NOT propose /robots.txt again!
        prop = agent.planner.propose_hypothesis(agent.session, agent.target_info)
        # Should not propose robots.txt
        if prop:
            self.assertNotIn("/robots.txt", prop.get("target_path", ""))

        # Attempting to manually plan a safe test with failed parameters is rejected by planner
        hyp_dummy = agent.session.get_hypothesis(step2["hypothesis_id"])
        test_plan = agent.planner.propose_safe_test(
            session=agent.session,
            hypothesis=hyp_dummy,
            target_info=agent.target_info,
            target_path="/robots.txt",
        )
        self.assertIsNone(test_plan)

    def test_7_conclusion_evidence_requirements(self):
        """Verify conclusions cannot be created without valid test results and evidence."""
        session = Session("sess-concl-ev", "target-01", sessions_dir=self.sessions_dir)
        ev_collector = EvidenceCollector(evidence_dir=self.evidence_dir)
        ev = ev_collector.store_evidence("http_probe", "target-01", {"data": 1})
        obs = session.add_observation("obs-1", ev.evidence_id, "Desc")
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Claim")
        test = session.add_safe_test("test-1", "hyp-1", "http_probe", "Justification", "Outcome")

        # Empty result refs must raise ValidationError
        with self.assertRaises(ValidationError):
            session.add_conclusion("concl-fail-1", "hyp-1", [], ConclusionStatus.VALIDATED, "Rationale")

        # Non-existent result ref must raise ValidationError
        with self.assertRaises(ValidationError):
            session.add_conclusion("concl-fail-2", "hyp-1", ["res-fake"], ConclusionStatus.VALIDATED, "Rationale")

        # Record genuine test result with evidence
        ev_test = ev_collector.store_evidence("http_probe", "target-01", {"status_code": 200})
        res = session.record_test_result("res-1", "test-1", ev_test.evidence_id, TestStatus.SUCCESS, "Summary")

        # Valid conclusion succeeds
        concl = session.add_conclusion("concl-ok", "hyp-1", ["res-1"], ConclusionStatus.VALIDATED, "Supported by test")
        self.assertEqual(concl.result_refs, ["res-1"])

    def test_8_rejection_of_unregistered_targets(self):
        """Verify agent initialization rejects any unregistered target."""
        # Target not in config
        with self.assertRaises(UnregisteredTargetError):
            ReconAgent(
                target_id="target-nonexistent",
                targets_config_path=self.targets_file,
                allowlist_path=self.allowlist_file,
                sessions_dir=self.sessions_dir,
                evidence_dir=self.evidence_dir,
            )

        # Disabled target
        with self.assertRaises(UnregisteredTargetError):
            ReconAgent(
                target_id="target-disabled",
                targets_config_path=self.targets_file,
                allowlist_path=self.allowlist_file,
                sessions_dir=self.sessions_dir,
                evidence_dir=self.evidence_dir,
            )

        # Localhost/Loopback attempted target ID
        with self.assertRaises(UnregisteredTargetError):
            ReconAgent(
                target_id="127.0.0.1",
                targets_config_path=self.targets_file,
                allowlist_path=self.allowlist_file,
                sessions_dir=self.sessions_dir,
                evidence_dir=self.evidence_dir,
            )

    def test_9_rejection_of_arbitrary_commands(self):
        """Verify strict rejection of arbitrary commands across agent, adapter, and tool."""
        agent = ReconAgent(
            target_id="target-01",
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            execution_adapter=self.mock_adapter,
        )

        # 1. Agent execute_command must be rejected
        with self.assertRaises(ArbitraryCommandError):
            agent.execute_command(["whoami"])

        # 2. Execution adapter execute_command must be rejected
        with self.assertRaises(ArbitraryCommandError):
            self.mock_adapter.execute_command("cat /etc/passwd")

        # 3. Tool parameter validation rejects command parameters
        tool = agent.tool_registry.get("http_probe")
        with self.assertRaises(ArbitraryCommandError):
            tool.validate_parameters({"path": "/", "cmd": "whoami"})

        with self.assertRaises(ArbitraryCommandError):
            tool.validate_parameters({"path": "/; rm -rf /"})

        with self.assertRaises(ArbitraryCommandError):
            tool.validate_parameters({"path": "/$(cat /etc/passwd)"})

        with self.assertRaises(ArbitraryCommandError):
            tool.validate_parameters({"path": "/", "shell": True})

    def test_10_complete_scientific_workflow(self):
        """Verify complete multi-step scientific loop executes and links all stages."""
        agent = ReconAgent(
            target_id="target-01",
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            execution_adapter=self.mock_adapter,
            session_id="session-e2e-workflow",
        )

        # Run 4 steps:
        # Step 1: probe / -> 200 OK -> Validated
        # Step 2: probe /robots.txt -> 200 OK -> Discovers /admin and /private -> Validated
        # Step 3: probe /admin -> 200 OK -> Validated
        # Step 4: probe /private -> 403 Forbidden -> Refuted
        history = agent.run(max_steps=4)
        self.assertEqual(len(history), 4)

        # Verify Step 1: Root check
        step1 = history[0]
        self.assertEqual(step1["conclusion_status"], ConclusionStatus.VALIDATED.value)
        test1 = agent.session.get_safe_test(step1["test_id"])
        self.assertEqual(test1.parameters["path"], "/")

        # Verify Step 2: robots.txt check
        step2 = history[1]
        self.assertEqual(step2["conclusion_status"], ConclusionStatus.VALIDATED.value)
        test2 = agent.session.get_safe_test(step2["test_id"])
        self.assertEqual(test2.parameters["path"], "/robots.txt")
        self.assertTrue(len(step2["new_observations"]) > 0)

        # Verify Step 3: /admin check
        step3 = history[2]
        self.assertEqual(step3["conclusion_status"], ConclusionStatus.VALIDATED.value)
        test3 = agent.session.get_safe_test(step3["test_id"])
        self.assertEqual(test3.parameters["path"], "/admin")

        # Verify Step 4: /private check
        step4 = history[3]
        self.assertEqual(step4["conclusion_status"], ConclusionStatus.REFUTED.value)
        test4 = agent.session.get_safe_test(step4["test_id"])
        self.assertEqual(test4.parameters["path"], "/private")

        # Verify session was persisted and can be reloaded with full integrity
        reloaded = Session.load("session-e2e-workflow", sessions_dir=self.sessions_dir)
        self.assertEqual(len(reloaded.safe_tests), 4)
        self.assertEqual(len(reloaded.test_results), 4)
        self.assertEqual(len(reloaded.conclusions), 4)
        self.assertEqual(len(reloaded.failed_approaches), 1)
        self.assertEqual(reloaded.failed_approaches[0].parameters["path"], "/private")


if __name__ == "__main__":
    unittest.main()
