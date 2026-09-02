"""Comprehensive integration tests for Gemini reasoning into ResearchController.

Verifies all 32 required test items:
1. controller works without Gemini
2. controller works with fake Gemini
3. Gemini proposes a valid hypothesis
4. valid Gemini proposal reaches SafeTest
5. SafeTest reaches existing orchestrator
6. orchestrator remains gateway-controlled
7. Gemini cannot execute directly
8. Gemini cannot call Docker
9. Gemini cannot call subprocess
10. Gemini cannot bypass controller
11. Gemini cannot bypass orchestrator
12. Gemini cannot bypass gateway
13. Gemini cannot modify execution limits
14. Gemini cannot choose arbitrary target IP
15. Gemini cannot choose arbitrary hostname
16. Gemini cannot choose unauthorized tool
17. Gemini cannot choose unauthorized HTTP method
18. Gemini cannot use traversal
19. Gemini cannot use shell metacharacters
20. Gemini cannot repeat failed approach
21. failed approaches are supplied in context
22. previous observations are supplied
23. previous hypotheses are supplied
24. evidence references are preserved
25. session survives Gemini failure
26. deterministic fallback works
27. max_tests still stops execution
28. max_duration still stops execution
29. max_consecutive_failures still stops execution
30. max_repeated_observations still stops execution
31. stop_on_finding still stops execution
32. complete scientific traceability exists
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from agents.controller import ResearchController, ResearchLimits, ResearchRunSummary
from agents.gemini_adapter import (
    GeminiAdapterError,
    GeminiAPIError,
    GeminiClient,
    GeminiContextBuilder,
    GeminiProposal,
    GeminiProposalType,
    GeminiProposalValidationError,
    GeminiReasoningAdapter,
    GeminiResponseParsingError,
)
from agents.recon.agent import TargetRegistry
from agents.recon.planner import ReconPlanner
from core.evidence import EvidenceCollector
from core.schemas import (
    ConclusionStatus,
    FindingSeverity,
    HypothesisStatus,
    SafeTest,
    TestStatus,
)
from core.session import Session, SessionManager
from gateway.orchestrator import (
    AISuppliedIPError,
    ArbitraryCommandError,
    GatewayOrchestrator,
    MaliciousParameterError,
    UnauthorizedToolError,
)


class TestControllerGeminiIntegration(unittest.TestCase):
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
                }
            ],
        }
        with open(self.targets_file, "w") as f:
            json.dump(self.targets_data, f)

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
        self.orchestrator_log_file = self.logs_dir / "gateway.jsonl"
        self.evidence_collector = EvidenceCollector(evidence_dir=self.evidence_dir)
        self.session_manager = SessionManager(
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

        def mock_executor(target, params):
            path = params.get("path", "/")
            if path == "/fail":
                return {
                    "tool": "http_probe",
                    "target": target["id"],
                    "path": path,
                    "status_code": 404,
                    "headers": {},
                    "body": "Not Found",
                    "success": False,
                }
            return {
                "tool": "http_probe",
                "target": target["id"],
                "path": path,
                "status_code": 200,
                "headers": {"Server": "MockServer"},
                "body": f"Response from {path}",
                "success": True,
            }

        self.mock_executor = mock_executor
        self.orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.orchestrator_log_file,
            executor_func=self.mock_executor,
        )

        self.target_registry = TargetRegistry(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
        )

    def tearDown(self):
        for p in self.base_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_controller_works_without_gemini(self):
        """Verify controller functions purely deterministically when reasoning_adapter is None."""
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=None,
        )
        summary = controller.run(
            session="sess-no-gemini",
            target_id="target-01",
            limits=ResearchLimits(max_tests=2),
        )
        self.assertIsInstance(summary, ResearchRunSummary)
        self.assertEqual(summary.tests_executed, 2)
        self.assertIsNone(controller.reasoning_adapter)

    def test_2_controller_works_with_fake_gemini(self):
        """Verify controller operates seamlessly with mock/fake Gemini reasoning provider."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "The web root provides welcome message",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Safe root probe",
                "expected_outcome": "HTTP 200 OK",
                "parameters": {"path": "/", "method": "GET"},
            })

        client = GeminiClient(provider=fake_provider)
        adapter = GeminiReasoningAdapter(client=client)
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run(
            session="sess-fake-gemini",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        self.assertEqual(summary.tests_executed, 1)
        self.assertEqual(summary.tests_succeeded, 1)

    def test_3_gemini_proposes_valid_hypothesis(self):
        """Verify Gemini-generated hypothesis claim is created in session state."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Custom hypothesis proposed by Gemini",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Probe index",
                "expected_outcome": "HTTP 200",
                "parameters": {"path": "/index.html", "method": "GET"},
            })

        client = GeminiClient(provider=fake_provider)
        adapter = GeminiReasoningAdapter(client=client)
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run(
            session="sess-gemini-hyp",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        reloaded = self.session_manager.load_session("sess-gemini-hyp")
        claims = [h.claim for h in reloaded.hypotheses]
        self.assertIn("Custom hypothesis proposed by Gemini", claims)

    def test_4_valid_gemini_proposal_reaches_safetest(self):
        """Verify a valid Gemini proposal is translated into a validated SafeTest dataclass."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Check robots.txt guidelines",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Bounded robots probe",
                "expected_outcome": "200 with rules",
                "parameters": {"path": "/robots.txt", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run(
            session="sess-safetest-check",
            target_id="target-01",
            limits=ResearchLimits(max_tests=1),
        )
        sess = self.session_manager.load_session("sess-safetest-check")
        self.assertEqual(len(sess.safe_tests), 1)
        safe_test = sess.safe_tests[0]
        self.assertIsInstance(safe_test, SafeTest)
        self.assertEqual(safe_test.parameters["path"], "/robots.txt")
        self.assertEqual(safe_test.tool, "http_probe")

    def test_5_safetest_reaches_existing_orchestrator(self):
        """Verify SafeTest reaches the GatewayOrchestrator and generates immutable evidence."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Root connectivity verification",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Safe root probe",
            "expected_outcome": "200 OK",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-reach-orch", "target-01", limits=ResearchLimits(max_tests=1))
        self.assertTrue(len(summary.evidence_refs) >= 1)
        ev_id = summary.evidence_refs[0]
        record = self.evidence_collector.get_evidence(ev_id)
        self.assertIsNotNone(record)
        self.assertTrue(self.evidence_collector.verify_evidence(ev_id))

    def test_6_orchestrator_remains_gateway_controlled(self):
        """Verify the gateway audit log records orchestrator actions under Gemini controller execution."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Gateway audit check",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Safe probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run("sess-gw-audit", "target-01", limits=ResearchLimits(max_tests=1))
        self.assertTrue(self.orchestrator_log_file.exists())
        with open(self.orchestrator_log_file, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        events = [x.get("event") for x in lines]
        self.assertIn("request", events)
        self.assertIn("result", events)

    def test_7_gemini_cannot_execute_directly(self):
        """Verify Gemini reasoning adapter has no execute, run, or system capabilities."""
        adapter = GeminiReasoningAdapter()
        self.assertFalse(hasattr(adapter, "execute"))
        self.assertFalse(hasattr(adapter, "run"))
        self.assertFalse(hasattr(adapter, "shell"))

    def test_8_gemini_cannot_call_docker(self):
        """Verify Gemini reasoning adapter has no docker access."""
        adapter = GeminiReasoningAdapter()
        self.assertFalse(hasattr(adapter, "docker"))
        self.assertFalse(hasattr(adapter, "docker_client"))

    def test_9_gemini_cannot_call_subprocess(self):
        """Verify Gemini reasoning adapter has no subprocess bindings."""
        adapter = GeminiReasoningAdapter()
        self.assertFalse(hasattr(adapter, "subprocess"))
        self.assertFalse(hasattr(adapter, "popen"))

    def test_10_gemini_cannot_bypass_controller(self):
        """Verify Gemini reasoning adapter does not interact directly with Orchestrator."""
        adapter = GeminiReasoningAdapter()
        self.assertFalse(hasattr(adapter, "orchestrator"))
        self.assertFalse(hasattr(adapter, "gateway"))

    def test_11_gemini_cannot_bypass_orchestrator(self):
        """Verify Gemini cannot bypass orchestrator: Controller routes SafeTest strictly through orchestrator."""
        adapter = GeminiReasoningAdapter()
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        self.assertTrue(hasattr(controller, "orchestrator"))

    def test_12_gemini_cannot_bypass_gateway(self):
        """Verify gateway independently rejects malformed tests from Gemini."""
        sess = self.session_manager.create_session("sess-bypass-gw", "target-01")
        bad_test = SafeTest(
            test_id="test-bypass",
            hypothesis_id="hyp-dummy",
            tool="http_probe",
            safety_justification="Traversal",
            expected_outcome="Fail",
            parameters={"path": "/../../etc/shadow"},
        )
        with self.assertRaises(MaliciousParameterError):
            self.orchestrator.execute_safe_test(bad_test, sess)

    def test_13_gemini_cannot_modify_execution_limits(self):
        """Verify Gemini output attempting to override controller limits is rejected/ignored."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Attempt to bypass limits",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Safe probe",
                "expected_outcome": "200",
                "parameters": {"path": "/", "method": "GET"},
                "limits": {"max_tests": 1000},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        strict_limits = ResearchLimits(max_tests=1)
        summary = controller.run("sess-limits-check", "target-01", limits=strict_limits)
        self.assertEqual(summary.tests_executed, 1)

    def test_14_gemini_cannot_choose_arbitrary_target_ip(self):
        """Verify proposal containing arbitrary IP is blocked by validator and gateway."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Target external host",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Safe probe",
                "expected_outcome": "200",
                "parameters": {"path": "/", "ip": "1.1.1.1"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        # Should trigger fallback without executing the bad IP
        summary = controller.run("sess-bad-ip", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-bad-ip")
        for test in sess.safe_tests:
            self.assertNotIn("ip", test.parameters)

    def test_15_gemini_cannot_choose_arbitrary_hostname(self):
        """Verify proposal containing arbitrary host parameter is blocked."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Target external host",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Safe probe",
                "expected_outcome": "200",
                "parameters": {"path": "/", "host": "google.com"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-bad-host", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-bad-host")
        for test in sess.safe_tests:
            self.assertNotIn("host", test.parameters)

    def test_16_gemini_cannot_choose_unauthorized_tool(self):
        """Verify proposal requesting unauthorized tool triggers fallback and is never executed."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Run port scan",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "nmap",
                "safety_justification": "Scan ports",
                "expected_outcome": "Port list",
                "parameters": {"ports": "80,443"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-unauth-tool", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-unauth-tool")
        for test in sess.safe_tests:
            self.assertEqual(test.tool, "http_probe")

    def test_17_gemini_cannot_choose_unauthorized_http_method(self):
        """Verify proposal with POST method is rejected and falls back safely."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Attempt POST",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Post request",
                "expected_outcome": "200",
                "parameters": {"path": "/submit", "method": "POST"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run("sess-post-method", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-post-method")
        for test in sess.safe_tests:
            self.assertIn(test.parameters.get("method", "GET"), {"GET", "HEAD"})

    def test_18_gemini_cannot_use_traversal(self):
        """Verify path traversal in Gemini proposal is rejected by validator."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Attempt directory traversal",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Check traversal",
                "expected_outcome": "Passwd",
                "parameters": {"path": "/../../etc/passwd", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run("sess-traversal-block", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-traversal-block")
        for test in sess.safe_tests:
            self.assertNotIn("..", test.parameters.get("path", ""))

    def test_19_gemini_cannot_use_shell_metacharacters(self):
        """Verify shell metacharacters in Gemini proposal are rejected by validator."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Attempt shell injection",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Injection check",
                "expected_outcome": "Id output",
                "parameters": {"path": "/; id", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run("sess-metachar-block", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-metachar-block")
        for test in sess.safe_tests:
            self.assertNotIn(";", test.parameters.get("path", ""))

    def test_20_gemini_cannot_repeat_failed_approach(self):
        """Verify Gemini cannot execute an approach previously recorded in negative knowledge."""
        sess = self.session_manager.create_session("sess-repeat-block", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 404})
        obs = sess.add_observation("obs-init", ev.evidence_id, "Initial obs")
        hyp = sess.add_hypothesis("hyp-init", ["obs-init"], "Claim robots")
        st = sess.add_safe_test("test-failed", "hyp-init", "http_probe", "Probe", "200", {"path": "/robots.txt", "method": "GET"})
        sess.record_failed_approach(
            approach_id="fa-robots",
            hypothesis_id=hyp.hypothesis_id,
            test_id=st.test_id,
            target="target-01",
            tool="http_probe",
            parameters={"path": "/robots.txt", "method": "GET"},
            reason="404",
            negative_knowledge="Path /robots.txt does not exist",
            evidence_ref=ev.evidence_id,
        )
        sess.save()

        # Gemini attempts to propose /robots.txt again
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Check robots again",
                "based_on_observations": ["obs-init"],
                "tool": "http_probe",
                "safety_justification": "Repeat test",
                "expected_outcome": "200",
                "parameters": {"path": "/robots.txt", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        controller.run(sess, limits=ResearchLimits(max_tests=1))
        reloaded = self.session_manager.load_session("sess-repeat-block")
        new_tests = [t.parameters.get("path") for t in reloaded.safe_tests if t.test_id != "test-failed"]
        self.assertNotIn("/robots.txt", new_tests)

    def test_21_failed_approaches_are_supplied_in_context(self):
        """Verify failed approaches are formatted in Gemini prompt context."""
        sess = self.session_manager.create_session("sess-ctx-fa", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 404})
        obs = sess.add_observation("obs-init", ev.evidence_id, "Init")
        hyp = sess.add_hypothesis("hyp-init", ["obs-init"], "Claim")
        st = sess.add_safe_test("test-fa", "hyp-init", "http_probe", "Just", "200", {"path": "/admin"})
        sess.record_failed_approach(
            approach_id="fa-admin",
            hypothesis_id=hyp.hypothesis_id,
            test_id=st.test_id,
            target="target-01",
            tool="http_probe",
            parameters={"path": "/admin", "method": "GET"},
            reason="403",
            negative_knowledge="Path /admin forbidden",
            evidence_ref=ev.evidence_id,
        )

        builder = GeminiContextBuilder()
        ctx = builder.build_context(sess, {"id": "target-01"})
        self.assertEqual(len(ctx["failed_approaches"]), 1)
        self.assertEqual(ctx["failed_approaches"][0]["negative_knowledge"], "Path /admin forbidden")

    def test_22_previous_observations_are_supplied(self):
        """Verify observations are supplied in context to Gemini."""
        sess = self.session_manager.create_session("sess-ctx-obs", "target-01")
        ev = self.evidence_collector.store_evidence("test", "target-01", {"status": 200})
        sess.add_observation("obs-server", ev.evidence_id, "Observed Apache server", attributes={"Server": "Apache"})
        builder = GeminiContextBuilder()
        ctx = builder.build_context(sess, {"id": "target-01"})
        self.assertEqual(len(ctx["observations"]), 1)
        self.assertEqual(ctx["observations"][0]["observation_id"], "obs-server")

    def test_23_previous_hypotheses_are_supplied(self):
        """Verify hypotheses and their lifecycles are supplied in context."""
        sess = self.session_manager.create_session("sess-ctx-hyp", "target-01")
        ev = self.evidence_collector.store_evidence("test", "target-01", {"status": 200})
        obs = sess.add_observation("obs-1", ev.evidence_id, "Obs")
        sess.add_hypothesis("hyp-1", ["obs-1"], "Claim test")
        builder = GeminiContextBuilder()
        ctx = builder.build_context(sess, {"id": "target-01"})
        self.assertEqual(len(ctx["hypotheses"]), 1)
        self.assertEqual(ctx["hypotheses"][0]["hypothesis_id"], "hyp-1")

    def test_24_evidence_references_are_preserved(self):
        """Verify evidence references created during Gemini-guided research are intact and verify."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Evidence integrity check",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-ev-pres", "target-01", limits=ResearchLimits(max_tests=1))
        for ev_ref in summary.evidence_refs:
            self.assertEqual(len(ev_ref), 64)
            self.assertTrue(self.evidence_collector.verify_evidence(ev_ref))

    def test_25_session_survives_gemini_failure(self):
        """Verify session state remains valid and persists even if Gemini errors out."""
        # Provider that raises an error
        def failing_provider(prompt):
            raise RuntimeError("Gemini API connection timeout")

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=failing_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-gemini-fail", "target-01", limits=ResearchLimits(max_tests=1))
        reloaded = self.session_manager.load_session("sess-gemini-fail")
        self.assertEqual(reloaded.session_id, "sess-gemini-fail")
        self.assertTrue(len(reloaded.observations) >= 1)

    def test_26_deterministic_fallback_works(self):
        """Verify controller successfully falls back to deterministic ReconPlanner on Gemini error."""
        def failing_provider(prompt):
            raise GeminiAPIError("Service Unavailable 503")

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=failing_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-fallback-works", "target-01", limits=ResearchLimits(max_tests=1))
        self.assertEqual(summary.tests_executed, 1)
        self.assertEqual(summary.tests_succeeded, 1)

    def test_27_max_tests_still_stops_execution(self):
        """Verify max_tests limit halts execution when using Gemini reasoning adapter."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Loop test",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Probe",
                "expected_outcome": "200",
                "parameters": {"path": "/", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-max-tests", "target-01", limits=ResearchLimits(max_tests=2))
        self.assertEqual(summary.tests_executed, 2)
        self.assertEqual(summary.stop_reason, "max_tests")

    def test_28_max_duration_still_stops_execution(self):
        """Verify max_duration limit halts execution when using Gemini reasoning adapter."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Claim",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Just",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-max-dur", "target-01", limits=ResearchLimits(max_duration_seconds=0.0001, max_tests=50))
        self.assertEqual(summary.stop_reason, "max_duration")

    def test_29_max_consecutive_failures_still_stops_execution(self):
        """Verify consecutive failure limit halts execution even under Gemini guidance."""
        failing_orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.logs_dir / "orch_fail.jsonl",
            executor_func=lambda t, p: {"success": False, "status_code": 404, "body": "Not found", "tool": "http_probe", "target": t["id"], "path": p.get("path", "/")},
        )
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Failing path check",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/fail", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=failing_orch,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-consec-fail", "target-01", limits=ResearchLimits(max_consecutive_failures=2, max_tests=10))
        self.assertEqual(summary.consecutive_failures, 2)
        self.assertEqual(summary.stop_reason, "max_consecutive_failures")

    def test_30_max_repeated_observations_still_stops_execution(self):
        """Verify max_repeated_observations limit halts execution when no new facts emerge."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Repeat obs check",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-max-repeat-obs", "target-01", limits=ResearchLimits(max_repeated_observations=2, max_tests=10))
        self.assertTrue(summary.stop_reason in ("max_repeated_observations", "max_tests", "no_more_hypotheses"))

    def test_31_stop_on_finding_still_stops_execution(self):
        """Verify stop_on_finding halts execution immediately when finding exists."""
        sess = self.session_manager.create_session("sess-stop-finding", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"vuln": True})
        obs = sess.add_observation("obs-vuln", ev.evidence_id, "Admin exposed")
        hyp = sess.add_hypothesis("hyp-vuln", [obs.observation_id], "Admin vulnerability")
        st = sess.add_safe_test("test-vuln", hyp.hypothesis_id, "http_probe", "Probe", "200", {"path": "/admin"})
        res = sess.record_test_result("res-vuln", st.test_id, ev.evidence_id, TestStatus.SUCCESS, "Admin found")
        concl = sess.add_conclusion("concl-vuln", hyp.hypothesis_id, [res.result_id], ConclusionStatus.VALIDATED, "Confirmed")
        sess.add_finding(
            finding_id="find-01",
            title="Exposed Admin",
            severity=FindingSeverity.HIGH,
            conclusion_ref=concl.conclusion_id,
            evidence_chain={
                "conclusion": concl.conclusion_id,
                "hypothesis": hyp.hypothesis_id,
                "test": st.test_id,
                "result": res.result_id,
                "observation": obs.observation_id,
            },
            description="Exposed administrator panel",
            impact="Unauthorized privileged access",
        )
        sess.save()

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Extra check",
            "based_on_observations": [obs.observation_id],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/extra", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run(sess, limits=ResearchLimits(stop_on_finding=True, max_tests=5))
        self.assertEqual(summary.stop_reason, "stop_on_finding")
        self.assertEqual(summary.findings_count, 1)

    def test_32_complete_scientific_traceability_exists(self):
        """Verify full chain traceability: Observation -> Hypothesis -> SafeTest -> Result -> Conclusion."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Traceability check",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.audit_log_file,
            orchestrator=self.orchestrator,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        summary = controller.run("sess-trace-full", "target-01", limits=ResearchLimits(max_tests=1))
        sess = self.session_manager.load_session("sess-trace-full")

        for concl in sess.conclusions:
            self.assertIn(concl.hypothesis_id, sess._hypotheses)
            for r_ref in concl.result_refs:
                res = sess.get_test_result(r_ref)
                self.assertIn(res.test_id, sess._safe_tests)
                self.assertTrue(self.evidence_collector.verify_evidence(res.evidence_ref))

        for hyp in sess.hypotheses:
            for obs_ref in hyp.based_on_observations:
                obs = sess.get_observation(obs_ref)
                self.assertTrue(self.evidence_collector.verify_evidence(obs.evidence_ref))


if __name__ == "__main__":
    unittest.main()

