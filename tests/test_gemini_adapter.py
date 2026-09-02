"""Comprehensive unit tests for the Gemini Reasoning Adapter.

Verifies:
1. Context builder includes all required scientific state
2. Context builder excludes sensitive credentials/secrets
3. Valid new hypothesis and test proposal is accepted
4. Valid test for existing hypothesis is accepted
5. Valid conclude proposal is accepted
6. Markdown code fences are cleanly stripped
7. Malformed JSON raises parsing error gracefully
8. Missing mandatory fields raise validation error
9. Hallucinated observation ID reference is rejected
10. Hallucinated hypothesis ID reference is rejected
11. Path traversal attempts are rejected
12. Shell metacharacters are rejected
13. AI-supplied host or IP parameters are rejected
14. Arbitrary command parameters (cmd, exec, shell) are rejected
15. Unauthorized tools are rejected
16. Invalid HTTP methods (POST, DELETE, PUT) are rejected
17. CRLF header injections are rejected
18. Approaches recorded in negative knowledge are rejected
19. GeminiClient works with mock provider callable
20. GeminiClient raises GeminiAPIError when unconfigured
21. Adapter implements propose_hypothesis and propose_safe_test
22. Adapter falls back to heuristic planner on error when configured
23. Adapter integrates seamlessly with ResearchController
24. Gateway remains final authority against malformed tests
25. Security regressions and Docker isolation invariants remain intact
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from agents.controller import ResearchController, ResearchLimits
from agents.gemini_adapter import (
    GeminiAdapterError,
    GeminiAPIError,
    GeminiClient,
    GeminiContextBuilder,
    GeminiProposal,
    GeminiProposalType,
    GeminiProposalValidationError,
    GeminiProposalValidator,
    GeminiReasoningAdapter,
    GeminiResponseParsingError,
)
from agents.recon.agent import TargetRegistry
from agents.recon.planner import ReconPlanner
from core.evidence import EvidenceCollector
from core.schemas import (
    ConclusionStatus,
    HypothesisStatus,
    SafeTest,
    TestStatus,
)
from core.session import Session, SessionManager
from gateway.orchestrator import GatewayOrchestrator, MaliciousParameterError


class TestGeminiReasoningAdapter(unittest.TestCase):
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

        self.evidence_collector = EvidenceCollector(evidence_dir=self.evidence_dir)
        self.session_manager = SessionManager(
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

        self.session = self.session_manager.create_session("sess-gemini-test", "target-01")
        self.ev = self.evidence_collector.store_evidence("target_registry", "target-01", {"status": "ok"})
        self.obs1 = self.session.add_observation(
            observation_id="obs-target-01-001",
            evidence_ref=self.ev.evidence_id,
            description="Target HTTP service active on port 8080",
            attributes={"path": "/", "status_code": 200},
        )
        self.hyp1 = self.session.add_hypothesis(
            hypothesis_id="hyp-target-01-001",
            based_on_observations=[self.obs1.observation_id],
            claim="Web service exposes crawling policies at /robots.txt",
        )
        self.session.save()

        self.target_info = {
            "id": "target-01",
            "protocol": "http",
            "port": 8080,
            "container": "koth-target-01",
            "network": "koth-lab",
            "enabled": True,
        }

        self.context_builder = GeminiContextBuilder()

    def tearDown(self):
        for p in self.base_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_context_builder_includes_scientific_state(self):
        """Verify context builder exports complete research state and bounds."""
        ctx = self.context_builder.build_context(self.session, self.target_info)
        self.assertEqual(ctx["session_id"], "sess-gemini-test")
        self.assertEqual(ctx["target"]["id"], "target-01")
        self.assertEqual(len(ctx["observations"]), 1)
        self.assertEqual(ctx["observations"][0]["observation_id"], "obs-target-01-001")
        self.assertEqual(len(ctx["hypotheses"]), 1)
        self.assertEqual(ctx["hypotheses"][0]["hypothesis_id"], "hyp-target-01-001")
        self.assertIn("bounds", ctx)
        self.assertIn("http_probe", ctx["bounds"]["allowed_tools"])

    def test_2_context_builder_excludes_sensitive_secrets(self):
        """Verify sensitive patterns are strictly blocked from prompt contexts."""
        # Attempt to inject sensitive attribute in observation
        ev_sec = self.evidence_collector.store_evidence("test", "target-01", {"data": "test"})
        self.session.add_observation(
            observation_id="obs-secret",
            evidence_ref=ev_sec.evidence_id,
            description="Leaked docker.sock location",
            attributes={"leak": "docker.sock"},
        )
        with self.assertRaises(GeminiAdapterError):
            self.context_builder.build_context(self.session, self.target_info)

    def test_3_valid_new_hypothesis_and_test_proposal(self):
        """Verify valid proposal with new hypothesis and safe test is validated."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "The root path returns HTML welcome page",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Standard HTTP GET request to root path",
            "expected_outcome": "HTTP 200 with HTML body",
            "parameters": {"path": "/", "method": "GET"},
            "reasoning": "Check service banner and landing page",
        }
        prop = validator.validate_proposal(raw, self.session, self.target_info)
        self.assertEqual(prop.proposal_type, GeminiProposalType.NEW_HYPOTHESIS_AND_TEST.value)
        self.assertEqual(prop.hypothesis_claim, "The root path returns HTML welcome page")
        self.assertEqual(prop.based_on_observations, ["obs-target-01-001"])
        self.assertEqual(prop.tool, "http_probe")
        self.assertEqual(prop.parameters["path"], "/")

    def test_4_valid_existing_hypothesis_test_proposal(self):
        """Verify valid proposal targeting existing hypothesis is validated."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "test_existing_hypothesis",
            "hypothesis_id": "hyp-target-01-001",
            "tool": "http_probe",
            "safety_justification": "Probe /robots.txt using bounded GET",
            "expected_outcome": "HTTP 200 with User-agent rules",
            "parameters": {"path": "/robots.txt", "method": "GET"},
            "reasoning": "Verify robots.txt presence",
        }
        prop = validator.validate_proposal(raw, self.session, self.target_info)
        self.assertEqual(prop.proposal_type, GeminiProposalType.TEST_EXISTING_HYPOTHESIS.value)
        self.assertEqual(prop.hypothesis_id, "hyp-target-01-001")
        self.assertEqual(prop.parameters["path"], "/robots.txt")

    def test_5_valid_conclude_proposal(self):
        """Verify valid conclusion proposal is validated."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "conclude",
            "reasoning": "All accessible reconnaissance vectors have been evaluated",
        }
        prop = validator.validate_proposal(raw, self.session, self.target_info)
        self.assertTrue(prop.is_conclusion())
        self.assertIn("reconnaissance vectors", prop.reasoning)

    def test_6_markdown_code_fences_stripped(self):
        """Verify JSON surrounded by markdown code fences is parsed successfully."""
        mock_response = (
            "```json\n"
            "{\n"
            '  "proposal_type": "conclude",\n'
            '  "reasoning": "Finished research"\n'
            "}\n"
            "```"
        )
        client = GeminiClient(provider=lambda prompt: mock_response)
        adapter = GeminiReasoningAdapter(client=client)
        prop = adapter.generate_proposal(self.session, self.target_info)
        self.assertTrue(prop.is_conclusion())

    def test_7_malformed_json_raises_parsing_error(self):
        """Verify malformed JSON from LLM raises GeminiResponseParsingError."""
        client = GeminiClient(provider=lambda prompt: "Invalid non-json response text")
        adapter = GeminiReasoningAdapter(client=client)
        with self.assertRaises(GeminiResponseParsingError):
            adapter.generate_proposal(self.session, self.target_info)

    def test_8_missing_claim_or_justification_rejected(self):
        """Verify missing mandatory fields raise validation error."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            # missing hypothesis_claim
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Safe test",
            "expected_outcome": "200 OK",
            "parameters": {"path": "/"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_9_unobserved_observation_ref_rejected(self):
        """Verify referencing hallucinated observation ID is strictly rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Admin portal exists",
            "based_on_observations": ["obs-hallucinated-999"],
            "tool": "http_probe",
            "safety_justification": "Safe test",
            "expected_outcome": "200 OK",
            "parameters": {"path": "/admin"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_10_unknown_hypothesis_ref_rejected(self):
        """Verify referencing hallucinated hypothesis ID is strictly rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "test_existing_hypothesis",
            "hypothesis_id": "hyp-hallucinated-999",
            "tool": "http_probe",
            "safety_justification": "Safe test",
            "expected_outcome": "200 OK",
            "parameters": {"path": "/admin"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_11_path_traversal_rejected(self):
        """Verify path traversal (..) attempt is strictly blocked."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Directory traversal vulnerability",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Check traversal",
            "expected_outcome": "200 OK",
            "parameters": {"path": "/../../etc/passwd"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_12_shell_metacharacters_rejected(self):
        """Verify shell metacharacters in parameters are strictly blocked."""
        validator = GeminiProposalValidator()
        dangerous_paths = [
            "/test; whoami",
            "/test && id",
            "/test | cat /etc/passwd",
            "/test`id`",
            "/test$(id)",
            "/test\nid",
        ]
        for bad_path in dangerous_paths:
            raw = {
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Check command injection",
                "based_on_observations": ["obs-target-01-001"],
                "tool": "http_probe",
                "safety_justification": "Justification",
                "expected_outcome": "Outcome",
                "parameters": {"path": bad_path},
            }
            with self.assertRaises(GeminiProposalValidationError):
                validator.validate_proposal(raw, self.session, self.target_info)

    def test_13_ai_supplied_host_or_ip_rejected(self):
        """Verify AI-supplied IP/host overrides are strictly rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Custom host routing",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"path": "/", "ip": "8.8.8.8"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_14_arbitrary_shell_command_keys_rejected(self):
        """Verify command keys (cmd, exec, shell, script) are strictly rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Run diagnostic",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"path": "/", "cmd": "whoami"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_15_unauthorized_tool_rejected(self):
        """Verify tools other than allowed tools are rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Nmap port scan",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "nmap",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"ports": "80,8080"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_16_invalid_http_method_rejected(self):
        """Verify non-whitelisted HTTP methods are rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "POST request endpoint",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"path": "/api", "method": "POST"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_17_crlf_header_injection_rejected(self):
        """Verify header CRLF injection is rejected."""
        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Header test",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"path": "/", "headers": {"X-Injected": "val\r\nSet-Cookie: admin=1"}},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_18_failed_approach_negative_knowledge_rejected(self):
        """Verify proposing an approach recorded in failed approaches is rejected."""
        test_fail = self.session.add_safe_test(
            test_id="test-robots",
            hypothesis_id=self.hyp1.hypothesis_id,
            tool="http_probe",
            safety_justification="Initial probe",
            expected_outcome="200 OK",
            parameters={"path": "/robots.txt", "method": "GET"},
        )
        ev_fail = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 404})
        self.session.record_failed_approach(
            approach_id="fa-robots",
            hypothesis_id=self.hyp1.hypothesis_id,
            test_id="test-robots",
            target="target-01",
            tool="http_probe",
            parameters={"path": "/robots.txt", "method": "GET"},
            reason="Not found 404",
            negative_knowledge="Path /robots.txt does not exist on target",
            evidence_ref=ev_fail.evidence_id,
        )
        self.session.save()

        validator = GeminiProposalValidator()
        raw = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Robots file check",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Justification",
            "expected_outcome": "Outcome",
            "parameters": {"path": "/robots.txt", "method": "GET"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw, self.session, self.target_info)

    def test_19_gemini_client_mock_provider(self):
        """Verify GeminiClient calls provider function."""
        client = GeminiClient(provider=lambda prompt: json.dumps({"echo": prompt[:10]}))
        resp = client.generate("Hello world prompt")
        self.assertIn("echo", resp)

    def test_20_gemini_client_missing_key_raises_error(self):
        """Verify GeminiClient raises GeminiAPIError when unconfigured."""
        client = GeminiClient(api_key=None, provider=None)
        # Clear env temporarily if set
        orig = os.environ.pop("GEMINI_API_KEY", None)
        try:
            with self.assertRaises(GeminiAPIError):
                client.generate("Test prompt")
        finally:
            if orig:
                os.environ["GEMINI_API_KEY"] = orig

    def test_21_adapter_propose_hypothesis_and_safe_test(self):
        """Verify adapter fulfills planner interface."""
        mock_payload = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Landing page exposes server header",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Safe probe",
            "expected_outcome": "HTTP 200",
            "parameters": {"path": "/", "method": "GET"},
        }
        client = GeminiClient(provider=lambda p: json.dumps(mock_payload))
        adapter = GeminiReasoningAdapter(client=client)

        hyp_dict = adapter.propose_hypothesis(self.session, self.target_info)
        self.assertEqual(hyp_dict["claim"], "Landing page exposes server header")
        self.assertEqual(hyp_dict["based_on_observations"], ["obs-target-01-001"])

        test_dict = adapter.propose_safe_test(self.session, self.hyp1, self.target_info)
        self.assertEqual(test_dict["tool"], "http_probe")
        self.assertEqual(test_dict["parameters"]["path"], "/")

    def test_22_adapter_fallback_to_heuristic_planner(self):
        """Verify adapter falls back to heuristic planner when Gemini fails."""
        # Client that raises parsing error
        bad_client = GeminiClient(provider=lambda p: "MALFORMED_OUTPUT")
        heuristic_planner = ReconPlanner()
        adapter = GeminiReasoningAdapter(client=bad_client, fallback_planner=heuristic_planner)

        # propose_hypothesis should fall back without crashing
        hyp_dict = adapter.propose_hypothesis(self.session, self.target_info)
        self.assertIsNotNone(hyp_dict)
        self.assertIn("claim", hyp_dict)

    def test_23_adapter_integration_with_research_controller(self):
        """Verify ResearchController operates with GeminiReasoningAdapter as planner."""
        # Create mock executor
        def mock_executor(target, params):
            return {
                "tool": "http_probe",
                "target": target["id"],
                "path": params.get("path", "/"),
                "status_code": 200,
                "headers": {"Server": "MockServer"},
                "body": "Welcome",
                "success": True,
            }

        orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.logs_dir / "orch.jsonl",
            executor_func=mock_executor,
        )

        # Mock Gemini that returns a valid proposal
        mock_payload = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "The web root is accessible",
            "based_on_observations": ["obs-target-01-001"],
            "tool": "http_probe",
            "safety_justification": "Safe HTTP probe",
            "expected_outcome": "HTTP 200",
            "parameters": {"path": "/", "method": "GET"},
        }
        client = GeminiClient(provider=lambda p: json.dumps(mock_payload))
        adapter = GeminiReasoningAdapter(client=client)

        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            audit_log_path=self.logs_dir / "controller.jsonl",
            orchestrator=orchestrator,
            evidence_collector=self.evidence_collector,
            planner=adapter,
        )

        summary = controller.run(
            session=self.session,
            limits=ResearchLimits(max_tests=1),
        )
        self.assertEqual(summary.tests_executed, 1)
        self.assertEqual(summary.tests_succeeded, 1)
        self.assertTrue(len(summary.evidence_refs) >= 1)

    def test_24_gateway_remains_final_authority(self):
        """Verify gateway orchestrator blocks forbidden SafeTest even if bypass occurred."""
        orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            audit_log_path=self.logs_dir / "orch_gw.jsonl",
            executor_func=lambda t, p: {"success": True},
        )
        bad_test = SafeTest(
            test_id="test-evil",
            hypothesis_id="hyp-target-01-001",
            tool="http_probe",
            safety_justification="Evil test",
            expected_outcome="Fail",
            parameters={"path": "/../../shadow"},
        )
        with self.assertRaises(MaliciousParameterError):
            orchestrator.execute_safe_test(bad_test, self.session)

    def test_25_security_invariants_and_regression(self):
        """Verify Docker runner security parameters and gateway policies remain unchanged."""
        base_dir = Path.home() / "koth-ai"
        executor_file = base_dir / "gateway" / "docker_executor.py"
        with open(executor_file, "r") as f:
            code = f.read()

        self.assertIn("--cap-drop=ALL", code)
        self.assertIn("--security-opt=no-new-privileges:true", code)
        self.assertIn("--read-only", code)
        self.assertIn("--network=none", code)


if __name__ == "__main__":
    unittest.main()

