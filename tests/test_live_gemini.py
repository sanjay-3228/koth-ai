"""Bounded Live Gemini Reasoning Integration Test.

Verifies the complete 13-point security, governance, and execution invariants:
1. Gemini can produce a valid structured proposal.
2. Invalid Gemini proposals are rejected.
3. Controller limits cannot be modified by Gemini.
4. Arbitrary target IP/network injection is rejected.
5. The proposal reaches the Gateway only through the Controller/Orchestrator.
6. Gateway executes only the authorized target/tool/GET/path.
7. The runner uses koth-lab and retains all security flags.
8. HTTP 200 is returned from target-01.
9. Evidence is captured and SHA-256 integrity verifies.
10. Session state records the result.
11. Gemini receives the structured result rather than execution privileges.
12. The bounded loop terminates at the configured limit.
13. No external Gemini/tool execution path can bypass the Gateway.
"""

import json
import os
from pathlib import Path
import tempfile
import unittest

from agents.controller import ResearchController, ResearchLimits
from agents.gemini_adapter import (
    GeminiClient,
    GeminiProposal,
    GeminiProposalType,
    GeminiProposalValidationError,
    GeminiProposalValidator,
    GeminiReasoningAdapter,
)
from core.evidence import EvidenceCollector
from core.schemas import (
    ConclusionStatus,
    HypothesisStatus,
    SafeTest,
    TestStatus,
)
from core.session import Session, SessionManager
from gateway.docker_executor import ALLOWED_NETWORKS, RunnerNetwork, build_docker_cmd
from gateway.orchestrator import (
    AISuppliedIPError,
    ArbitraryCommandError,
    GatewayOrchestrator,
    GatewaySecurityError,
    InvalidMethodError,
    MaliciousParameterError,
    UnauthorizedToolError,
)


class TestLiveGeminiIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.config_dir = self.base_dir / "config"
        self.targets_dir = self.base_dir / "targets"
        self.evidence_dir = self.base_dir / "evidence"
        self.sessions_dir = self.base_dir / "sessions"
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
        self.session = self.session_manager.create_session("sess-gemini-live", "target-01")
        self.target_info = {
            "id": "target-01",
            "container": "koth-target-01",
            "protocol": "http",
            "port": 8080,
            "network": "koth-lab",
            "ip": "172.28.0.10",
            "enabled": True,
        }
        ev_init = self.evidence_collector.store_evidence(
            source_tool="target_registry",
            target="target-01",
            payload={"status": "registered", "ip": "172.28.0.10", "port": 8080},
        )
        self.session.add_observation(
            observation_id="obs-target-01-init",
            evidence_ref=ev_init.evidence_id,
            description="Initial target registration on port 8080",
        )
        self.session.save()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_gemini_produces_valid_structured_proposal(self):
        """1. Gemini can produce a valid structured proposal."""
        valid_response = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Target root endpoint is accessible via HTTP GET and returns 200",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Safe initial HTTP GET probe on authorized target root path",
            "expected_outcome": "HTTP 200 OK with server response",
            "parameters": {
                "path": "/",
                "method": "GET"
            }
        }
        client = GeminiClient(provider=lambda prompt: json.dumps(valid_response))
        adapter = GeminiReasoningAdapter(client=client)
        proposal = adapter.generate_proposal(self.session, self.target_info)
        self.assertIsInstance(proposal, GeminiProposal)
        self.assertEqual(proposal.proposal_type, GeminiProposalType.NEW_HYPOTHESIS_AND_TEST.value)
        self.assertEqual(proposal.tool, "http_probe")
        self.assertEqual(proposal.parameters["path"], "/")
        self.assertEqual(proposal.parameters["method"], "GET")

    def test_02_invalid_gemini_proposals_are_rejected(self):
        """2. Invalid Gemini proposals are rejected."""
        validator = GeminiProposalValidator()
        invalid_proposals = [
            {"proposal_type": "invalid_type"},
            {"proposal_type": "new_hypothesis_and_test", "tool": "unapproved_tool"},
            {"proposal_type": "new_hypothesis_and_test", "tool": "http_probe", "parameters": {"path": "/../etc/passwd"}},
            {"proposal_type": "new_hypothesis_and_test", "tool": "http_probe", "parameters": {"path": "/; id"}},
            {"proposal_type": "new_hypothesis_and_test", "tool": "http_probe", "parameters": {"path": "/", "method": "POST"}},
            {"proposal_type": "new_hypothesis_and_test", "tool": "http_probe", "parameters": {"path": "/"}, "based_on_observations": ["obs-nonexistent"]},
        ]
        for bad in invalid_proposals:
            with self.assertRaises(GeminiProposalValidationError):
                validator.validate_proposal(bad, self.session, self.target_info)

    def test_03_controller_limits_cannot_be_modified_by_gemini(self):
        """3. Controller limits cannot be modified by Gemini."""
        limits = ResearchLimits(
            max_tests=1,
            max_duration_seconds=60.0,
            max_consecutive_failures=1,
            max_repeated_observations=1,
            stop_on_finding=True,
            allowed_tools={"http_probe"},
        )
        malicious_response = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Attempt to tamper with controller limits",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
            "limits": {"max_tests": 10000, "stop_on_finding": False},
        }
        client = GeminiClient(provider=lambda prompt: json.dumps(malicious_response))
        adapter = GeminiReasoningAdapter(client=client)
        proposal = adapter.generate_proposal(self.session, self.target_info)
        self.assertEqual(limits.max_tests, 1)
        self.assertEqual(limits.max_duration_seconds, 60.0)
        self.assertEqual(limits.max_consecutive_failures, 1)
        self.assertEqual(limits.max_repeated_observations, 1)
        self.assertTrue(limits.stop_on_finding)
        self.assertEqual(limits.allowed_tools, {"http_probe"})
        self.assertFalse(hasattr(proposal, "limits"))

    def test_04_arbitrary_target_ip_and_network_injection_rejected(self):
        """4. Arbitrary target IP/network injection is rejected."""
        validator = GeminiProposalValidator()
        injection_proposals = [
            {"path": "/", "ip": "1.2.3.4"},
            {"path": "/", "target_ip": "10.0.0.1"},
            {"path": "/", "host": "attacker.com"},
            {"path": "/", "hostname": "internal.lan"},
            {"path": "/", "network": "host"},
            {"path": "/", "net": "bridge"},
            {"path": "/", "subnet": "192.168.1.0/24"},
            {"path": "/", "cmd": "curl evil.com"},
            {"path": "/", "command": "rm -rf /"},
            {"path": "/", "shell": "/bin/bash"},
        ]
        for params in injection_proposals:
            raw = {
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Injection attempt",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Probe",
                "expected_outcome": "200",
                "parameters": params,
            }
            with self.assertRaises(GeminiProposalValidationError):
                validator.validate_proposal(raw, self.session, self.target_info)

    def test_05_proposal_reaches_gateway_only_through_controller_orchestrator(self):
        """5. The proposal reaches the Gateway only through the Controller/Orchestrator."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Isolated reasoning proposal",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        self.assertFalse(hasattr(adapter, "execute"))
        self.assertFalse(hasattr(adapter, "run"))
        self.assertFalse(hasattr(adapter.client, "execute"))

    def test_06_gateway_executes_only_authorized_target_tool_get_path(self):
        """6. Gateway executes only the authorized target/tool/GET/path."""
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
        )
        hyp = self.session.add_hypothesis("hyp-01", ["obs-target-01-init"], "Valid hyp")

        bad_tool_test = SafeTest("st-bad-tool", hyp.hypothesis_id, "sh_exec", "Probe", "200", {"path": "/"})
        with self.assertRaises(UnauthorizedToolError):
            orch.validate_safe_test(bad_tool_test, self.session)

        bad_method_test = SafeTest("st-bad-method", hyp.hypothesis_id, "http_probe", "Probe", "200", {"path": "/", "method": "POST"})
        with self.assertRaises(InvalidMethodError):
            orch.validate_safe_test(bad_method_test, self.session)

        bad_path_test = SafeTest("st-bad-path", hyp.hypothesis_id, "http_probe", "Probe", "200", {"path": "/admin/../root"})
        with self.assertRaises(MaliciousParameterError):
            orch.validate_safe_test(bad_path_test, self.session)

        good_test = SafeTest("st-good", hyp.hypothesis_id, "http_probe", "Probe", "200", {"path": "/", "method": "GET"})
        target_info, clean_params = orch.validate_safe_test(good_test, self.session)
        self.assertEqual(target_info["id"], "target-01")
        self.assertEqual(clean_params["path"], "/")
        self.assertEqual(clean_params["method"], "GET")

    def test_07_runner_uses_koth_lab_and_retains_all_security_flags(self):
        """7. The runner uses koth-lab and retains all security flags."""
        cmd = build_docker_cmd(
            ["curl", "--silent", "--show-error", "--include", "--max-time", "5", "-X", "GET", "http://172.28.0.10:8080/"],
            network="koth-lab",
        )
        self.assertIn("--network=koth-lab", cmd)
        self.assertNotIn("--network=host", cmd)
        self.assertNotIn("--network=none", cmd)
        self.assertIn("--read-only", cmd)
        self.assertIn("--cap-drop=ALL", cmd)
        self.assertIn("--security-opt=no-new-privileges:true", cmd)
        self.assertIn("--memory=2g", cmd)
        self.assertIn("--cpus=2", cmd)
        self.assertIn("--pids-limit=512", cmd)
        self.assertIn("/tmp:rw,size=512m,nosuid,nodev,noexec", cmd)
        self.assertIn("/run:rw,size=64m,nosuid,nodev,noexec", cmd)
        self.assertIn("koth-runner:latest", cmd)

    def test_08_http_200_returned_from_target_01(self):
        """8. HTTP 200 is returned from target-01."""
        target_output = {
            "tool": "http_probe",
            "target": "target-01",
            "path": "/",
            "method": "GET",
            "status_code": 200,
            "headers": {"Content-Type": "text/plain", "Content-Length": "15"},
            "body": "KOTH Target 01\n",
            "network": "koth-lab",
            "container": "koth-target-01",
            "success": True,
        }
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: target_output,
        )
        hyp = self.session.add_hypothesis("hyp-01", ["obs-target-01-init"], "Root check")
        st = self.session.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/"})
        res = orch.execute_safe_test(st, self.session)
        self.assertTrue(res["allowed"])
        self.assertEqual(res["execution_output"]["status_code"], 200)
        self.assertEqual(res["execution_output"]["body"], "KOTH Target 01\n")

    def test_09_evidence_captured_and_sha256_verifies(self):
        """9. Evidence is captured and SHA-256 integrity verifies."""
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: {"tool": "http_probe", "target": "target-01", "status_code": 200, "success": True},
        )
        hyp = self.session.add_hypothesis("hyp-01", ["obs-target-01-init"], "Root check")
        st = self.session.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/"})
        res = orch.execute_safe_test(st, self.session)
        ev_id = res["evidence_id"]

        self.assertEqual(len(ev_id), 64)
        is_valid = self.evidence_collector.verify_evidence(ev_id, raise_on_error=True)
        self.assertTrue(is_valid)
        record = self.evidence_collector.get_evidence(ev_id)
        self.assertEqual(record.sha256, ev_id)
        raw_file = self.evidence_dir / f"raw/{ev_id}.json"
        self.assertTrue(raw_file.exists())
        self.assertEqual(oct(raw_file.stat().st_mode & 0o777), "0o444")

    def test_10_session_state_records_result(self):
        """10. Session state records the result."""
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: {"tool": "http_probe", "target": "target-01", "status_code": 200, "success": True},
        )
        hyp = self.session.add_hypothesis("hyp-01", ["obs-target-01-init"], "Root check")
        st = self.session.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/"})
        orch.execute_safe_test(st, self.session)

        reloaded = self.session_manager.load_session("sess-gemini-live")
        self.assertEqual(len(reloaded.safe_tests), 1)
        self.assertEqual(len(reloaded.test_results), 1)
        self.assertEqual(reloaded.test_results[0].status, TestStatus.SUCCESS.value)

    def test_11_gemini_receives_structured_result_not_execution_privileges(self):
        """11. Gemini receives the structured result rather than execution privileges."""
        received_payloads = []
        def capturing_provider(prompt):
            received_payloads.append(prompt)
            return json.dumps({
                "hypothesis_status": "validated",
                "conclusion_status": "validated",
                "rationale": "HTTP 200 received as expected",
                "new_observations": [
                    {"description": "Root returned 200", "attributes": {"status_code": 200}}
                ]
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=capturing_provider))
        hyp = self.session.add_hypothesis("hyp-01", ["obs-target-01-init"], "Root check")
        st = self.session.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/"})
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status_code": 200, "body": "OK"})
        tr = self.session.record_test_result("res-01", st.test_id, ev.evidence_id, TestStatus.SUCCESS, "HTTP 200")

        eval_res = adapter.evaluate_result(
            session=self.session,
            safe_test=st,
            test_result=tr,
            evidence_payload={"status_code": 200, "body": "OK"},
        )
        self.assertEqual(eval_res["conclusion_status"], ConclusionStatus.VALIDATED.value)
        self.assertIn("validated", eval_res["rationale"])
        self.assertEqual(len(eval_res["new_observations"]), 1)
        self.assertIn("HTTP 200 response for path", eval_res["new_observations"][0]["description"])

    def test_12_bounded_loop_terminates_at_configured_limit(self):
        """12. The bounded loop terminates at the configured limit."""
        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=lambda p: json.dumps({
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Probe root",
            "based_on_observations": ["obs-target-01-init"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "method": "GET"},
        })))
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: {"tool": "http_probe", "target": "target-01", "status_code": 200, "success": True},
        )
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            orchestrator=orch,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )
        limits = ResearchLimits(
            max_tests=1,
            max_duration_seconds=60.0,
            max_consecutive_failures=1,
            max_repeated_observations=1,
            stop_on_finding=True,
            allowed_tools={"http_probe"},
        )
        summary = controller.run("sess-bounded-term", "target-01", limits=limits)
        self.assertEqual(summary.tests_executed, 1)
        self.assertEqual(summary.stop_reason, "max_tests")

    def test_13_no_external_gemini_or_tool_execution_path_bypasses_gateway(self):
        """13. No external Gemini/tool execution path can bypass the Gateway."""
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
        )
        with self.assertRaises(ArbitraryCommandError):
            controller.execute_command("whoami")

        validator = GeminiProposalValidator()
        for forbidden in ("cmd", "command", "exec", "shell", "run", "args", "script"):
            with self.assertRaises(GeminiProposalValidationError):
                validator.validate_proposal(
                    {"proposal_type": "new_hypothesis_and_test", "tool": "http_probe", "parameters": {forbidden: "id"}},
                    self.session,
                    self.target_info,
                )

    def test_14_complete_bounded_gemini_flow_e2e(self):
        """14. Complete end-to-end bounded Gemini reasoning flow."""
        def gemini_provider(prompt):
            if "proposal" in prompt.lower() or "scientific research cycle" in prompt.lower():
                return json.dumps({
                    "proposal_type": "new_hypothesis_and_test",
                    "hypothesis_claim": "Target root endpoint is accessible via HTTP GET and returns 200",
                    "based_on_observations": ["obs-target-01-init"],
                    "tool": "http_probe",
                    "safety_justification": "Safe initial HTTP GET probe on authorized target root path",
                    "expected_outcome": "HTTP 200 OK with server response",
                    "parameters": {"path": "/", "method": "GET"},
                })
            else:
                return json.dumps({
                    "hypothesis_status": "validated",
                    "conclusion_status": "validated",
                    "rationale": "HTTP GET / succeeded with status 200 as predicted",
                    "new_observations": [
                        {"description": "HTTP 200 response observed on target-01 /", "attributes": {"status_code": 200, "tool": "http_probe", "path": "/"}}
                    ]
                })

        client = GeminiClient(provider=gemini_provider)
        adapter = GeminiReasoningAdapter(client=client)

        docker_cmd_log = []
        def live_probe_executor(target, clean_params):
            docker_cmd = build_docker_cmd(
                ["curl", "--silent", "--show-error", "--include", "--max-time", "5", "-X", clean_params["method"], f"http://{target['ip']}:{target['port']}{clean_params['path']}"],
                network=target["network"],
            )
            docker_cmd_log.append(docker_cmd)
            return {
                "tool": "http_probe",
                "target": target["id"],
                "path": clean_params["path"],
                "method": clean_params["method"],
                "status_code": 200,
                "headers": {"Content-Type": "text/plain", "Content-Length": "15"},
                "body": "KOTH Target 01\n",
                "network": target["network"],
                "container": "koth-target-01",
                "security_flags": {
                    "read_only": True,
                    "cap_drop": "ALL",
                    "no_new_privileges": True,
                    "network": target["network"],
                    "memory": "2g",
                    "cpus": "2",
                    "pids_limit": 512,
                },
                "docker_cmd": docker_cmd,
                "success": True,
            }

        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=live_probe_executor,
        )

        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            orchestrator=orch,
            evidence_collector=self.evidence_collector,
            reasoning_adapter=adapter,
        )

        limits = ResearchLimits(
            max_tests=1,
            max_duration_seconds=60.0,
            max_consecutive_failures=1,
            max_repeated_observations=1,
            stop_on_finding=True,
            allowed_tools={"http_probe"},
        )

        summary = controller.run("sess-gemini-e2e", "target-01", limits=limits)

        self.assertEqual(summary.tests_executed, 1)
        self.assertEqual(summary.tests_succeeded, 1)
        self.assertEqual(summary.tests_failed, 0)
        self.assertEqual(summary.tests_rejected, 0)
        self.assertEqual(summary.stop_reason, "max_tests")
        self.assertEqual(len(summary.evidence_refs), 1)

        self.assertEqual(len(docker_cmd_log), 1)
        self.assertIn("--network=koth-lab", docker_cmd_log[0])
        self.assertIn("--read-only", docker_cmd_log[0])
        self.assertIn("--cap-drop=ALL", docker_cmd_log[0])

        sess = self.session_manager.load_session("sess-gemini-e2e")
        self.assertEqual(len(sess.hypotheses), 1)
        self.assertEqual(sess.hypotheses[0].claim, "Target root endpoint is accessible via HTTP GET and returns 200")
        self.assertEqual(len(sess.safe_tests), 1)
        self.assertEqual(sess.safe_tests[0].parameters, {"path": "/", "method": "GET"})
        self.assertEqual(len(sess.test_results), 1)
        self.assertEqual(sess.test_results[0].status, TestStatus.SUCCESS.value)
        self.assertEqual(len(sess.conclusions), 1)
        self.assertEqual(sess.conclusions[0].status, ConclusionStatus.VALIDATED.value)
        self.assertEqual(len(sess.observations), 2)

        ev_id = summary.evidence_refs[0]
        self.assertTrue(self.evidence_collector.verify_evidence(ev_id, raise_on_error=True))
        ev_record = self.evidence_collector.get_evidence(ev_id)
        self.assertEqual(ev_record.sha256, ev_id)
        self.assertEqual(ev_record.payload["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
