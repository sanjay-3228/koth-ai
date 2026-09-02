"""Unit and integration tests for KOTH lab infrastructure and network architecture.

Verifies:
1. Standalone runner remains network-isolated (--network=none)
2. KOTH runner uses only authorized target network (--network=koth-lab)
3. Network cannot be supplied by Gemini
4. Target registry determines network
5. Arbitrary network rejected
6. Target IP remains registry-controlled
7. Docker socket is never mounted
8. Host networking rejected
9. Security flags remain present (--read-only, --cap-drop=ALL, etc.)
10. Existing Gateway tests remain passing
11. Existing Controller tests remain passing
12. Existing Gemini tests remain passing
"""

import json
from pathlib import Path
import tempfile
import unittest

from agents.controller import ResearchController, ResearchLimits
from agents.gemini_adapter import (
    GeminiClient,
    GeminiProposalValidator,
    GeminiProposalValidationError,
    GeminiReasoningAdapter,
)
from agents.recon.agent import TargetRegistry
from core.evidence import EvidenceCollector
from core.session import SessionManager
from gateway.docker_executor import ALLOWED_NETWORKS, build_docker_cmd
from gateway.orchestrator import (
    AISuppliedIPError,
    ArbitraryCommandError,
    GatewayOrchestrator,
    GatewaySecurityError,
)


class TestLabInfrastructure(unittest.TestCase):
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

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_1_standalone_sandbox_remains_network_none(self):
        """1. Standalone sandbox remains --network=none."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--network=none", cmd)
        self.assertNotIn("--network=host", cmd)
        self.assertNotIn("--network=koth-lab", cmd)

    def test_2_koth_runner_uses_authorized_target_network(self):
        """2. KOTH runner uses authorized target network."""
        cmd = build_docker_cmd(["python3", "tools/http_probe.py"], network="koth-lab")
        self.assertIn("--network=koth-lab", cmd)
        self.assertNotIn("--network=none", cmd)
        self.assertNotIn("--network=host", cmd)

    def test_3_gemini_cannot_provide_network(self):
        """3. Gemini cannot provide network."""
        sess = self.session_manager.create_session("sess-net-test", "target-01")
        ev = self.evidence_collector.store_evidence("test", "target-01", {"ok": True})
        obs = sess.add_observation("obs-01", ev.evidence_id, "Init")
        target_info = {"id": "target-01", "network": "koth-lab", "protocol": "http", "port": 8080}

        validator = GeminiProposalValidator()
        raw_proposal = {
            "proposal_type": "new_hypothesis_and_test",
            "hypothesis_claim": "Attempt network injection",
            "based_on_observations": ["obs-01"],
            "tool": "http_probe",
            "safety_justification": "Probe",
            "expected_outcome": "200",
            "parameters": {"path": "/", "network": "host"},
        }
        with self.assertRaises(GeminiProposalValidationError):
            validator.validate_proposal(raw_proposal, sess, target_info)

    def test_4_target_registry_determines_network(self):
        """4. TargetRegistry determines network."""
        registry = TargetRegistry(config_path=self.targets_file, allowlist_path=self.allowlist_file)
        target = registry.get_target("target-01")
        self.assertEqual(target["network"], "koth-lab")

    def test_5_arbitrary_network_rejected(self):
        """5. Arbitrary network rejected."""
        dangerous_networks = ["host", "bridge", "overlay", "macvlan", "external", "internet"]
        for net in dangerous_networks:
            with self.assertRaises(ValueError):
                build_docker_cmd(["whoami"], network=net)

    def test_6_arbitrary_ip_rejected(self):
        """6. Arbitrary IP rejected."""
        orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
        )
        sess = self.session_manager.create_session("sess-ip-test", "target-01")
        ev = self.evidence_collector.store_evidence("test", "target-01", {"ok": True})
        obs = sess.add_observation("obs-01", ev.evidence_id, "Init")
        hyp = sess.add_hypothesis("hyp-01", [obs.observation_id], "Probe")
        st = sess.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/", "ip": "1.2.3.4"})

        with self.assertRaises(AISuppliedIPError):
            orchestrator.validate_safe_test(st, sess)

    def test_7_target_ip_remains_dynamically_registry_controlled(self):
        """7. Target IP remains dynamically registry-controlled."""
        orchestrator = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
        )
        resolved = orchestrator.resolve_target("target-01")
        self.assertEqual(resolved["ip"], "172.28.0.10")

    def test_8_docker_socket_never_mounted(self):
        """8. Docker socket never mounted."""
        cmd_none = build_docker_cmd(["whoami"], network="none")
        cmd_lab = build_docker_cmd(["whoami"], network="koth-lab")

        for cmd in (cmd_none, cmd_lab):
            cmd_str = " ".join(cmd)
            self.assertNotIn("docker.sock", cmd_str)
            self.assertNotIn("/var/run", cmd_str)

    def test_9_network_host_rejected(self):
        """9. --network=host rejected."""
        with self.assertRaises(ValueError):
            build_docker_cmd(["whoami"], network="host")

    def test_10_privileged_mode_rejected(self):
        """10. --privileged rejected."""
        with self.assertRaises(ValueError):
            build_docker_cmd(["--privileged", "whoami"])

    def test_11_cap_drop_all_retained(self):
        """11. cap-drop=ALL retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--cap-drop=ALL", cmd)

    def test_12_no_new_privileges_retained(self):
        """12. no-new-privileges retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--security-opt=no-new-privileges:true", cmd)

    def test_13_read_only_retained(self):
        """13. read-only retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--read-only", cmd)

    def test_14_cpu_limit_retained(self):
        """14. CPU limit retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--cpus=2", cmd)

    def test_15_memory_limit_retained(self):
        """15. Memory limit retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--memory=2g", cmd)

    def test_16_pid_limit_retained(self):
        """16. PID limit retained."""
        cmd = build_docker_cmd(["whoami"])
        self.assertIn("--pids-limit=512", cmd)

    def test_17_existing_gateway_tests_pass(self):
        """17. Existing Gateway tests pass."""
        mock_output = {
            "tool": "http_probe",
            "target": "target-01",
            "path": "/",
            "status_code": 200,
            "headers": {},
            "body": "Mock response",
            "success": True,
        }
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: mock_output,
        )
        sess = self.session_manager.create_session("sess-orch-gw", "target-01")
        ev = self.evidence_collector.store_evidence("test", "target-01", {"status": "ok"})
        obs = sess.add_observation("obs-01", ev.evidence_id, "Init")
        hyp = sess.add_hypothesis("hyp-01", [obs.observation_id], "Root test")
        st = sess.add_safe_test("test-01", hyp.hypothesis_id, "http_probe", "Safe probe", "200", {"path": "/"})

        res = orch.execute_safe_test(st, sess)
        self.assertTrue(res["allowed"])
        self.assertEqual(res["status"], "success")

    def test_18_existing_controller_tests_pass(self):
        """18. Existing Controller tests pass."""
        mock_output = {
            "tool": "http_probe",
            "target": "target-01",
            "path": "/",
            "status_code": 200,
            "headers": {},
            "body": "Mock response",
            "success": True,
        }
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: mock_output,
        )
        controller = ResearchController(
            targets_config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            sessions_dir=self.sessions_dir,
            evidence_dir=self.evidence_dir,
            orchestrator=orch,
            evidence_collector=self.evidence_collector,
        )
        summary = controller.run("sess-ctrl-test", "target-01", limits=ResearchLimits(max_tests=1))
        self.assertEqual(summary.tests_executed, 1)

    def test_19_existing_gemini_tests_pass(self):
        """19. Existing Gemini tests pass."""
        def fake_provider(prompt):
            return json.dumps({
                "proposal_type": "new_hypothesis_and_test",
                "hypothesis_claim": "Gemini infrastructure check",
                "based_on_observations": ["obs-target-01-init"],
                "tool": "http_probe",
                "safety_justification": "Probe",
                "expected_outcome": "200",
                "parameters": {"path": "/", "method": "GET"},
            })

        adapter = GeminiReasoningAdapter(client=GeminiClient(provider=fake_provider))
        orch = GatewayOrchestrator(
            config_path=self.targets_file,
            allowlist_path=self.allowlist_file,
            evidence_collector=self.evidence_collector,
            executor_func=lambda t, p: {"success": True, "status_code": 200, "tool": "http_probe", "target": t["id"], "path": "/"},
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
        summary = controller.run("sess-gemini-infra", "target-01", limits=ResearchLimits(max_tests=1))
        self.assertEqual(summary.tests_executed, 1)


if __name__ == "__main__":
    unittest.main()


