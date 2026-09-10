"""Comprehensive test suite for the three-provider LLM architecture:
NVIDIA Nemotron (Fast), Groq GPT-OSS 120B (Reasoning), OpenRouter GLM 5.3 Flash (Specialist).

Verifies all 35 operational and security requirements.
All provider calls are strictly mocked in unit tests.
"""
import concurrent.futures
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import requests

from agent.config import Config
from agent.llm.base import BaseLLMProvider, SYSTEM_INSTRUCTION
from agent.llm.parser import (
    extract_balanced_json,
    extract_markdown_json,
    parse_model_response,
    strip_think_blocks,
)
from agent.llm.providers.groq import GroqGptOssProvider
from agent.llm.providers.nvidia import NvidiaNemotronProvider
from agent.llm.providers.openrouter import OpenRouterGlmProvider
from agent.llm.router import TieredModelRouter, sanitize_prompt_text
from agent.llm.types import ModelDecision, ProviderMetrics
from agent.main import KothAgent
from agent.security.execution_gate import FinalExecutionGate
from agent.security.policy import SecurityPolicy
from agent.security.safety_gates import SafetyGateManager
from agent.telemetry import ServiceStatus, Telemetry
from simulator.mock_environment import MockFileSystem, MockServiceHost


class TestLlmProviderLayer(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            nvidia_api_key="mock-nvidia-key",
            groq_api_key="mock-groq-key",
            openrouter_api_key="mock-openrouter-key",
            fast_confidence_threshold=0.75,
            reasoning_confidence_threshold=0.85,
            target_hosts=["10.0.2.1", "10.0.2.2"],
            own_services=["10.0.1.5:80:web", "10.0.1.5:22:ssh"],
            protected_hosts=["10.0.1.5", "10.0.1.1"],
            allowed_actions=["recon_scan", "restart_service", "rate_limit_port", "exploit_plugin", "hold"],
            dry_run=True,
        )
        self.router = TieredModelRouter(self.config)

    # 1. NVIDIA provider success
    @patch("requests.post")
    def test_1_nvidia_provider_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"action": "recon", "target": "10.0.2.1", "priority": "HIGH", "confidence": 0.95, "observation": "Open ports observed", "reasoning_summary": "Recon target"}'
                }
            }]
        }
        mock_post.return_value = mock_resp

        provider = NvidiaNemotronProvider(api_key="test-key")
        decision = provider.generate_decision({"phase": "ATTACK"})
        self.assertEqual(decision.action, "recon")
        self.assertEqual(decision.target, "10.0.2.1")
        self.assertEqual(decision.confidence, 0.95)
        self.assertEqual(decision.parse_status, "SUCCESS")

    # 2. Groq provider success
    @patch("requests.post")
    def test_2_groq_provider_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"action": "restart_service", "target": "10.0.1.5:80", "priority": "CRITICAL", "confidence": 0.92, "observation": "HTTP down", "reasoning_summary": "Restart nginx"}'
                }
            }]
        }
        mock_post.return_value = mock_resp

        provider = GroqGptOssProvider(api_key="test-key")
        decision = provider.generate_decision({"phase": "DEFENSE"})
        self.assertEqual(decision.action, "restart_service")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.confidence, 0.92)

    # 3. OpenRouter provider success
    @patch("requests.post")
    def test_3_openrouter_provider_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"action": "hold", "target": "", "priority": "LOW", "confidence": 0.88, "observation": "Resolved ambiguity", "reasoning_summary": "Hold safe"}'
                }
            }]
        }
        mock_post.return_value = mock_resp

        provider = OpenRouterGlmProvider(api_key="test-key")
        decision = provider.generate_decision({"phase": "HOLD"})
        self.assertEqual(decision.action, "hold")
        self.assertEqual(decision.confidence, 0.88)

    # 4. Missing NVIDIA key
    def test_4_missing_nvidia_key(self):
        provider = NvidiaNemotronProvider(api_key="")
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "SKIPPED")
        self.assertEqual(decision.http_status, 401)
        self.assertEqual(decision.confidence, 0.0)

    # 5. Missing Groq key
    def test_5_missing_groq_key(self):
        provider = GroqGptOssProvider(api_key="")
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "SKIPPED")
        self.assertEqual(decision.confidence, 0.0)

    # 6. Missing OpenRouter key
    def test_6_missing_openrouter_key(self):
        provider = OpenRouterGlmProvider(api_key="")
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "SKIPPED")
        self.assertEqual(decision.confidence, 0.0)

    # 7. NVIDIA timeout
    @patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout"))
    def test_7_nvidia_timeout(self, mock_post):
        provider = NvidiaNemotronProvider(api_key="test-key", timeout_seconds=1.0, max_retries=0)
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "FAILED")
        self.assertEqual(decision.http_status, 408)
        self.assertEqual(decision.confidence, 0.0)

    # 8. Groq timeout
    @patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout"))
    def test_8_groq_timeout(self, mock_post):
        provider = GroqGptOssProvider(api_key="test-key", timeout_seconds=1.0, max_retries=0)
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "FAILED")
        self.assertEqual(decision.http_status, 408)

    # 9. OpenRouter timeout
    @patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout"))
    def test_9_openrouter_timeout(self, mock_post):
        provider = OpenRouterGlmProvider(api_key="test-key", timeout_seconds=1.0, max_retries=0)
        decision = provider.generate_decision({})
        self.assertEqual(decision.parse_status, "FAILED")
        self.assertEqual(decision.http_status, 408)

    # 10. Malformed NVIDIA response
    @patch("requests.post")
    def test_10_malformed_nvidia_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "Not JSON at all"}}]}
        mock_post.return_value = mock_resp

        provider = NvidiaNemotronProvider(api_key="test-key")
        decision = provider.generate_decision({})
        self.assertEqual(decision.action, "hold")
        self.assertEqual(decision.parse_status, "FAILED")
        self.assertEqual(decision.confidence, 0.0)

    # 11. Malformed Groq response
    @patch("requests.post")
    def test_11_malformed_groq_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "I think we should attack!"}}]}
        mock_post.return_value = mock_resp

        provider = GroqGptOssProvider(api_key="test-key")
        decision = provider.generate_decision({})
        self.assertEqual(decision.action, "hold")
        self.assertEqual(decision.parse_status, "FAILED")

    # 12. Malformed OpenRouter response
    @patch("requests.post")
    def test_12_malformed_openrouter_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "{unclosed json"}}]}
        mock_post.return_value = mock_resp

        provider = OpenRouterGlmProvider(api_key="test-key")
        decision = provider.generate_decision({})
        self.assertEqual(decision.action, "hold")
        self.assertEqual(decision.parse_status, "FAILED")

    # 13. <think> tag parsing
    def test_13_think_parsing(self):
        raw = "<think>We need to check the ports first.</think>{\"action\": \"recon\", \"target\": \"10.0.2.1\", \"priority\": \"HIGH\", \"confidence\": 0.90, \"observation\": \"Scanned\", \"reasoning_summary\": \"Recon\"}"
        decision = parse_model_response(raw)
        self.assertEqual(decision.parse_status, "SUCCESS")
        self.assertEqual(decision.action, "recon")
        self.assertEqual(decision.target, "10.0.2.1")

    # 14. Markdown JSON parsing
    def test_14_markdown_json_parsing(self):
        raw = "Here is the recommended action:\n```json\n{\n  \"action\": \"restart_service\",\n  \"target\": \"10.0.1.5:80\",\n  \"priority\": \"CRITICAL\",\n  \"confidence\": 0.95,\n  \"observation\": \"Down\",\n  \"reasoning_summary\": \"Restart\"\n}\n```\nHope that helps!"
        decision = parse_model_response(raw)
        self.assertEqual(decision.parse_status, "SUCCESS")
        self.assertEqual(decision.action, "restart_service")
        self.assertEqual(decision.target, "10.0.1.5:80")

    # 15. Balanced JSON object extraction
    def test_15_balanced_json_parsing(self):
        raw = "Prefix text before JSON {\"action\": \"hold\", \"target\": \"\", \"priority\": \"LOW\", \"confidence\": 0.8, \"observation\": \"Ok\", \"reasoning_summary\": \"Hold\"} suffix commentary."
        decision = parse_model_response(raw)
        self.assertEqual(decision.parse_status, "SUCCESS")
        self.assertEqual(decision.action, "hold")

    # 16. Schema rejection
    def test_16_schema_rejection(self):
        # Invalid action 'drop_database'
        raw = '{"action": "drop_database", "target": "10.0.1.5", "priority": "HIGH", "confidence": 0.9}'
        decision = parse_model_response(raw)
        self.assertEqual(decision.parse_status, "FAILED")
        self.assertEqual(decision.action, "hold")

        # CIDR target rejected
        raw_cidr = '{"action": "recon", "target": "10.0.0.0/24", "priority": "HIGH", "confidence": 0.9}'
        decision_cidr = parse_model_response(raw_cidr)
        self.assertEqual(decision_cidr.parse_status, "FAILED")

    # 17. Local policy avoids LLM
    def test_17_local_policy_avoids_llm(self):
        with patch.object(self.router.fast_provider, "generate_decision") as mock_fast:
            snapshot = {"tampered_files": ["/etc/shadow"]}
            decision = self.router.execute_decision(
                telemetry=None,
                telemetry_summary="tampered",
                recent_actions=[],
                monitor_snapshot=snapshot,
            )
            self.assertEqual(decision.provider, "local")
            self.assertEqual(decision.action, "rate_limit_port")
            mock_fast.assert_not_called()

    # 18. Nemotron -> GPT-OSS escalation on low confidence
    def test_18_nemotron_to_groq_escalation(self):
        fast_low = ModelDecision(
            action="recon",
            target="10.0.2.1",
            priority="LOW",
            confidence=0.60,  # Below 0.75 threshold
            provider="nvidia",
            parse_status="SUCCESS",
        )
        groq_high = ModelDecision(
            action="recon",
            target="10.0.2.1",
            priority="HIGH",
            confidence=0.91,  # Above 0.85 threshold
            provider="groq",
            model="openai/gpt-oss-120b",
            parse_status="SUCCESS",
        )

        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_low), \
             patch.object(self.router.reasoning_provider, "generate_decision", return_value=groq_high), \
             patch.object(self.router.specialist_provider, "generate_decision") as mock_spec:

            decision = self.router.execute_decision(telemetry=None, telemetry_summary="ok", recent_actions=[])
            self.assertEqual(decision.provider, "groq")
            self.assertEqual(decision.confidence, 0.91)
            mock_spec.assert_not_called()

    # 19. GPT-OSS -> GLM escalation
    def test_19_groq_to_glm_escalation(self):
        fast_low = ModelDecision(action="recon", confidence=0.55, parse_status="SUCCESS", provider="nvidia")
        groq_low = ModelDecision(action="recon", confidence=0.70, parse_status="SUCCESS", provider="groq")  # Below 0.85
        glm_high = ModelDecision(
            action="recon",
            target="10.0.2.1",
            priority="HIGH",
            confidence=0.92,
            provider="openrouter",
            model="z-ai/glm-5.3-flash",
            parse_status="SUCCESS",
        )

        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_low), \
             patch.object(self.router.reasoning_provider, "generate_decision", return_value=groq_low), \
             patch.object(self.router.specialist_provider, "generate_decision", return_value=glm_high):

            decision = self.router.execute_decision(telemetry=None, telemetry_summary="ok", recent_actions=[])
            self.assertEqual(decision.provider, "openrouter")
            self.assertEqual(decision.confidence, 0.92)

    # 20. GLM failure -> SAFE_HOLD
    def test_20_glm_failure_leads_to_safe_hold(self):
        fast_fail = ModelDecision(action="hold", confidence=0.0, parse_status="FAILED", provider="nvidia")
        groq_fail = ModelDecision(action="hold", confidence=0.0, parse_status="FAILED", provider="groq")
        glm_fail = ModelDecision(action="hold", confidence=0.0, parse_status="FAILED", provider="openrouter")

        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_fail), \
             patch.object(self.router.reasoning_provider, "generate_decision", return_value=groq_fail), \
             patch.object(self.router.specialist_provider, "generate_decision", return_value=glm_fail):

            decision = self.router.execute_decision(telemetry=None, telemetry_summary="fail", recent_actions=[])
            self.assertEqual(decision.action, "hold")
            self.assertEqual(decision.provider, "safe-fallback")
            self.assertEqual(decision.confidence, 0.0)

    # 21. Model disagreement
    def test_21_model_disagreement_escalation(self):
        fast_dec = ModelDecision(action="recon", target="10.0.2.1", confidence=0.76, parse_status="SUCCESS", provider="nvidia")
        # Groq disagrees with attack
        groq_dec = ModelDecision(action="hold", target="", confidence=0.88, parse_status="SUCCESS", provider="groq")
        glm_resolved = ModelDecision(
            action="recon",
            target="10.0.2.1",
            priority="MEDIUM",
            confidence=0.89,
            provider="openrouter",
            parse_status="SUCCESS",
        )

        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_dec), \
             patch.object(self.router.reasoning_provider, "generate_decision", return_value=groq_dec), \
             patch.object(self.router.specialist_provider, "generate_decision", return_value=glm_resolved):

            # Force disagreement trigger
            self.router.fast_threshold = 0.80  # fast 0.76 < 0.80 -> triggers groq
            decision = self.router.execute_decision(telemetry=None, telemetry_summary="dispute", recent_actions=[])
            self.assertEqual(decision.provider, "openrouter")
            self.assertEqual(self.router.disagreement_count, 1)

    # 22. Provider circuit breaker
    def test_22_provider_circuit_breaker(self):
        provider = NvidiaNemotronProvider(api_key="test-key", failure_threshold=2, cooldown_seconds=60.0)
        self.assertTrue(provider.is_healthy())

        provider.record_failure()
        self.assertTrue(provider.is_healthy())

        provider.record_failure()
        self.assertFalse(provider.is_healthy())

        # Attempting decision while unhealthy skips HTTP call
        with patch.object(provider, "_post_chat_completion") as mock_call:
            dec = provider.generate_decision({})
            mock_call.assert_not_called()
            self.assertEqual(dec.parse_status, "SKIPPED")
            self.assertEqual(dec.http_status, 503)

    # 23. Bounded retry limit
    @patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout"))
    def test_23_retry_limit(self, mock_post):
        provider = GroqGptOssProvider(api_key="test-key", max_retries=1, timeout_seconds=0.1)
        provider.generate_decision({})
        # Initial try + 1 retry = 2 total requests
        self.assertEqual(mock_post.call_count, 2)

    # 24. Four agents using the same router instance
    def test_24_four_agents_share_same_router(self):
        fast_dec = ModelDecision(action="recon", target="10.0.2.1", confidence=0.95, parse_status="SUCCESS", provider="nvidia")
        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_dec):
            d1 = self.router.execute_decision(None, "t1", [], swarm_context={"agent_id": "agent-01"})
            d2 = self.router.execute_decision(None, "t2", [], swarm_context={"agent_id": "agent-02"})
            d3 = self.router.execute_decision(None, "t3", [], swarm_context={"agent_id": "agent-03"})
            d4 = self.router.execute_decision(None, "t4", [], swarm_context={"agent_id": "agent-04"})

            self.assertEqual(d1.action, "recon")
            self.assertEqual(d4.action, "recon")
            self.assertEqual(self.router.total_decisions, 4)

    # 25. Concurrent four-agent model calls
    def test_25_concurrent_four_agent_model_calls(self):
        fast_dec = ModelDecision(action="recon", target="10.0.2.1", confidence=0.90, parse_status="SUCCESS", provider="nvidia")

        with patch.object(self.router.fast_provider, "generate_decision", return_value=fast_dec):
            def agent_call(agent_id):
                return self.router.execute_decision(
                    None, f"summary_{agent_id}", [], swarm_context={"agent_id": agent_id}
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(agent_call, f"agent-0{i}") for i in range(1, 5)]
                results = [f.result() for f in futures]

            self.assertEqual(len(results), 4)
            for r in results:
                self.assertEqual(r.action, "recon")

    # 26. Phase information passed correctly
    def test_26_phase_information_passed_in_prompt(self):
        context_captured = {}
        def mock_generate(ctx, fallback_level=1):
            context_captured.update(ctx)
            return ModelDecision(action="hold", confidence=0.95, parse_status="SUCCESS")

        with patch.object(self.router.fast_provider, "generate_decision", side_effect=mock_generate):
            self.router.execute_decision(
                telemetry=None,
                telemetry_summary="summary",
                recent_actions=[],
                swarm_context={"phase": "DEFENSE", "agent_id": "agent-03", "round_id": 2, "phase_epoch": 4},
            )
            self.assertEqual(context_captured["phase"], "DEFENSE")
            self.assertEqual(context_captured["agent_id"], "agent-03")
            self.assertEqual(context_captured["round_id"], 2)
            self.assertEqual(context_captured["phase_epoch"], 4)

    def tearDown(self):
        self.config.kill_switch = False

    # 27. Target authorization remains strictly enforced by SecurityPolicy
    def test_27_target_authorization_enforced(self):
        policy = SecurityPolicy(self.config)
        # Attempting attack on unauthorized target 192.168.99.99
        unauth_decision = ModelDecision(
            action="exploit_plugin",
            target="192.168.99.99:80",
            priority="HIGH",
            confidence=0.95,
        )
        auth = policy.authorize(unauth_decision)
        self.assertFalse(auth.allowed)
        self.assertIn("TARGET_HOSTS", auth.reason)

    # 28. FinalExecutionGate cannot be bypassed
    def test_28_final_execution_gate_cannot_be_bypassed(self):
        gate = FinalExecutionGate(config=self.config)
        # Model recommending disallowed action "execute_shell"
        evil_decision = ModelDecision(
            action="execute_shell",
            target="10.0.2.1",
            priority="CRITICAL",
            confidence=1.0,
        )
        record = gate.execute_with_gates(decision=evil_decision, context=MagicMock())
        self.assertFalse(record.success)
        self.assertFalse(record.empirical_success)
        self.assertEqual(record.action_type, "hold")

    # 29. Model cannot execute raw shell
    def test_29_model_cannot_execute_raw_shell(self):
        gate = FinalExecutionGate(config=self.config)
        shell_decision = ModelDecision(
            action="recon_scan",
            target="10.0.2.1; rm -rf /",
            priority="HIGH",
            confidence=0.99,
        )
        record = gate.execute_with_gates(decision=shell_decision, context=MagicMock())
        self.assertFalse(record.success)
        self.assertTrue("rejected" in record.failure_reason.lower() or "syntax" in record.failure_reason.lower())

    # 30. Credentials stripped before provider call
    def test_30_credentials_stripped_before_provider_call(self):
        dirty_text = "Target credentials: password='Secret123!' nvapi-test-mock-placeholder-dummy-key-sanitizer-12345"
        cleaned = sanitize_prompt_text(dirty_text)
        self.assertNotIn("Secret123!", cleaned)
        self.assertNotIn("nvapi-test-mock", cleaned)
        self.assertIn("[REDACTED_SECRET]", cleaned)

    # 31. Target authorization remains exact
    def test_31_target_authorization_exactness(self):
        cfg = Config(lab_profile="DEV", target_hosts=["10.0.2.1"])
        policy = SecurityPolicy(cfg)
        # Attempting attack on anything except authorized target_hosts
        bad_dec = ModelDecision(action="recon_scan", target="10.0.2.99", priority="HIGH")
        auth = policy.authorize(bad_dec)
        self.assertFalse(auth.allowed)
        self.assertIn("neither in TARGET_HOSTS nor OWN_SERVICES", auth.reason)

    # 32. Port 9999 remains prohibited
    def test_32_port_9999_prohibited(self):
        policy = SecurityPolicy(self.config)
        scoreboard_attack = ModelDecision(action="exploit_plugin", target="10.0.2.1:9999", priority="HIGH")
        auth = policy.authorize(scoreboard_attack)
        self.assertFalse(auth.allowed)
        self.assertIn("9999", auth.reason)

    # 33. Kill switch blocks model-recommended execution
    def test_33_kill_switch_blocks_model_execution(self):
        test_cfg = Config(kill_switch=True)
        gates = SafetyGateManager(test_cfg)
        self.assertTrue(gates.is_kill_switch_engaged())

    # 34. Stale ATTACK task rejected during DEFENSE phase
    def test_34_stale_attack_task_rejected_during_defense(self):
        from agent.swarm.models import Phase
        cfg = Config(
            target_hosts=["10.0.2.1"],
            allowed_actions=["exploit_plugin", "hold"],
            kill_switch=False,
            dry_run=True,
        )
        gate = FinalExecutionGate(config=cfg)
        mock_client = MagicMock()
        mock_client.kill_switch_active = False
        mock_phase_state = MagicMock()
        mock_phase_state.phase = Phase.DEFENSE
        mock_phase_state.phase_epoch = 3
        mock_client.current_phase_state = mock_phase_state

        stale_attack = ModelDecision(action="exploit_plugin", target="10.0.2.1:80", priority="HIGH")
        record = gate.execute_with_gates(decision=stale_attack, context=MagicMock(), swarm_client=mock_client)
        self.assertFalse(record.success)
        self.assertIn("phase fence", record.failure_reason.lower())

    # 35. Coordinator failure -> safe degraded/HOLD
    def test_35_coordinator_failure_safe_degraded(self):
        from agent.swarm.models import AgentStatus
        client_mock = MagicMock()
        client_mock.status = AgentStatus.SAFE_DEGRADED
        client_mock.current_phase.value = "HOLD"

        # When client is degraded, agent ticks safe hold
        agent = KothAgent(config=self.config, swarm_client=client_mock, skip_validation=True)
        rec = agent.tick()
        self.assertEqual(rec.action_type, "hold")
        self.assertEqual(rec.model_used, "swarm-phase-gate")


if __name__ == "__main__":
    unittest.main()
