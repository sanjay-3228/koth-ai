"""Unit tests for NvidiaDecisionEngine (NVIDIA NIM client).

Tests OpenAI-compatible completions, structured JSON schema parsing,
wall-clock API latency tracking, rate limit cooldown, target sanitization,
health check, and non-destructive smoke tests.
"""
import json
import time
import unittest
from unittest.mock import MagicMock, patch
import requests

from agent.nvidia_client import (
    Decision,
    NvidiaAPIError,
    NvidiaDecisionEngine,
    NvidiaRateLimitError,
    extract_json_from_text,
)


class TestNvidiaDecisionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = NvidiaDecisionEngine(
            api_key="nvapi-mock-test-key",
            base_url="https://integrate.api.nvidia.com/v1",
            fast_model="nvidia/nemotron-3.5-lightning-30b-a3b",
            reasoning_model="nvidia/nemotron-3-super-120b-a12b",
        )

    def _mock_openai_response(self, content_str: str, status_code: int = 200, headers: dict = None):
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = status_code
        mock_resp.headers = headers or {"Content-Type": "application/json"}
        mock_resp.text = json.dumps({
            "id": "chatcmpl-test-123",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "nvidia/nemotron-3.5-lightning-30b-a3b",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content_str,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        })
        mock_resp.json.return_value = json.loads(mock_resp.text)
        return mock_resp

    @patch("agent.nvidia_client.requests.post")
    def test_valid_json_decision(self, mock_post):
        payload = json.dumps({
            "action_type": "defend",
            "target": "10.0.1.5:80",
            "priority": "critical",
            "reasoning": "Port 80 is unresponsive.",
            "confidence": 0.95,
        })
        mock_post.return_value = self._mock_openai_response(payload)

        decision = self.engine.decide("telemetry summary", [])

        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.priority, "critical")
        self.assertEqual(decision.reasoning, "Port 80 is unresponsive.")
        self.assertEqual(decision.confidence, 0.95)
        self.assertGreaterEqual(decision.api_latency_ms, 0.0)

    @patch("agent.nvidia_client.requests.post")
    def test_markdown_fenced_json_parsing(self, mock_post):
        raw_text = """```json
{
  "action_type": "recon",
  "target": "10.0.2.1",
  "priority": "medium",
  "reasoning": "Need port scan."
}
```"""
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "recon")
        self.assertEqual(decision.target, "10.0.2.1")
        self.assertEqual(decision.priority, "medium")
        self.assertEqual(decision.reasoning, "Need port scan.")

    @patch("agent.nvidia_client.requests.post")
    def test_thinking_tokens_stripped(self, mock_post):
        raw_text = "<think>Considering web service outage...</think>{\"action_type\": \"defend\", \"target\": \"10.0.1.5:80\", \"priority\": \"high\", \"reasoning\": \"Recovering service\"}"
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.reasoning, "Recovering service")

    @patch("agent.nvidia_client.requests.post")
    def test_malformed_json_fallback(self, mock_post):
        raw_text = "{action_type: unquoted, broken"
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("Failed to parse", decision.reasoning)

    @patch("agent.nvidia_client.requests.post")
    def test_rate_limit_429_activates_cooldown(self, mock_post):
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 429
        mock_resp.headers = {"Retry-After": "5"}
        mock_resp.text = "Too Many Requests"
        mock_post.return_value = mock_resp

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("NVIDIA quota exhausted", decision.reasoning)
        self.assertTrue(self.engine._cooldown_remaining() > 0)

        # Subsequent call should immediately return cooldown fallback without network request
        mock_post.reset_mock()
        second_decision = self.engine.decide("telemetry summary", [])
        mock_post.assert_not_called()
        self.assertEqual(second_decision.action_type, "hold")
        self.assertIn("quota cooldown active", second_decision.reasoning)

    @patch("agent.nvidia_client.requests.post")
    def test_timeout_returns_safe_hold(self, mock_post):
        mock_post.side_effect = requests.Timeout("Connection timed out")

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("timed out", decision.reasoning.lower())

    def test_target_sanitization_rejects_injection(self):
        malicious = Decision(
            action_type="defend",
            target="10.0.1.5:80; rm -rf /",
            priority="critical",
            reasoning="injection attack",
        )
        sanitized = malicious.sanitize()
        self.assertEqual(sanitized.action_type, "hold")
        self.assertEqual(sanitized.target, "")
        self.assertIn("Target validation failed", sanitized.reasoning)

    @patch("agent.nvidia_client.requests.post")
    def test_health_check_healthy(self, mock_post):
        mock_post.return_value = self._mock_openai_response('{"status":"ok"}')

        status = self.engine.health_check()
        self.assertTrue(status["healthy"])
        self.assertTrue(status["api_key_configured"])
        self.assertTrue(status["endpoint_reachable"])
        self.assertTrue(status["model_responding"])
        self.assertTrue(status["json_parse_ok"])
        self.assertEqual(status["http_status"], 200)

    @patch("agent.nvidia_client.requests.post")
    def test_smoke_test_success(self, mock_post):
        mock_post.return_value = self._mock_openai_response('{"status":"ok"}')

        result = self.engine.smoke_test()
        self.assertTrue(result["success"])
        self.assertEqual(result["response_payload"], {"status": "ok"})
        self.assertGreaterEqual(result["api_latency_ms"], 0.0)

    # -------------------------------------------------------------------------
    # NVIDIA ADVISORY RESPONSE REGRESSION TESTS
    # -------------------------------------------------------------------------

    @patch("agent.nvidia_client.requests.post")
    def test_regression_1_valid_json(self, mock_post):
        """1. Valid JSON matching schema is properly parsed and validated."""
        payload = json.dumps({
            "decision": "HOLD",
            "priority": "LOW",
            "confidence": 0.82,
            "observation": "Target 10.0.1.5 baseline healthy; holding safely."
        })
        mock_post.return_value = self._mock_openai_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.priority, "low")
        self.assertEqual(decision.confidence, 0.82)
        self.assertEqual(decision.reasoning, "Target 10.0.1.5 baseline healthy; holding safely.")
        self.assertIsNotNone(decision.diagnostics)
        self.assertEqual(decision.diagnostics["http_status"], 200)
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertTrue(decision.diagnostics["validation_success"])
        self.assertEqual(decision.diagnostics["model_name"], self.engine.fast_model)
        self.assertGreater(decision.diagnostics["response_length"], 0)
        self.assertGreaterEqual(decision.diagnostics["latency_ms"], 0.0)

    @patch("agent.nvidia_client.requests.post")
    def test_regression_2_json_surrounded_only_by_whitespace(self, mock_post):
        """2. JSON surrounded only by whitespace is cleanly extracted and validated."""
        raw_text = """
        
        {
          "decision": "PRIORITIZE_HTTP",
          "priority": "HIGH",
          "confidence": 0.90,
          "observation": "HTTP service port 80 observed; prioritizing."
        }
        
        """
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "PRIORITIZE_HTTP")
        self.assertEqual(decision.priority, "high")
        self.assertEqual(decision.confidence, 0.90)
        self.assertEqual(decision.reasoning, "HTTP service port 80 observed; prioritizing.")
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertTrue(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_3_reasoning_prose_plus_valid_json(self, mock_post):
        """3. Reasoning/prose preceding valid JSON is stripped and the JSON object extracted."""
        raw_text = """Here's a thinking process:
1. Analyze User Input: Recon telemetry shows target 10.0.1.5 with port 80.
2. Formulate strategic recommendation: Recommend safe hold pending detailed telemetry.
3. Construct required output JSON matching expected schema.

{
  "decision": "HOLD",
  "priority": "LOW",
  "confidence": 0.82,
  "observation": "Target 10.0.1.5 reachable with HTTP service on port 80."
}
"""
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.priority, "low")
        self.assertEqual(decision.confidence, 0.82)
        self.assertEqual(decision.reasoning, "Target 10.0.1.5 reachable with HTTP service on port 80.")
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertTrue(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_4_malformed_json(self, mock_post):
        """4. Malformed JSON triggers SAFE_HOLD and never interprets prose as an action."""
        raw_text = "Here's a thinking process:\nWe should attack port 80 now.\n{ decision: unquoted, broken"
        mock_post.return_value = self._mock_openai_response(raw_text)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertFalse(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_5_missing_field(self, mock_post):
        """5. JSON missing required fields (e.g. confidence & observation) triggers SAFE_HOLD."""
        payload = json.dumps({
            "decision": "HOLD",
            "priority": "LOW"
        })
        mock_post.return_value = self._mock_openai_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_6_invalid_decision(self, mock_post):
        """6. Invalid decision enum value triggers SAFE_HOLD."""
        payload = json.dumps({
            "decision": "ATTACK_EXPLOIT_HOST",
            "priority": "HIGH",
            "confidence": 0.95,
            "observation": "Attempting exploit"
        })
        mock_post.return_value = self._mock_openai_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_7_invalid_confidence(self, mock_post):
        """7. Invalid confidence value (out of [0.0, 1.0] range or non-numeric) triggers SAFE_HOLD."""
        payload = json.dumps({
            "decision": "HOLD",
            "priority": "LOW",
            "confidence": 1.45,
            "observation": "Confidence too high"
        })
        mock_post.return_value = self._mock_openai_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertTrue(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_8_empty_response(self, mock_post):
        """8. Empty response text triggers SAFE_HOLD."""
        mock_post.return_value = self._mock_openai_response("")

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertEqual(decision.diagnostics["response_length"], 0)
        self.assertFalse(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])

    @patch("agent.nvidia_client.requests.post")
    def test_regression_9_nvidia_http_error(self, mock_post):
        """9. NVIDIA API HTTP error (e.g. 500) triggers SAFE_HOLD with status logged."""
        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 500
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.text = "Internal Server Error"
        mock_post.return_value = mock_resp

        decision = self.engine.decide_from_recon({"target": "10.0.1.5", "open_ports": [80]})

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.confidence, 0.0)
        self.assertIn("SAFE_HOLD", decision.reasoning)
        self.assertEqual(decision.diagnostics["http_status"], 500)
        self.assertFalse(decision.diagnostics["parse_success"])
        self.assertFalse(decision.diagnostics["validation_success"])


if __name__ == "__main__":
    unittest.main()
