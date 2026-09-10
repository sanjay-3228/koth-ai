"""Unit tests for GeminiDecisionEngine JSON parsing and fallback behaviors."""
import json
import unittest
from unittest.mock import MagicMock, patch

from agent.gemini_client import Decision, GeminiDecisionEngine


class TestGeminiDecisionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = GeminiDecisionEngine(api_key="test-key", model="gemini-test")

    def _mock_response(self, text_payload: str):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": text_payload}
                        ]
                    }
                }
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    @patch("agent.gemini_client.requests.post")
    def test_valid_json_decision(self, mock_post):
        payload = json.dumps({
            "action_type": "defend",
            "target": "10.0.1.5:80",
            "priority": "critical",
            "reasoning": "Port 80 is unresponsive.",
        })
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide("telemetry summary", [])

        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.priority, "critical")
        self.assertEqual(decision.reasoning, "Port 80 is unresponsive.")

    @patch("agent.gemini_client.requests.post")
    def test_markdown_fenced_json_parsing(self, mock_post):
        raw_text = """```json
{
  "action_type": "recon",
  "target": "10.0.2.1",
  "priority": "medium",
  "reasoning": "Need port scan."
}
```"""
        mock_post.return_value = self._mock_response(raw_text)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "recon")
        self.assertEqual(decision.target, "10.0.2.1")
        self.assertEqual(decision.priority, "medium")
        self.assertEqual(decision.reasoning, "Need port scan.")

    @patch("agent.gemini_client.requests.post")
    def test_malformed_json_syntax_fallback(self, mock_post):
        # Invalid JSON syntax (unquoted keys, trailing garbage)
        raw_text = "{action_type: 'defend', target: '10.0.0.1'"
        mock_post.return_value = self._mock_response(raw_text)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Failed to parse decision", decision.reasoning)

    @patch("agent.gemini_client.requests.post")
    def test_missing_fields_schema_mismatch_fallback(self, mock_post):
        # Missing required dataclass fields: action_type, priority, reasoning
        payload = json.dumps({"target": "10.0.1.5:80"})
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Failed to parse decision", decision.reasoning)

    @patch("agent.gemini_client.requests.post")
    def test_extra_unexpected_fields_fallback(self, mock_post):
        # Unexpected fields cause TypeError during Decision(**parsed)
        payload = json.dumps({
            "action_type": "hold",
            "target": "",
            "priority": "low",
            "reasoning": "Standard hold",
            "unexpected_extra_key": "causes_type_error",
        })
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Failed to parse decision", decision.reasoning)

    @patch("agent.gemini_client.requests.post")
    def test_empty_string_response_fallback(self, mock_post):
        mock_post.return_value = self._mock_response("")

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Failed to parse decision", decision.reasoning)

    @patch("agent.gemini_client.requests.post")
    def test_non_dict_json_response_fallback(self, mock_post):
        # Returning a JSON list instead of an object
        payload = json.dumps(["defend", "10.0.1.5:80"])
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide("telemetry summary", [])

        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Failed to parse decision", decision.reasoning)

    def test_default_model_and_normalization(self):
        engine_default = GeminiDecisionEngine()
        self.assertEqual(engine_default.model, "nvidia/nemotron-3.5-lightning-30b-a3b")

        engine_custom = GeminiDecisionEngine(model="nvidia/nemotron-3.5-lightning-30b-a3b")
        self.assertEqual(engine_custom.model, "nvidia/nemotron-3.5-lightning-30b-a3b")

    @patch("agent.gemini_client.requests.post")
    def test_decide_from_recon_strictly_advisory(self, mock_post):
        payload = json.dumps({
            "decision": "PRIORITIZE_HTTP",
            "target": "10.49.134.114:80",
            "priority": "high",
            "reasoning": "Observed HTTP service.",
            "confidence": 0.85,
        })
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.49.134.114", "open_ports": [80]})

        self.assertEqual(decision.proposed_decision, "PRIORITIZE_HTTP")
        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "10.49.134.114:80")
        self.assertEqual(decision.priority, "high")
        self.assertEqual(decision.confidence, 0.85)

    @patch("agent.gemini_client.requests.post")
    def test_decide_from_recon_neutralizes_attack_decision_and_shell_injection(self, mock_post):
        payload = json.dumps({
            "decision": "attack",
            "target": "10.49.134.114; cat /etc/passwd",
            "reasoning": "Malicious payload attempt",
        })
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.decide_from_recon({"target": "10.49.134.114", "open_ports": [80]})

        self.assertEqual(decision.proposed_decision, "HOLD")
        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.target, "")

    @patch("agent.gemini_client.requests.post")
    def test_analyze_test_result_returns_advisory(self, mock_post):
        payload = json.dumps({
            "decision": "NO_ACTION",
            "reasoning": "Testing concluded; hold safe position.",
            "confidence": 0.9,
        })
        mock_post.return_value = self._mock_response(payload)

        decision = self.engine.analyze_test_result({"status": "no_action", "reason": "No plugin available"})

        self.assertEqual(decision.proposed_decision, "NO_ACTION")
        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.confidence, 0.9)


if __name__ == "__main__":
    unittest.main()


