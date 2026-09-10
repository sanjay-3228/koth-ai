"""Unit tests verifying Monitor -> Router integration and deterministic Local Policy routing."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock

from agent.config import Config
from agent.gemini_client import Decision
from agent.model_router import ModelRouter


@dataclass
class MockTelemetryService:
    host: str
    port: int
    up: bool
    note: str = ""


@dataclass
class MockTelemetry:
    our_score: float = 100.0
    rank: int = 1
    our_services: List[MockTelemetryService] = None
    competitor_scores: Dict[str, float] = None
    raw: Any = None

    def __post_init__(self):
        if self.our_services is None:
            self.our_services = [
                MockTelemetryService(host="10.0.1.5", port=80, up=True),
                MockTelemetryService(host="10.0.1.5", port=443, up=True),
            ]
        if self.competitor_scores is None:
            self.competitor_scores = {"team2": 80.0}
        if self.raw is None:
            self.raw = {}


class TestMonitorRouterIntegration(unittest.TestCase):
    def setUp(self):
        self.router = ModelRouter()
        self.mock_brain = MagicMock()
        # Brain decide should never be called when local policy triggers
        self.mock_brain.decide.side_effect = AssertionError("Gemini brain should NOT be called during local policy execution!")

    def test_tampered_file_selects_local_policy(self):
        """Proof: When a file has been tampered, local policy is deterministically selected."""
        telemetry = MockTelemetry()
        monitor_snapshot = {
            "tampered_files": ["/var/www/html/index.php"],
            "services": [{"host": "10.0.1.5", "port": 80, "up": True}],
            "down_services": [],
        }

        decision = self.router.execute_decision(
            telemetry=telemetry,
            telemetry_summary="all services up",
            recent_actions=[],
            brain=self.mock_brain,
            monitor_snapshot=monitor_snapshot,
        )

        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.priority, "critical")
        self.assertIn("File tampering detected", decision.reasoning)
        self.mock_brain.decide.assert_not_called()

    def test_single_down_service_selects_local_policy(self):
        """Proof: When a single service is down, local policy is deterministically selected."""
        telemetry = MockTelemetry()
        monitor_snapshot = {
            "tampered_files": [],
            "services": [
                {"host": "10.0.1.5", "port": 80, "up": False},
                {"host": "10.0.1.5", "port": 443, "up": True},
            ],
            "down_services": [{"host": "10.0.1.5", "port": 80}],
        }

        decision = self.router.execute_decision(
            telemetry=telemetry,
            telemetry_summary="port 80 is down",
            recent_actions=[],
            brain=self.mock_brain,
            monitor_snapshot=monitor_snapshot,
        )

        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:80")
        self.assertEqual(decision.priority, "critical")
        self.assertIn("Deterministic service restart", decision.reasoning)
        self.mock_brain.decide.assert_not_called()

    def test_single_down_service_in_telemetry_selects_local_policy(self):
        """Proof: When a single service down is reported via telemetry without monitor snapshot, local policy triggers."""
        telemetry = MockTelemetry(
            our_services=[
                MockTelemetryService(host="10.0.1.5", port=443, up=False),
                MockTelemetryService(host="10.0.1.5", port=80, up=True),
            ]
        )

        decision = self.router.execute_decision(
            telemetry=telemetry,
            telemetry_summary="port 443 is down",
            recent_actions=[],
            brain=self.mock_brain,
            monitor_snapshot=None,
        )

        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "defend")
        self.assertEqual(decision.target, "10.0.1.5:443")
        self.assertEqual(decision.priority, "critical")
        self.assertIn("Deterministic service restart", decision.reasoning)
        self.mock_brain.decide.assert_not_called()

    def test_scoreboard_failure_selects_safe_local_policy_none_telemetry(self):
        """Proof: None telemetry triggers safe local policy hold without calling AI."""
        decision = self.router.execute_decision(
            telemetry=None,
            telemetry_summary="telemetry failed",
            recent_actions=[],
            brain=self.mock_brain,
            monitor_snapshot=None,
        )

        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Scoreboard telemetry unavailable", decision.reasoning)
        self.mock_brain.decide.assert_not_called()

    def test_scoreboard_failure_selects_safe_local_policy_error_dict(self):
        """Proof: Raw error dict in telemetry triggers safe local policy hold without calling AI."""
        telemetry = MockTelemetry(raw={"error": "Connection timed out to scoreboard"})

        decision = self.router.execute_decision(
            telemetry=telemetry,
            telemetry_summary="telemetry timeout",
            recent_actions=[],
            brain=self.mock_brain,
            monitor_snapshot=None,
        )

        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "hold")
        self.assertIn("Scoreboard unreachable", decision.reasoning)
        self.mock_brain.decide.assert_not_called()


if __name__ == "__main__":
    unittest.main()
