"""Tests for SafetyGateManager, LIVE readiness validation, and RateLimiter."""
import time
import unittest

from agent.config import Config
from agent.security.safety_gates import RateLimiter, SafetyGateError, SafetyGateManager


class TestSafetyGates(unittest.TestCase):
    def test_dry_run_startup_allowed_with_partial_config(self):
        # In DRY_RUN, agent should never crash even if live configs are absent
        cfg = Config(
            koth_mode="DRY_RUN",
            own_services=[],
            target_hosts=[],
            allowed_plugins=[],
        )
        manager = SafetyGateManager(cfg)
        # Should not raise
        manager.validate_for_start()

    def test_live_startup_refused_when_own_services_missing(self):
        cfg = Config(
            koth_mode="LIVE",
            own_services=[],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_plugin"],
        )
        cfg.dry_run = False
        manager = SafetyGateManager(cfg)
        with self.assertRaises(SafetyGateError) as ctx:
            manager.validate_for_start()
        self.assertIn("OWN_SERVICES_CONFIGURED", str(ctx.exception))

    def test_live_startup_refused_when_target_hosts_missing(self):
        cfg = Config(
            koth_mode="LIVE",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=[],
            allowed_plugins=["test_plugin"],
        )
        cfg.dry_run = False
        manager = SafetyGateManager(cfg)
        with self.assertRaises(SafetyGateError) as ctx:
            manager.validate_for_start()
        self.assertIn("TARGET_HOSTS_CONFIGURED", str(ctx.exception))

    def test_live_startup_refused_when_allowed_plugins_missing(self):
        cfg = Config(
            koth_mode="LIVE",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=[],
        )
        cfg.dry_run = False
        manager = SafetyGateManager(cfg)
        with self.assertRaises(SafetyGateError) as ctx:
            manager.validate_for_start()
        self.assertIn("ALLOWED_PLUGINS_CONFIGURED", str(ctx.exception))

    def test_live_startup_refused_when_kill_switch_engaged(self):
        cfg = Config(
            koth_mode="LIVE",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_plugin"],
            kill_switch=True,
        )
        cfg.dry_run = False
        manager = SafetyGateManager(cfg)
        with self.assertRaises(SafetyGateError) as ctx:
            manager.validate_for_start()
        self.assertIn("KILL_SWITCH_STATUS", str(ctx.exception))

    def test_live_startup_succeeds_when_all_criteria_met(self):
        cfg = Config(
            koth_mode="LIVE",
            own_services=["10.0.1.5:80:web-service"],
            target_hosts=["198.51.100.10"],
            allowed_plugins=["test_plugin"],
            kill_switch=False,
            max_actions_per_minute=10,
            action_timeout_seconds=5.0,
        )
        cfg.dry_run = False
        manager = SafetyGateManager(cfg)
        manager.validate_for_start()
        gates = manager.evaluate_gates()
        failing = [g for g in gates if not g.passed]
        self.assertEqual(len(failing), 0)

    def test_rate_limiter(self):
        limiter = RateLimiter(max_actions_per_minute=3)
        self.assertTrue(limiter.allow())
        self.assertTrue(limiter.allow())
        self.assertTrue(limiter.allow())
        self.assertFalse(limiter.allow())  # 4th in same minute rejected
        self.assertEqual(limiter.current_usage, 3)


if __name__ == "__main__":
    unittest.main()
