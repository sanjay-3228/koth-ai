"""Tests for PwnGrounds network and environment adapter.

Covers all 15 test scenarios using unittest.TestCase:
  1. Wi-Fi only environment classification
  2. Wi-Fi + VPN environment classification
  3. VPN only environment classification
  4. Unknown environment classification
  5. No competition route detected
  6. Wrong network VPN (VPN connected to wrong subnet)
  7. Malformed/invalid CIDR configuration handling
  8. Destination outside competition CIDR rejected -> safe HOLD
  9. Attack target not in authorized TARGET_HOSTS rejected -> safe HOLD
 10. Defend target not in configured OWN_SERVICES rejected -> safe HOLD
 11. Destination format injection / invalid syntax rejected -> safe HOLD
 12. Kill-switch engaged enforces safe HOLD
 13. Rate-limiter saturation causes safe HOLD
 14. Startup safety state machine nominal progression -> DRY_RUN_READY
 15. Startup safety state machine halts on failure -> SAFE_HOLD
"""
import ipaddress
import os
import unittest

from agent.config import Config
from agent.gemini_client import Decision
from agent.network.competition_scope import (
    CompetitionNetworkGuard,
    CompetitionScope,
    detect_environment,
)
from agent.network.detector import NetworkDetector
from agent.network.models import (
    EnvironmentMode,
    InterfaceType,
    NetworkInterface,
    Route,
    VpnStatus,
)
from agent.network.state_machine import (
    StartupSafetyState,
    StartupSafetyStateMachine,
)
from agent.network.vpn import VpnDetector
from agent.security.policy import SecurityPolicy
from agent.security.safety_gates import SafetyGateManager


def build_mock_detector(interfaces, routes, gateway="192.168.1.1"):
    return NetworkDetector(
        interfaces=interfaces,
        routes=routes,
        default_gateway=gateway,
    )


class TestNetworkAdapter(unittest.TestCase):

    # ==============================================================================
    # 1. Wi-Fi Only Environment Classification
    # ==============================================================================
    def test_wifi_only_environment(self):
        interfaces = [
            NetworkInterface(
                name="wlan0",
                addresses=["192.168.100.25"],
                cidrs=["192.168.100.0/24"],
                is_up=True,
                interface_type=InterfaceType.WIFI,
            ),
            NetworkInterface(
                name="lo",
                addresses=["127.0.0.1"],
                cidrs=["127.0.0.0/8"],
                is_up=True,
                interface_type=InterfaceType.LOOPBACK,
            ),
        ]
        routes = [
            Route(destination="192.168.100.0", netmask="24", gateway=None, interface="wlan0"),
            Route(destination="0.0.0.0", netmask="0", gateway="192.168.100.1", interface="wlan0"),
        ]
        detector = build_mock_detector(interfaces, routes, gateway="192.168.100.1")
        scope = CompetitionScope(
            mode="wifi_only",
            competition_cidrs=[ipaddress.ip_network("192.168.100.0/24")],
            own_hosts=["192.168.100.25"],
        )

        env = detect_environment(scope, detector)
        self.assertEqual(env.mode, EnvironmentMode.WIFI_ONLY)
        self.assertTrue(env.competition_route_present)
        self.assertFalse(env.vpn_present)
        self.assertGreaterEqual(env.confidence, 0.9)

    # ==============================================================================
    # 2. Wi-Fi + VPN Environment Classification
    # ==============================================================================
    def test_wifi_plus_vpn_environment(self):
        interfaces = [
            NetworkInterface(
                name="wlan0",
                addresses=["192.168.1.50"],
                cidrs=["192.168.1.0/24"],
                is_up=True,
                interface_type=InterfaceType.WIFI,
            ),
            NetworkInterface(
                name="tun0",
                addresses=["10.100.1.42"],
                cidrs=["10.100.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
        ]
        routes = [
            Route(destination="0.0.0.0", netmask="0", gateway="192.168.1.1", interface="wlan0"),
            Route(destination="10.100.0.0", netmask="16", gateway=None, interface="tun0"),
        ]
        detector = build_mock_detector(interfaces, routes, gateway="192.168.1.1")
        scope = CompetitionScope(
            mode="wifi_plus_vpn",
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.42"],
        )

        env = detect_environment(scope, detector)
        self.assertEqual(env.mode, EnvironmentMode.WIFI_PLUS_VPN)
        self.assertTrue(env.competition_route_present)
        self.assertTrue(env.vpn_present)
        self.assertGreaterEqual(env.confidence, 0.9)

    # ==============================================================================
    # 3. VPN Only Environment Classification
    # ==============================================================================
    def test_vpn_only_environment(self):
        interfaces = [
            NetworkInterface(
                name="wg0",
                addresses=["10.50.0.5"],
                cidrs=["10.50.0.0/24"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
            NetworkInterface(
                name="lo",
                addresses=["127.0.0.1"],
                cidrs=["127.0.0.0/8"],
                is_up=True,
                interface_type=InterfaceType.LOOPBACK,
            ),
        ]
        routes = [
            Route(destination="10.50.0.0", netmask="24", gateway=None, interface="wg0"),
        ]
        detector = build_mock_detector(interfaces, routes, gateway=None)
        scope = CompetitionScope(
            mode="vpn_only",
            competition_cidrs=[ipaddress.ip_network("10.50.0.0/24")],
            own_hosts=["10.50.0.5"],
        )

        env = detect_environment(scope, detector)
        self.assertEqual(env.mode, EnvironmentMode.VPN_ONLY)
        self.assertTrue(env.competition_route_present)
        self.assertTrue(env.vpn_present)

    # ==============================================================================
    # 4. Unknown Environment Classification
    # ==============================================================================
    def test_unknown_environment_when_scope_unconfigured(self):
        interfaces = [
            NetworkInterface(
                name="eth0",
                addresses=["192.168.1.10"],
                cidrs=["192.168.1.0/24"],
                is_up=True,
                interface_type=InterfaceType.ETHERNET,
            )
        ]
        detector = build_mock_detector(interfaces, [])
        # Unconfigured scope (empty CIDRs)
        scope = CompetitionScope(competition_cidrs=[])

        env = detect_environment(scope, detector)
        self.assertEqual(env.mode, EnvironmentMode.UNKNOWN)
        self.assertFalse(env.competition_route_present)
        self.assertEqual(env.confidence, 0.0)

    # ==============================================================================
    # 5. No Competition Route Detected
    # ==============================================================================
    def test_no_competition_route_detected(self):
        interfaces = [
            NetworkInterface(
                name="wlan0",
                addresses=["192.168.1.100"],
                cidrs=["192.168.1.0/24"],
                is_up=True,
                interface_type=InterfaceType.WIFI,
            )
        ]
        routes = [
            Route(destination="192.168.1.0", netmask="24", gateway=None, interface="wlan0"),
        ]
        detector = build_mock_detector(interfaces, routes)
        # Competition is in 10.200.0.0/16, but local route is only 192.168.1.0/24
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.200.0.0/16")],
        )

        env = detect_environment(scope, detector)
        self.assertEqual(env.mode, EnvironmentMode.UNKNOWN)
        self.assertFalse(env.competition_route_present)

    # ==============================================================================
    # 6. Wrong Network VPN
    # ==============================================================================
    def test_wrong_network_vpn(self):
        # VPN connects to corporate 172.16.0.0/16, while competition is 10.50.0.0/16
        interfaces = [
            NetworkInterface(
                name="tun0",
                addresses=["172.16.1.10"],
                cidrs=["172.16.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            )
        ]
        routes = [
            Route(destination="172.16.0.0", netmask="16", gateway=None, interface="tun0"),
        ]
        detector = build_mock_detector(interfaces, routes)
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.50.0.0/16")],
        )

        env = detect_environment(scope, detector)
        self.assertTrue(env.vpn_present)
        # Competition route should NOT be present because tun0 routes wrong subnet
        self.assertFalse(env.competition_route_present)
        self.assertEqual(env.mode, EnvironmentMode.UNKNOWN)

    # ==============================================================================
    # 7. Malformed / Invalid CIDR Handling
    # ==============================================================================
    def test_malformed_cidr_handling(self):
        old_val = os.environ.get("PWN_COMPETITION_CIDRS")
        try:
            os.environ["PWN_COMPETITION_CIDRS"] = "not-a-cidr, 192.168.1.0/24, 999.999.999.999/32"
            cfg = Config()
            scope = CompetitionScope.from_config(cfg)
            # Invalid CIDRs should be skipped without throwing exception; valid CIDR should be retained
            self.assertEqual(len(scope.competition_cidrs), 1)
            self.assertEqual(scope.competition_cidrs[0], ipaddress.ip_network("192.168.1.0/24"))
        finally:
            if old_val is not None:
                os.environ["PWN_COMPETITION_CIDRS"] = old_val
            else:
                os.environ.pop("PWN_COMPETITION_CIDRS", None)

    # ==============================================================================
    # 8. Destination Outside Competition CIDR Rejected -> Safe HOLD
    # ==============================================================================
    def test_destination_outside_cidr_rejected(self):
        cfg = Config(
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            own_services=["10.100.1.10:80"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        # Attack on 8.8.8.8 (outside competition CIDR)
        decision = Decision(action_type="attack", target="8.8.8.8", priority="high", reasoning="external")
        result = guard.verify_action(decision)
        self.assertFalse(result.allowed)
        self.assertIn("outside competition CIDR", result.reason)
        self.assertEqual(result.decision.action_type, "hold")

    # ==============================================================================
    # 9. Attack Target Not in TARGET_HOSTS Rejected -> Safe HOLD
    # ==============================================================================
    def test_attack_target_not_in_target_hosts_rejected(self):
        cfg = Config(
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            own_services=["10.100.1.10:80"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        # 10.100.1.99 is inside CIDR, but not authorized in TARGET_HOSTS
        decision = Decision(action_type="attack", target="10.100.1.99", priority="high", reasoning="exploit")
        result = guard.verify_action(decision)
        self.assertFalse(result.allowed)
        self.assertIn("not in authorized TARGET_HOSTS", result.reason)
        self.assertEqual(result.decision.action_type, "hold")

    # ==============================================================================
    # 10. Defend Target Not in OWN_SERVICES Rejected -> Safe HOLD
    # ==============================================================================
    def test_defend_target_not_in_own_services_rejected(self):
        cfg = Config(
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            own_services=["10.100.1.10:80"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        # Attempting to defend an unauthorized service/port
        decision = Decision(action_type="defend", target="10.100.1.10:443", priority="high", reasoning="restart")
        result = guard.verify_action(decision)
        self.assertFalse(result.allowed)
        self.assertIn("not in configured OWN_SERVICES", result.reason)
        self.assertEqual(result.decision.action_type, "hold")

    # ==============================================================================
    # 11. Destination Format Injection / Invalid Syntax Rejected -> Safe HOLD
    # ==============================================================================
    def test_target_syntax_injection_rejected(self):
        cfg = Config(
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        bad_targets = [
            "10.100.1.20; rm -rf /",
            "10.100.1.20 && whoami",
            "10.100.1.20|cat /etc/passwd",
            "10.100.1.20`id`",
        ]
        for bad in bad_targets:
            decision = Decision(action_type="attack", target=bad, priority="high", reasoning="injection")
            result = guard.verify_action(decision)
            self.assertFalse(result.allowed)
            self.assertIn("violates format allowlist", result.reason)
            self.assertEqual(result.decision.action_type, "hold")

    # ==============================================================================
    # 12. Kill-Switch Engaged Causes Safe HOLD
    # ==============================================================================
    def test_kill_switch_forces_safe_hold(self):
        cfg = Config(
            kill_switch=True,
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        decision = Decision(action_type="attack", target="10.100.1.20", priority="high", reasoning="attack")
        result = guard.verify_action(decision)
        self.assertFalse(result.allowed)
        self.assertIn("Kill-switch is engaged", result.reason)
        self.assertEqual(result.decision.action_type, "hold")

    # ==============================================================================
    # 13. Rate-Limiter Saturation Causes Safe HOLD
    # ==============================================================================
    def test_rate_limiter_saturation_causes_hold(self):
        cfg = Config(
            max_actions_per_minute=2,
            own_services=["10.100.1.10:80:web"],
            target_hosts=["10.100.1.20"],
        )
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.100.0.0/16")],
            own_hosts=["10.100.1.10"],
            own_services=["10.100.1.10:80"],
            target_hosts=["10.100.1.20"],
        )
        guard = CompetitionNetworkGuard(scope=scope, cfg=cfg)

        decision = Decision(action_type="defend", target="10.100.1.10:80", priority="high", reasoning="restart nginx")

        # Action 1: allowed
        r1 = guard.verify_action(decision)
        self.assertTrue(r1.allowed)

        # Action 2: allowed
        r2 = guard.verify_action(decision)
        self.assertTrue(r2.allowed)

        # Action 3: throttled by rate limit
        r3 = guard.verify_action(decision)
        self.assertFalse(r3.allowed)
        self.assertIn("Rate limit exceeded", r3.reason)
        self.assertEqual(r3.decision.action_type, "hold")

    # ==============================================================================
    # 14. Startup Safety State Machine Nominal Progression
    # ==============================================================================
    def test_state_machine_nominal_dry_run(self):
        interfaces = [
            NetworkInterface(
                name="wlan0",
                addresses=["192.168.100.25"],
                cidrs=["192.168.100.0/24"],
                is_up=True,
                interface_type=InterfaceType.WIFI,
            )
        ]
        routes = [
            Route(destination="192.168.100.0", netmask="24", gateway=None, interface="wlan0"),
        ]
        detector = build_mock_detector(interfaces, routes)
        scope = CompetitionScope(
            mode="wifi_only",
            competition_cidrs=[ipaddress.ip_network("192.168.100.0/24")],
            own_hosts=["192.168.100.25"],
        )
        cfg = Config(koth_mode="DRY_RUN", observation_only=True)

        sm = StartupSafetyStateMachine(cfg=cfg, detector=detector, scope=scope)
        state = sm.run_startup_sequence()
        self.assertEqual(state, StartupSafetyState.DRY_RUN_READY)
        self.assertTrue(sm.can_execute_actions())

    # ==============================================================================
    # 15. Startup Safety State Machine Halts on Failure -> SAFE_HOLD
    # ==============================================================================
    def test_state_machine_halts_on_unconfigured_scope(self):
        interfaces = [
            NetworkInterface(
                name="wlan0",
                addresses=["192.168.1.100"],
                cidrs=["192.168.1.0/24"],
                is_up=True,
                interface_type=InterfaceType.WIFI,
            )
        ]
        detector = build_mock_detector(interfaces, [])
        # Scope is empty
        scope = CompetitionScope(competition_cidrs=[])
        cfg = Config(koth_mode="DRY_RUN")

        sm = StartupSafetyStateMachine(cfg=cfg, detector=detector, scope=scope)
        state = sm.run_startup_sequence()
        self.assertEqual(state, StartupSafetyState.SAFE_HOLD)
        self.assertFalse(sm.can_execute_actions())
        self.assertTrue(sm.is_safe_hold())
        self.assertIn("PWN_COMPETITION_CIDRS is empty", sm.failure_reason)


if __name__ == "__main__":
    unittest.main()
