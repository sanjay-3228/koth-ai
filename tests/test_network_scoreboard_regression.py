"""Regression tests for PwnGrounds network adapter and scoreboard semantics.

Addresses issues identified during network and OpenVPN validation:
  1. VPN NetworkInterface rendering (rendering single VPN object via .name)
  2. Multiple VPN interfaces rendering (rendering multiple VPN objects without TypeError)
  3. Scoreboard connection refused produces UNREACHABLE
  4. Scoreboard timeout produces UNREACHABLE
  5. Scoreboard successful response produces REACHABLE
  6. Scoreboard stale response produces STALE
  7. Scoreboard malformed response produces MALFORMED
  8. No scoreboard URL produces UNCONFIGURED
  9. VPN detected but competition scope absent
 10. VPN detected with non-PwnGrounds route (e.g. external VPN 10.77.0.0/16 not classified as PwnGrounds)
 11. Failed scoreboard request cannot produce REACHABLE
 12. Failed scoreboard response cannot produce fake score/rank
 13. Local-policy fallback when scoreboard unavailable
"""
import io
import ipaddress
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

from agent.config import Config
from agent.model_router import ModelRouter
from agent.network.competition_scope import (
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
from agent.network.vpn import VpnDetector
from agent.scoreboard.adapter import ConfigurableScoreboardAdapter
from agent.scoreboard.base import NormalizedScoreboardState, ScoreboardStatus
from agent.scoreboard.config_parser import ScoreboardSchemaConfig
from agent.telemetry import Telemetry, TelemetryPoller


class TestNetworkScoreboardRegression(unittest.TestCase):

    # ==========================================================================
    # 1. VPN NetworkInterface Rendering
    # ==========================================================================
    def test_vpn_interface_rendering(self):
        """Single VPN NetworkInterface must render by .name without crashing."""
        iface = NetworkInterface(
            name="tun0",
            addresses=["10.77.0.5"],
            cidrs=["10.77.0.0/16"],
            is_up=True,
            interface_type=InterfaceType.VPN,
        )
        status, active_vpns = VpnDetector.detect_vpn_status([iface])
        self.assertEqual(status, VpnStatus.CONNECTED)
        self.assertEqual(len(active_vpns), 1)

        # Presentation layer join by .name
        rendered = ", ".join(v.name for v in active_vpns)
        self.assertEqual(rendered, "tun0")

    # ==========================================================================
    # 2. Multiple VPN Interfaces Rendering
    # ==========================================================================
    def test_multiple_vpn_interfaces_rendering(self):
        """Multiple VPN NetworkInterface objects must render without TypeError."""
        ifaces = [
            NetworkInterface(
                name="tun0",
                addresses=["10.77.0.5"],
                cidrs=["10.77.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
            NetworkInterface(
                name="wg0",
                addresses=["10.100.1.2"],
                cidrs=["10.100.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
        ]
        status, active_vpns = VpnDetector.detect_vpn_status(ifaces)
        self.assertEqual(status, VpnStatus.CONNECTED)
        self.assertEqual(len(active_vpns), 2)

        # Presentation layer rendering proof
        rendered = ", ".join(v.name for v in active_vpns)
        self.assertEqual(rendered, "tun0, wg0")

    # ==========================================================================
    # 3. Scoreboard Connection Refused
    # ==========================================================================
    def test_scoreboard_connection_refused(self):
        adapter = ConfigurableScoreboardAdapter(url="http://127.0.0.1:8000/api")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertEqual(state.status, ScoreboardStatus.UNREACHABLE)
        self.assertIn("Network error", state.error)
        self.assertGreater(state.metadata["scoreboard_latency_ms"], 0.0)
        self.assertEqual(state.metadata["json_parsing_latency_ms"], 0.0)
        self.assertIsNone(state.own_score)
        self.assertIsNone(state.rank)

    # ==========================================================================
    # 4. Scoreboard Timeout
    # ==========================================================================
    def test_scoreboard_timeout(self):
        adapter = ConfigurableScoreboardAdapter(url="http://127.0.0.1:8000/api")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.Timeout("Read timed out")
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertEqual(state.status, ScoreboardStatus.UNREACHABLE)
        self.assertIn("timed out", state.error.lower())
        self.assertGreater(state.metadata["scoreboard_latency_ms"], 0.0)
        self.assertGreater(state.metadata["scoreboard_timeout_ms"], 0.0)
        self.assertEqual(state.metadata["json_parsing_latency_ms"], 0.0)
        self.assertIsNone(state.own_score)
        self.assertIsNone(state.rank)

    # ==========================================================================
    # 5. Scoreboard Successful Response
    # ==========================================================================
    def test_scoreboard_successful_response(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock-scoreboard/api")
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "timestamp": time.time(),
            "our_score": 1500.0,
            "rank": 1,
            "our_services": [{"host": "10.0.1.5", "port": 80, "up": True}],
        }
        mock_session.get.return_value = mock_resp
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertTrue(state.is_valid)
        self.assertEqual(state.status, ScoreboardStatus.REACHABLE)
        self.assertEqual(state.own_score, 1500.0)
        self.assertEqual(state.rank, 1)
        self.assertIsNone(state.error)

    # ==========================================================================
    # 6. Scoreboard Stale Response
    # ==========================================================================
    def test_scoreboard_stale_response(self):
        adapter = ConfigurableScoreboardAdapter(
            url="http://mock-scoreboard/api",
            schema_config=ScoreboardSchemaConfig(stale_threshold_seconds=30.0),
        )
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Timestamp is 100 seconds in the past
        mock_resp.json.return_value = {
            "timestamp": time.time() - 100.0,
            "our_score": 1200.0,
            "rank": 2,
        }
        mock_session.get.return_value = mock_resp
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertTrue(state.is_stale)
        self.assertEqual(state.status, ScoreboardStatus.STALE)
        self.assertIn("stale", state.error.lower())

    # ==========================================================================
    # 7. Scoreboard Malformed Response
    # ==========================================================================
    def test_scoreboard_malformed_response(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock-scoreboard/api")
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Root element is a list, not a dict
        mock_resp.json.return_value = [{"invalid": "list_payload"}]
        mock_session.get.return_value = mock_resp
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertEqual(state.status, ScoreboardStatus.MALFORMED)
        self.assertIn("Malformed payload", state.error)

    # ==========================================================================
    # 8. No Scoreboard URL
    # ==========================================================================
    def test_no_scoreboard_url(self):
        adapter = ConfigurableScoreboardAdapter(url="")
        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertEqual(state.status, ScoreboardStatus.UNCONFIGURED)
        self.assertEqual(state.metadata["scoreboard_latency_ms"], 0.0)
        self.assertEqual(state.metadata["json_parsing_latency_ms"], 0.0)

    # ==========================================================================
    # 9. VPN Detected but Competition Scope Absent
    # ==========================================================================
    def test_vpn_detected_but_competition_scope_absent(self):
        interfaces = [
            NetworkInterface(
                name="tun0",
                addresses=["10.77.0.5"],
                cidrs=["10.77.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
        ]
        routes = [
            Route(destination="10.77.0.0", netmask="16", gateway=None, interface="tun0"),
        ]
        detector = NetworkDetector(interfaces=interfaces, routes=routes)
        scope = CompetitionScope(competition_cidrs=[])  # Unconfigured

        env = detect_environment(scope, detector)
        self.assertTrue(env.vpn_present)
        self.assertTrue(env.vpn_route_present)
        self.assertEqual(env.active_vpn_interfaces, ["tun0"])
        self.assertFalse(env.competition_route_present)
        self.assertIsNone(env.competition_cidr)
        self.assertEqual(env.mode, EnvironmentMode.UNKNOWN)

    # ==========================================================================
    # 10. VPN Detected with Non-PwnGrounds Route (External VPN Subnet)
    # ==========================================================================
    def test_vpn_detected_with_non_pwngrounds_route(self):
        # Connected to external VPN (10.77.0.0/16)
        interfaces = [
            NetworkInterface(
                name="tun0",
                addresses=["10.77.1.100"],
                cidrs=["10.77.0.0/16"],
                is_up=True,
                interface_type=InterfaceType.VPN,
            ),
            NetworkInterface(
                name="eth0",
                addresses=["192.168.1.50"],
                cidrs=["192.168.1.0/24"],
                is_up=True,
                interface_type=InterfaceType.ETHERNET,
            ),
        ]
        routes = [
            Route(destination="10.77.0.0", netmask="16", gateway=None, interface="tun0"),
            Route(destination="0.0.0.0", netmask="0", gateway="192.168.1.1", interface="eth0"),
        ]
        detector = NetworkDetector(interfaces=interfaces, routes=routes)
        # Competition CIDR is different (PwnGrounds 10.200.0.0/16)
        scope = CompetitionScope(
            competition_cidrs=[ipaddress.ip_network("10.200.0.0/16")],
        )

        env = detect_environment(scope, detector)
        self.assertTrue(env.vpn_present)
        self.assertTrue(env.vpn_route_present)
        self.assertEqual(env.active_vpn_interfaces, ["tun0"])
        # Crucial guarantee: External VPN route is NEVER mistaken for PwnGrounds
        self.assertFalse(env.competition_route_present)
        self.assertEqual(env.mode, EnvironmentMode.UNKNOWN)

    # ==========================================================================
    # 11. Failed Scoreboard Request Cannot Produce REACHABLE
    # ==========================================================================
    def test_failed_scoreboard_cannot_produce_reachable(self):
        adapter = ConfigurableScoreboardAdapter(url="http://127.0.0.1:8000/api")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.RequestException("Host unreachable")
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertNotEqual(state.status, ScoreboardStatus.REACHABLE)
        self.assertEqual(state.status, ScoreboardStatus.UNREACHABLE)

        tel = adapter.to_telemetry(state)
        self.assertEqual(tel.raw.get("scoreboard_status"), "UNREACHABLE")

    # ==========================================================================
    # 12. Failed Scoreboard Response Cannot Produce Fake Score/Rank
    # ==========================================================================
    def test_failed_scoreboard_cannot_produce_fake_score_rank(self):
        adapter = ConfigurableScoreboardAdapter(url="http://127.0.0.1:8000/api")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")
        adapter.session = mock_session

        state = adapter.get_state()
        tel = adapter.to_telemetry(state)

        # Telemetry must not have fabricated or placeholder score/rank
        self.assertIsNone(tel.our_score)
        self.assertIsNone(tel.rank)
        self.assertEqual(tel.our_services, [])
        self.assertEqual(tel.competitor_scores, {})

    # ==========================================================================
    # 13. Local-Policy Fallback When Scoreboard Unavailable
    # ==========================================================================
    def test_local_policy_fallback_when_scoreboard_unavailable(self):
        router = ModelRouter()
        # Telemetry with UNREACHABLE error
        telemetry = Telemetry(
            timestamp=time.time(),
            our_score=None,
            rank=None,
            our_services=[],
            raw={"error": "Connection refused", "scoreboard_status": "UNREACHABLE"},
        )
        mock_brain = MagicMock()

        decision = router.execute_decision(
            telemetry=telemetry,
            telemetry_summary="Scoreboard unreachable",
            recent_actions=[],
            brain=mock_brain,
            monitor_snapshot={"services": [], "tampered_files": []},
        )

        # Must select local-policy and enforce safe hold
        self.assertEqual(decision.model_used, "local-policy")
        self.assertEqual(decision.action_type, "hold")
        self.assertEqual(decision.priority, "low")
        self.assertIn("Scoreboard unreachable", decision.reasoning)
        # Brain should never be called when local safe hold handles scoreboard fault
        mock_brain.decide.assert_not_called()


if __name__ == "__main__":
    unittest.main()
