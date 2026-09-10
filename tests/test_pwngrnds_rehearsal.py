"""Comprehensive automated test suite for PwnGrounds Rehearsal Mode.

Tests all individual scenarios, 33-step full lifecycle, explicit fake objects,
hard safety assertions (actually_executed == False), 14-section report generation,
and CLI execution.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from agent.pwngrnds_rehearsal import (
    PwnGroundsRehearsalHarness,
    SimulatedActionRecord,
)
from agent.rehearsal_fakes import (
    SafetyInterceptor,
    SimulatedActionExecutor,
    SimulatedCompetitionScope,
    SimulatedDecisionEngine,
    SimulatedNetworkState,
    SimulatedScoreboard,
    SimulatedTelemetry,
    SimulatedTimeEvents,
    SimulatedVerificationResults,
)
from agent.attack.recon import HostFingerprint


class TestRehearsalFakes(unittest.TestCase):
    """Test fake objects used in rehearsal simulation."""

    def test_simulated_network_state(self):
        net = SimulatedNetworkState()
        interfaces = net.get_interfaces()
        self.assertEqual(len(interfaces), 3)
        self.assertTrue(any(iface.name == "tun0" for iface in interfaces))
        self.assertTrue(any(iface.name == "wlan0" for iface in interfaces))

        routes = net.get_routes()
        self.assertTrue(any(r.interface == "tun0" for r in routes))
        self.assertTrue(any(r.gateway == "192.168.1.1" for r in routes))

        # Test anomaly injection
        net.wrong_vpn_subnet = True
        anom_routes = net.get_routes()
        self.assertFalse(any(r.destination == "10.200.0.0" for r in anom_routes))
        self.assertTrue(any(r.destination == "10.99.0.0" for r in anom_routes))

    def test_simulated_competition_scope(self):
        scope_fake = SimulatedCompetitionScope()
        scope = scope_fake.to_scope()
        self.assertIn("10.200.1.5", scope.own_hosts)
        self.assertIn("10.200.2.10", scope.target_hosts)
        self.assertEqual(str(scope.competition_cidrs[0]), "10.200.0.0/16")
        self.assertIn("10.200.1.5:80:web-service", scope.own_services)
        self.assertIn("10.200.1.5:22:sshd", scope.own_services)
        self.assertEqual(scope.scoreboard_url, "http://scoreboard.pwngrounds.local/api")

    def test_simulated_scoreboard(self):
        sb = SimulatedScoreboard()
        self.assertEqual(sb.our_score, 1000.0)
        self.assertEqual(sb.rank, 1)

        sb.update_score(50.0)
        self.assertEqual(sb.our_score, 1050.0)

        data = sb.fetch()
        self.assertEqual(data.our_score, 1050.0)
        self.assertEqual(data.rank, 1)

        # Test outage
        sb.set_unavailable("Scoreboard HTTP 504")
        status = sb.get_state()
        self.assertFalse(status.is_valid)
        self.assertEqual(status.status.value, "UNREACHABLE")

    def test_simulated_telemetry(self):
        sb = SimulatedScoreboard()
        telemetry = SimulatedTelemetry(sb)
        self.assertTrue(telemetry.is_healthy)

        snap = telemetry.poll()
        self.assertIsNotNone(snap)
        self.assertEqual(snap.our_score, 1000.0)
        self.assertTrue(all(s.up for s in snap.our_services))

        # Mark service down
        sb.fail_service("10.200.1.5", 80, "Service down")
        self.assertFalse(telemetry.is_healthy)
        snap2 = telemetry.poll()
        down_service = next(s for s in snap2.our_services if s.port == 80)
        self.assertFalse(down_service.up)

    def test_simulated_action_executor_hard_safety(self):
        sb = SimulatedScoreboard()
        executor = SimulatedActionExecutor(scoreboard=sb)

        res = executor.restart("web-service")
        self.assertTrue(res.success)
        self.assertIn("[rehearsal-simulated]", res.output)
        self.assertEqual(executor.actually_executed_count, 0)
        self.assertEqual(executor.simulated_actions_count, 1)

        fp = HostFingerprint(host="10.200.2.10", open_ports=[8080])
        exploit_res = executor.dispatch(fp, 8080, {})
        self.assertTrue(exploit_res.success)
        self.assertIn("[rehearsal-simulated]", exploit_res.notes)
        self.assertEqual(executor.actually_executed_count, 0)
        self.assertEqual(executor.simulated_actions_count, 2)

    def test_safety_interceptor_blocks_real_operations(self):
        safety = SafetyInterceptor()
        with safety.guard():
            # Attempted socket connection should be blocked and recorded
            import socket
            s = socket.socket()
            with self.assertRaises(RuntimeError):
                s.connect(("10.200.1.5", 80))
            self.assertEqual(safety.real_socket_connections, 1)
            self.assertEqual(len(safety.safety_violations), 1)

            # Attempted subprocess call should be blocked and recorded
            with self.assertRaises(RuntimeError):
                subprocess.run(["echo", "hello"])
            self.assertEqual(safety.real_subprocess_executions, 1)
            self.assertEqual(len(safety.safety_violations), 2)

    def test_simulated_action_record_hard_assertion(self):
        # Must succeed when actually_executed=False
        rec = SimulatedActionRecord(
            timestamp=123.0,
            decision={"action_type": "defend"},
            model="local-policy",
            confidence=1.0,
            target="10.200.1.5:80",
            action="restart_service",
            authorized=True,
            attempted=True,
            actually_executed=False,
            simulated_result={"simulated": True},
            verification={"up": True},
            empirical_success=True,
        )
        self.assertFalse(rec.actually_executed)

        # Hard assertion: constructing with actually_executed=True must raise AssertionError or RuntimeError
        with self.assertRaises((AssertionError, RuntimeError)):
            SimulatedActionRecord(
                timestamp=123.0,
                decision={"action_type": "attack"},
                model="exploit",
                confidence=1.0,
                target="10.200.2.10:8080",
                action="exploit_plugin",
                authorized=True,
                attempted=True,
                actually_executed=True,  # VIOLATION!
                simulated_result={},
                verification={},
                empirical_success=True,
            )


class TestRehearsalScenarios(unittest.TestCase):
    """Test all individual scenarios and full lifecycle."""

    def test_scenario_network(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_network_scenario()
        self.assertEqual(report["scenario"], "network")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_telemetry(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_telemetry_scenario()
        self.assertEqual(report["scenario"], "telemetry")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_ai(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_ai_scenario()
        self.assertEqual(report["scenario"], "ai")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_authorization(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_authorization_scenario()
        self.assertEqual(report["scenario"], "authorization")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        self.assertTrue(report["sections"]["authorization"]["rejected_forbidden_port_9999"])
        self.assertTrue(report["sections"]["authorization"]["rejected_unauthorized_cidr_target"])
        self.assertEqual(report["sections"]["safety_violations"]["policy_rejections_recorded"], 5)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_recovery(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_recovery_scenario()
        self.assertEqual(report["scenario"], "recovery")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_failures(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_failures_scenario()
        self.assertEqual(report["scenario"], "failures")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)

    def test_scenario_full_33_steps(self):
        harness = PwnGroundsRehearsalHarness()
        report = harness.run_full_scenario()
        self.assertEqual(report["scenario"], "full")
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["summary"]["total_steps"], 33)
        self.assertEqual(report["summary"]["passed_steps"], 33)
        self.assertEqual(report["summary"]["actual_executions"], 0)
        self.assertEqual(report["summary"]["safety_violations"], 0)
        self.assertGreater(report["summary"]["simulated_actions"], 0)

        # Verify all 33 steps are documented in harness
        self.assertEqual(len(harness.lifecycle_steps), 33)
        for step in harness.lifecycle_steps:
            self.assertNotEqual(step["status"], "FAILED")

        # Hard assertion on action records
        self.assertGreater(len(harness.action_records), 0)
        for rec in harness.action_records:
            self.assertFalse(rec.actually_executed)


class TestRehearsalReports(unittest.TestCase):
    """Test report generation and presence of all 14 mandatory sections."""

    def test_14_mandatory_sections_in_json_and_markdown(self):
        harness = PwnGroundsRehearsalHarness()
        harness.run_full_scenario()

        md_path, json_path = harness.generate_reports()
        self.assertTrue(os.path.exists(md_path))
        self.assertTrue(os.path.exists(json_path))

        # Check JSON structure
        with open(json_path, "r") as f:
            data = json.load(f)

        required_sections = [
            "network",
            "scope",
            "safety_gates",
            "telemetry",
            "ai_routing",
            "authorization",
            "actions",
            "verification",
            "scoreboard",
            "recovery",
            "failure_injection",
            "kill_switch",
            "safety_violations",
            "final_result",
        ]
        self.assertEqual(len(data["sections"]), 14)
        for section in required_sections:
            self.assertIn(section, data["sections"])

        # Check Markdown content
        with open(md_path, "r") as f:
            md_content = f.read()

        required_md_headers = [
            "## 1. NETWORK",
            "## 2. SCOPE",
            "## 3. SAFETY GATES",
            "## 4. TELEMETRY",
            "## 5. AI ROUTING",
            "## 6. AUTHORIZATION",
            "## 7. ACTIONS",
            "## 8. VERIFICATION",
            "## 9. SCOREBOARD",
            "## 10. RECOVERY",
            "## 11. FAILURE INJECTION",
            "## 12. KILL SWITCH",
            "## 13. SAFETY VIOLATIONS",
            "## 14. FINAL RESULT",
        ]
        for header in required_md_headers:
            self.assertIn(header, md_content)

        # Safety metrics in report
        self.assertEqual(data["summary"]["actual_executions"], 0)
        self.assertEqual(data["summary"]["safety_violations"], 0)
        self.assertIn("PASSED", md_content)


class TestRehearsalCLI(unittest.TestCase):
    """Test CLI execution for supported scenarios."""

    def test_cli_full(self):
        res = subprocess.run(
            [sys.executable, "-m", "agent.pwngrnds_rehearsal", "--scenario", "full"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("33/33 LIFECYCLE STEPS SUCCESSFUL", res.stdout)
        self.assertIn("Actual Executions : 0 (HARD ASSERTION: 0)", res.stdout)

    def test_cli_network(self):
        res = subprocess.run(
            [sys.executable, "-m", "agent.pwngrnds_rehearsal", "--scenario", "network"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("RUNNING SCENARIO: NETWORK", res.stdout)

    def test_cli_failures(self):
        res = subprocess.run(
            [sys.executable, "-m", "agent.pwngrnds_rehearsal", "--scenario", "failures"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("RUNNING SCENARIO: FAILURES", res.stdout)


if __name__ == "__main__":
    unittest.main()
