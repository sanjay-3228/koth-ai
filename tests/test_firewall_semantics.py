"""Unit tests verifying explicit firewall port semantics, transactional validation, and rollback."""
import unittest
from unittest.mock import MagicMock, patch

from agent.defense.firewall import FirewallManager, FirewallRule


class TestFirewallSemantics(unittest.TestCase):
    def test_explicit_single_port_tcp(self):
        rule = FirewallRule(action="rate_limit", proto="tcp", port=80, note="rate limit HTTP")
        self.assertEqual(
            rule.to_nft(),
            "add rule inet filter input tcp dport 80 limit rate 10/second accept",
        )

    def test_explicit_single_port_udp(self):
        rule = FirewallRule(action="drop", proto="udp", port=53, source="10.0.0.5", note="drop rogue DNS")
        self.assertEqual(
            rule.to_nft(),
            "add rule inet filter input ip saddr 10.0.0.5 udp dport 53 drop",
        )

    def test_explicit_port_range(self):
        rule = FirewallRule(
            action="drop",
            proto="tcp",
            port_range=(8000, 9000),
            source="192.168.1.100",
            note="block dev port range",
        )
        self.assertEqual(
            rule.to_nft(),
            "add rule inet filter input ip saddr 192.168.1.100 tcp dport 8000-9000 drop",
        )

    def test_explicit_all_ports_with_proto_any(self):
        rule = FirewallRule(
            action="drop",
            proto="any",
            all_ports=True,
            source="172.16.0.99",
            note="block host entirely",
        )
        self.assertEqual(
            rule.to_nft(),
            "add rule inet filter input ip saddr 172.16.0.99 drop",
        )

    def test_implicit_port_zero_forbidden(self):
        """Proof: Implicit port=0 is strictly rejected with ValueError."""
        with self.assertRaises(ValueError) as ctx:
            FirewallRule(action="drop", proto="tcp", port=0)
        self.assertIn("Invalid port 0", str(ctx.exception))

    def test_port_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="drop", proto="tcp", port=70000)
        with self.assertRaises(ValueError):
            FirewallRule(action="drop", proto="tcp", port=-1)

    def test_port_range_inverted_rejected(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="drop", proto="tcp", port_range=(9000, 8000))

    def test_ambiguous_port_specifications_rejected(self):
        # 1. Both port and port_range set
        with self.assertRaises(ValueError) as ctx1:
            FirewallRule(action="drop", proto="tcp", port=80, port_range=(80, 90))
        self.assertIn("must specify exactly one port specification", str(ctx1.exception))

        # 2. Both port and all_ports=True set
        with self.assertRaises(ValueError) as ctx2:
            FirewallRule(action="drop", proto="tcp", port=80, all_ports=True)
        self.assertIn("must specify exactly one port specification", str(ctx2.exception))

        # 3. None specified
        with self.assertRaises(ValueError) as ctx3:
            FirewallRule(action="drop", proto="tcp")
        self.assertIn("must specify exactly one port specification", str(ctx3.exception))

    def test_invalid_action_rejected(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="reject", proto="tcp", port=80)

    def test_invalid_proto_rejected(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="drop", proto="icmp", port=80)

    def test_dry_run_mode_preview_only(self):
        mgr = FirewallManager(dry_run=True)
        rule = FirewallRule(action="drop", proto="tcp", port=8080, source="1.2.3.4")
        preview = mgr.apply(rule)
        self.assertIn("nft add rule inet filter input ip saddr 1.2.3.4 tcp dport 8080 drop", preview)
        self.assertEqual(len(mgr.applied), 0)

    @patch("subprocess.run")
    def test_transactional_rollback_on_nft_failure(self, mock_subproc):
        """Proof: When nft application fails, the manager automatically restores the backup ruleset."""
        mgr = FirewallManager(dry_run=False)

        # Mock sequence:
        # 1. backup: nft list ruleset -> success with old rules
        # 2. syntax check: nft --check ... -> success
        # 3. apply: nft add rule ... -> FAILURE (returncode=1)
        # 4. rollback restore: nft -f - -> success
        mock_backup = MagicMock(returncode=0, stdout="# old ruleset content", stderr="")
        mock_check = MagicMock(returncode=0, stdout="", stderr="")
        mock_apply_fail = MagicMock(returncode=1, stdout="", stderr="Error: syntax error or table missing")
        mock_restore = MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = [mock_backup, mock_check, mock_apply_fail, mock_restore]

        rule = FirewallRule(action="drop", proto="tcp", port=22, source="10.0.0.99")
        with self.assertRaises(RuntimeError) as ctx:
            mgr.apply(rule)

        self.assertIn("nft failed (rolled back)", str(ctx.exception))
        # Rule must not have been appended to applied list
        self.assertEqual(len(mgr.applied), 0)

        # Verify rollback was called with the backed-up ruleset
        calls = mock_subproc.call_args_list
        self.assertEqual(len(calls), 4)
        # 4th call was restore
        self.assertEqual(calls[3][0][0], ["nft", "-f", "-"])
    @patch("subprocess.run")
    def test_syntax_check_failure_aborts_before_apply(self, mock_subproc):
        """Proof: If nft --check fails, apply is never attempted."""
        mgr = FirewallManager(dry_run=False)
        mock_backup = MagicMock(returncode=0, stdout="# old rules", stderr="")
        mock_check_fail = MagicMock(returncode=1, stdout="", stderr="syntax error near 'dport'")

        mock_subproc.side_effect = [mock_backup, mock_check_fail]

        rule = FirewallRule(action="drop", proto="tcp", port=80)
        with self.assertRaises(RuntimeError) as ctx:
            mgr.apply(rule)

        self.assertIn("nft syntax check failed", str(ctx.exception))
        self.assertEqual(len(mgr.applied), 0)
        # Verify apply was never called (only backup and check were run)
        self.assertEqual(len(mock_subproc.call_args_list), 2)


if __name__ == "__main__":
    unittest.main()
