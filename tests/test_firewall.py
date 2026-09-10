"""Unit tests for FirewallRule.to_nft() rule generation and FirewallManager dry-run mode."""
import unittest

from agent.defense.firewall import FirewallManager, FirewallRule


class TestFirewallRule(unittest.TestCase):
    def test_to_nft_allow_any_source(self):
        rule = FirewallRule(action="allow", proto="tcp", port=80, source="any", note="allow HTTP")
        expected = "add rule inet filter input tcp dport 80 accept"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_drop_any_source(self):
        rule = FirewallRule(action="drop", proto="tcp", port=22, source="any", note="drop SSH")
        expected = "add rule inet filter input tcp dport 22 drop"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_rate_limit_any_source(self):
        rule = FirewallRule(action="rate_limit", proto="tcp", port=443, source="any", note="rate limit HTTPS")
        expected = "add rule inet filter input tcp dport 443 limit rate 10/second accept"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_specific_source_ip(self):
        rule = FirewallRule(
            action="drop",
            proto="tcp",
            port=22,
            source="192.168.1.100",
            note="block specific attacker",
        )
        expected = "add rule inet filter input ip saddr 192.168.1.100 tcp dport 22 drop"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_udp_protocol(self):
        rule = FirewallRule(
            action="allow",
            proto="udp",
            port=53,
            source="10.0.0.1",
            note="allow DNS from resolver",
        )
        expected = "add rule inet filter input ip saddr 10.0.0.1 udp dport 53 accept"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_all_ports_block_source(self):
        rule = FirewallRule(
            action="drop",
            proto="any",
            all_ports=True,
            source="10.20.30.40",
            note="block IP entirely",
        )
        expected = "add rule inet filter input ip saddr 10.20.30.40 drop"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_all_ports_tcp_only(self):
        rule = FirewallRule(
            action="drop",
            proto="tcp",
            all_ports=True,
            source="10.20.30.40",
            note="block TCP entirely from IP",
        )
        expected = "add rule inet filter input ip saddr 10.20.30.40 ip protocol tcp drop"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_port_range(self):
        rule = FirewallRule(
            action="drop",
            proto="tcp",
            port_range=(1000, 2000),
            source="any",
            note="drop port range",
        )
        expected = "add rule inet filter input tcp dport 1000-2000 drop"
        self.assertEqual(rule.to_nft(), expected)

    def test_to_nft_invalid_action_raises_value_error(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="reject", proto="tcp", port=80, source="any")

    def test_ambiguous_port_and_all_ports_raises_value_error(self):
        with self.assertRaises(ValueError):
            FirewallRule(action="drop", proto="tcp", port=80, all_ports=True, source="any")

    def test_firewall_manager_dry_run_does_not_execute_subprocesses(self):
        mgr = FirewallManager(dry_run=True)
        rule = FirewallRule(action="drop", proto="tcp", port=8080, source="172.16.0.5", note="test rule")
        preview = mgr.apply(rule)
        self.assertEqual(preview, "nft add rule inet filter input ip saddr 172.16.0.5 tcp dport 8080 drop")
        # In dry-run mode, applied list should not have appended (dry-run only previews)
        self.assertEqual(len(mgr.applied), 0)


if __name__ == "__main__":
    unittest.main()
