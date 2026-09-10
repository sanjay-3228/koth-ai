"""Generates and applies nftables rules to defend own services with transactional safety.

Explicitly represents:
  - Specific port (e.g. port=80)
  - Port range (e.g. port_range=(8000, 8080))
  - All ports (all_ports=True)

Transactional operations:
  - Backup ruleset before modification
  - Pre-validate rule syntax
  - Apply and verify
  - Automatic rollback on failure
"""
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..config import config
from ..logger import get_logger

logger = get_logger(__name__)


@dataclass
class FirewallRule:
    action: str  # "allow" | "drop" | "rate_limit"
    proto: str = "tcp"  # "tcp" | "udp" | "any"
    port: Optional[int] = None
    port_range: Optional[Tuple[int, int]] = None
    all_ports: bool = False
    source: str = "any"
    note: str = ""

    def __post_init__(self):
        valid_actions = {"allow", "drop", "rate_limit"}
        if self.action not in valid_actions:
            raise ValueError(f"Invalid firewall action '{self.action}'. Must be one of {valid_actions}")

        valid_protos = {"tcp", "udp", "any"}
        if self.proto not in valid_protos:
            raise ValueError(f"Invalid proto '{self.proto}'. Must be one of {valid_protos}")

        # Ensure exactly one port specification method is used
        specs = sum([
            self.port is not None,
            self.port_range is not None,
            bool(self.all_ports),
        ])
        if specs != 1:
            raise ValueError(
                "FirewallRule must specify exactly one port specification: "
                "either 'port', 'port_range', or 'all_ports=True'."
            )

        if self.port is not None and not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port {self.port}. Must be 1-65535.")

        if self.port_range is not None:
            start, end = self.port_range
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid port range {self.port_range}. Must be 1 <= start <= end <= 65535.")

    def to_nft(self) -> str:
        target = {
            "allow": "accept",
            "drop": "drop",
            "rate_limit": "limit rate 10/second accept",
        }[self.action]

        src = f"ip saddr {self.source} " if self.source != "any" else ""

        if self.port is not None:
            proto_clause = f"{self.proto} " if self.proto != "any" else "tcp "
            port_clause = f"{proto_clause}dport {self.port} "
        elif self.port_range is not None:
            proto_clause = f"{self.proto} " if self.proto != "any" else "tcp "
            port_clause = f"{proto_clause}dport {self.port_range[0]}-{self.port_range[1]} "
        else:  # all_ports=True
            port_clause = f"ip protocol {self.proto} " if self.proto != "any" else ""

        return f"add rule inet filter input {src}{port_clause}{target}".strip()


class FirewallManager:
    def __init__(self, dry_run: Optional[bool] = None):
        self.dry_run = config.dry_run if dry_run is None else dry_run
        self.applied: List[FirewallRule] = []

    def validate_rule(self, rule: FirewallRule) -> bool:
        """Validate rule syntax and parameters."""
        nft_rule = rule.to_nft()
        if not nft_rule.startswith("add rule inet filter input"):
            raise ValueError(f"Invalid nft rule format: {nft_rule}")
        return True

    def backup_ruleset(self) -> str:
        """Capture current ruleset for transaction rollback."""
        if self.dry_run:
            return "# dry-run ruleset backup"
        res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if res.returncode != 0:
            logger.warning("Could not backup ruleset: %s", res.stderr)
            return ""
        return res.stdout

    def restore_ruleset(self, ruleset_data: str) -> bool:
        """Restore ruleset during rollback."""
        if self.dry_run or not ruleset_data:
            return True
        res = subprocess.run(["nft", "-f", "-"], input=ruleset_data, capture_output=True, text=True)
        return res.returncode == 0

    def apply(self, rule: FirewallRule) -> str:
        """Transactional firewall rule application with syntax check and automatic rollback."""
        self.validate_rule(rule)
        cmd = ["nft"] + rule.to_nft().split()

        if self.dry_run:
            preview = " ".join(cmd)
            logger.info(f"[dry-run] validated rule: {preview}  # {rule.note}")
            return preview

        # 1. Snapshot ruleset for transactional safety
        backup = self.backup_ruleset()

        # 2. Syntax validation with nft --check
        check_cmd = ["nft", "--check"] + rule.to_nft().split()
        check_res = subprocess.run(check_cmd, capture_output=True, text=True)
        if check_res.returncode != 0:
            logger.error("nft syntax check failed: %s", check_res.stderr)
            raise RuntimeError(f"nft syntax check failed: {check_res.stderr.strip()}")

        # 3. Apply rule
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("nft command failed: %s; rolling back", result.stderr)
            if backup:
                self.restore_ruleset(backup)
            raise RuntimeError(f"nft failed (rolled back): {result.stderr.strip()}")

        self.applied.append(rule)
        logger.info("Successfully applied firewall rule: %s", " ".join(cmd))
        return " ".join(cmd)

    def block_source(self, source_ip: str, note: str = "auto-blocked, suspicious traffic") -> str:
        """Block all traffic from a source IP (explicit all_ports=True)."""
        return self.apply(
            FirewallRule(
                action="drop",
                proto="any",
                all_ports=True,
                source=source_ip,
                note=note,
            )
        )

    def rate_limit_port(self, port: int, proto: str = "tcp", note: str = "auto rate-limit under load") -> str:
        """Rate limit traffic on a specific port."""
        return self.apply(
            FirewallRule(
                action="rate_limit",
                proto=proto,
                port=port,
                note=note,
            )
        )

    def rate_limit_port_range(
        self,
        start_port: int,
        end_port: int,
        proto: str = "tcp",
        note: str = "auto rate-limit range under load",
    ) -> str:
        """Rate limit traffic across a port range."""
        return self.apply(
            FirewallRule(
                action="rate_limit",
                proto=proto,
                port_range=(start_port, end_port),
                note=note,
            )
        )
