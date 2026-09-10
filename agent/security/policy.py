"""Authorization and Security Policy Gate for koth-agent.

Enforces strict separation of:
  - OWN_SERVICES (for 'defend' operations only)
  - TARGET_HOSTS (for 'attack' and competition 'recon' operations only)

Guarantees:
  - AI decisions cannot execute unauthorized actions
  - AI decisions cannot target unauthorized hosts/services
  - AI decisions never supply arbitrary systemd service units
  - Malicious target injections are rejected and logged
"""
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from ..config import Config, ServiceConfig, config
from ..gemini_client import Decision
from ..logger import get_logger

logger = get_logger(__name__)

TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]+(?::\d{1,5})?$")


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AuthorizationResult:
    allowed: bool
    reason: str
    risk_level: RiskLevel
    resolved_service: Optional[ServiceConfig] = None
    sanitized_target: str = ""
    safe_decision: Optional[Decision] = None


class SecurityPolicy:
    """Central authorization gate inspecting all AI and local decisions before execution."""

    def __init__(self, cfg: Optional[Config] = None):
        self.cfg = cfg or config

    def authorize(self, decision: Decision) -> AuthorizationResult:
        """Inspect and authorize a Decision.

        Returns AuthorizationResult. If unauthorized, provides safe 'hold' fallback.
        """
        # 1. Action type validation
        valid_actions = {"defend", "attack", "recon", "hold"}
        if decision.action_type not in valid_actions:
            return self._reject(
                decision,
                f"Action type '{decision.action_type}' is not permitted by policy.",
                RiskLevel.CRITICAL,
            )

        # 1b. Config.allowed_actions validation
        action_name = getattr(decision, "action_name", None)
        if action_name and action_name != "hold" and not self.cfg.is_action_allowed(action_name):
            return self._reject(
                decision,
                f"Action '{action_name}' is not in Config.allowed_actions allowlist ({self.cfg.allowed_actions}).",
                RiskLevel.CRITICAL,
            )

        # 2. Hold action is always benign and permitted
        if decision.action_type == "hold":
            return AuthorizationResult(
                allowed=True,
                reason="Safe hold permitted.",
                risk_level=RiskLevel.LOW,
                sanitized_target="",
                safe_decision=decision,
            )

        # 3. Target sanitization and syntax check
        target = (decision.target or "").strip()
        if not target:
            return self._reject(
                decision,
                "Target cannot be empty for active operations.",
                RiskLevel.CRITICAL,
            )

        # Explicitly reject subnet/CIDR scanning (ranges strictly forbidden)
        if "/" in target:
            return self._reject(
                decision,
                f"Target '{target}' contains subnet/CIDR notation ('/'). Subnet and range scanning are strictly forbidden.",
                RiskLevel.CRITICAL,
            )

        if not TARGET_PATTERN.match(target):
            return self._reject(
                decision,
                f"Target '{target}' violates format allowlist (contains invalid characters or injection attempt).",
                RiskLevel.CRITICAL,
            )

        # Parse host and port
        if ":" in target:
            host, port_str = target.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return self._reject(decision, f"Invalid port in target: {target}", RiskLevel.HIGH)
            if not (1 <= port <= 65535):
                return self._reject(
                    decision,
                    f"Port {port} is outside valid TCP/UDP range (1-65535).",
                    RiskLevel.HIGH,
                )
        else:
            host = target
            port = 0

        # Check localhost / loopback rejection
        if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0") or host.startswith("127."):
            return self._reject(
                decision,
                f"Target host '{host}' is localhost/loopback. Localhost scanning and interactions are strictly forbidden.",
                RiskLevel.CRITICAL,
            )

        # 4. Action-specific authorization checks
        if decision.action_type == "defend":
            return self._authorize_defend(decision, host, port)

        elif decision.action_type == "attack":
            return self._authorize_attack(decision, host, port)

        elif decision.action_type == "recon":
            return self._authorize_recon(decision, host, port)

        return self._reject(decision, "Unhandled policy rule.", RiskLevel.CRITICAL)

    def _authorize_defend(self, decision: Decision, host: str, port: int) -> AuthorizationResult:
        """Defend actions may ONLY operate on configured OWN_SERVICES."""
        # Prevent defending competitor hosts
        if self.cfg.is_target_host(host):
            return self._reject(
                decision,
                f"Defend action attempted on competitor TARGET_HOST '{host}'. Defend is restricted to OWN_SERVICES.",
                RiskLevel.CRITICAL,
            )

        # Must be in configured own services
        if not self.cfg.is_own_service(host, port):
            configured = list(self.cfg.parsed_services.keys())
            return self._reject(
                decision,
                f"Target '{host}:{port}' is not in configured OWN_SERVICES ({configured}).",
                RiskLevel.HIGH,
            )

        service_cfg = self.cfg.parsed_services.get(f"{host}:{port}")
        return AuthorizationResult(
            allowed=True,
            reason=f"Authorized defense target '{host}:{port}' (mapped unit: {service_cfg.systemd_unit or 'none'}).",
            risk_level=RiskLevel.HIGH,
            resolved_service=service_cfg,
            sanitized_target=f"{host}:{port}",
            safe_decision=decision,
        )

    def _authorize_attack(self, decision: Decision, host: str, port: int) -> AuthorizationResult:
        """Attack actions may ONLY operate on explicitly configured TARGET_HOSTS."""
        if port == 9999:
            return self._reject(
                decision,
                f"Port {port} is reserved for competition organizer / scoreboard infrastructure. Attacking organizer ports is strictly forbidden.",
                RiskLevel.CRITICAL,
            )

        # Never attack own infrastructure or protected hosts
        if (
            self.cfg.is_own_service(host, port)
            or host in self.cfg.own_hosts
            or self.cfg.is_protected_host(host)
        ):
            return self._reject(
                decision,
                f"Attack action targeted own infrastructure or protected host '{host}:{port}'. Forbidden by safety policy.",
                RiskLevel.CRITICAL,
            )

        if not self.cfg.is_target_host(host):
            return self._reject(
                decision,
                f"Target host '{host}' is not in authorized competition TARGET_HOSTS ({self.cfg.target_hosts}).",
                RiskLevel.CRITICAL,
            )

        if port == 0:
            return self._reject(
                decision,
                f"Attack action requires a valid target port, got: {decision.target}",
                RiskLevel.MEDIUM,
            )

        if self.cfg.allowed_ports and port not in self.cfg.allowed_ports:
            return self._reject(
                decision,
                f"Port {port} is not in allowed competition ports ({self.cfg.allowed_ports}).",
                RiskLevel.HIGH,
            )

        return AuthorizationResult(
            allowed=True,
            reason=f"Authorized attack target '{host}:{port}' within competition scope.",
            risk_level=RiskLevel.HIGH,
            sanitized_target=f"{host}:{port}",
            safe_decision=decision,
        )

    def _authorize_recon(self, decision: Decision, host: str, port: int) -> AuthorizationResult:
        """Recon actions may operate on TARGET_HOSTS or own hosts for verification."""

        is_target = self.cfg.is_target_host(host)
        is_own = host in self.cfg.own_hosts or self.cfg.is_own_service(host, port)

        if not (is_target or is_own):
            return self._reject(
                decision,
                f"Recon host '{host}' is neither in TARGET_HOSTS nor OWN_SERVICES.",
                RiskLevel.HIGH,
            )

        sanitized = f"{host}:{port}" if port else host
        return AuthorizationResult(
            allowed=True,
            reason=f"Authorized recon target '{sanitized}'.",
            risk_level=RiskLevel.LOW,
            sanitized_target=sanitized,
            safe_decision=decision,
        )

    def _reject(
        self, decision: Decision, reason: str, risk_level: RiskLevel
    ) -> AuthorizationResult:
        logger.error(
            "[SECURITY ALERT] [%s] Rejected unauthorized %s action on '%s': %s",
            risk_level.value,
            decision.action_type,
            decision.target,
            reason,
        )
        safe_fallback = Decision(
            action_type="hold",
            target="",
            priority="low",
            reasoning=f"Security Policy Rejection: {reason}",
            confidence=1.0,
            model_used=decision.model_used or "security-gate",
        )
        return AuthorizationResult(
            allowed=False,
            reason=reason,
            risk_level=risk_level,
            sanitized_target="",
            safe_decision=safe_fallback,
        )


security_policy = SecurityPolicy()
