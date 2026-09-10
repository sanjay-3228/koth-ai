"""PwnGrounds competition scope configuration, environment classification, and network guard.

Enforces:
  1. Destination syntax validation
  2. Destination IP normalization
  3. Competition CIDR membership check
  4. Explicit TARGET_HOSTS check for attack operations
  5. OWN_HOSTS / OWN_SERVICES check for defense operations
  6. SecurityPolicy authorization
  7. ActionRegistry catalog resolution
  8. Rate limiting (max 12 actions/minute)
  9. Kill-switch check

If ANY check fails: returns safe HOLD.
Never broadens scope to 0.0.0.0/0, RFC1918 broad ranges, or entire local subnets.
"""
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..actions.registry import action_registry
from ..config import Config, config as global_config
from ..gemini_client import Decision
from ..logger import get_logger
from ..security.policy import RiskLevel, SecurityPolicy, security_policy
from ..security.safety_gates import SafetyGateManager
from .detector import NetworkDetector
from .models import EnvironmentMode, EnvironmentState, InterfaceType, NetworkInterface, Route, VpnStatus
from .vpn import VpnDetector

logger = get_logger(__name__)

TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]+(?::\d{1,5})?$")


@dataclass
class CompetitionScope:
    """Explicit competition scope configuration."""
    mode: str = "auto"
    competition_cidrs: List[ipaddress.IPv4Network] = field(default_factory=list)
    own_hosts: List[str] = field(default_factory=list)
    own_services: List[str] = field(default_factory=list)
    target_hosts: List[str] = field(default_factory=list)
    protected_hosts: List[str] = field(default_factory=list)
    scoreboard_url: str = ""

    @classmethod
    def from_config(cls, cfg: Optional[Config] = None) -> "CompetitionScope":
        c = cfg or global_config

        # 1. Mode
        mode = os.getenv("PWN_MODE", getattr(c, "pwn_mode", "auto")).lower()

        # 2. CIDRs
        raw_cidrs = os.getenv("PWN_COMPETITION_CIDRS", getattr(c, "pwn_competition_cidrs_raw", ""))
        cidrs: List[ipaddress.IPv4Network] = []
        if raw_cidrs:
            for item in raw_cidrs.split(","):
                item_str = item.strip()
                if item_str:
                    try:
                        cidrs.append(ipaddress.ip_network(item_str, strict=False))
                    except ValueError as exc:
                        logger.warning("[scope] Invalid competition CIDR '%s': %s", item_str, exc)

        # 3. Own Hosts
        raw_own_hosts = os.getenv("PWN_OWN_HOSTS", getattr(c, "pwn_own_hosts_raw", ""))
        own_hosts = [h.strip() for h in raw_own_hosts.split(",") if h.strip()]
        if not own_hosts and c.own_hosts:
            own_hosts = list(c.own_hosts)

        # 4. Own Services
        raw_own_services = os.getenv("PWN_OWN_SERVICES", getattr(c, "pwn_own_services_raw", ""))
        own_services = [s.strip() for s in raw_own_services.split(",") if s.strip()]
        if not own_services and c.own_services:
            own_services = list(c.own_services)

        # 5. Target Hosts
        raw_targets = os.getenv("PWN_TARGET_HOSTS", getattr(c, "pwn_target_hosts_raw", ""))
        target_hosts = [t.strip() for t in raw_targets.split(",") if t.strip()]
        if not target_hosts and c.target_hosts:
            target_hosts = list(c.target_hosts)

        # 6. Scoreboard URL
        sb_url = os.getenv("PWN_SCOREBOARD_URL", getattr(c, "pwn_scoreboard_url", ""))
        if not sb_url:
            sb_url = c.scoreboard_url

        # 7. Protected Hosts
        raw_protected = os.getenv("PWN_PROTECTED_HOSTS", os.getenv("PROTECTED_HOSTS", ""))
        protected_hosts = [p.strip() for p in raw_protected.split(",") if p.strip()]
        if not protected_hosts and getattr(c, "protected_hosts", None):
            protected_hosts = list(c.protected_hosts)
        if not protected_hosts and own_hosts:
            protected_hosts = list(own_hosts)

        return cls(
            mode=mode,
            competition_cidrs=cidrs,
            own_hosts=own_hosts,
            own_services=own_services,
            target_hosts=target_hosts,
            protected_hosts=protected_hosts,
            scoreboard_url=sb_url,
        )

    def is_configured(self) -> bool:
        """Scope is considered configured only when at least one valid CIDR is specified."""
        return len(self.competition_cidrs) > 0

    def is_in_competition_cidr(self, host_or_ip: str) -> bool:
        """Verify an IP address strictly falls within configured competition CIDRs."""
        if not self.is_configured():
            return False
        try:
            ip_obj = ipaddress.ip_address(host_or_ip)
        except ValueError:
            return False

        for net in self.competition_cidrs:
            if ip_obj in net:
                return True
        return False

    def is_own_host(self, host: str) -> bool:
        return host in self.own_hosts

    def is_protected_host(self, host: str) -> bool:
        return host in self.protected_hosts or host in self.own_hosts

    def is_target_host(self, host: str) -> bool:
        return host in self.target_hosts

    def is_own_service(self, host: str, port: int) -> bool:
        target = f"{host}:{port}"
        for s in self.own_services:
            parts = s.split(":")
            if len(parts) >= 2 and parts[0] == host and str(parts[1]) == str(port):
                return True
        return False

    def validate_scope(self) -> Tuple[bool, str]:
        """Comprehensive verification of scope consistency."""
        if not self.competition_cidrs:
            return False, "PWN_COMPETITION_CIDRS is empty. Scope cannot be verified."

        # Verify own hosts belong to competition CIDRs
        for oh in self.own_hosts:
            if not self.is_in_competition_cidr(oh):
                return False, f"Configured own host '{oh}' is outside competition CIDRs ({self.competition_cidrs})."

        # Verify target hosts belong to competition CIDRs
        for th in self.target_hosts:
            if not self.is_in_competition_cidr(th):
                return False, f"Configured target host '{th}' is outside competition CIDRs ({self.competition_cidrs})."

        # Verify no intersection between target_hosts and own_hosts or protected_hosts
        forbidden = set(self.own_hosts).union(set(self.protected_hosts))
        intersection = set(self.target_hosts).intersection(forbidden)
        if intersection:
            return False, f"Target hosts intersect own/protected hosts: {list(intersection)}"

        return True, "Competition scope verified and bounded."


def detect_environment(
    scope: Optional[CompetitionScope] = None,
    detector: Optional[NetworkDetector] = None,
) -> EnvironmentState:
    """Classify current environment: WIFI_ONLY, WIFI_PLUS_VPN, VPN_ONLY, or UNKNOWN.

    Rules:
      WIFI_ONLY: Competition CIDR is routed through regular Wi-Fi/LAN interface and no VPN routes it.
      WIFI_PLUS_VPN: Regular Wi-Fi/LAN exists, and competition CIDR is routed through a VPN interface.
      VPN_ONLY: Competition route exists exclusively through a VPN interface with no normal LAN/Wi-Fi.
      UNKNOWN: Competition CIDR route cannot be resolved or scope is unconfigured.
    """
    scope_inst = scope or CompetitionScope.from_config()
    detector_inst = detector or NetworkDetector()

    interfaces = detector_inst.get_interfaces()
    routes = detector_inst.get_routes()
    vpn_status, active_vpns = VpnDetector.detect_vpn_status(interfaces)
    vpn_present = (vpn_status == VpnStatus.CONNECTED)

    # Determine if any route goes through an active VPN interface
    vpn_iface_identifiers = set()
    for v in active_vpns:
        vpn_iface_identifiers.add(v.name)
        for addr in v.addresses:
            vpn_iface_identifiers.add(addr)

    vpn_route_present = any(
        (r.interface in vpn_iface_identifiers or r.gateway in vpn_iface_identifiers)
        for r in routes
    )
    active_vpn_names = [v.name for v in active_vpns]

    if not scope_inst.is_configured():
        return EnvironmentState(
            mode=EnvironmentMode.UNKNOWN,
            competition_route_present=False,
            competition_cidr=None,
            vpn_present=vpn_present,
            vpn_route_present=vpn_route_present,
            active_vpn_interfaces=active_vpn_names,
            interfaces=interfaces,
            routes=routes,
            confidence=0.0,
            details="PWN_COMPETITION_CIDRS unconfigured; environment classification unavailable.",
        )

    cidr_str = ", ".join(str(c) for c in scope_inst.competition_cidrs)

    # 1. Determine which interface routes into the competition CIDRs
    competition_interface: Optional[NetworkInterface] = None
    competition_route_present = False

    # Check explicit routes
    for r in routes:
        try:
            net_dst = ipaddress.ip_network(
                f"{r.destination}/{r.netmask if r.netmask else '32'}",
                strict=False,
            )
            # Never treat default route (0.0.0.0/0) or entire address space as competition route
            if net_dst.prefixlen == 0 or net_dst.num_addresses > (2**24):
                continue

            for comp_net in scope_inst.competition_cidrs:
                if net_dst == comp_net or net_dst.subnet_of(comp_net) or comp_net.subnet_of(net_dst):
                    competition_route_present = True
                    # Find matching interface
                    for iface in interfaces:
                        if iface.name == r.interface or r.interface in iface.addresses:
                            competition_interface = iface
                            break
                    break
        except ValueError:
            continue

    # Also check if any interface assigned address directly belongs to competition CIDR
    if not competition_interface:
        for iface in interfaces:
            for addr in iface.addresses:
                if scope_inst.is_in_competition_cidr(addr):
                    competition_route_present = True
                    competition_interface = iface
                    break
            if competition_interface:
                break

    # If competition route cannot be found
    if not competition_route_present:
        return EnvironmentState(
            mode=EnvironmentMode.UNKNOWN,
            competition_route_present=False,
            competition_cidr=cidr_str,
            vpn_present=vpn_present,
            vpn_route_present=vpn_route_present,
            active_vpn_interfaces=active_vpn_names,
            interfaces=interfaces,
            routes=routes,
            confidence=0.2,
            details=f"No route found matching competition CIDRs ({cidr_str}).",
        )

    # 2. Check interface classification for the competition route
    is_comp_via_vpn = False
    if competition_interface:
        is_comp_via_vpn = VpnDetector.is_vpn_interface(competition_interface)
    elif vpn_present:
        # Fallback heuristic: VPN is connected and route matched
        is_comp_via_vpn = True

    # Check for normal active non-VPN, non-loopback interfaces (Wi-Fi or Ethernet)
    normal_interfaces = [
        i for i in interfaces
        if i.is_up and len(i.addresses) > 0 and not VpnDetector.is_vpn_interface(i)
        and i.interface_type != InterfaceType.LOOPBACK
    ]

    has_wifi_lan = len(normal_interfaces) > 0

    if is_comp_via_vpn:
        if has_wifi_lan:
            return EnvironmentState(
                mode=EnvironmentMode.WIFI_PLUS_VPN,
                competition_route_present=True,
                competition_cidr=cidr_str,
                vpn_present=True,
                vpn_route_present=vpn_route_present,
                active_vpn_interfaces=active_vpn_names,
                interfaces=interfaces,
                routes=routes,
                confidence=0.95,
                details=f"Competition CIDR routed via VPN ({competition_interface.name if competition_interface else 'vpn'}) over local Wi-Fi/LAN.",
            )
        else:
            return EnvironmentState(
                mode=EnvironmentMode.VPN_ONLY,
                competition_route_present=True,
                competition_cidr=cidr_str,
                vpn_present=True,
                vpn_route_present=vpn_route_present,
                active_vpn_interfaces=active_vpn_names,
                interfaces=interfaces,
                routes=routes,
                confidence=0.9,
                details=f"Competition route present exclusively on VPN ({competition_interface.name if competition_interface else 'vpn'}).",
            )
    else:
        # Routed via normal Wi-Fi / Ethernet
        return EnvironmentState(
            mode=EnvironmentMode.WIFI_ONLY,
            competition_route_present=True,
            competition_cidr=cidr_str,
            vpn_present=vpn_present,
            vpn_route_present=vpn_route_present,
            active_vpn_interfaces=active_vpn_names,
            interfaces=interfaces,
            routes=routes,
            confidence=0.95,
            details=f"Competition CIDR directly routed via LAN/Wi-Fi interface ({competition_interface.name if competition_interface else 'lan'}).",
        )


@dataclass
class GuardResult:
    allowed: bool
    reason: str
    decision: Optional[Decision] = None
    sanitized_target: str = ""
    risk_level: RiskLevel = RiskLevel.LOW


class CompetitionNetworkGuard:
    """Rigorous gate validating every network action against the 9 safety criteria."""

    def __init__(
        self,
        scope: Optional[CompetitionScope] = None,
        policy: Optional[SecurityPolicy] = None,
        gates: Optional[SafetyGateManager] = None,
        cfg: Optional[Config] = None,
    ):
        self.cfg = cfg or global_config
        self.scope = scope or CompetitionScope.from_config(self.cfg)
        self.policy = policy or SecurityPolicy(self.cfg)
        self.gates = gates or SafetyGateManager(self.cfg)

    def verify_action(self, decision: Decision) -> GuardResult:
        """Evaluate action across all 9 criteria. Returns safe hold on any failure."""
        # 1. Kill-switch check
        if self.gates.is_kill_switch_engaged():
            return GuardResult(
                allowed=False,
                reason="[GUARD REJECT] Kill-switch is engaged. Safe hold enforced.",
                decision=self._make_hold(decision, "Kill-switch engaged"),
                risk_level=RiskLevel.CRITICAL,
            )

        # 2. Hold action is always unconditionally safe
        if decision.action_type == "hold":
            return GuardResult(
                allowed=True,
                reason="Hold action permitted.",
                decision=decision,
                sanitized_target="",
                risk_level=RiskLevel.LOW,
            )

        # 3. Destination syntax validation
        target = (decision.target or "").strip()
        if not target or not TARGET_PATTERN.match(target):
            return GuardResult(
                allowed=False,
                reason=f"[GUARD REJECT] Target '{target}' violates format allowlist (injection or invalid syntax).",
                decision=self._make_hold(decision, "Format rejection"),
                risk_level=RiskLevel.CRITICAL,
            )

        # 4. Destination IP/hostname normalization
        host = target.split(":")[0]
        port = 0
        if ":" in target:
            try:
                port = int(target.split(":")[1])
            except ValueError:
                return GuardResult(
                    allowed=False,
                    reason=f"[GUARD REJECT] Invalid port in target '{target}'.",
                    decision=self._make_hold(decision, "Invalid port"),
                    risk_level=RiskLevel.HIGH,
                )

        # 5. Competition CIDR check (CRITICAL: Never broaden scope to 0.0.0.0/0 or broad RFC1918)
        if not self.scope.is_configured():
            return GuardResult(
                allowed=False,
                reason="[GUARD REJECT] Competition CIDR unconfigured. Action rejected to prevent unauthorized traffic.",
                decision=self._make_hold(decision, "Unconfigured competition CIDR"),
                risk_level=RiskLevel.CRITICAL,
            )

        if not self.scope.is_in_competition_cidr(host):
            return GuardResult(
                allowed=False,
                reason=f"[GUARD REJECT] Target '{host}' is outside competition CIDR(s) {self.scope.competition_cidrs}. Never attacking outside scope.",
                decision=self._make_hold(decision, f"Out of CIDR bounds: {host}"),
                risk_level=RiskLevel.CRITICAL,
            )

        # 6. Action-specific boundary checks
        if decision.action_type in ("attack", "recon"):
            # Target must be in explicit TARGET_HOSTS for attack operations
            if decision.action_type == "attack" and not self.scope.is_target_host(host):
                return GuardResult(
                    allowed=False,
                    reason=f"[GUARD REJECT] Attack target '{host}' is not in authorized TARGET_HOSTS ({self.scope.target_hosts}).",
                    decision=self._make_hold(decision, f"Unauthorized attack target: {host}"),
                    risk_level=RiskLevel.CRITICAL,
                )

        elif decision.action_type == "defend":
            # Defend operations strictly confined to OWN_SERVICES
            if not self.scope.is_own_service(host, port):
                return GuardResult(
                    allowed=False,
                    reason=f"[GUARD REJECT] Defense target '{target}' is not in configured OWN_SERVICES ({self.scope.own_services}).",
                    decision=self._make_hold(decision, f"Unauthorized defense target: {target}"),
                    risk_level=RiskLevel.HIGH,
                )

        # 7. SecurityPolicy authorization pass-through
        auth = self.policy.authorize(decision)
        if not auth.allowed:
            return GuardResult(
                allowed=False,
                reason=f"[GUARD REJECT] SecurityPolicy rejected action: {auth.reason}",
                decision=auth.safe_decision or self._make_hold(decision, auth.reason),
                risk_level=auth.risk_level,
            )

        # 8. ActionRegistry catalog resolution
        action = action_registry.resolve(decision.action_type, decision.target, decision.reasoning)
        if not action or action.action_name == "hold" and decision.action_type != "hold":
            return GuardResult(
                allowed=False,
                reason=f"[GUARD REJECT] Action '{decision.action_type}' failed catalog resolution.",
                decision=self._make_hold(decision, "Catalog resolution failure"),
                risk_level=RiskLevel.MEDIUM,
            )

        # 9. Rate limit check
        if not self.gates.rate_limiter.allow():
            return GuardResult(
                allowed=False,
                reason=f"[GUARD REJECT] Rate limit exceeded ({self.cfg.max_actions_per_minute}/min). Action throttled.",
                decision=self._make_hold(decision, "Rate limit exceeded"),
                risk_level=RiskLevel.MEDIUM,
            )

        return GuardResult(
            allowed=True,
            reason="Action passed all 9 competition network guard gates.",
            decision=decision,
            sanitized_target=target,
            risk_level=RiskLevel.LOW,
        )

    @staticmethod
    def _make_hold(decision: Decision, reason: str) -> Decision:
        return Decision(
            action_type="hold",
            target="",
            priority="low",
            reasoning=f"Guard held action: {reason}",
            confidence=decision.confidence,
            model_used=decision.model_used or "network-guard",
        ).sanitize()
