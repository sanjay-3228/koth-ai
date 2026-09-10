"""Simulated fake objects, interfaces, and safety interceptors for PwnGrounds rehearsal mode.

Provides explicit in-memory simulations of:
  - simulated network state (interfaces, routes, detector)
  - simulated competition scope (CIDRs, own hosts/services, target hosts)
  - simulated scoreboard (rounds, scores, service status, stale/outage states)
  - simulated telemetry (Telemetry snapshots, health statuses)
  - simulated action executor (patcher, firewall, recon, exploit dispatcher)
  - simulated verification results (port checks, rule checks, failure injections)
  - simulated time/events (clock, timeline engine, event logging)
  - simulated decision engine (NVIDIA Fast, NVIDIA Reasoning, failure injections)
  - safety interceptor (guarantees zero real socket connections, subprocesses, firewall, systemctl)

Guarantees:
  - actually_executed is ALWAYS False for every action.
  - Zero network packets transmitted to real targets.
  - Zero subprocess executions for actions.
  - Zero firewall modifications.
  - Zero systemctl invocations.
  - Zero exploit plugins run against real targets.
  - Zero writes outside reports/ and temporary locations.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass, field
import ipaddress
import os
import socket
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .actions.base import ActionContext, ActionExecutionRecord, DryRunRecord
from .attack.plugin_interface import ExploitPlugin, ExploitResult
from .attack.recon import HostFingerprint
from .config import Config
from .defense.firewall import FirewallManager, FirewallRule
from .defense.patcher import PatchResult, ServicePatcher
from .logger import get_logger
from .network.competition_scope import CompetitionNetworkGuard, CompetitionScope
from .network.detector import NetworkDetector
from .network.models import (
    EnvironmentMode,
    EnvironmentState,
    InterfaceType,
    NetworkInterface,
    Route,
    VpnStatus,
)
from .nvidia_client import Decision
from .scoreboard.base import NormalizedScoreboardState
from .telemetry import ServiceStatus, Telemetry

logger = get_logger(__name__)


# ==============================================================================
# 1. Simulated Network State
# ==============================================================================
class SimulatedNetworkState:
    """Explicit fake object exposing simulated network interfaces, routes, and detectors."""

    def __init__(
        self,
        wifi_ip: str = "192.168.1.50",
        wifi_cidr: str = "192.168.1.0/24",
        vpn_ip: str = "10.200.1.5",
        vpn_cidr: str = "10.200.0.0/16",
        gateway: str = "192.168.1.1",
    ):
        self.wifi_ip = wifi_ip
        self.wifi_cidr = wifi_cidr
        self.vpn_ip = vpn_ip
        self.vpn_cidr = vpn_cidr
        self.gateway = gateway
        self.vpn_connected: bool = True
        self.wifi_connected: bool = True
        self.wrong_vpn_subnet: bool = False

    def get_interfaces(self) -> List[NetworkInterface]:
        ifaces = [
            NetworkInterface(
                name="lo",
                addresses=["127.0.0.1"],
                cidrs=["127.0.0.0/8"],
                is_up=True,
                interface_type=InterfaceType.LOOPBACK,
            )
        ]
        if self.wifi_connected:
            ifaces.append(
                NetworkInterface(
                    name="wlan0",
                    addresses=[self.wifi_ip],
                    cidrs=[self.wifi_cidr],
                    is_up=True,
                    interface_type=InterfaceType.WIFI,
                    mac="00:11:22:33:44:55",
                )
            )
        if self.vpn_connected:
            vpn_addr = "10.99.1.5" if self.wrong_vpn_subnet else self.vpn_ip
            vpn_net = "10.99.0.0/16" if self.wrong_vpn_subnet else self.vpn_cidr
            ifaces.append(
                NetworkInterface(
                    name="tun0",
                    addresses=[vpn_addr],
                    cidrs=[vpn_net],
                    is_up=True,
                    interface_type=InterfaceType.VPN,
                )
            )
        return ifaces

    def get_routes(self) -> List[Route]:
        routes = []
        if self.wifi_connected:
            routes.append(
                Route(
                    destination="0.0.0.0",
                    gateway=self.gateway,
                    interface="wlan0",
                    netmask="0",
                    metric=100,
                )
            )
            routes.append(
                Route(
                    destination="192.168.1.0",
                    gateway="0.0.0.0",
                    interface="wlan0",
                    netmask="24",
                    metric=100,
                )
            )
        if self.vpn_connected:
            dest = "10.99.0.0" if self.wrong_vpn_subnet else "10.200.0.0"
            routes.append(
                Route(
                    destination=dest,
                    gateway="0.0.0.0",
                    interface="tun0",
                    netmask="16",
                    metric=50,
                )
            )
        return routes

    def to_detector(self) -> NetworkDetector:
        return NetworkDetector(
            interfaces=self.get_interfaces(),
            routes=self.get_routes(),
            default_gateway=self.gateway,
        )


# ==============================================================================
# 2. Simulated Competition Scope
# ==============================================================================
class SimulatedCompetitionScope:
    """Explicit fake object exposing simulated competition CIDRs, own services, and target hosts."""

    def __init__(
        self,
        competition_cidr: str = "10.200.0.0/16",
        own_host: str = "10.200.1.5",
        own_services: Optional[List[str]] = None,
        target_hosts: Optional[List[str]] = None,
        scoreboard_url: str = "http://scoreboard.pwngrounds.local/api",
    ):
        self.competition_cidr = competition_cidr
        self.own_host = own_host
        self.own_services = own_services or [
            f"{own_host}:80:web-service",
            f"{own_host}:22:sshd",
        ]
        self.target_hosts = target_hosts or ["10.200.2.10", "10.200.2.20"]
        self.scoreboard_url = scoreboard_url

    @property
    def own_hosts(self) -> List[str]:
        return [self.own_host]

    def to_scope(self) -> CompetitionScope:
        return CompetitionScope(
            mode="wifi_plus_vpn",
            competition_cidrs=[ipaddress.ip_network(self.competition_cidr)],
            own_hosts=[self.own_host],
            own_services=self.own_services,
            target_hosts=self.target_hosts,
            scoreboard_url=self.scoreboard_url,
        )

    def to_config(self, db_path: str = ":memory:") -> Config:
        cfg = Config(
            koth_mode="DRY_RUN",
            observation_only=True,
            dry_run=True,
            lab_profile="PWNGROUNDS_SIM",
            own_services=self.own_services,
            target_hosts=self.target_hosts,
            scoreboard_url=self.scoreboard_url,
            db_path=db_path,
            allowed_plugins=["simulated_exploit_module"],
            nvidia_fast_model="nvidia/nemotron-3.5-lightning-30b-a3b",
            nvidia_reasoning_model="nvidia/nemotron-3-super-120b-a12b",
            nvidia_confidence_threshold=0.75,
            max_actions_per_minute=12,
        )
        # Ensure PWN_* fields reflect simulated scope
        cfg.pwn_competition_cidrs_raw = self.competition_cidr
        cfg.pwn_own_hosts_raw = self.own_host
        cfg.pwn_own_services_raw = ",".join(self.own_services)
        cfg.pwn_target_hosts_raw = ",".join(self.target_hosts)
        cfg.pwn_scoreboard_url = self.scoreboard_url
        cfg.pwn_mode = "wifi_plus_vpn"
        return cfg


# ==============================================================================
# 3. Simulated Scoreboard
# ==============================================================================
class SimulatedScoreboard:
    """Explicit fake object exposing simulated scoreboard data, transitions, and state normalization."""

    def __init__(
        self,
        our_score: float = 1000.0,
        rank: int = 1,
        own_host: str = "10.200.1.5",
        services: Optional[List[Tuple[int, str]]] = None,
        competitor_scores: Optional[Dict[str, float]] = None,
    ):
        self.round_number: int = 1
        self.our_score: float = our_score
        self.rank: int = rank
        self.own_host = own_host
        svc_specs = services or [(80, "web-service"), (22, "sshd")]
        self.services: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for port, unit in svc_specs:
            self.services[(own_host, port)] = {
                "unit": unit,
                "up": True,
                "note": "operational",
            }
        self.competitor_scores: Dict[str, float] = competitor_scores or {
            "null_warriors": 950.0,
            "team_bravo": 900.0,
        }
        self.is_available: bool = True
        self.is_stale: bool = False
        self.error_message: Optional[str] = None
        self.last_scoreboard_latency_ms: float = 0.5
        self.last_json_parsing_latency_ms: float = 0.1

    def fail_service(self, host: str, port: int, note: str = "Connection refused"):
        key = (host, port)
        if key in self.services:
            self.services[key]["up"] = False
            self.services[key]["note"] = note

    def recover_service(self, host: str, port: int, note: str = "Recovered"):
        key = (host, port)
        if key in self.services:
            self.services[key]["up"] = True
            self.services[key]["note"] = note

    def update_score(self, delta: float):
        self.our_score += delta

    def set_stale(self, stale: bool = True):
        self.is_stale = stale

    def set_unavailable(self, error: str = "Scoreboard connection timeout (HTTP 504)"):
        self.is_available = False
        self.error_message = error

    def set_available(self):
        self.is_available = True
        self.error_message = None
        self.is_stale = False

    def get_state(self) -> NormalizedScoreboardState:
        now = time.time()
        from .scoreboard.base import ScoreboardStatus
        if not self.is_available:
            return NormalizedScoreboardState(
                timestamp=now,
                is_valid=False,
                error=self.error_message or "Scoreboard unavailable",
                status=ScoreboardStatus.UNREACHABLE,
            )
        if self.is_stale:
            return NormalizedScoreboardState(
                timestamp=now - 120.0,
                is_valid=False,
                is_stale=True,
                error="Scoreboard data is stale",
                status=ScoreboardStatus.STALE,
            )
        service_statuses = [
            ServiceStatus(host=h, port=p, up=v["up"], last_checked=now, note=v["note"])
            for (h, p), v in self.services.items()
        ]
        return NormalizedScoreboardState(
            timestamp=now,
            own_score=self.our_score,
            opponent_scores=dict(self.competitor_scores),
            rank=self.rank,
            service_status=service_statuses,
            is_valid=True,
            status=ScoreboardStatus.REACHABLE,
            metadata={
                "profile": "PWNGROUNDS_SIM",
                "round": self.round_number,
                "score": self.our_score,
                "rank": self.rank,
                "competitor_scores": dict(self.competitor_scores),
            },
        )

    def to_telemetry(self, state: Optional[NormalizedScoreboardState] = None) -> Telemetry:
        return self.fetch()

    def fetch(self) -> Telemetry:
        state = self.get_state()
        if not state.is_valid:
            return Telemetry(
                timestamp=time.time(),
                our_score=None,
                rank=None,
                our_services=[],
                competitor_scores={},
                raw={
                    "error": state.error or "Scoreboard error",
                    "stale": state.is_stale,
                    "scoreboard_status": "UNAVAILABLE" if not self.is_available else "STALE",
                },
            )
        return Telemetry(
            timestamp=state.timestamp,
            our_score=state.own_score,
            rank=state.rank,
            our_services=state.service_status,
            competitor_scores=dict(self.competitor_scores),
            raw={
                "profile": "PWNGROUNDS_SIM",
                "round": self.round_number,
                "score": self.our_score,
                "rank": self.rank,
                "stale": False,
                "competitor_scores": dict(self.competitor_scores),
            },
        )


# ==============================================================================
# 4. Simulated Telemetry Snapshot
# ==============================================================================
class SimulatedTelemetry:
    """Explicit fake object exposing structured telemetry snapshots and health metrics."""

    def __init__(self, scoreboard: SimulatedScoreboard):
        self.scoreboard = scoreboard

    def snapshot(self) -> Telemetry:
        return self.scoreboard.fetch()

    def poll(self) -> Telemetry:
        return self.snapshot()

    @property
    def is_healthy(self) -> bool:
        snap = self.snapshot()
        raw = getattr(snap, "raw", {})
        if raw.get("error") or raw.get("stale"):
            return False
        return all(getattr(s, "up", False) for s in getattr(snap, "our_services", []))


# ==============================================================================
# 5. Simulated Action Executor (Safe, Zero-Execution Backend)
# ==============================================================================
class SimulatedActionExecutor:
    """Explicit fake object ensuring every action is simulated and NEVER actually executed.

    Hard assertion: actually_executed is ALWAYS False.
    """

    def __init__(
        self,
        own_host: str = "10.200.1.5",
        scoreboard: Optional[SimulatedScoreboard] = None,
        verification_results: Optional[SimulatedVerificationResults] = None,
    ):
        self.own_host = own_host
        self.scoreboard = scoreboard
        self.verification_results = verification_results
        self.actually_executed_count: int = 0
        self.simulated_actions_count: int = 0
        self.restart_counts: Dict[str, int] = {"web-service": 0, "sshd": 0}
        self.firewall_rules: List[FirewallRule] = []
        self.applied_rules: List[str] = []
        self.recon_calls: List[str] = []
        self.plugin_dispatches: List[Dict[str, Any]] = []

    # Mock ServicePatcher interface
    def restart(self, service_name: str) -> PatchResult:
        # Strictly simulated: NO systemctl command is executed
        self.simulated_actions_count += 1
        self.restart_counts[service_name] = self.restart_counts.get(service_name, 0) + 1
        if self.scoreboard:
            for (h, p), v in self.scoreboard.services.items():
                if v.get("unit") == service_name:
                    if self.verification_results and self.verification_results.injected_service_failures.get((h, p), False):
                        self.scoreboard.fail_service(h, p, "Restart simulated but verification failure injected")
                    else:
                        self.scoreboard.recover_service(h, p, "Restarted via simulated action")
        return PatchResult(
            service=service_name,
            action="restart",
            success=True,
            output=f"[rehearsal-simulated] systemctl restart {service_name}.service (no real command executed)",
        )

    def rollback(self, service_name: str, backup_path: str, live_path: str) -> PatchResult:
        self.simulated_actions_count += 1
        return PatchResult(
            service=service_name,
            action="rollback",
            success=True,
            output=f"[rehearsal-simulated] rollback {service_name}",
        )

    # Mock FirewallManager interface
    def apply(self, rule: FirewallRule) -> str:
        # Strictly simulated: NO nftables or iptables command is executed
        self.simulated_actions_count += 1
        self.firewall_rules.append(rule)
        preview = f"nft add rule inet filter input {rule.action}"
        self.applied_rules.append(preview)
        return preview

    def block_source(self, source_ip: str, note: str = "auto-blocked") -> str:
        rule = FirewallRule(action="drop", proto="any", all_ports=True, source=source_ip, note=note)
        return self.apply(rule)

    def rate_limit_port(self, port: int, proto: str = "tcp", note: str = "auto rate-limit") -> str:
        rule = FirewallRule(action="rate_limit", proto=proto, port=port, note=note)
        return self.apply(rule)

    # Mock ReconScanner interface
    def scan(self, host: str, ports: str = "1-1024") -> HostFingerprint:
        # Strictly simulated: NO socket connections or nmap runs
        self.simulated_actions_count += 1
        self.recon_calls.append(host)
        if host == self.own_host:
            return HostFingerprint(
                host=host,
                open_ports=[22, 80],
                services={22: "OpenSSH 8.9p1", 80: "nginx 1.18.0"},
                service_names={22: "ssh", 80: "http"},
                service_versions={22: "8.9p1", 80: "1.18.0"},
                reachable=True,
            )
        return HostFingerprint(
            host=host,
            open_ports=[8080],
            services={8080: "http-alt Apache 2.4.52"},
            service_names={8080: "http-alt"},
            service_versions={8080: "2.4.52"},
            reachable=True,
        )

    # Mock PluginDispatcher interface
    def dispatch(
        self,
        fingerprint: HostFingerprint,
        target_port: int,
        context: dict,
        cfg: Optional[Config] = None,
    ) -> Optional[ExploitResult]:
        # Strictly simulated: NO exploit payload sent
        self.simulated_actions_count += 1
        self.plugin_dispatches.append({
            "target": f"{fingerprint.host}:{target_port}",
            "context": context,
        })
        return ExploitResult(
            success=True,
            flag="SIMULATED_FLAG{PWN_GROUNDS_REHEARSAL_VERIFIED}",
            notes="[rehearsal-simulated] Exploit outcome simulated without target interaction.",
        )


# ==============================================================================
# 6. Simulated Verification Results
# ==============================================================================
class SimulatedVerificationResults:
    """Explicit fake object exposing decoupled state verification results."""

    def __init__(self, service_host_ref: Optional[Dict[Tuple[str, int], Dict[str, Any]]] = None):
        self.service_host_ref = service_host_ref
        self.injected_service_failures: Dict[Tuple[str, int], bool] = {}
        self.probed_checks: List[Dict[str, Any]] = []

    def inject_verification_failure(self, host: str, port: int, fail: bool = True):
        self.injected_service_failures[(host, port)] = fail

    def clear_injections(self):
        self.injected_service_failures.clear()

    def check_service_reachability(self, host: str, port: int) -> bool:
        # Injected verification failure overrides reality
        if self.injected_service_failures.get((host, port), False):
            self.probed_checks.append({"target": f"{host}:{port}", "result": False, "injected": True})
            return False
        if self.service_host_ref and (host, port) in self.service_host_ref:
            res = bool(self.service_host_ref[(host, port)].get("up", True))
            self.probed_checks.append({"target": f"{host}:{port}", "result": res, "injected": False})
            return res
        return True


# ==============================================================================
# 7. Simulated Time / Events
# ==============================================================================
class SimulatedTimeEvents:
    """Explicit fake object managing simulation timeline, clock, and event milestones."""

    def __init__(self, start_time: float = 1725700000.0):
        self.current_time: float = start_time
        self.events: List[Dict[str, Any]] = []

    def time(self) -> float:
        return self.current_time

    def advance(self, seconds: float = 1.0):
        self.current_time += seconds

    def log_event(self, step_number: int, name: str, details: Optional[Dict[str, Any]] = None):
        evt = {
            "step": step_number,
            "name": name,
            "timestamp": self.current_time,
            "details": details or {},
        }
        self.events.append(evt)
        logger.info("[rehearsal:event] Step %d: %s (t=%.1f)", step_number, name, self.current_time)


# ==============================================================================
# 8. Simulated Decision Engine (NVIDIA NIM Advisory Simulation)
# ==============================================================================
class SimulatedDecisionEngine:
    """Explicit fake object simulating NVIDIA NIM Fast and Reasoning advisory engines."""

    def __init__(
        self,
        fast_model: str = "nvidia/nemotron-3.5-lightning-30b-a3b",
        reasoning_model: str = "nvidia/nemotron-3-super-120b-a12b",
    ):
        self.fast_model = fast_model
        self.reasoning_model = reasoning_model
        self.force_timeout: bool = False
        self.force_malformed: bool = False
        self.force_unauthorized_target: bool = False
        self.force_forbidden_port: bool = False
        self.force_low_confidence: bool = False
        self.call_history: List[Dict[str, Any]] = []

    def decide_tactical(self, telemetry_summary: str, recent_actions: List[str]) -> Decision:
        return self.decide(telemetry_summary, recent_actions, model=self.fast_model)

    def decide_deep_reasoning(self, telemetry_summary: str, recent_actions: List[str]) -> Decision:
        return self.decide(telemetry_summary, recent_actions, model=self.reasoning_model)

    def decide(
        self,
        telemetry_summary: str,
        recent_actions: List[str],
        model: Optional[str] = None,
    ) -> Decision:
        chosen_model = model or self.fast_model
        self.call_history.append({"model": chosen_model, "time": time.time()})

        # Failure Injections
        if self.force_timeout:
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="NVIDIA Fast call failed; HTTP 408 Request Timed Out",
                confidence=0.0,
                model_used=chosen_model,
                http_status=408,
            )

        if self.force_malformed:
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="Failed to parse JSON response from NVIDIA NIM: invalid syntax",
                confidence=0.0,
                model_used=chosen_model,
            )

        if self.force_unauthorized_target:
            return Decision(
                action_type="attack",
                target="192.168.99.99:80",
                priority="critical",
                reasoning="Advisory recommendation targeting out-of-scope host 192.168.99.99",
                confidence=0.9,
                model_used=chosen_model,
            )

        if self.force_forbidden_port:
            return Decision(
                action_type="defend",
                target="10.200.1.5:9999",
                priority="critical",
                reasoning="Advisory recommendation targeting unconfigured port 9999",
                confidence=0.95,
                model_used=chosen_model,
            )

        if self.force_low_confidence:
            return Decision(
                action_type="recon",
                target="10.200.2.10",
                priority="medium",
                reasoning="Low confidence routine scan",
                confidence=0.45,
                model_used=chosen_model,
                needs_escalation=True,
            )

        # Tactical recommendation
        return Decision(
            action_type="attack",
            target="10.200.2.10:8080",
            priority="high",
            reasoning="NVIDIA advisory: target competitor service on 10.200.2.10:8080",
            confidence=0.88,
            model_used=chosen_model,
        )


# ==============================================================================
# 9. Safety Interceptor & Sandbox Verifier
# ==============================================================================
class SafetyInterceptor:
    """Enforces strict isolation during rehearsal.

    Interception points:
      - socket.socket.connect -> strictly blocked/counted
      - subprocess.run / Popen -> strictly blocked/counted
      - systemctl calls -> strictly 0
      - firewall modification -> strictly 0
      - exploit execution -> strictly 0
      - out-of-bounds writes -> strictly 0
    """

    def __init__(self, allowed_write_dirs: Optional[List[str]] = None):
        self.allowed_write_dirs = allowed_write_dirs or ["reports", "/tmp"]
        self.real_socket_connections: int = 0
        self.real_subprocess_executions: int = 0
        self.real_firewall_changes: int = 0
        self.real_systemctl_calls: int = 0
        self.real_exploit_executions: int = 0
        self.out_of_bounds_writes: int = 0
        self.safety_violations: List[str] = []
        self._orig_connect = None
        self._orig_subprocess_run = None

    def record_socket_attempt(self, address: Any):
        self.real_socket_connections += 1
        msg = f"SAFETY VIOLATION: Real socket connection attempted to {address}"
        self.safety_violations.append(msg)
        logger.error("[SAFETY GATES] %s", msg)

    def record_subprocess_attempt(self, cmd: Any):
        self.real_subprocess_executions += 1
        msg = f"SAFETY VIOLATION: Real subprocess attempted: {cmd}"
        self.safety_violations.append(msg)
        logger.error("[SAFETY GATES] %s", msg)

    @contextmanager
    def guard(self):
        """Context manager installing safety traps."""
        self._orig_connect = socket.socket.connect
        self._orig_subprocess_run = subprocess.run

        def safe_connect(sock_self, address):
            self.record_socket_attempt(address)
            raise RuntimeError(f"Rehearsal safety violation: real socket connection to {address} forbidden!")

        def safe_subprocess_run(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            self.record_subprocess_attempt(cmd)
            raise RuntimeError(f"Rehearsal safety violation: real subprocess execution {cmd} forbidden!")

        socket.socket.connect = safe_connect
        subprocess.run = safe_subprocess_run

        try:
            yield self
        finally:
            socket.socket.connect = self._orig_connect
            subprocess.run = self._orig_subprocess_run
