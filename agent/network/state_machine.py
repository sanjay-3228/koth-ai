"""Startup safety state machine for PwnGrounds KOTH agent.

Enforces sequential verification before allowing any operations:
  STARTING
    ↓
  NETWORK_DETECTED
    ↓
  COMPETITION_SCOPE_VERIFIED
    ↓
  SCOREBOARD_VERIFIED
    ↓
  TELEMETRY_VERIFIED
    ↓
  DRY_RUN_READY  ──(explicit LIVE authorization)──> AUTHORIZED_COMPETITION_MODE
    │
    └──(any failure)──> SAFE_HOLD

AI decisions CANNOT bypass this state machine.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config import Config, config as global_config
from ..logger import get_logger
from .competition_scope import CompetitionScope, detect_environment
from .detector import NetworkDetector
from .models import EnvironmentMode, EnvironmentState

logger = get_logger(__name__)


class StartupSafetyState(str, Enum):
    STARTING = "STARTING"
    NETWORK_DETECTED = "NETWORK_DETECTED"
    COMPETITION_SCOPE_VERIFIED = "COMPETITION_SCOPE_VERIFIED"
    OWN_HOSTS_VERIFIED = "OWN_HOSTS_VERIFIED"
    TARGET_HOSTS_VERIFIED = "TARGET_HOSTS_VERIFIED"
    PHASE_SOURCE_VERIFIED = "PHASE_SOURCE_VERIFIED"
    SCOREBOARD_VERIFIED = "SCOREBOARD_VERIFIED"
    TELEMETRY_VERIFIED = "TELEMETRY_VERIFIED"
    TELEMETRY_READY = "TELEMETRY_READY"
    DRY_RUN_READY = "DRY_RUN_READY"
    AUTHORIZED_COMPETITION_MODE = "AUTHORIZED_COMPETITION_MODE"
    LIVE_READY = "LIVE_READY"
    SAFE_HOLD = "SAFE_HOLD"


@dataclass
class StepResult:
    step_name: str
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


class StartupSafetyStateMachine:
    """Manages the startup verification gates and enforces SAFE_HOLD on failures."""

    def __init__(
        self,
        cfg: Optional[Config] = None,
        detector: Optional[NetworkDetector] = None,
        scope: Optional[CompetitionScope] = None,
        scoreboard_provider: Optional[Any] = None,
        telemetry_provider: Optional[Any] = None,
        phase_provider: Optional[Any] = None,
    ):
        self.cfg = cfg or global_config
        self.detector = detector or NetworkDetector()
        self.scope = scope or CompetitionScope.from_config(self.cfg)
        self.scoreboard_provider = scoreboard_provider
        self.telemetry_provider = telemetry_provider
        self.phase_provider = phase_provider

        self.current_state: StartupSafetyState = StartupSafetyState.STARTING
        self.history: List[StepResult] = []
        self.env_state: Optional[EnvironmentState] = None
        self.failure_reason: str = ""

    def can_execute_actions(self) -> bool:
        """Only DRY_RUN_READY, AUTHORIZED_COMPETITION_MODE, or LIVE_READY allow action execution."""
        return self.current_state in (
            StartupSafetyState.DRY_RUN_READY,
            StartupSafetyState.AUTHORIZED_COMPETITION_MODE,
            StartupSafetyState.LIVE_READY,
        )

    def is_safe_hold(self) -> bool:
        return self.current_state == StartupSafetyState.SAFE_HOLD

    def _fail(self, step_name: str, message: str, details: Optional[Dict[str, Any]] = None) -> StepResult:
        res = StepResult(step_name=step_name, success=False, message=message, details=details or {})
        self.history.append(res)
        self.current_state = StartupSafetyState.SAFE_HOLD
        self.failure_reason = f"{step_name}: {message}"
        logger.error("[state_machine] %s FAILED: %s -> Reverting to SAFE_HOLD", step_name, message)
        return res

    def _pass(self, step_name: str, next_state: StartupSafetyState, message: str, details: Optional[Dict[str, Any]] = None) -> StepResult:
        res = StepResult(step_name=step_name, success=True, message=message, details=details or {})
        self.history.append(res)
        self.current_state = next_state
        logger.info("[state_machine] %s PASSED: %s -> State: %s", step_name, message, next_state.value)
        return res

    # ----------------------------------------------------------------------
    # Step 1: Detect Network
    # ----------------------------------------------------------------------
    def step_detect_network(self) -> StepResult:
        if self.current_state != StartupSafetyState.STARTING:
            return self._fail("step_detect_network", f"Invalid prior state: {self.current_state.value}")

        interfaces = self.detector.get_interfaces()
        routes = self.detector.get_routes()
        active_ifaces = [i for i in interfaces if i.is_up and i.addresses]

        if not active_ifaces:
            return self._fail("step_detect_network", "No active network interfaces with IP addresses found.")

        self.env_state = detect_environment(self.scope, self.detector)

        return self._pass(
            "step_detect_network",
            StartupSafetyState.NETWORK_DETECTED,
            f"Detected {len(interfaces)} interfaces ({len(active_ifaces)} active), {len(routes)} routes.",
            {
                "interfaces_count": len(interfaces),
                "active_interfaces": [i.name for i in active_ifaces],
                "routes_count": len(routes),
                "detected_mode": self.env_state.mode.value if self.env_state else "UNKNOWN",
            },
        )

    # ----------------------------------------------------------------------
    # Step 2: Verify Competition Scope
    # ----------------------------------------------------------------------
    def step_verify_scope(self) -> StepResult:
        if self.current_state != StartupSafetyState.NETWORK_DETECTED:
            return self._fail("step_verify_scope", f"Must detect network before verifying scope (current: {self.current_state.value}).")

        valid, reason = self.scope.validate_scope()
        if not valid:
            return self._fail("step_verify_scope", f"Competition scope validation failed: {reason}")

        # Update environment state with verified scope
        self.env_state = detect_environment(self.scope, self.detector)
        if not self.env_state.competition_route_present:
            return self._fail(
                "step_verify_scope",
                f"No route matching configured competition CIDRs ({self.env_state.competition_cidr}) found in routing table.",
                {"env_state": self.env_state.to_dict()},
            )

        return self._pass(
            "step_verify_scope",
            StartupSafetyState.COMPETITION_SCOPE_VERIFIED,
            f"Competition scope verified. CIDRs: {self.scope.competition_cidrs}, Mode: {self.env_state.mode.value}",
            {
                "cidrs": [str(c) for c in self.scope.competition_cidrs],
                "own_hosts": self.scope.own_hosts,
                "target_hosts": self.scope.target_hosts,
                "env_mode": self.env_state.mode.value,
            },
        )

    # ----------------------------------------------------------------------
    # Step 2a: Verify Own Hosts
    # ----------------------------------------------------------------------
    def step_verify_own_hosts(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.COMPETITION_SCOPE_VERIFIED,
            StartupSafetyState.NETWORK_DETECTED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_verify_own_hosts", f"Invalid prior state: {self.current_state.value}")

        if not self.scope.own_hosts:
            return self._fail("step_verify_own_hosts", "No own_hosts configured to defend.")

        for h in self.scope.own_hosts:
            if not self.scope.is_in_competition_cidr(h):
                return self._fail("step_verify_own_hosts", f"Own host {h} is outside competition CIDRs.")

        return self._pass(
            "step_verify_own_hosts",
            StartupSafetyState.OWN_HOSTS_VERIFIED,
            f"Verified {len(self.scope.own_hosts)} own host(s) in competition scope.",
            {"own_hosts": self.scope.own_hosts},
        )

    # ----------------------------------------------------------------------
    # Step 2b: Verify Target Hosts
    # ----------------------------------------------------------------------
    def step_verify_target_hosts(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.OWN_HOSTS_VERIFIED,
            StartupSafetyState.COMPETITION_SCOPE_VERIFIED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_verify_target_hosts", f"Invalid prior state: {self.current_state.value}")

        if not self.scope.target_hosts:
            return self._fail("step_verify_target_hosts", "No target_hosts configured for competition.")

        # Check against protected and own hosts
        forbidden = set(self.scope.own_hosts).union(set(self.scope.protected_hosts))
        for th in self.scope.target_hosts:
            if th in forbidden:
                return self._fail("step_verify_target_hosts", f"Target host {th} is in own/protected hosts.")
            if not self.scope.is_in_competition_cidr(th):
                return self._fail("step_verify_target_hosts", f"Target host {th} is outside competition CIDRs.")

        return self._pass(
            "step_verify_target_hosts",
            StartupSafetyState.TARGET_HOSTS_VERIFIED,
            f"Verified {len(self.scope.target_hosts)} competition target host(s).",
            {"target_hosts": self.scope.target_hosts},
        )

    # ----------------------------------------------------------------------
    # Step 2c: Verify Phase Source / Scoreboard
    # ----------------------------------------------------------------------
    def step_verify_phase_source(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.TARGET_HOSTS_VERIFIED,
            StartupSafetyState.OWN_HOSTS_VERIFIED,
            StartupSafetyState.COMPETITION_SCOPE_VERIFIED,
            StartupSafetyState.SCOREBOARD_VERIFIED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_verify_phase_source", f"Invalid prior state: {self.current_state.value}")

        if self.phase_provider:
            try:
                state = self.phase_provider.get_phase()
                return self._pass(
                    "step_verify_phase_source",
                    StartupSafetyState.PHASE_SOURCE_VERIFIED,
                    f"Phase source verified: {state.phase.value} (epoch {state.phase_epoch})",
                    {"phase_state": state.to_dict()},
                )
            except Exception as exc:
                return self._fail("step_verify_phase_source", f"Phase provider poll error: {exc}")

        # Fallback to scoreboard check if no dedicated phase provider
        return self.step_verify_scoreboard()

    # ----------------------------------------------------------------------
    # Step 3: Verify Scoreboard (Retained for backwards compatibility)
    # ----------------------------------------------------------------------
    def step_verify_scoreboard(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.COMPETITION_SCOPE_VERIFIED,
            StartupSafetyState.TARGET_HOSTS_VERIFIED,
            StartupSafetyState.OWN_HOSTS_VERIFIED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_verify_scoreboard", f"Must verify scope before scoreboard (current: {self.current_state.value}).")

        if not self.scoreboard_provider:
            if not self.scope.scoreboard_url:
                return self._pass(
                    "step_verify_scoreboard",
                    StartupSafetyState.SCOREBOARD_VERIFIED,
                    "Scoreboard URL unconfigured; skipped for mock/offline validation.",
                )
            return self._fail("step_verify_scoreboard", "Scoreboard provider instance is missing.")

        try:
            state = self.scoreboard_provider.get_state()
            if state is None:
                return self._fail("step_verify_scoreboard", "Scoreboard returned None state.")
            return self._pass(
                "step_verify_scoreboard",
                StartupSafetyState.SCOREBOARD_VERIFIED,
                "Scoreboard verified and reachable.",
                {"round": getattr(state, "round_number", 0), "services_count": len(getattr(state, "services", []))},
            )
        except Exception as exc:
            return self._fail("step_verify_scoreboard", f"Scoreboard probe failed: {exc}")

    # ----------------------------------------------------------------------
    # Step 4: Verify Telemetry
    # ----------------------------------------------------------------------
    def step_verify_telemetry(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.SCOREBOARD_VERIFIED,
            StartupSafetyState.PHASE_SOURCE_VERIFIED,
            StartupSafetyState.TARGET_HOSTS_VERIFIED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_verify_telemetry", f"Invalid prior state for telemetry: {self.current_state.value}")

        if not self.telemetry_provider:
            return self._pass(
                "step_verify_telemetry",
                StartupSafetyState.TELEMETRY_VERIFIED,
                "Telemetry provider omitted; passed for unit/offline harness.",
            )

        try:
            snap = self.telemetry_provider.poll()
            if snap is None:
                return self._fail("step_verify_telemetry", "Telemetry provider returned empty snapshot.")
            return self._pass(
                "step_verify_telemetry",
                StartupSafetyState.TELEMETRY_VERIFIED,
                f"Telemetry snapshot verified (timestamp={getattr(snap, 'timestamp', 'N/A')}).",
            )
        except Exception as exc:
            return self._fail("step_verify_telemetry", f"Telemetry poll failed: {exc}")

    # ----------------------------------------------------------------------
    # Step 5: Enter DRY_RUN or AUTHORIZED_COMPETITION_MODE / LIVE_READY
    # ----------------------------------------------------------------------
    def step_enter_operating_mode(self) -> StepResult:
        valid_priors = (
            StartupSafetyState.TELEMETRY_VERIFIED,
            StartupSafetyState.TELEMETRY_READY,
            StartupSafetyState.SCOREBOARD_VERIFIED,
            StartupSafetyState.PHASE_SOURCE_VERIFIED,
        )
        if self.current_state not in valid_priors:
            return self._fail("step_enter_operating_mode", f"Must verify telemetry before entering operating mode (current: {self.current_state.value}).")

        koth_mode = getattr(self.cfg, "koth_mode", "DRY_RUN").upper()
        obs_only = getattr(self.cfg, "observation_only", True)

        # Explicit LIVE competition authorization requires strict affirmative flags
        if koth_mode == "LIVE" and not obs_only:
            return self._pass(
                "step_enter_operating_mode",
                StartupSafetyState.AUTHORIZED_COMPETITION_MODE,
                "AUTHORIZED COMPETITION MODE ACTIVE. Live actions enabled under SecurityPolicy gates.",
                {"koth_mode": "LIVE", "observation_only": False},
            )

        # Default is safe DRY_RUN_READY
        return self._pass(
            "step_enter_operating_mode",
            StartupSafetyState.DRY_RUN_READY,
            f"DRY RUN READY. Operating mode safe (KOTH_MODE={koth_mode}, OBSERVATION_ONLY={obs_only}).",
            {"koth_mode": koth_mode, "observation_only": obs_only},
        )

    # ----------------------------------------------------------------------
    # Execute full sequence
    # ----------------------------------------------------------------------
    def run_startup_sequence(self) -> StartupSafetyState:
        """Run all startup steps sequentially. Returns final StartupSafetyState."""
        logger.info("[state_machine] Starting PwnGrounds safety verification sequence...")

        steps: List[Callable[[], StepResult]] = [
            self.step_detect_network,
            self.step_verify_scope,
            self.step_verify_scoreboard,
            self.step_verify_telemetry,
            self.step_enter_operating_mode,
        ]

        for step in steps:
            result = step()
            if not result.success:
                logger.error("[state_machine] Verification sequence halted at step '%s'. Status: SAFE_HOLD", result.step_name)
                return StartupSafetyState.SAFE_HOLD

        logger.info("[state_machine] Safety verification sequence completed. Status: %s", self.current_state.value)
        return self.current_state
