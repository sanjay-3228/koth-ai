"""PwnGrounds network and environment adapter for koth-agent."""

from .competition_scope import (
    CompetitionNetworkGuard,
    CompetitionScope,
    GuardResult,
    detect_environment,
)
from .detector import NetworkDetector
from .models import (
    EnvironmentMode,
    EnvironmentState,
    InterfaceType,
    NetworkInterface,
    Route,
    VpnStatus,
)
from .state_machine import (
    StartupSafetyState,
    StartupSafetyStateMachine,
    StepResult,
)
from .vpn import VpnDetector

__all__ = [
    "CompetitionNetworkGuard",
    "CompetitionScope",
    "GuardResult",
    "detect_environment",
    "NetworkDetector",
    "EnvironmentMode",
    "EnvironmentState",
    "InterfaceType",
    "NetworkInterface",
    "Route",
    "VpnStatus",
    "StartupSafetyState",
    "StartupSafetyStateMachine",
    "StepResult",
    "VpnDetector",
]
