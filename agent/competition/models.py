"""
Domain models, Enums, and Dataclasses for KOTH & Red vs Blue Competition Platform.
Supports two distinct modes:
1. KOTH (5 formats: SINGLE_HILL, MULTI_HILL, TEAM_VS_TEAM, ELIMINATION, TIMED)
2. RED_VS_BLUE (6 formats: CLASSIC, MULTI_TEAM, MULTI_HILL, ELIMINATION, TIMED, CONTINUOUS)
   Both Red and Blue sides can attack, capture, defend, and recapture hills.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CompetitionMode(str, Enum):
    KOTH = "KOTH"
    RED_VS_BLUE = "RED_VS_BLUE"


class KothFormat(str, Enum):
    SINGLE_HILL = "SINGLE_HILL"
    MULTI_HILL = "MULTI_HILL"
    TEAM_VS_TEAM = "TEAM_VS_TEAM"
    ELIMINATION = "ELIMINATION"
    TIMED = "TIMED"


class RedVsBlueFormat(str, Enum):
    CLASSIC = "CLASSIC"
    MULTI_TEAM = "MULTI_TEAM"
    MULTI_HILL = "MULTI_HILL"
    ELIMINATION = "ELIMINATION"
    TIMED = "TIMED"
    CONTINUOUS = "CONTINUOUS"


class TeamSide(str, Enum):
    RED = "RED"
    BLUE = "BLUE"
    NEUTRAL = "NEUTRAL"


class HillEnvironmentType(str, Enum):
    LINUX = "LINUX"
    WINDOWS = "WINDOWS"
    WEB_APPLICATION = "WEB_APPLICATION"
    DATABASE = "DATABASE"
    NETWORK = "NETWORK"
    ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
    CLOUD_SECURITY = "CLOUD_SECURITY"
    CONTAINER_K8S = "CONTAINER_K8S"
    FORENSICS_IR = "FORENSICS_IR"


class OwnershipState(str, Enum):
    UNASSIGNED = "UNASSIGNED"
    AVAILABLE = "AVAILABLE"
    OWNED = "OWNED"
    UNDER_ATTACK = "UNDER_ATTACK"
    CAPTURE_PENDING = "CAPTURE_PENDING"
    CAPTURED = "CAPTURED"
    COMPROMISED = "COMPROMISED"
    LOST = "LOST"
    RECOVERY_PENDING = "RECOVERY_PENDING"
    UNKNOWN = "UNKNOWN"


class CompetitionStatus(str, Enum):
    DRAFT = "DRAFT"
    SCHEDULED = "SCHEDULED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class VerifierType(str, Enum):
    SIMULATED = "SIMULATED"
    FLAG_MATCH = "FLAG_MATCH"
    SERVICE_PROBE = "SERVICE_PROBE"
    SCRIPT_CHECK = "SCRIPT_CHECK"


class ScoreCategory(str, Enum):
    CAPTURE = "CAPTURE"
    HOLD_INTERVAL = "HOLD_INTERVAL"
    DEFENSE = "DEFENSE"
    RECAPTURE = "RECAPTURE"
    AVAILABILITY = "AVAILABILITY"
    PENALTY = "PENALTY"


@dataclass
class CompetitionRules:
    capture_points: int = 100
    defense_points: int = 50
    hold_interval_seconds: int = 60
    hold_interval_points: int = 10
    recapture_bonus: int = 25
    penalty_points: int = 15
    elimination_threshold: Optional[int] = None
    overtime_allowed: bool = False
    max_team_size: int = 4
    min_team_size: int = 1
    require_authorization_gate: bool = True
    simulation_mode: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CompetitionRules:
        if not data:
            return cls()
        return cls(
            capture_points=int(data.get("capture_points", 100)),
            defense_points=int(data.get("defense_points", 50)),
            hold_interval_seconds=int(data.get("hold_interval_seconds", 60)),
            hold_interval_points=int(data.get("hold_interval_points", 10)),
            recapture_bonus=int(data.get("recapture_bonus", 25)),
            penalty_points=int(data.get("penalty_points", 15)),
            elimination_threshold=data.get("elimination_threshold"),
            overtime_allowed=bool(data.get("overtime_allowed", False)),
            max_team_size=int(data.get("max_team_size", 4)),
            min_team_size=int(data.get("min_team_size", 1)),
            require_authorization_gate=bool(data.get("require_authorization_gate", True)),
            simulation_mode=bool(data.get("simulation_mode", True)),
        )


@dataclass
class CompetitionHill:
    hill_id: int
    competition_id: str
    name: str
    environment_type: HillEnvironmentType = HillEnvironmentType.LINUX
    target_host: str = "127.0.0.1"
    target_port: int = 80
    service_name: str = "generic-service"
    initial_owner_team_id: Optional[str] = None
    initial_owner_side: Optional[TeamSide] = None
    current_owner_team_id: Optional[str] = None
    current_owner_side: Optional[TeamSide] = None
    state: OwnershipState = OwnershipState.AVAILABLE
    health_status: str = "HEALTHY"
    points_per_interval: int = 10
    capture_points: int = 100
    flag_hash: str = ""
    verifier_type: VerifierType = VerifierType.SIMULATED
    verifier_endpoint: str = ""
    last_captured_at: float = 0.0
    last_verified_at: float = 0.0
    defense_notes: str = ""

    def to_safe_dict(self, viewer_team_id: Optional[str] = None, viewer_side: Optional[TeamSide] = None) -> Dict[str, Any]:
        """
        Produce a safe dictionary representation.
        Protects flag hash and sensitive defense notes from opposing sides/teams.
        """
        is_owner = (viewer_team_id and viewer_team_id == self.current_owner_team_id) or (
            viewer_side and self.current_owner_side and viewer_side == self.current_owner_side
        )
        return {
            "hill_id": self.hill_id,
            "competition_id": self.competition_id,
            "name": self.name,
            "environment_type": self.environment_type.value if hasattr(self.environment_type, "value") else str(self.environment_type),
            "target_host": self.target_host,
            "target_port": self.target_port,
            "service_name": self.service_name,
            "initial_owner_team_id": self.initial_owner_team_id,
            "initial_owner_side": self.initial_owner_side.value if self.initial_owner_side else None,
            "current_owner_team_id": self.current_owner_team_id,
            "current_owner_side": self.current_owner_side.value if self.current_owner_side else None,
            "state": self.state.value if hasattr(self.state, "value") else str(self.state),
            "health_status": self.health_status,
            "points_per_interval": self.points_per_interval,
            "capture_points": self.capture_points,
            "flag_configured": bool(self.flag_hash),
            "flag_hash_prefix": (self.flag_hash[:8] + "...") if (is_owner and self.flag_hash) else "",
            "verifier_type": self.verifier_type.value if hasattr(self.verifier_type, "value") else str(self.verifier_type),
            "verifier_endpoint": self.verifier_endpoint,
            "last_captured_at": self.last_captured_at,
            "last_verified_at": self.last_verified_at,
            "defense_notes": self.defense_notes if is_owner else "",
            "is_controlled_by_viewer": bool(is_owner),
        }


@dataclass
class CompetitionTeam:
    competition_id: str
    team_id: str
    team_name: str
    side: TeamSide = TeamSide.NEUTRAL
    score: int = 0
    eliminated: bool = False
    eliminated_reason: str = ""
    captures_count: int = 0
    defenses_count: int = 0
    recaptures_count: int = 0
    penalties_count: int = 0
    uptime_seconds: float = 0.0
    joined_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "competition_id": self.competition_id,
            "team_id": self.team_id,
            "team_name": self.team_name,
            "side": self.side.value if hasattr(self.side, "value") else str(self.side),
            "score": self.score,
            "eliminated": self.eliminated,
            "eliminated_reason": self.eliminated_reason,
            "captures_count": self.captures_count,
            "defenses_count": self.defenses_count,
            "recaptures_count": self.recaptures_count,
            "penalties_count": self.penalties_count,
            "uptime_seconds": self.uptime_seconds,
            "joined_at": self.joined_at,
        }


@dataclass
class Competition:
    competition_id: str
    name: str
    description: str
    mode: CompetitionMode
    format: str  # String representation of KothFormat or RedVsBlueFormat
    status: CompetitionStatus = CompetitionStatus.DRAFT
    start_time: float = 0.0
    end_time: float = 0.0
    duration_minutes: int = 60
    rules: CompetitionRules = field(default_factory=CompetitionRules)
    created_at: float = field(default_factory=time.time)
    created_by: str = "admin"

    def to_dict(self) -> Dict[str, Any]:
        now = time.time()
        time_remaining = max(0, int(self.end_time - now)) if self.end_time > 0 and self.status == CompetitionStatus.ACTIVE else 0
        return {
            "competition_id": self.competition_id,
            "name": self.name,
            "description": self.description,
            "mode": self.mode.value if hasattr(self.mode, "value") else str(self.mode),
            "format": self.format,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_minutes": self.duration_minutes,
            "time_remaining_seconds": time_remaining,
            "rules": self.rules.to_dict(),
            "created_at": self.created_at,
            "created_by": self.created_by,
        }


@dataclass
class CaptureSubmission:
    submission_id: str
    competition_id: str
    hill_id: int
    team_id: str
    side: TeamSide
    agent_id: str
    evidence_hash: str
    verified: bool
    awarded_points: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "competition_id": self.competition_id,
            "hill_id": self.hill_id,
            "team_id": self.team_id,
            "side": self.side.value if hasattr(self.side, "value") else str(self.side),
            "agent_id": self.agent_id,
            "evidence_hash": self.evidence_hash[:16] + "...",
            "verified": self.verified,
            "awarded_points": self.awarded_points,
            "timestamp": self.timestamp,
        }


@dataclass
class DefenseSubmission:
    submission_id: str
    competition_id: str
    hill_id: int
    team_id: str
    side: TeamSide
    agent_id: str
    service_status: str
    patch_summary: str
    verified: bool
    awarded_points: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "competition_id": self.competition_id,
            "hill_id": self.hill_id,
            "team_id": self.team_id,
            "side": self.side.value if hasattr(self.side, "value") else str(self.side),
            "agent_id": self.agent_id,
            "service_status": self.service_status,
            "patch_summary": self.patch_summary,
            "verified": self.verified,
            "awarded_points": self.awarded_points,
            "timestamp": self.timestamp,
        }


@dataclass
class OwnershipHistoryEvent:
    id: int
    competition_id: str
    hill_id: int
    previous_owner_team_id: Optional[str]
    previous_side: Optional[str]
    new_owner_team_id: str
    new_side: str
    event_type: str  # "CAPTURE", "RECAPTURE", "INITIAL_ASSIGNMENT", "REVOCATION"
    evidence_hash: str
    timestamp: float
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "competition_id": self.competition_id,
            "hill_id": self.hill_id,
            "previous_owner_team_id": self.previous_owner_team_id,
            "previous_side": self.previous_side,
            "new_owner_team_id": self.new_owner_team_id,
            "new_side": self.new_side,
            "event_type": self.event_type,
            "evidence_hash": self.evidence_hash[:12] + "..." if self.evidence_hash else "",
            "timestamp": self.timestamp,
            "details": self.details,
        }

