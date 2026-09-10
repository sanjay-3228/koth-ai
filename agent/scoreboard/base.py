"""Base interfaces and data structures for scoreboard ingestion."""
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..telemetry import ServiceStatus


class ScoreboardStatus(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    STALE = "STALE"
    MALFORMED = "MALFORMED"
    UNCONFIGURED = "UNCONFIGURED"


@dataclass
class NormalizedScoreboardState:
    """Normalized representation of competition scoreboard state."""
    timestamp: float = field(default_factory=time.time)
    own_score: Optional[float] = None
    opponent_scores: Dict[str, float] = field(default_factory=dict)
    score_delta: float = 0.0
    rank: Optional[int] = None
    round_state: str = "active"  # "active", "paused", "finished", "unknown"
    service_status: List[ServiceStatus] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    error: Optional[str] = None
    is_stale: bool = False
    status: ScoreboardStatus = ScoreboardStatus.REACHABLE

    @property
    def has_error(self) -> bool:
        return not self.is_valid or self.error is not None or self.is_stale


class ScoreboardProvider(ABC):
    """Abstract interface for ingesting competition scoreboard data."""

    @abstractmethod
    def get_state(self) -> NormalizedScoreboardState:
        """Poll the scoreboard and return normalized state.

        Implementations must never raise unhandled exceptions on network,
        HTTP, or parsing errors; instead return a NormalizedScoreboardState
        with is_valid=False and error set.
        """
        raise NotImplementedError
