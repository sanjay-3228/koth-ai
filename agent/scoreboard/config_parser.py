"""Configuration-driven parser for dynamic competition scoreboard JSON formats."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def resolve_json_path(data: Any, path: str, default: Any = None) -> Any:
    """Resolve a dot-delimited path in a nested dictionary or list.

    Examples:
        resolve_json_path({"a": {"b": 10}}, "a.b") -> 10
        resolve_json_path({"teams": [{"name": "A", "score": 50}]}, "teams.0.score") -> 50
    """
    if not path or data is None:
        return default

    current = data
    for part in path.strip().split("."):
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                return default
        elif isinstance(current, (list, tuple)):
            try:
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return default
            except ValueError:
                return default
        else:
            return default
    return current


@dataclass
class ScoreboardSchemaConfig:
    """Configurable schema mapping for dynamic scoreboard JSON formats.

    Allows teams to adapt to any CTF/KOTH scoreboard without changing code.
    """
    score_path: str = "our_score"
    rank_path: str = "rank"
    round_state_path: str = "round_state"
    services_path: str = "our_services"
    service_host_path: str = "host"
    service_port_path: str = "port"
    service_up_path: str = "up"
    service_note_path: str = "note"
    competitors_path: str = "competitor_scores"
    timestamp_path: str = "timestamp"

    # Optional team identifier when scoreboard returns all teams in a list
    team_name: Optional[str] = None
    teams_list_path: Optional[str] = None
    team_name_key: str = "name"
    team_score_key: str = "score"
    team_rank_key: str = "rank"

    # Thresholds
    stale_threshold_seconds: float = 60.0
    timeout_seconds: float = 5.0
