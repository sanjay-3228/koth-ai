"""Polls the competition scoreboard/API and normalizes state.

Every KOTH platform exposes scoring differently, so this module is the one
place you'll likely need to adapt to your specific competition's API shape.
Adjust `_parse_scoreboard` to match the JSON your platform returns.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .config import config



@dataclass
class ServiceStatus:
    host: str
    port: int
    up: bool
    last_checked: float
    note: str = ""


@dataclass
class Telemetry:
    timestamp: float
    our_score: Optional[float] = None
    rank: Optional[int] = None
    our_services: List[ServiceStatus] = field(default_factory=list)
    competitor_scores: Dict[str, float] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


class TelemetryPoller:
    def __init__(
        self,
        scoreboard_url: Optional[str] = None,
        timeout: float = 5.0,
        provider: Optional[Any] = None,
    ):
        self.scoreboard_url = scoreboard_url or config.scoreboard_url
        self.timeout = timeout
        self.last_scoreboard_latency_ms: float = 0.0
        self.last_json_parsing_latency_ms: float = 0.0
        self.last_telemetry_latency_ms: float = 0.0


        if provider is not None:
            self.provider = provider
        elif self.scoreboard_url:
            from .scoreboard.adapter import ConfigurableScoreboardAdapter
            from .scoreboard.config_parser import ScoreboardSchemaConfig
            self.provider = ConfigurableScoreboardAdapter(
                url=self.scoreboard_url,
                schema_config=ScoreboardSchemaConfig(
                    timeout_seconds=self.timeout,
                    stale_threshold_seconds=config.stale_telemetry_threshold,
                ),
            )
        else:
            self.provider = None

    def fetch(self) -> Telemetry:
        t_start = time.perf_counter()
        telemetry = self._do_fetch()
        self.last_telemetry_latency_ms = (time.perf_counter() - t_start) * 1000.0

        # Propagate adapter latency metrics if available
        if hasattr(self.provider, "last_scoreboard_latency_ms"):
            self.last_scoreboard_latency_ms = self.provider.last_scoreboard_latency_ms
        elif "scoreboard_latency_ms" in getattr(telemetry, "raw", {}):
            self.last_scoreboard_latency_ms = telemetry.raw["scoreboard_latency_ms"]

        if hasattr(self.provider, "last_json_parsing_latency_ms"):
            self.last_json_parsing_latency_ms = self.provider.last_json_parsing_latency_ms
        elif "json_parsing_latency_ms" in getattr(telemetry, "raw", {}):
            self.last_json_parsing_latency_ms = telemetry.raw["json_parsing_latency_ms"]

        return telemetry

    def _do_fetch(self) -> Telemetry:
        if self.provider is not None:
            try:
                state = self.provider.get_state()
                if hasattr(self.provider, "to_telemetry"):
                    res = self.provider.to_telemetry(state)
                    if isinstance(res, Telemetry):
                        return res
                # Fallback manual conversion
                raw_payload = dict(getattr(state, "metadata", {}).get("raw", {}))
                if getattr(state, "error", None):
                    raw_payload["error"] = state.error
                if getattr(state, "is_stale", False):
                    raw_payload["stale"] = True
                    if not raw_payload.get("error"):
                        raw_payload["error"] = "Scoreboard data is stale"
                comp_scores = getattr(state, "opponent_scores", {})
                if not isinstance(comp_scores, dict):
                    comp_scores = {}
                return Telemetry(
                    timestamp=getattr(state, "timestamp", time.time()),
                    our_score=getattr(state, "own_score", None),
                    rank=getattr(state, "rank", None),
                    our_services=getattr(state, "service_status", []),
                    competitor_scores=comp_scores,
                    raw=raw_payload,
                )
            except Exception as exc:
                return Telemetry(timestamp=time.time(), raw={"error": str(exc)})

        # Direct HTTP fallback if provider is not configured
        if not self.scoreboard_url:
            self.last_scoreboard_latency_ms = 0.0
            self.last_json_parsing_latency_ms = 0.0
            return Telemetry(
                timestamp=time.time(),
                raw={"error": "Scoreboard URL is not configured.", "scoreboard_status": "UNCONFIGURED"},
            )

        try:
            t0 = time.perf_counter()
            resp = requests.get(self.scoreboard_url, timeout=self.timeout)
            self.last_scoreboard_latency_ms = (time.perf_counter() - t0) * 1000.0
            resp.raise_for_status()

            t1 = time.perf_counter()
            data = resp.json()
            self.last_json_parsing_latency_ms = (time.perf_counter() - t1) * 1000.0
            if isinstance(data, dict):
                data["scoreboard_status"] = "REACHABLE"
        except requests.RequestException as exc:
            self.last_json_parsing_latency_ms = 0.0
            return Telemetry(
                timestamp=time.time(),
                our_score=None,
                rank=None,
                our_services=[],
                competitor_scores={},
                raw={"error": str(exc), "scoreboard_status": "UNREACHABLE", "scoreboard_latency_ms": self.last_scoreboard_latency_ms},
            )
        except ValueError as exc:
            self.last_json_parsing_latency_ms = 0.0
            return Telemetry(
                timestamp=time.time(),
                our_score=None,
                rank=None,
                our_services=[],
                competitor_scores={},
                raw={"error": f"Malformed JSON: {exc}", "scoreboard_status": "MALFORMED", "scoreboard_latency_ms": self.last_scoreboard_latency_ms},
            )

        return self._parse_scoreboard(data)

    def _parse_scoreboard(self, data: dict) -> Telemetry:
        """Fallback scoreboard parsing scoped to configured services."""
        our_services = [
            ServiceStatus(
                host=s.get("host", ""),
                port=s.get("port", 0),
                up=s.get("up", False),
                last_checked=time.time(),
                note=s.get("note", ""),
            )
            for s in data.get("our_services", [])
        ]

        return Telemetry(
            timestamp=time.time(),
            our_score=data.get("our_score"),
            rank=data.get("rank"),
            our_services=our_services,
            competitor_scores=data.get("competitor_scores", {}),
            raw=data,
        )

