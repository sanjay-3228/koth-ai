"""Configurable scoreboard adapter handling HTTP ingestion, schema normalization, and error isolation."""
import time
from typing import Any, Dict, List, Optional

import requests

from .base import NormalizedScoreboardState, ScoreboardProvider, ScoreboardStatus
from .config_parser import ScoreboardSchemaConfig, resolve_json_path
from ..logger import get_logger
from ..telemetry import ServiceStatus, Telemetry

logger = get_logger(__name__)


class ConfigurableScoreboardAdapter(ScoreboardProvider):
    """Production-grade configurable scoreboard adapter with strict failure isolation."""

    def __init__(
        self,
        url: str = "",
        schema_config: Optional[ScoreboardSchemaConfig] = None,
        auth_token: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ):
        self.url = url
        self.schema = schema_config or ScoreboardSchemaConfig()
        self.auth_token = auth_token
        self.session = session or requests.Session()
        self._last_valid_score: Optional[float] = None
        self._last_poll_time: float = 0.0
        self.last_scoreboard_latency_ms: float = 0.0
        self.last_json_parsing_latency_ms: float = 0.0
        self.last_scoreboard_timeout_ms: float = 0.0

    def get_state(self) -> NormalizedScoreboardState:
        """Poll scoreboard URL and return normalized state.

        Guarantees:
          - Never throws on network, timeout, or parsing failure.
          - Returns is_valid=False and explicit ScoreboardStatus on any fault.
          - Network latency records failed-request duration without implying connectivity.
          - JSON parse latency is 0.0 when no valid response body was received.
          - Flags stale data if timestamp lags behind stale threshold.
        """
        now = time.time()
        self._last_poll_time = now
        self.last_scoreboard_timeout_ms = 0.0

        if not self.url:
            self.last_scoreboard_latency_ms = 0.0
            self.last_json_parsing_latency_ms = 0.0
            return NormalizedScoreboardState(
                timestamp=now,
                is_valid=False,
                status=ScoreboardStatus.UNCONFIGURED,
                error="Scoreboard URL is not configured.",
                metadata={
                    "scoreboard_latency_ms": 0.0,
                    "json_parsing_latency_ms": 0.0,
                    "scoreboard_status": ScoreboardStatus.UNCONFIGURED.value,
                },
            )

        headers = {"User-Agent": "KOTH-Agent-Telemetry/2.0"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        t_http_start = time.perf_counter()
        try:
            resp = self.session.get(
                self.url,
                headers=headers,
                timeout=self.schema.timeout_seconds,
            )
            net_latency_ms = (time.perf_counter() - t_http_start) * 1000.0
            self.last_scoreboard_latency_ms = net_latency_ms

            if resp.status_code != 200:
                self.last_json_parsing_latency_ms = 0.0
                logger.warning("[SCOREBOARD] HTTP error %d: %s", resp.status_code, resp.text[:200])
                return NormalizedScoreboardState(
                    timestamp=now,
                    is_valid=False,
                    status=ScoreboardStatus.UNREACHABLE,
                    error=f"Scoreboard returned HTTP {resp.status_code}",
                    metadata={
                        "scoreboard_latency_ms": net_latency_ms,
                        "json_parsing_latency_ms": 0.0,
                        "scoreboard_status": ScoreboardStatus.UNREACHABLE.value,
                    },
                )

            t_parse_json = time.perf_counter()
            data = resp.json()
            initial_json_lat = (time.perf_counter() - t_parse_json) * 1000.0
            self.last_json_parsing_latency_ms = initial_json_lat

            if not isinstance(data, dict):
                logger.warning("[SCOREBOARD] Malformed payload (expected JSON object, got %s)", type(data).__name__)
                return NormalizedScoreboardState(
                    timestamp=now,
                    is_valid=False,
                    status=ScoreboardStatus.MALFORMED,
                    error=f"Malformed payload: root element must be a JSON object, got {type(data).__name__}",
                    metadata={
                        "scoreboard_latency_ms": net_latency_ms,
                        "json_parsing_latency_ms": initial_json_lat,
                        "scoreboard_status": ScoreboardStatus.MALFORMED.value,
                    },
                )

        except requests.Timeout:
            net_latency_ms = (time.perf_counter() - t_http_start) * 1000.0
            self.last_scoreboard_latency_ms = net_latency_ms
            self.last_scoreboard_timeout_ms = net_latency_ms
            self.last_json_parsing_latency_ms = 0.0
            logger.warning("[SCOREBOARD] Polling timed out after %.1fs", self.schema.timeout_seconds)
            return NormalizedScoreboardState(
                timestamp=now,
                is_valid=False,
                status=ScoreboardStatus.UNREACHABLE,
                error=f"Connection timed out after {self.schema.timeout_seconds}s",
                metadata={
                    "scoreboard_latency_ms": net_latency_ms,
                    "scoreboard_timeout_ms": net_latency_ms,
                    "json_parsing_latency_ms": 0.0,
                    "scoreboard_status": ScoreboardStatus.UNREACHABLE.value,
                },
            )
        except requests.RequestException as exc:
            net_latency_ms = (time.perf_counter() - t_http_start) * 1000.0
            self.last_scoreboard_latency_ms = net_latency_ms
            self.last_json_parsing_latency_ms = 0.0
            logger.warning("[SCOREBOARD] Network request failed: %s", exc)
            return NormalizedScoreboardState(
                timestamp=now,
                is_valid=False,
                status=ScoreboardStatus.UNREACHABLE,
                error=f"Network error: {str(exc)}",
                metadata={
                    "scoreboard_latency_ms": net_latency_ms,
                    "json_parsing_latency_ms": 0.0,
                    "scoreboard_status": ScoreboardStatus.UNREACHABLE.value,
                },
            )
        except ValueError as exc:  # Includes JSONDecodeError
            net_latency_ms = (time.perf_counter() - t_http_start) * 1000.0
            self.last_scoreboard_latency_ms = net_latency_ms
            self.last_json_parsing_latency_ms = 0.0
            logger.warning("[SCOREBOARD] JSON decode error: %s", exc)
            return NormalizedScoreboardState(
                timestamp=now,
                is_valid=False,
                status=ScoreboardStatus.MALFORMED,
                error=f"Malformed JSON: {str(exc)}",
                metadata={
                    "scoreboard_latency_ms": net_latency_ms,
                    "json_parsing_latency_ms": 0.0,
                    "scoreboard_status": ScoreboardStatus.MALFORMED.value,
                },
            )

        return self.parse_data(data, received_at=now, scoreboard_latency_ms=net_latency_ms)

    def parse_data(
        self,
        data: dict,
        received_at: Optional[float] = None,
        scoreboard_latency_ms: Optional[float] = None,
    ) -> NormalizedScoreboardState:
        """Parse raw scoreboard JSON dictionary according to configured schema."""
        t_start = time.perf_counter()
        now = received_at or time.time()

        # 1. Parse timestamp and check staleness
        raw_ts = resolve_json_path(data, self.schema.timestamp_path)
        ts = now
        is_stale = False
        if raw_ts is not None:
            try:
                ts = float(raw_ts)
                # If remote timestamp is older than threshold
                if (now - ts) > self.schema.stale_threshold_seconds:
                    is_stale = True
                    logger.warning(
                        "[SCOREBOARD] Stale data detected: remote timestamp %.1f is %.1fs old (threshold %.1fs)",
                        ts,
                        now - ts,
                        self.schema.stale_threshold_seconds,
                    )
            except (ValueError, TypeError):
                ts = now

        # 2. Extract score and rank
        own_score = None
        rank = None
        opponent_scores: Dict[str, float] = {}

        # Mode A: scoreboard provides teams list
        if self.schema.teams_list_path and self.schema.team_name:
            teams_list = resolve_json_path(data, self.schema.teams_list_path, [])
            if isinstance(teams_list, list):
                for team in teams_list:
                    if not isinstance(team, dict):
                        continue
                    tname = str(team.get(self.schema.team_name_key, ""))
                    tscore = team.get(self.schema.team_score_key)
                    trank = team.get(self.schema.team_rank_key)
                    try:
                        score_val = float(tscore) if tscore is not None else 0.0
                    except (ValueError, TypeError):
                        score_val = 0.0

                    if tname == self.schema.team_name:
                        own_score = score_val
                        try:
                            rank = int(trank) if trank is not None else None
                        except (ValueError, TypeError):
                            rank = None
                    elif tname:
                        opponent_scores[tname] = score_val

        # Mode B: direct fields
        if own_score is None:
            raw_score = resolve_json_path(data, self.schema.score_path)
            if raw_score is not None:
                try:
                    own_score = float(raw_score)
                except (ValueError, TypeError):
                    own_score = None

        if rank is None:
            raw_rank = resolve_json_path(data, self.schema.rank_path)
            if raw_rank is not None:
                try:
                    rank = int(raw_rank)
                except (ValueError, TypeError):
                    rank = None

        if not opponent_scores:
            raw_opponents = resolve_json_path(data, self.schema.competitors_path, {})
            if isinstance(raw_opponents, dict):
                for k, v in raw_opponents.items():
                    try:
                        opponent_scores[str(k)] = float(v)
                    except (ValueError, TypeError):
                        pass

        # 3. Compute score delta
        score_delta = 0.0
        if own_score is not None:
            if self._last_valid_score is not None:
                score_delta = own_score - self._last_valid_score
            self._last_valid_score = own_score

        # 4. Extract round state
        round_state = str(resolve_json_path(data, self.schema.round_state_path, "active"))

        # 5. Extract service status
        services: List[ServiceStatus] = []
        raw_services = resolve_json_path(data, self.schema.services_path, [])
        if isinstance(raw_services, list):
            for item in raw_services:
                if not isinstance(item, dict):
                    continue
                h = str(resolve_json_path(item, self.schema.service_host_path, ""))
                p_raw = resolve_json_path(item, self.schema.service_port_path, 0)
                try:
                    p = int(p_raw)
                except (ValueError, TypeError):
                    p = 0
                u = bool(resolve_json_path(item, self.schema.service_up_path, False))
                note = str(resolve_json_path(item, self.schema.service_note_path, ""))
                services.append(
                    ServiceStatus(
                        host=h,
                        port=p,
                        up=u,
                        last_checked=now,
                        note=note,
                    )
                )

        parse_latency_ms = (time.perf_counter() - t_start) * 1000.0
        self.last_json_parsing_latency_ms = parse_latency_ms

        error_msg = "Scoreboard data is stale" if is_stale else None
        sb_lat = scoreboard_latency_ms if scoreboard_latency_ms is not None else self.last_scoreboard_latency_ms

        status = ScoreboardStatus.STALE if is_stale else ScoreboardStatus.REACHABLE
        metadata = {
            "raw": data,
            "scoreboard_latency_ms": sb_lat,
            "json_parsing_latency_ms": parse_latency_ms,
            "scoreboard_status": status.value,
        }

        return NormalizedScoreboardState(
            timestamp=ts,
            own_score=own_score,
            opponent_scores=opponent_scores,
            score_delta=score_delta,
            rank=rank,
            round_state=round_state,
            service_status=services,
            metadata=metadata,
            is_valid=not is_stale,
            error=error_msg,
            is_stale=is_stale,
            status=status,
        )

    def to_telemetry(self, state: NormalizedScoreboardState) -> Telemetry:
        """Convert NormalizedScoreboardState into agent Telemetry instance."""
        raw_payload = dict(state.metadata.get("raw", {}))
        if "scoreboard_latency_ms" in state.metadata:
            raw_payload["scoreboard_latency_ms"] = state.metadata["scoreboard_latency_ms"]
        if "json_parsing_latency_ms" in state.metadata:
            raw_payload["json_parsing_latency_ms"] = state.metadata["json_parsing_latency_ms"]

        raw_payload["scoreboard_status"] = state.status.value

        if state.error:
            raw_payload["error"] = state.error
        if state.is_stale:
            raw_payload["stale"] = True
            if "error" not in raw_payload:
                raw_payload["error"] = "Scoreboard data is stale"

        # Explicit safety constraint: Failed scoreboard response cannot produce fake score/rank
        is_reachable = (state.status == ScoreboardStatus.REACHABLE)
        return Telemetry(
            timestamp=state.timestamp,
            our_score=state.own_score if is_reachable else None,
            rank=state.rank if is_reachable else None,
            our_services=state.service_status if is_reachable else [],
            competitor_scores=state.opponent_scores if is_reachable else {},
            raw=raw_payload,
        )
