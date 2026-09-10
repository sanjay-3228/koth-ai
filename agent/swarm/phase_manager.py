"""
Authoritative Phase Provider and Phase Transition Manager for 4-Agent Swarm.
Enforces fail-safe HOLD on expired or unknown phase.
"""

from __future__ import annotations

import abc
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.models import Phase, PhaseState

logger = logging.getLogger("koth.swarm.phase")


class PhaseProvider(abc.ABC):
    """Abstract interface for receiving competition phase state."""

    @abc.abstractmethod
    def get_phase(self) -> PhaseState:
        """Return the current phase state."""
        pass


class SimulatedPhaseProvider(PhaseProvider):
    """
    Simulation phase provider for local rehearsals, unit tests, and multi-round verification.
    """

    def __init__(
        self,
        initial_phase: Phase = Phase.HOLD,
        initial_round: int = 1,
        ttl_seconds: float = 30.0,
    ):
        self._lock = threading.RLock()
        self._phase = initial_phase
        self._round_id = initial_round
        self._epoch = 1
        self._ttl_seconds = ttl_seconds
        self._last_updated = time.time()
        self._metadata: Dict[str, any] = {}

    def set_phase(
        self, phase: Phase, round_id: Optional[int] = None, metadata: Optional[Dict[str, any]] = None
    ) -> PhaseState:
        with self._lock:
            if phase != self._phase or (round_id is not None and round_id != self._round_id):
                self._epoch += 1
            self._phase = phase
            if round_id is not None:
                self._round_id = round_id
            self._last_updated = time.time()
            if metadata:
                self._metadata.update(metadata)

            return self.get_phase()

    def advance_round(self) -> PhaseState:
        with self._lock:
            self._round_id += 1
            self._epoch += 1
            self._last_updated = time.time()
            return self.get_phase()

    def get_phase(self) -> PhaseState:
        with self._lock:
            return PhaseState(
                phase=self._phase,
                round_id=self._round_id,
                phase_epoch=self._epoch,
                timestamp=self._last_updated,
                ttl_seconds=self._ttl_seconds,
                source="simulated_phase_provider",
                metadata=dict(self._metadata),
            )


class ManualPhaseProvider(SimulatedPhaseProvider):
    """Operator-controlled phase provider for live competitions without a scoreboard API.

    It intentionally keeps the existing PhaseProvider -> PhaseManager architecture.
    The coordinator changes phase only through its privileged operator endpoint.
    """

    def __init__(self, initial_phase: Phase = Phase.HOLD, initial_round: int = 1, ttl_seconds: float = 3600.0):
        super().__init__(initial_phase=initial_phase, initial_round=initial_round, ttl_seconds=ttl_seconds)
        self._metadata["control_mode"] = "manual_operator"

    def get_phase(self) -> PhaseState:
        state = super().get_phase()
        state.source = "manual_operator"
        state.metadata["control_mode"] = "manual_operator"
        return state


class ScoreboardPhaseProvider(PhaseProvider):
    """
    Polls competition organizer scoreboard or phase API endpoint.
    Safely degrades to Phase.UNKNOWN on network error or parsing error.
    """

    def __init__(
        self,
        api_url: str,
        auth_token: Optional[str] = None,
        timeout_seconds: float = 5.0,
        ttl_seconds: float = 30.0,
    ):
        self.api_url = api_url
        self.auth_token = auth_token
        self.timeout_seconds = timeout_seconds
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._epoch = 0
        self._last_state: Optional[PhaseState] = None

    def get_phase(self) -> PhaseState:
        import requests

        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        now = time.time()
        try:
            resp = requests.get(self.api_url, headers=headers, timeout=self.timeout_seconds)
            if resp.status_code == 200:
                data = resp.json()
                raw_phase = str(data.get("phase", "unknown")).upper()
                phase_enum = Phase.UNKNOWN
                if raw_phase in Phase.__members__:
                    phase_enum = Phase[raw_phase]

                round_id = int(data.get("round", data.get("round_id", 1)))

                with self._lock:
                    if not self._last_state or self._last_state.phase != phase_enum or self._last_state.round_id != round_id:
                        self._epoch += 1

                    self._last_state = PhaseState(
                        phase=phase_enum,
                        round_id=round_id,
                        phase_epoch=self._epoch,
                        timestamp=now,
                        ttl_seconds=self.ttl_seconds,
                        source="scoreboard_api",
                        metadata=data,
                    )
                    return self._last_state
        except Exception as e:
            logger.warning(f"ScoreboardPhaseProvider fetch failed from {self.api_url}: {e}")

        # In case of fetch failure, inspect cached state
        with self._lock:
            if self._last_state and not self._last_state.is_expired(now):
                return self._last_state

            # If no cached state or cached state expired -> safe UNKNOWN
            return PhaseState(
                phase=Phase.UNKNOWN,
                round_id=self._last_state.round_id if self._last_state else 0,
                phase_epoch=self._epoch,
                timestamp=now,
                ttl_seconds=self.ttl_seconds,
                source="scoreboard_api_fallback",
            )


class PhaseManager:
    """
    Central phase manager running on coordinator or client.
    Enforces safe phase transitions, lease invalidation, and fail-safe HOLD.
    """

    def __init__(
        self,
        provider: PhaseProvider,
        event_bus: Optional[SwarmEventBus] = None,
        on_phase_change: Optional[Callable[[PhaseState, PhaseState], None]] = None,
    ):
        self.provider = provider
        self.event_bus = event_bus
        self.on_phase_change = on_phase_change
        self._lock = threading.RLock()
        self._current_state: PhaseState = self.provider.get_phase()

    @property
    def current_state(self) -> PhaseState:
        with self._lock:
            return self._current_state

    @property
    def current_phase(self) -> Phase:
        with self._lock:
            # Check for TTL expiration
            if self._current_state.is_expired():
                logger.warning(
                    f"Current phase {self._current_state.phase.value} expired (ttl={self._current_state.ttl_seconds}s). Fallback to HOLD."
                )
                return Phase.HOLD
            return self._current_state.phase

    def poll(self) -> tuple[PhaseState, bool]:
        """
        Poll the phase provider, detect transitions, and trigger callbacks.
        Returns (current_phase_state, has_changed: bool).
        """
        new_state = self.provider.get_phase()
        has_changed = False
        old_state: Optional[PhaseState] = None

        with self._lock:
            # Check if expired
            if new_state.is_expired() and new_state.phase != Phase.HOLD:
                new_state.phase = Phase.HOLD

            if (
                new_state.phase != self._current_state.phase
                or new_state.phase_epoch != self._current_state.phase_epoch
                or new_state.round_id != self._current_state.round_id
            ):
                has_changed = True
                old_state = self._current_state
                self._current_state = new_state

        if has_changed and old_state is not None:
            logger.info(
                f"PHASE TRANSITION: {old_state.phase.value} (epoch {old_state.phase_epoch}) "
                f"-> {new_state.phase.value} (epoch {new_state.phase_epoch}, round {new_state.round_id})"
            )

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.PHASE_CHANGED,
                        data={
                            "old_phase": old_state.phase.value,
                            "new_phase": new_state.phase.value,
                            "round_id": new_state.round_id,
                            "phase_epoch": new_state.phase_epoch,
                            "source": new_state.source,
                        },
                    )
                )

            if self.on_phase_change:
                try:
                    self.on_phase_change(old_state, new_state)
                except Exception as e:
                    logger.error(f"Error in on_phase_change handler: {e}", exc_info=True)

        return new_state, has_changed
