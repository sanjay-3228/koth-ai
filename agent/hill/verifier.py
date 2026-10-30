"""
Competition State and Hill Verification Engine for KOTH Swarm.

Implements pluggable hill verification with simulated verifier by default:
- Represents states distinctly: UNVERIFIED, SUBMITTED, OWNED, LOST, UNKNOWN
- Decouples hill health (HEALTHY, DEGRADED, DOWN, UNKNOWN) from ownership
- Verifies flags and service tokens without exposing plaintext flags
- Provides a clean extension adapter for external competition engines
"""
from __future__ import annotations

import abc
import hashlib
import hmac
import logging
import socket
import time
from typing import Any, Dict, Optional, Tuple

from agent.hill.manager import HillHealth, HillState, OwnershipStatus

logger = logging.getLogger("koth.hill.verifier")


class HillVerifier(abc.ABC):
    """Abstract interface for hill verification adapters."""

    @abc.abstractmethod
    def verify(
        self,
        hill_id: int,
        hill_state: HillState,
    ) -> Tuple[OwnershipStatus, HillHealth, Dict[str, Any]]:
        """
        Verify the current ownership and health status for the given hill.

        Returns:
            Tuple of (OwnershipStatus, HillHealth, details_dict)
        """
        pass

    @abc.abstractmethod
    def submit_flag(
        self,
        hill_id: int,
        flag_candidate: str,
        expected_flag_hash: str,
    ) -> bool:
        """
        Submit a flag candidate for verification against expected flag hash.
        """
        pass


class SimulatedHillVerifier(HillVerifier):
    """
    Default simulated verifier for safe offline rehearsals.
    Does not connect to external competition scoreboards unless explicitly configured.
    """

    def __init__(self, check_network_probe: bool = False, probe_timeout: float = 0.5):
        self.check_network_probe = check_network_probe
        self.probe_timeout = probe_timeout
        self._manual_overrides: Dict[int, OwnershipStatus] = {}
        self._health_overrides: Dict[int, HillHealth] = {}
        self._verification_history: Dict[int, list] = {}

    def set_simulated_ownership(self, hill_id: int, status: OwnershipStatus) -> None:
        """Manually override ownership status for testing / rehearsal."""
        self._manual_overrides[hill_id] = status
        logger.info(f"[SIMULATED_VERIFIER] Hill {hill_id} ownership manually set to {status.value}")

    def set_simulated_health(self, hill_id: int, health: HillHealth) -> None:
        """Manually override health status for testing / rehearsal."""
        self._health_overrides[hill_id] = health
        logger.info(f"[SIMULATED_VERIFIER] Hill {hill_id} health manually set to {health.value}")

    def clear_overrides(self, hill_id: Optional[int] = None) -> None:
        if hill_id is not None:
            self._manual_overrides.pop(hill_id, None)
            self._health_overrides.pop(hill_id, None)
        else:
            self._manual_overrides.clear()
            self._health_overrides.clear()

    def submit_flag(
        self,
        hill_id: int,
        flag_candidate: str,
        expected_flag_hash: str,
    ) -> bool:
        """
        Validate submitted flag against the stored SHA-256 hash in constant time.
        Never stores or echoes the plaintext flag.
        """
        if not flag_candidate or not expected_flag_hash:
            return False
        candidate_hash = hashlib.sha256(flag_candidate.strip().encode("utf-8")).hexdigest()
        is_match = hmac.compare_digest(candidate_hash, expected_flag_hash)
        logger.info(
            f"[SIMULATED_VERIFIER] Flag submission for Hill {hill_id}: "
            f"{'MATCH (OWNED)' if is_match else 'REJECTED'}"
        )
        if is_match:
            self._manual_overrides[hill_id] = OwnershipStatus.OWNED
        else:
            self._manual_overrides[hill_id] = OwnershipStatus.LOST
        return is_match

    def verify(
        self,
        hill_id: int,
        hill_state: HillState,
    ) -> Tuple[OwnershipStatus, HillHealth, Dict[str, Any]]:
        """
        Perform a simulated verification check.
        Decouples ownership status from service health.
        """
        now = time.time()
        details: Dict[str, Any] = {"timestamp": now, "verifier": "simulated"}

        # 1. Determine Health Status
        health = self._health_overrides.get(hill_id)
        latency_ms = 0.0

        if health is None:
            if self.check_network_probe and hill_state.target_host and hill_state.target_port:
                start = time.perf_counter()
                try:
                    s = socket.create_connection(
                        (hill_state.target_host, hill_state.target_port),
                        timeout=self.probe_timeout,
                    )
                    s.close()
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    health = HillHealth.HEALTHY
                except (socket.timeout, OSError):
                    health = HillHealth.DOWN
                    latency_ms = (time.perf_counter() - start) * 1000.0
            else:
                # In pure simulation, default to HEALTHY if host is configured, otherwise UNKNOWN
                health = HillHealth.HEALTHY if hill_state.target_host else HillHealth.UNKNOWN

        details["latency_ms"] = round(latency_ms, 2)
        details["health"] = health.value

        # 2. Determine Ownership Status
        ownership = self._manual_overrides.get(hill_id)
        if ownership is None:
            if not hill_state.flag_configured:
                ownership = OwnershipStatus.UNVERIFIED
            elif hill_state.ownership_status == OwnershipStatus.SUBMITTED:
                # If submitted, simulated verifier confirms ownership if flag hash present
                ownership = OwnershipStatus.OWNED if hill_state.flag_hash else OwnershipStatus.LOST
            elif hill_state.ownership_status in (OwnershipStatus.OWNED, OwnershipStatus.LOST):
                ownership = hill_state.ownership_status
            else:
                ownership = OwnershipStatus.UNVERIFIED

        details["ownership"] = ownership.value

        # Record history
        if hill_id not in self._verification_history:
            self._verification_history[hill_id] = []
        self._verification_history[hill_id].append({
            "timestamp": now,
            "ownership": ownership.value,
            "health": health.value,
            "latency_ms": round(latency_ms, 2),
        })
        # Keep last 20
        self._verification_history[hill_id] = self._verification_history[hill_id][-20:]

        return ownership, health, details


class CompetitionHillVerifier(HillVerifier):
    """
    Pluggable adapter interface for official competition scoreboard / CTF platform verification.
    Subclasses implement custom HTTP/API protocols without altering internal swarm logic.
    """

    def __init__(self, endpoint_url: str, api_token: Optional[str] = None):
        self.endpoint_url = endpoint_url
        self.api_token = api_token

    def submit_flag(
        self,
        hill_id: int,
        flag_candidate: str,
        expected_flag_hash: str,
    ) -> bool:
        """Submit candidate flag to external competition endpoint."""
        # Subclasses implement official submission protocol
        logger.info(f"[COMPETITION_VERIFIER] Flag submission to {self.endpoint_url} for hill {hill_id}")
        return False

    def verify(
        self,
        hill_id: int,
        hill_state: HillState,
    ) -> Tuple[OwnershipStatus, HillHealth, Dict[str, Any]]:
        """Query official scoreboard for authoritative ownership status."""
        # Subclasses implement official poll protocol
        return hill_state.ownership_status, hill_state.health_status, {"verifier": "competition_stub"}

