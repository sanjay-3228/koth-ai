"""
Shared team state storage for the 4-agent swarm.
NO PASSWORDS, PRIVATE KEYS, OR RAW CREDENTIALS STORED.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("koth.swarm.shared_state")

SENSITIVE_KEY_SUBSTRINGS = ["password", "private_key", "secret", "passwd", "token_auth", "credential"]


class SharedTeamState:
    """
    Thread-safe knowledge base shared across the 4 agents of null_warriors.
    Enforces security boundary: rejects attempts to store credentials/secrets.
    """

    def __init__(self, team_id: str = "null_warriors"):
        self._lock = threading.RLock()
        self.team_id = team_id

        # Target host knowledge
        # host -> {"ports": [22, 80], "os": "linux", "last_scanned": timestamp}
        self._host_discoveries: Dict[str, Dict[str, Any]] = {}

        # Compromised target hosts: host -> {"pwned_by": agent_id, "timestamp": timestamp}
        self._compromised_hosts: Dict[str, Dict[str, Any]] = {}

        # Defended services: service_name / host -> {"patched_by": agent_id, "timestamp": timestamp}
        self._patched_services: Dict[str, Dict[str, Any]] = {}

        # Flags captured: [{"flag_hash": hash, "agent_id": agent_id, "round_id": round_id, "timestamp": timestamp}]
        self._captured_flags: List[Dict[str, Any]] = []

        # Arbitrary team metadata (sanitized)
        self._metadata: Dict[str, Any] = {}
        self._updated_at = time.time()

    def _check_sensitive(self, key: str, value: Any) -> None:
        key_lower = key.lower()
        for s in SENSITIVE_KEY_SUBSTRINGS:
            if s in key_lower:
                raise ValueError(
                    f"Security violation: Storing sensitive credential key '{key}' "
                    f"in shared team state is forbidden by policy."
                )

    def record_host_scan(
        self, host: str, ports: List[int], os_hint: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        with self._lock:
            current = self._host_discoveries.get(host, {})
            existing_ports = set(current.get("ports", []))
            existing_ports.update(ports)
            self._host_discoveries[host] = {
                "ports": sorted(list(existing_ports)),
                "os": os_hint or current.get("os", "unknown"),
                "last_scanned": time.time(),
                "metadata": metadata or current.get("metadata", {}),
            }
            self._updated_at = time.time()
            logger.info(f"Team state: Updated scan for host {host}, open ports={self._host_discoveries[host]['ports']}")

    def record_compromise(self, host: str, agent_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._compromised_hosts[host] = {
                "pwned_by": agent_id,
                "timestamp": time.time(),
                "details": details or {},
            }
            self._updated_at = time.time()
            logger.info(f"Team state: Host {host} compromised by {agent_id}")

    def record_patch(self, service_or_host: str, agent_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._patched_services[service_or_host] = {
                "patched_by": agent_id,
                "timestamp": time.time(),
                "details": details or {},
            }
            self._updated_at = time.time()
            logger.info(f"Team state: Service {service_or_host} patched by {agent_id}")

    def record_flag(self, flag_hash: str, agent_id: str, round_id: int) -> None:
        with self._lock:
            # Store only hash/token metadata, no plaintext secrets
            entry = {
                "flag_hash": flag_hash,
                "agent_id": agent_id,
                "round_id": round_id,
                "timestamp": time.time(),
            }
            if not any(f["flag_hash"] == flag_hash for f in self._captured_flags):
                self._captured_flags.append(entry)
                self._updated_at = time.time()
                logger.info(f"Team state: Flag {flag_hash[:8]}... captured by {agent_id} in round {round_id}")

    def set_metadata(self, key: str, value: Any) -> None:
        self._check_sensitive(key, value)
        with self._lock:
            self._metadata[key] = value
            self._updated_at = time.time()

    def get_metadata(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._metadata.get(key, default)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "team_id": self.team_id,
                "updated_at": self._updated_at,
                "host_discoveries": dict(self._host_discoveries),
                "compromised_hosts": dict(self._compromised_hosts),
                "patched_services": dict(self._patched_services),
                "captured_flags_count": len(self._captured_flags),
                "captured_flags": list(self._captured_flags),
                "metadata": dict(self._metadata),
            }

    def clear(self) -> None:
        with self._lock:
            self._host_discoveries.clear()
            self._compromised_hosts.clear()
            self._patched_services.clear()
            self._captured_flags.clear()
            self._metadata.clear()
            self._updated_at = time.time()
