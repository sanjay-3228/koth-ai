"""
Lease Manager for mutual-exclusion task and target reservation across the 4-agent swarm.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Dict, List, Optional

from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.models import Phase, TaskLease

logger = logging.getLogger("koth.swarm.leases")


class LeaseManager:
    """
    Manages exclusive leases on tasks and target hosts.
    Guarantees no two agents operate on the same target host simultaneously,
    preventing duplicate scans, race conditions, or conflicting exploit attempts.
    """

    def __init__(self, default_ttl: float = 15.0, event_bus: Optional[SwarmEventBus] = None):
        self._lock = threading.RLock()
        self.default_ttl = default_ttl
        self.event_bus = event_bus
        # lease_id -> TaskLease
        self._leases: Dict[str, TaskLease] = {}
        # task_id -> lease_id
        self._task_leases: Dict[str, str] = {}
        # target_host -> lease_id
        self._target_leases: Dict[str, str] = {}

    def acquire_lease(
        self,
        task_id: str,
        agent_id: str,
        phase: Phase,
        phase_epoch: int,
        target_host: Optional[str] = None,
        duration: Optional[float] = None,
    ) -> Optional[TaskLease]:
        """
        Attempt to acquire an exclusive lease for a task and optional target host.
        Returns TaskLease on success, None on conflict.
        """
        now = time.time()
        ttl = duration if duration is not None else self.default_ttl

        with self._lock:
            # Check existing task lease
            existing_task_lease_id = self._task_leases.get(task_id)
            if existing_task_lease_id:
                existing_lease = self._leases.get(existing_task_lease_id)
                if existing_lease and not existing_lease.is_expired(now):
                    if existing_lease.agent_id != agent_id:
                        logger.debug(
                            f"Task {task_id} already leased to {existing_lease.agent_id}"
                        )
                        return None
                    # Renew if same agent
                    existing_lease.expires_at = now + ttl
                    existing_lease.renew_count += 1
                    return existing_lease
                else:
                    # Clean up expired lease
                    self._internal_remove_lease(existing_task_lease_id)

            # Check target host exclusivity
            if target_host:
                existing_target_lease_id = self._target_leases.get(target_host)
                if existing_target_lease_id:
                    existing_target_lease = self._leases.get(existing_target_lease_id)
                    if existing_target_lease and not existing_target_lease.is_expired(now):
                        if existing_target_lease.agent_id != agent_id:
                            logger.debug(
                                f"Target {target_host} already leased to {existing_target_lease.agent_id}"
                            )
                            return None
                    else:
                        self._internal_remove_lease(existing_target_lease_id)

            # Create new lease
            lease_id = f"lease-{uuid.uuid4().hex[:8]}"
            lease = TaskLease(
                lease_id=lease_id,
                task_id=task_id,
                agent_id=agent_id,
                phase=phase,
                phase_epoch=phase_epoch,
                target_host=target_host,
                granted_at=now,
                expires_at=now + ttl,
                renew_count=0,
            )

            self._leases[lease_id] = lease
            self._task_leases[task_id] = lease_id
            if target_host:
                self._target_leases[target_host] = lease_id

            logger.info(
                f"Lease {lease_id} granted to {agent_id} for task {task_id} "
                f"(target={target_host}, ttl={ttl}s, epoch={phase_epoch})"
            )

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.LEASE_ACQUIRED,
                        source_agent_id=agent_id,
                        data=lease.to_dict(),
                    )
                )

            return lease

    def renew_lease(
        self, lease_id: str, agent_id: str, duration: Optional[float] = None
    ) -> bool:
        """Renew lease expiry if held by the requesting agent."""
        now = time.time()
        ttl = duration if duration is not None else self.default_ttl

        with self._lock:
            lease = self._leases.get(lease_id)
            if not lease:
                return False
            if lease.agent_id != agent_id:
                logger.warning(
                    f"Agent {agent_id} attempted to renew lease {lease_id} owned by {lease.agent_id}"
                )
                return False
            if lease.is_expired(now):
                self._internal_remove_lease(lease_id)
                return False

            lease.expires_at = now + ttl
            lease.renew_count += 1

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.LEASE_RENEWED,
                        source_agent_id=agent_id,
                        data={"lease_id": lease_id, "expires_at": lease.expires_at},
                    )
                )
            return True

    def release_lease(self, lease_id: str, agent_id: Optional[str] = None) -> bool:
        """Release a specific lease."""
        with self._lock:
            lease = self._leases.get(lease_id)
            if not lease:
                return False
            if agent_id and lease.agent_id != agent_id:
                logger.warning(
                    f"Agent {agent_id} attempted to release lease {lease_id} owned by {lease.agent_id}"
                )
                return False

            self._internal_remove_lease(lease_id)
            logger.info(f"Lease {lease_id} released (agent={lease.agent_id}, task={lease.task_id})")

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.LEASE_RELEASED,
                        source_agent_id=agent_id or lease.agent_id,
                        data=lease.to_dict(),
                    )
                )
            return True

    def release_all_for_agent(self, agent_id: str) -> List[str]:
        """Release all leases held by an agent (e.g. on disconnect or phase shift)."""
        released_ids = []
        with self._lock:
            agent_leases = [l for l in self._leases.values() if l.agent_id == agent_id]
            for lease in agent_leases:
                self._internal_remove_lease(lease.lease_id)
                released_ids.append(lease.lease_id)

        if released_ids and self.event_bus:
            for lid in released_ids:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.LEASE_RELEASED,
                        source_agent_id=agent_id,
                        data={"lease_id": lid, "agent_id": agent_id},
                    )
                )
        return released_ids

    def release_all_for_phase(self) -> List[TaskLease]:
        """Release ALL leases across the swarm when the phase transitions."""
        released: List[TaskLease] = []
        with self._lock:
            for lease in list(self._leases.values()):
                self._internal_remove_lease(lease.lease_id)
                released.append(lease)

        if released and self.event_bus:
            for lease in released:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.LEASE_RELEASED,
                        source_agent_id=lease.agent_id,
                        data=lease.to_dict(),
                    )
                )
        return released

    def reap_expired_leases(self, now: Optional[float] = None) -> List[TaskLease]:
        """Find and remove expired leases. Returns the expired leases."""
        current_time = now if now is not None else time.time()
        expired: List[TaskLease] = []

        with self._lock:
            for lease in list(self._leases.values()):
                if lease.is_expired(current_time):
                    self._internal_remove_lease(lease.lease_id)
                    expired.append(lease)

        if expired:
            logger.warning(f"Reaped {len(expired)} expired lease(s): {[l.lease_id for l in expired]}")
            if self.event_bus:
                for lease in expired:
                    self.event_bus.publish(
                        SwarmEvent(
                            event_type=EventType.LEASE_EXPIRED,
                            source_agent_id=lease.agent_id,
                            data=lease.to_dict(),
                        )
                    )
        return expired

    def get_lease(self, lease_id: str) -> Optional[TaskLease]:
        with self._lock:
            return self._leases.get(lease_id)

    def get_lease_for_task(self, task_id: str) -> Optional[TaskLease]:
        with self._lock:
            lid = self._task_leases.get(task_id)
            return self._leases.get(lid) if lid else None

    def get_lease_for_target(self, target_host: str) -> Optional[TaskLease]:
        with self._lock:
            lid = self._target_leases.get(target_host)
            return self._leases.get(lid) if lid else None

    def get_active_leases(self) -> List[TaskLease]:
        with self._lock:
            return list(self._leases.values())

    def is_target_busy(self, target_host: str) -> bool:
        with self._lock:
            lid = self._target_leases.get(target_host)
            if not lid:
                return False
            lease = self._leases.get(lid)
            return bool(lease and not lease.is_expired())

    def _internal_remove_lease(self, lease_id: str) -> None:
        lease = self._leases.pop(lease_id, None)
        if lease:
            if self._task_leases.get(lease.task_id) == lease_id:
                self._task_leases.pop(lease.task_id, None)
            if lease.target_host and self._target_leases.get(lease.target_host) == lease_id:
                self._target_leases.pop(lease.target_host, None)
