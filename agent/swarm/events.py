"""
Event system for 4-Agent Swarm coordination and audit logging.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

from agent.swarm.models import AgentStatus, Phase, TaskStatus

logger = logging.getLogger("koth.swarm.events")


class EventType(str, Enum):
    PHASE_CHANGED = "PHASE_CHANGED"
    TASK_ASSIGNED = "TASK_ASSIGNED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TASK_CANCELLED = "TASK_CANCELLED"
    LEASE_ACQUIRED = "LEASE_ACQUIRED"
    LEASE_RENEWED = "LEASE_RENEWED"
    LEASE_RELEASED = "LEASE_RELEASED"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    AGENT_HEARTBEAT = "AGENT_HEARTBEAT"
    AGENT_JOINED = "AGENT_JOINED"
    AGENT_DROPPED = "AGENT_DROPPED"
    KILL_SWITCH_TRIGGERED = "KILL_SWITCH_TRIGGERED"
    SECURITY_ALERT = "SECURITY_ALERT"


@dataclass
class SwarmEvent:
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    source_agent_id: Optional[str] = None
    agent_id: Optional[str] = None
    team_id: str = "null_warriors"
    round_id: int = 0
    phase_epoch: int = 0
    task_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.agent_id and self.source_agent_id:
            self.agent_id = self.source_agent_id
        elif not self.source_agent_id and self.agent_id:
            self.source_agent_id = self.agent_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "source_agent_id": self.source_agent_id,
            "agent_id": self.agent_id,
            "team_id": self.team_id,
            "round_id": self.round_id,
            "phase_epoch": self.phase_epoch,
            "task_id": self.task_id,
            "data": self.data,
        }


class SwarmEventBus:
    """Thread-safe event bus for swarm coordination and audit log tracking."""

    def __init__(self, max_history: int = 1000):
        self._lock = threading.RLock()
        self._subscribers: Dict[EventType, List[Callable[[SwarmEvent], None]]] = {
            et: [] for et in EventType
        }
        self._global_subscribers: List[Callable[[SwarmEvent], None]] = []
        self._event_history: List[SwarmEvent] = []
        self._max_history = max_history

    def subscribe(
        self, event_type: EventType, callback: Callable[[SwarmEvent], None]
    ) -> None:
        with self._lock:
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable[[SwarmEvent], None]) -> None:
        with self._lock:
            if callback not in self._global_subscribers:
                self._global_subscribers.append(callback)

    def unsubscribe(
        self, event_type: EventType, callback: Callable[[SwarmEvent], None]
    ) -> None:
        with self._lock:
            if callback in self._subscribers[event_type]:
                self._subscribers[event_type].remove(callback)
            if callback in self._global_subscribers:
                self._global_subscribers.remove(callback)

    def publish(self, event: SwarmEvent) -> None:
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)

            handlers = list(self._subscribers.get(event.event_type, []))
            global_handlers = list(self._global_subscribers)

        for handler in handlers + global_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(
                    f"Error in swarm event handler for {event.event_type.value}: {e}",
                    exc_info=True,
                )

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        limit: int = 50,
        since_timestamp: Optional[float] = None,
    ) -> List[SwarmEvent]:
        with self._lock:
            events = self._event_history
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            if since_timestamp:
                events = [e for e in events if e.timestamp >= since_timestamp]
            return list(events[-limit:])

    def clear(self) -> None:
        with self._lock:
            self._event_history.clear()
