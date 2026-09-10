"""
Heartbeat monitoring and periodic beaconing for the 4-agent swarm.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.models import AgentHeartbeat, AgentStatus, Phase

logger = logging.getLogger("koth.swarm.heartbeat")


class HeartbeatMonitor:
    """
    Monitors heartbeat signals from all 4 swarm agents.
    Detects agent disconnections and triggers recovery events.
    """

    def __init__(
        self,
        heartbeat_timeout_seconds: float = 10.0,
        event_bus: Optional[SwarmEventBus] = None,
    ):
        self._lock = threading.RLock()
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self.event_bus = event_bus
        self._heartbeats: Dict[str, AgentHeartbeat] = {}
        self._last_seen: Dict[str, float] = {}

    def record_heartbeat(self, heartbeat: AgentHeartbeat) -> None:
        now = time.time()
        agent_id = heartbeat.agent_id
        with self._lock:
            first_seen = agent_id not in self._heartbeats
            self._heartbeats[agent_id] = heartbeat
            self._last_seen[agent_id] = now

        if first_seen and self.event_bus:
            self.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.AGENT_JOINED,
                    source_agent_id=agent_id,
                    data=heartbeat.to_dict(),
                )
            )

        if self.event_bus:
            self.event_bus.publish(
                SwarmEvent(
                    event_type=EventType.AGENT_HEARTBEAT,
                    source_agent_id=agent_id,
                    data=heartbeat.to_dict(),
                )
            )

    def check_agent_health(self, now: Optional[float] = None) -> List[str]:
        """
        Identify dead agents whose heartbeats have expired.
        Returns list of dead agent_ids.
        """
        current_time = now if now is not None else time.time()
        dead_agents: List[str] = []

        with self._lock:
            for agent_id, last_time in self._last_seen.items():
                hb = self._heartbeats.get(agent_id)
                if (current_time - last_time) > self.heartbeat_timeout_seconds:
                    if hb and hb.status != AgentStatus.DISCONNECTED:
                        hb.status = AgentStatus.DISCONNECTED
                        dead_agents.append(agent_id)
                        logger.warning(
                            f"Agent {agent_id} missed heartbeats for "
                            f"{current_time - last_time:.1f}s (> {self.heartbeat_timeout_seconds}s). Marked DISCONNECTED."
                        )

        if dead_agents and self.event_bus:
            for aid in dead_agents:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.AGENT_DROPPED,
                        source_agent_id=aid,
                        data={
                            "agent_id": aid,
                            "last_seen": self._last_seen.get(aid, 0.0),
                            "reason": "heartbeat_timeout",
                        },
                    )
                )

        return dead_agents

    def is_agent_alive(self, agent_id: str, now: Optional[float] = None) -> bool:
        current_time = now if now is not None else time.time()
        with self._lock:
            last_time = self._last_seen.get(agent_id)
            if last_time is None:
                return False
            return (current_time - last_time) <= self.heartbeat_timeout_seconds

    def get_heartbeat(self, agent_id: str) -> Optional[AgentHeartbeat]:
        with self._lock:
            return self._heartbeats.get(agent_id)

    def get_all_heartbeats(self) -> Dict[str, AgentHeartbeat]:
        with self._lock:
            return dict(self._heartbeats)

    def get_active_agent_ids(self, now: Optional[float] = None) -> List[str]:
        current_time = now if now is not None else time.time()
        with self._lock:
            return [
                aid
                for aid, t in self._last_seen.items()
                if (current_time - t) <= self.heartbeat_timeout_seconds
            ]


class HeartbeatSender:
    """Periodic heartbeat sender for an individual agent instance."""

    def __init__(
        self,
        agent_id: str,
        team_id: str,
        send_fn: Callable[[AgentHeartbeat], bool],
        interval_seconds: float = 3.0,
        status_provider: Optional[Callable[[], AgentStatus]] = None,
        phase_provider: Optional[Callable[[], tuple[Phase, int]]] = None,
        task_provider: Optional[Callable[[], tuple[Optional[str], Optional[str]]]] = None,
    ):
        self.agent_id = agent_id
        self.team_id = team_id
        self.send_fn = send_fn
        self.interval_seconds = interval_seconds
        self.status_provider = status_provider
        self.phase_provider = phase_provider
        self.task_provider = task_provider

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def tick(self) -> bool:
        """Construct and send a single heartbeat."""
        status = (
            self.status_provider()
            if self.status_provider
            else AgentStatus.READY
        )
        phase, epoch = (
            self.phase_provider()
            if self.phase_provider
            else (Phase.UNKNOWN, 0)
        )
        task_id, target = (
            self.task_provider()
            if self.task_provider
            else (None, None)
        )

        hb = AgentHeartbeat(
            agent_id=self.agent_id,
            team_id=self.team_id,
            status=status,
            current_phase=phase,
            phase_epoch=epoch,
            current_task_id=task_id,
            current_target=target,
            timestamp=time.time(),
        )
        try:
            return self.send_fn(hb)
        except Exception as e:
            logger.error(f"Failed to send heartbeat for {self.agent_id}: {e}")
            return False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name=f"heartbeat-{self.agent_id}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while self._running:
            self.tick()
            time.sleep(self.interval_seconds)
