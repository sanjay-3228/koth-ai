"""
4-Agent Swarm package for PwnGrounds King of the Hill competition.
"""

from agent.swarm.client import SwarmClient
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint
from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.heartbeat import HeartbeatMonitor, HeartbeatSender
from agent.swarm.leases import LeaseManager
from agent.swarm.models import (
    AgentHeartbeat,
    AgentRole,
    AgentStatus,
    Phase,
    PhaseState,
    Task,
    TaskLease,
    TaskStatus,
    TaskType,
)
from agent.swarm.phase_manager import (
    PhaseManager,
    PhaseProvider,
    ScoreboardPhaseProvider,
    SimulatedPhaseProvider,
)
from agent.swarm.shared_state import SharedTeamState
from agent.swarm.task_manager import TaskManager

__all__ = [
    "Phase",
    "TaskType",
    "TaskStatus",
    "AgentStatus",
    "AgentRole",
    "PhaseState",
    "Task",
    "TaskLease",
    "AgentHeartbeat",
    "SwarmEvent",
    "EventType",
    "SwarmEventBus",
    "LeaseManager",
    "HeartbeatMonitor",
    "HeartbeatSender",
    "SharedTeamState",
    "PhaseProvider",
    "SimulatedPhaseProvider",
    "ScoreboardPhaseProvider",
    "PhaseManager",
    "TaskManager",
    "SwarmCoordinator",
    "create_coordinator_blueprint",
    "SwarmClient",
]
