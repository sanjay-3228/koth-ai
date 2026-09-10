"""
Data models and Enums for the 4-Agent Swarm architecture.
Designed for PwnGrounds competition: null_warriors with agent-01 to agent-04.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Phase(str, Enum):
    """Authoritative competition phase."""
    ATTACK = "ATTACK"
    DEFENSE = "DEFENSE"
    HOLD = "HOLD"
    UNKNOWN = "UNKNOWN"


class TaskType(str, Enum):
    """Categorized task types for swarm execution."""
    TARGET_DISCOVERY = "TARGET_DISCOVERY"
    ATTACK_SCAN = "ATTACK_SCAN"
    ATTACK_EXPLOIT = "ATTACK_EXPLOIT"
    ATTACK_PERSIST = "ATTACK_PERSIST"
    DEFENSE_AUDIT = "DEFENSE_AUDIT"
    DEFENSE_PATCH = "DEFENSE_PATCH"
    DEFENSE_MONITOR = "DEFENSE_MONITOR"
    DEFENSE_HARDEN = "DEFENSE_HARDEN"


class TaskStatus(str, Enum):
    """Lifecycle status for a distributed task."""
    PENDING = "PENDING"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class AgentStatus(str, Enum):
    """Health and lifecycle status of a swarm agent instance."""
    STARTING = "STARTING"
    READY = "READY"
    RUNNING = "RUNNING"
    SAFE_HOLD = "SAFE_HOLD"
    SAFE_DEGRADED = "SAFE_DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    STOPPED = "STOPPED"


class AgentRole(str, Enum):
    """Role in the swarm: Primary (can run coordinator), Worker, or Operator."""
    PRIMARY = "PRIMARY"
    WORKER = "WORKER"
    OPERATOR = "OPERATOR"


@dataclass
class PhaseState:
    """
    Authoritative phase state published by coordinator or provider.
    Includes epoch counter, round number, TTL, and timestamp.
    """
    phase: Phase
    round_id: int
    phase_epoch: int
    timestamp: float = field(default_factory=time.time)
    ttl_seconds: float = 30.0
    source: str = "coordinator"
    signature_or_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: Optional[float] = None) -> bool:
        current = now if now is not None else time.time()
        return (current - self.timestamp) > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "round_id": self.round_id,
            "phase_epoch": self.phase_epoch,
            "timestamp": self.timestamp,
            "ttl_seconds": self.ttl_seconds,
            "source": self.source,
            "signature_or_token": self.signature_or_token,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PhaseState:
        return cls(
            phase=Phase(data.get("phase", Phase.UNKNOWN.value)),
            round_id=int(data.get("round_id", 0)),
            phase_epoch=int(data.get("phase_epoch", 0)),
            timestamp=float(data.get("timestamp", time.time())),
            ttl_seconds=float(data.get("ttl_seconds", 30.0)),
            source=str(data.get("source", "unknown")),
            signature_or_token=data.get("signature_or_token"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class Task:
    """A unit of work distributed across the swarm."""
    task_id: str
    task_type: TaskType
    phase: Phase
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    action_name: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    assigned_agent_id: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    lease_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    phase_epoch: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "phase": self.phase.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "action_name": self.action_name,
            "params": self.params,
            "assigned_agent_id": self.assigned_agent_id,
            "status": self.status.value,
            "lease_id": self.lease_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": self.result,
            "error": self.error,
            "phase_epoch": self.phase_epoch,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Task:
        return cls(
            task_id=data["task_id"],
            task_type=TaskType(data["task_type"]),
            phase=Phase(data["phase"]),
            target_host=data.get("target_host"),
            target_port=data.get("target_port"),
            action_name=data.get("action_name"),
            params=dict(data.get("params", {})),
            assigned_agent_id=data.get("assigned_agent_id"),
            status=TaskStatus(data.get("status", TaskStatus.PENDING.value)),
            lease_id=data.get("lease_id"),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
            result=data.get("result"),
            error=data.get("error"),
            phase_epoch=data.get("phase_epoch"),
        )


@dataclass
class TaskLease:
    """Exclusive reservation on a task and/or target host for an agent."""
    lease_id: str
    task_id: str
    agent_id: str
    phase: Phase
    phase_epoch: int
    target_host: Optional[str] = None
    granted_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 15.0)
    renew_count: int = 0

    def is_expired(self, now: Optional[float] = None) -> bool:
        current = now if now is not None else time.time()
        return current >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "phase": self.phase.value,
            "phase_epoch": self.phase_epoch,
            "target_host": self.target_host,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "renew_count": self.renew_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaskLease:
        return cls(
            lease_id=data["lease_id"],
            task_id=data["task_id"],
            agent_id=data["agent_id"],
            phase=Phase(data["phase"]),
            phase_epoch=int(data["phase_epoch"]),
            target_host=data.get("target_host"),
            granted_at=float(data.get("granted_at", time.time())),
            expires_at=float(data.get("expires_at", time.time() + 15.0)),
            renew_count=int(data.get("renew_count", 0)),
        )


@dataclass
class AgentHeartbeat:
    """Heartbeat payload sent by each agent to the coordinator."""
    agent_id: str
    team_id: str
    status: AgentStatus
    current_phase: Phase
    phase_epoch: int
    current_task_id: Optional[str] = None
    current_target: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "team_id": self.team_id,
            "status": self.status.value,
            "current_phase": self.current_phase.value,
            "phase_epoch": self.phase_epoch,
            "current_task_id": self.current_task_id,
            "current_target": self.current_target,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentHeartbeat:
        return cls(
            agent_id=data["agent_id"],
            team_id=data["team_id"],
            status=AgentStatus(data.get("status", AgentStatus.READY.value)),
            current_phase=Phase(data.get("current_phase", Phase.UNKNOWN.value)),
            phase_epoch=int(data.get("phase_epoch", 0)),
            current_task_id=data.get("current_task_id"),
            current_target=data.get("current_target"),
            timestamp=float(data.get("timestamp", time.time())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class AgentSession:
    """Authenticated session for a registered agent instance."""
    session_id: str
    agent_id: str
    role: AgentRole
    created_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    ttl: float = 30.0
    revoked: bool = False

    def is_active(self, now: Optional[float] = None) -> bool:
        if self.revoked:
            return False
        current = now if now is not None else time.time()
        return (current - self.last_heartbeat) < self.ttl

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "role": self.role.value,
            "created_at": self.created_at,
            "last_heartbeat": self.last_heartbeat,
            "ttl": self.ttl,
            "revoked": self.revoked,
        }
