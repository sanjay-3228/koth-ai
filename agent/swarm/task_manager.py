"""
Task Manager for distributing phase-specific tasks across the 4-agent swarm.
Guarantees partitioned target allocation and handles cancellation/reassignment.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from agent.swarm.events import EventType, SwarmEvent, SwarmEventBus
from agent.swarm.leases import LeaseManager
from agent.swarm.models import Phase, Task, TaskLease, TaskStatus, TaskType
from agent.swarm.shared_state import SharedTeamState

logger = logging.getLogger("koth.swarm.tasks")

AGENT_HILL_MAPPING = {
    "agent-01": 1,
    "agent-02": 2,
    "agent-03": 3,
    "agent-04": 4,
}


class TaskManager:
    """
    Coordinates task scheduling, target partitioning, and task lifecycles for null_warriors.
    Integrates with LeaseManager to guarantee mutual exclusion on target hosts.
    """

    def __init__(
        self,
        lease_manager: LeaseManager,
        shared_state: Optional[SharedTeamState] = None,
        event_bus: Optional[SwarmEventBus] = None,
    ):
        self._lock = threading.RLock()
        self.lease_manager = lease_manager
        self.shared_state = shared_state or SharedTeamState()
        self.event_bus = event_bus

        # task_id -> Task
        self._tasks: Dict[str, Task] = {}

    def create_task(
        self,
        task_type: TaskType,
        phase: Phase,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        action_name: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        hill_id: Optional[int] = None,
        phase_epoch: Optional[int] = None,
        dependencies: Optional[List[str]] = None,
        parent_task_id: Optional[str] = None,
        description: str = "",
        coordination_role: str = "",
    ) -> Task:
        tid = task_id or f"task-{task_type.value.lower()}-{uuid.uuid4().hex[:8]}"
        with self._lock:
            if tid in self._tasks:
                raise ValueError(f"Duplicate task_id '{tid}': Task already exists")

            task = Task(
                task_id=tid,
                task_type=task_type,
                phase=phase,
                target_host=target_host,
                target_port=target_port,
                action_name=action_name,
                params=params or {},
                status=TaskStatus.PENDING,
                hill_id=hill_id,
                phase_epoch=phase_epoch,
                dependencies=list(dependencies or []),
                parent_task_id=parent_task_id,
                description=description,
                coordination_role=coordination_role,
            )
            self._tasks[tid] = task

        logger.debug(f"Created task {tid} [{task_type.value}] for target {target_host} (hill {hill_id}) in phase {phase.value}")
        return task

    def detect_duplicate_work(
        self,
        target_host: str,
        action_name: str,
        phase: Optional[Phase] = None,
        exclude_task_id: Optional[str] = None,
    ) -> bool:
        """Check if an equivalent task is already PENDING, LEASED, or RUNNING."""
        with self._lock:
            for task in self._tasks.values():
                if exclude_task_id and task.task_id == exclude_task_id:
                    continue
                if phase and task.phase != phase:
                    continue
                if task.status in (TaskStatus.PENDING, TaskStatus.LEASED, TaskStatus.RUNNING):
                    if task.target_host == target_host and task.action_name == action_name:
                        return True
            return False

    def break_down_objective(
        self,
        objective_text: str,
        leader_agent_id: str = "agent-01",
        phase: Phase = Phase.ATTACK,
        target_hosts: Optional[List[str]] = None,
        hills: Optional[List[int]] = None,
        phase_epoch: Optional[int] = None,
    ) -> List[Task]:
        """
        Decomposes a high-level competition objective into ordered swarm tasks with dependencies.
        Leader (agent-01) delegates tasks across the 4 agents according to role/hill mapping.
        """
        if leader_agent_id not in ("agent-01", "operator", "admin"):
            raise PermissionError(f"Agent '{leader_agent_id}' is not authorized to decompose objectives (must be leader)")

        created_tasks: List[Task] = []
        hosts = target_hosts or ["10.0.1.10", "10.0.2.20", "10.0.3.30", "10.0.4.40"]
        active_hills = hills or [1, 2, 3, 4]

        with self._lock:
            for idx, host in enumerate(hosts):
                hill_idx = active_hills[idx % len(active_hills)]
                assigned_aid = f"agent-0{hill_idx}"

                # Step 1: Reconnaissance / Scanning task
                recon_tid = f"task-recon-hill{hill_idx}-{uuid.uuid4().hex[:6]}"
                if not self.detect_duplicate_work(host, "nmap_scan", phase):
                    t_recon = self.create_task(
                        task_id=recon_tid,
                        task_type=TaskType.ATTACK_SCAN if phase == Phase.ATTACK else TaskType.DEFENSE_AUDIT,
                        phase=phase,
                        target_host=host,
                        action_name="nmap_scan" if phase == Phase.ATTACK else "audit_local_services",
                        params={"ports": "21,22,80,443,8080", "objective": objective_text},
                        hill_id=hill_idx,
                        phase_epoch=phase_epoch,
                        description=f"Initial reconnaissance & port scan on {host} for objective: {objective_text[:40]}",
                        coordination_role="Specialist Recon",
                    )
                    created_tasks.append(t_recon)

                # Step 2: Exploitation / Patching (depends on Step 1 Recon)
                exploit_tid = f"task-action-hill{hill_idx}-{uuid.uuid4().hex[:6]}"
                action_name = "exploit_service" if phase == Phase.ATTACK else "patch_vulnerability"
                if not self.detect_duplicate_work(host, action_name, phase):
                    t_exploit = self.create_task(
                        task_id=exploit_tid,
                        task_type=TaskType.ATTACK_EXPLOIT if phase == Phase.ATTACK else TaskType.DEFENSE_PATCH,
                        phase=phase,
                        target_host=host,
                        action_name=action_name,
                        params={"objective": objective_text, "phase": phase.value.lower()},
                        hill_id=hill_idx,
                        phase_epoch=phase_epoch,
                        dependencies=[recon_tid],
                        description=f"{action_name.replace('_', ' ').title()} on {host} (depends on recon)",
                        coordination_role="Specialist Action",
                    )
                    created_tasks.append(t_exploit)

        logger.info(
            f"Objective '{objective_text[:50]}' broken down into {len(created_tasks)} tasks by {leader_agent_id}"
        )
        return created_tasks

    def reassign_task(
        self,
        task_id: str,
        new_agent_id: str,
        caller_agent_id: str,
        reason: str = "Reassignment by leader",
    ) -> Tuple[bool, str]:
        """
        Reassigns an existing task to another agent.
        Only the leader (agent-01) or operator can trigger reassignment.
        """
        if caller_agent_id not in ("agent-01", "operator", "admin"):
            return False, f"Agent '{caller_agent_id}' is not authorized to reassign tasks (leader only)"

        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False, f"Task '{task_id}' not found"

            old_agent_id = task.assigned_agent_id
            if task.lease_id:
                self.lease_manager.release_lease(task.lease_id)
                task.lease_id = None

            task.assigned_agent_id = new_agent_id
            if new_agent_id in AGENT_HILL_MAPPING:
                task.hill_id = AGENT_HILL_MAPPING[new_agent_id]
            task.status = TaskStatus.PENDING
            task.updated_at = time.time()

            logger.info(
                f"Task '{task_id}' reassigned from {old_agent_id} to {new_agent_id} by {caller_agent_id}: {reason}"
            )

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.TASK_REASSIGNED,
                        source_agent_id=caller_agent_id,
                        agent_id=new_agent_id,
                        task_id=task_id,
                        data={
                            "task_id": task_id,
                            "previous_agent_id": old_agent_id,
                            "new_agent_id": new_agent_id,
                            "reassigned_by": caller_agent_id,
                            "reason": reason,
                        },
                    )
                )

            return True, f"Task successfully reassigned to {new_agent_id}"

    def populate_phase_tasks(
        self,
        phase: Phase,
        target_hosts: List[str],
        own_hosts: List[str],
        phase_epoch: Optional[int] = None,
    ) -> List[Task]:
        """
        Generate default phase tasks for authorized targets or defended hosts.
        Partitions distinct targets for parallel assignment across the 4 agents.
        """
        created: List[Task] = []
        with self._lock:
            if phase == Phase.ATTACK:
                for idx, host in enumerate(target_hosts):
                    hill_id = (idx % 4) + 1
                    t1 = self.create_task(
                        task_type=TaskType.ATTACK_SCAN,
                        phase=Phase.ATTACK,
                        target_host=host,
                        action_name="nmap_scan",
                        params={"ports": "21,22,80,443,8080"},
                        hill_id=hill_id,
                        phase_epoch=phase_epoch,
                    )
                    t2 = self.create_task(
                        task_type=TaskType.ATTACK_EXPLOIT,
                        phase=Phase.ATTACK,
                        target_host=host,
                        action_name="exploit_service",
                        params={"phase": "attack"},
                        hill_id=hill_id,
                        phase_epoch=phase_epoch,
                    )
                    created.extend([t1, t2])

            elif phase == Phase.DEFENSE:
                for idx, host in enumerate(own_hosts):
                    hill_id = (idx % 4) + 1
                    t1 = self.create_task(
                        task_type=TaskType.DEFENSE_AUDIT,
                        phase=Phase.DEFENSE,
                        target_host=host,
                        action_name="audit_local_services",
                        hill_id=hill_id,
                        phase_epoch=phase_epoch,
                    )
                    t2 = self.create_task(
                        task_type=TaskType.DEFENSE_PATCH,
                        phase=Phase.DEFENSE,
                        target_host=host,
                        action_name="patch_vulnerability",
                        hill_id=hill_id,
                        phase_epoch=phase_epoch,
                    )
                    t3 = self.create_task(
                        task_type=TaskType.DEFENSE_MONITOR,
                        phase=Phase.DEFENSE,
                        target_host=host,
                        action_name="monitor_connections",
                        hill_id=hill_id,
                        phase_epoch=phase_epoch,
                    )
                    created.extend([t1, t2, t3])

        logger.info(f"Populated {len(created)} tasks for phase {phase.value}")
        return created

    def request_next_task(
        self,
        agent_id: str,
        phase: Phase,
        phase_epoch: int,
    ) -> Tuple[Optional[Task], Optional[TaskLease]]:
        """
        Select an eligible PENDING task for the agent.
        Crucial requirement: Avoid target collision!
        If a task's target_host is currently leased by another agent, skip it.
        """
        with self._lock:
            # Check if agent already has an active lease
            for lease in self.lease_manager.get_active_leases():
                if lease.agent_id == agent_id and not lease.is_expired():
                    existing_task = self._tasks.get(lease.task_id)
                    if existing_task and existing_task.phase == phase:
                        return existing_task, lease

            for task in self._tasks.values():
                if task.phase != phase:
                    continue
                if task.status != TaskStatus.PENDING:
                    continue

                # Check task dependencies
                if task.dependencies:
                    deps_met = all(
                        self._tasks.get(dep_id) and self._tasks[dep_id].status == TaskStatus.COMPLETED
                        for dep_id in task.dependencies
                    )
                    if not deps_met:
                        continue

                # Hill assignment isolation check
                if task.hill_id is not None and agent_id in AGENT_HILL_MAPPING:
                    if task.hill_id != AGENT_HILL_MAPPING[agent_id]:
                        continue

                # Check target host lease exclusivity
                if task.target_host and self.lease_manager.is_target_busy(task.target_host):
                    continue

                # Attempt to lease
                lease = self.lease_manager.acquire_lease(
                    task_id=task.task_id,
                    agent_id=agent_id,
                    phase=phase,
                    phase_epoch=phase_epoch,
                    target_host=task.target_host,
                )
                if lease:
                    task.status = TaskStatus.LEASED
                    task.assigned_agent_id = agent_id
                    task.lease_id = lease.lease_id
                    task.phase_epoch = phase_epoch
                    task.updated_at = time.time()

                    logger.info(
                        f"Assigned task {task.task_id} to {agent_id} (target={task.target_host})"
                    )

                    if self.event_bus:
                        self.event_bus.publish(
                            SwarmEvent(
                                event_type=EventType.TASK_ASSIGNED,
                                source_agent_id=agent_id,
                                data={"task": task.to_dict(), "lease": lease.to_dict()},
                            )
                        )
                    return task, lease

            # Pass 2: If leader (agent-01) and no Hill 1 task pending, allow failover to any pending task
            if agent_id == "agent-01":
                for task in self._tasks.values():
                    if task.phase != phase:
                        continue
                    if task.status != TaskStatus.PENDING:
                        continue
                    if task.dependencies:
                        deps_met = all(
                            self._tasks.get(dep_id) and self._tasks[dep_id].status == TaskStatus.COMPLETED
                            for dep_id in task.dependencies
                        )
                        if not deps_met:
                            continue
                    if task.target_host and self.lease_manager.is_target_busy(task.target_host):
                        continue
                    lease = self.lease_manager.acquire_lease(
                        task_id=task.task_id,
                        agent_id=agent_id,
                        phase=phase,
                        phase_epoch=phase_epoch,
                        target_host=task.target_host,
                    )
                    if lease:
                        task.status = TaskStatus.LEASED
                        task.assigned_agent_id = agent_id
                        task.lease_id = lease.lease_id
                        task.phase_epoch = phase_epoch
                        task.updated_at = time.time()
                        logger.info(
                            f"Leader failover assigned task {task.task_id} to {agent_id} (target={task.target_host})"
                        )
                        if self.event_bus:
                            self.event_bus.publish(
                                SwarmEvent(
                                    event_type=EventType.TASK_ASSIGNED,
                                    source_agent_id=agent_id,
                                    data={"task": task.to_dict(), "lease": lease.to_dict()},
                                )
                            )
                        return task, lease

        return None, None

    def claim_task(
        self,
        task_id: str,
        agent_id: str,
        phase: Phase,
        phase_epoch: int,
    ) -> Tuple[Optional[Task], Optional[TaskLease]]:
        """Attempt to claim a specific task by task_id with mutual-exclusion checks."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                logger.warning(f"Claim task failed: {task_id} not found")
                return None, None
            if task.phase != phase:
                logger.warning(f"Claim task failed: {task_id} phase mismatch ({task.phase.value} != {phase.value})")
                return None, None
            if task.status != TaskStatus.PENDING:
                logger.warning(f"Claim task failed: {task_id} is not PENDING (status={task.status.value})")
                return None, None
            if task.dependencies:
                deps_met = all(
                    self._tasks.get(dep_id) and self._tasks[dep_id].status == TaskStatus.COMPLETED
                    for dep_id in task.dependencies
                )
                if not deps_met:
                    logger.warning(f"Claim task failed: {task_id} has unmet dependencies {task.dependencies}")
                    return None, None
            if task.hill_id is not None and agent_id in AGENT_HILL_MAPPING:
                if task.hill_id != AGENT_HILL_MAPPING[agent_id] and agent_id != "agent-01":
                    logger.warning(
                        f"Claim task failed: {task_id} belongs to hill {task.hill_id}, "
                        f"but agent {agent_id} is assigned to hill {AGENT_HILL_MAPPING[agent_id]}"
                    )
                    return None, None
            if task.target_host and self.lease_manager.is_target_busy(task.target_host):
                logger.warning(f"Claim task failed: target {task.target_host} is already leased")
                return None, None

            lease = self.lease_manager.acquire_lease(
                task_id=task.task_id,
                agent_id=agent_id,
                phase=phase,
                phase_epoch=phase_epoch,
                target_host=task.target_host,
            )
            if lease:
                task.status = TaskStatus.LEASED
                task.assigned_agent_id = agent_id
                task.lease_id = lease.lease_id
                task.phase_epoch = phase_epoch
                task.updated_at = time.time()
                if self.event_bus:
                    self.event_bus.publish(
                        SwarmEvent(
                            event_type=EventType.TASK_ASSIGNED,
                            source_agent_id=agent_id,
                            agent_id=agent_id,
                            task_id=task.task_id,
                            phase_epoch=phase_epoch,
                            data={"task": task.to_dict(), "lease": lease.to_dict()},
                        )
                    )
                return task, lease
            return None, None

    def complete_task(
        self,
        task_id: str,
        agent_id: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                logger.warning(f"Complete task failed: {task_id} not found")
                return False

            if task.status == TaskStatus.COMPLETED:
                logger.warning(f"Complete task failed: {task_id} is already completed")
                return False

            if task.assigned_agent_id != agent_id:
                logger.warning(
                    f"Agent {agent_id} tried to complete {task_id} assigned to {task.assigned_agent_id}"
                )
                return False

            task.status = TaskStatus.COMPLETED
            task.result = result or {}
            task.updated_at = time.time()

            # Release lease
            if task.lease_id:
                self.lease_manager.release_lease(task.lease_id, agent_id=agent_id)
                task.lease_id = None

            # Update shared knowledge base if applicable
            if result and task.target_host:
                if "open_ports" in result:
                    self.shared_state.record_host_scan(
                        task.target_host, result["open_ports"], os_hint=result.get("os")
                    )
                if result.get("compromised"):
                    self.shared_state.record_compromise(task.target_host, agent_id, result)
                if result.get("flag_captured"):
                    self.shared_state.record_flag(
                        flag_hash=result["flag_captured"],
                        agent_id=agent_id,
                        round_id=result.get("round_id", 1),
                    )
                if result.get("patched"):
                    self.shared_state.record_patch(task.target_host, agent_id, result)

            logger.info(f"Task {task_id} marked COMPLETED by {agent_id}")

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.TASK_COMPLETED,
                        source_agent_id=agent_id,
                        data={"task_id": task_id, "result": task.result},
                    )
                )
            return True

    def fail_task(
        self,
        task_id: str,
        agent_id: str,
        error: str,
        retryable: bool = True,
    ) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False

            task.error = error
            task.updated_at = time.time()

            if task.lease_id:
                self.lease_manager.release_lease(task.lease_id, agent_id=agent_id)
                task.lease_id = None

            if retryable:
                task.status = TaskStatus.PENDING
                task.assigned_agent_id = None
                logger.info(f"Task {task_id} failed by {agent_id} (retryable reset to PENDING): {error}")
            else:
                task.status = TaskStatus.FAILED
                logger.warning(f"Task {task_id} marked FAILED permanently by {agent_id}: {error}")

            if self.event_bus:
                self.event_bus.publish(
                    SwarmEvent(
                        event_type=EventType.TASK_FAILED,
                        source_agent_id=agent_id,
                        data={"task_id": task_id, "error": error, "retryable": retryable},
                    )
                )
            return True

    def cancel_tasks_for_phase(self, old_phase: Phase) -> int:
        """Cancel all pending or leased tasks belonging to old_phase."""
        cancelled_count = 0
        with self._lock:
            for task in self._tasks.values():
                if task.phase == old_phase and task.status in (
                    TaskStatus.PENDING,
                    TaskStatus.LEASED,
                    TaskStatus.RUNNING,
                ):
                    task.status = TaskStatus.CANCELLED
                    task.updated_at = time.time()
                    if task.lease_id:
                        self.lease_manager.release_lease(task.lease_id)
                        task.lease_id = None
                    cancelled_count += 1

        logger.info(f"Cancelled {cancelled_count} tasks from previous phase {old_phase.value}")
        return cancelled_count

    def reset_tasks_for_agent(self, agent_id: str) -> int:
        """Reset any tasks currently held by agent_id back to PENDING and release their leases."""
        reset_count = 0
        with self._lock:
            for task in self._tasks.values():
                if task.assigned_agent_id == agent_id and task.status in (TaskStatus.LEASED, TaskStatus.RUNNING):
                    if task.lease_id:
                        self.lease_manager.release_lease(task.lease_id)
                        task.lease_id = None
                    task.status = TaskStatus.PENDING
                    task.assigned_agent_id = None
                    task.updated_at = time.time()
                    reset_count += 1
                    logger.info(f"Reset task {task.task_id} held by agent {agent_id} back to PENDING")
        return reset_count

    def reap_abandoned_tasks(self, now: Optional[float] = None) -> int:
        """
        Reap expired leases from LeaseManager and reset their tasks to PENDING.
        """
        reaped_count = 0
        with self._lock:
            expired_leases = self.lease_manager.reap_expired_leases(now=now)
            for lease in expired_leases:
                task = self._tasks.get(lease.task_id)
                if task and task.status in (TaskStatus.LEASED, TaskStatus.RUNNING):
                    task.status = TaskStatus.PENDING
                    task.assigned_agent_id = None
                    task.lease_id = None
                    task.updated_at = time.time()
                    reaped_count += 1
                    logger.info(f"Reset abandoned task {task.task_id} back to PENDING")
        return reaped_count

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def get_all_tasks(self) -> List[Task]:
        with self._lock:
            return list(self._tasks.values())

    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.status == status]
