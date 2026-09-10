"""Async Orchestrator with priority queues and decoupled worker pools.

Ensures critical service recovery, patching, and firewall blocks run immediately
without being blocked or starved by long-running background recon or plugin operations.
"""
import asyncio
from dataclasses import dataclass, field
from enum import IntEnum
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from .actions.base import ActionContext, ActionExecutionRecord, BaseAction
from .logger import get_logger

logger = get_logger(__name__)


class TaskPriority(IntEnum):
    CRITICAL = 1      # Immediate service recovery, file tampering response, active attack drops
    HIGH = 2          # Service restarts, high-priority firewall rules
    NORMAL = 3        # Routine tactical maneuvers, targeted plugin exploits
    BACKGROUND = 4    # Port scans, directory sweeps, broad recon, integrity audits


@dataclass(order=True)
class PrioritizedTask:
    priority: int
    timestamp: float = field(compare=True)
    task_id: str = field(compare=False)
    action: BaseAction = field(compare=False)
    target: str = field(compare=False)
    context: ActionContext = field(compare=False)
    model_used: str = field(default="", compare=False)
    model_confidence: float = field(default=1.0, compare=False)
    on_complete: Optional[Callable[[ActionExecutionRecord], None]] = field(default=None, compare=False)
    future: Optional[asyncio.Future] = field(default=None, compare=False)


class AsyncOrchestrator:
    """Manages priority-based task dispatching across isolated worker pools."""

    def __init__(self, critical_workers: int = 2, background_workers: int = 2):
        self.num_critical_workers = critical_workers
        self.num_background_workers = background_workers

        self._critical_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._background_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()

        self._worker_tasks: List[asyncio.Task] = []
        self._running: bool = False

        self.metrics: Dict[str, Any] = {
            "queued_critical": 0,
            "queued_background": 0,
            "completed_critical": 0,
            "completed_background": 0,
            "failed_tasks": 0,
            "history": [],
        }

    async def start(self) -> None:
        """Start async worker routines."""
        if self._running:
            return
        self._running = True

        for i in range(self.num_critical_workers):
            task = asyncio.create_task(self._critical_worker_loop(f"critical-worker-{i+1}"))
            self._worker_tasks.append(task)

        for i in range(self.num_background_workers):
            task = asyncio.create_task(self._background_worker_loop(f"background-worker-{i+1}"))
            self._worker_tasks.append(task)

        logger.info(
            "AsyncOrchestrator started (%d critical workers, %d background workers).",
            self.num_critical_workers,
            self.num_background_workers,
        )

    async def stop(self) -> None:
        """Stop all background workers gracefully."""
        self._running = False
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()
        logger.info("AsyncOrchestrator stopped.")

    def enqueue(
        self,
        action: BaseAction,
        target: str,
        context: ActionContext,
        priority: TaskPriority = TaskPriority.NORMAL,
        model_used: str = "",
        model_confidence: float = 1.0,
        on_complete: Optional[Callable[[ActionExecutionRecord], None]] = None,
    ) -> asyncio.Future:
        """Enqueue an action with explicit priority. Returns an awaitable Future."""
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()

        task = PrioritizedTask(
            priority=int(priority),
            timestamp=time.time(),
            task_id=str(uuid.uuid4())[:8],
            action=action,
            target=target,
            context=context,
            model_used=model_used,
            model_confidence=model_confidence,
            on_complete=on_complete,
            future=fut,
        )

        if priority in (TaskPriority.CRITICAL, TaskPriority.HIGH):
            self.metrics["queued_critical"] += 1
            self._critical_queue.put_nowait(task)
            logger.info(
                "[ASYNC] Enqueued %s task '%s' (target: %s, ID: %s) to CRITICAL queue.",
                priority.name,
                action.action_name,
                target,
                task.task_id,
            )
        else:
            self.metrics["queued_background"] += 1
            self._background_queue.put_nowait(task)
            logger.info(
                "[ASYNC] Enqueued %s task '%s' (target: %s, ID: %s) to BACKGROUND queue.",
                priority.name,
                action.action_name,
                target,
                task.task_id,
            )

        return fut

    async def execute_now(
        self,
        action: BaseAction,
        target: str,
        context: ActionContext,
        priority: TaskPriority = TaskPriority.HIGH,
        model_used: str = "",
        model_confidence: float = 1.0,
    ) -> ActionExecutionRecord:
        """Enqueue and immediately await the action completion."""
        fut = self.enqueue(
            action=action,
            target=target,
            context=context,
            priority=priority,
            model_used=model_used,
            model_confidence=model_confidence,
        )
        return await fut

    async def _critical_worker_loop(self, worker_id: str) -> None:
        """Worker loop dedicated to CRITICAL and HIGH priority tasks."""
        while self._running:
            try:
                task: PrioritizedTask = await self._critical_queue.get()
                await self._execute_task(task, worker_id, is_critical=True)
                self._critical_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[%s] Unexpected worker error: %s", worker_id, exc)

    async def _background_worker_loop(self, worker_id: str) -> None:
        """Worker loop dedicated to NORMAL and BACKGROUND priority tasks."""
        while self._running:
            try:
                task: PrioritizedTask = await self._background_queue.get()
                await self._execute_task(task, worker_id, is_critical=False)
                self._background_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[%s] Unexpected worker error: %s", worker_id, exc)

    async def _execute_task(self, task: PrioritizedTask, worker_id: str, is_critical: bool) -> None:
        """Execute action via asyncio.to_thread so blocking calls don't stall the loop."""
        logger.debug("[%s] Executing task %s ('%s' on %s)...", worker_id, task.task_id, task.action.action_name, task.target)
        try:
            record: ActionExecutionRecord = await asyncio.to_thread(
                task.action.execute,
                task.target,
                task.context,
                task.model_used,
                task.model_confidence,
            )
            if is_critical:
                self.metrics["completed_critical"] += 1
            else:
                self.metrics["completed_background"] += 1

            if not record.success:
                self.metrics["failed_tasks"] += 1

            self.metrics["history"].append({
                "task_id": task.task_id,
                "action": task.action.action_name,
                "target": task.target,
                "priority": task.priority,
                "success": record.success,
                "empirical_success": record.empirical_success,
                "worker": worker_id,
            })

            if task.on_complete:
                try:
                    task.on_complete(record)
                except Exception as cb_exc:
                    logger.warning("[%s] on_complete callback failed: %s", worker_id, cb_exc)

            if task.future and not task.future.done():
                task.future.set_result(record)

        except Exception as exc:
            logger.error("[%s] Action execution failed for task %s: %s", worker_id, task.task_id, exc)
            self.metrics["failed_tasks"] += 1
            err_record = ActionExecutionRecord(
                action_id=task.task_id,
                action_type=task.action.action_type,
                action_name=task.action.action_name,
                target=task.target,
                model_used=task.model_used,
                model_confidence=task.model_confidence,
                attempted=True,
                started_at=task.timestamp,
                completed_at=time.time(),
                success=False,
                failure_reason=str(exc),
                verification_result={"error": str(exc)},
                empirical_success=False,
            )
            if task.future and not task.future.done():
                task.future.set_result(err_record)
