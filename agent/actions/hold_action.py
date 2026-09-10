"""Registered HoldAction for safe baseline monitoring."""
import time
from typing import Any, Dict

from .base import ActionContext, ActionExecutionRecord, BaseAction


class HoldAction(BaseAction):
    action_name = "hold"
    action_type = "hold"

    def execute(
        self,
        target: str,
        context: ActionContext,
        model_used: str = "",
        model_confidence: float = 1.0,
    ) -> ActionExecutionRecord:
        now = time.time()
        return ActionExecutionRecord(
            action_type=self.action_type,
            action_name=self.action_name,
            target="",
            model_used=model_used,
            model_confidence=model_confidence,
            started_at=now,
            completed_at=now,
            success=True,
            failure_reason=None,
            verification_result={"state": "baseline_monitoring", "hold_active": True},
            empirical_success=True,
        )

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        return {"state": "holding", "hold_active": True}
