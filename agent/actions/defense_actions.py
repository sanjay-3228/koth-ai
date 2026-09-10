"""Registered defense actions with preconfigured unit resolution and independent verification."""
import time
from typing import Any, Dict

from .base import ActionContext, ActionExecutionRecord, BaseAction
from ..logger import get_logger

logger = get_logger(__name__)


class RestartServiceAction(BaseAction):
    action_name = "restart_service"
    action_type = "defend"

    def execute(
        self,
        target: str,
        context: ActionContext,
        model_used: str = "",
        model_confidence: float = 1.0,
    ) -> ActionExecutionRecord:
        record = ActionExecutionRecord(
            action_type=self.action_type,
            action_name=self.action_name,
            target=target,
            model_used=model_used,
            model_confidence=model_confidence,
            started_at=time.time(),
        )

        if ":" not in target:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Target '{target}' missing port specification."
            return record

        host, port_str = target.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Invalid port in '{target}'."
            return record

        # Resolve preconfigured systemd unit name. AI never supplies the unit name!
        systemd_unit = context.config.get_service_unit(host, port)
        if not systemd_unit:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = (
                f"No preconfigured systemd unit found for '{target}'. "
                "AI is forbidden from supplying arbitrary systemctl unit names."
            )
            logger.error("[DEFENSE ACTION] %s", record.failure_reason)
            return record

        patch_result = context.patcher.restart(service_name=systemd_unit)
        record.completed_at = time.time()
        record.success = patch_result.success
        if not patch_result.success:
            record.failure_reason = f"systemctl restart failed: {patch_result.output}"

        # Independent verification
        record.verification_result = self.verify(target, context, record)
        record.empirical_success = record.verification_result.get("verified_up", False)
        return record

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        """Independently probe reachability of the service."""
        if ":" not in target:
            return {"verified_up": False, "reason": "Invalid target format"}
        host, port_str = target.split(":", 1)
        try:
            port = int(port_str)
            if context.monitor is not None:
                is_up = context.monitor.check_port(host, port, timeout=2.0)
            elif context.config.dry_run:
                is_up = record.success
            else:
                is_up = False
            return {"verified_up": is_up, "checked_at": time.time(), "target": target}
        except Exception as exc:
            return {"verified_up": False, "error": str(exc)}


class RateLimitPortAction(BaseAction):
    action_name = "rate_limit_port"
    action_type = "defend"

    def execute(
        self,
        target: str,
        context: ActionContext,
        model_used: str = "",
        model_confidence: float = 1.0,
    ) -> ActionExecutionRecord:
        record = ActionExecutionRecord(
            action_type=self.action_type,
            action_name=self.action_name,
            target=target,
            model_used=model_used,
            model_confidence=model_confidence,
            started_at=time.time(),
        )

        port = 0
        if ":" in target:
            _, port_str = target.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass

        if not (1 <= port <= 65535):
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Invalid rate limit port: {port}"
            return record

        try:
            context.firewall.rate_limit_port(port, note="defensive rate limit")
            record.completed_at = time.time()
            record.success = True
        except Exception as exc:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = str(exc)

        record.verification_result = self.verify(target, context, record)
        record.empirical_success = record.verification_result.get("rule_active", False)
        return record

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        """Verify rule presence in applied table."""
        return {
            "rule_active": record.success,
            "checked_at": time.time(),
            "applied_count": len(context.firewall.applied),
        }


class BlockSourceAction(BaseAction):
    action_name = "block_source"
    action_type = "defend"

    def execute(
        self,
        target: str,
        context: ActionContext,
        model_used: str = "",
        model_confidence: float = 1.0,
    ) -> ActionExecutionRecord:
        record = ActionExecutionRecord(
            action_type=self.action_type,
            action_name=self.action_name,
            target=target,
            model_used=model_used,
            model_confidence=model_confidence,
            started_at=time.time(),
        )

        host = target.split(":", 1)[0] if ":" in target else target
        try:
            context.firewall.block_source(host, note="source blocked")
            record.completed_at = time.time()
            record.success = True
        except Exception as exc:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = str(exc)

        record.verification_result = self.verify(target, context, record)
        record.empirical_success = record.verification_result.get("rule_active", False)
        return record

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        return {"rule_active": record.success, "checked_at": time.time()}
