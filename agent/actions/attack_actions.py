"""Registered attack and recon actions restricted to TARGET_HOSTS allowlists."""
import time
from typing import Any, Dict

from .base import ActionContext, ActionExecutionRecord, BaseAction
from ..logger import get_logger

logger = get_logger(__name__)


class ReconScanAction(BaseAction):
    action_name = "recon_scan"
    action_type = "recon"

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

        host = target.split(":", 1)[0]
        if not (context.config.is_target_host(host) or host in context.config.own_hosts):
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Host '{host}' not in authorized TARGET_HOSTS."
            return record

        try:
            fingerprint = context.recon.scan(host)
            record.completed_at = time.time()
            record.success = True
            record.verification_result = {
                "host": host,
                "reachable": getattr(fingerprint, "reachable", True),
                "open_ports": fingerprint.open_ports,
                "services": fingerprint.services,
                "service_names": getattr(fingerprint, "service_names", {}),
                "service_versions": getattr(fingerprint, "service_versions", {}),
                "services_count": len(fingerprint.services),
                "duration_seconds": getattr(fingerprint, "duration_seconds", 0.0),
                "started_at": getattr(fingerprint, "started_at", record.started_at),
                "completed_at": getattr(fingerprint, "completed_at", record.completed_at),
                "checked_at": time.time(),
            }
            record.empirical_success = True
        except Exception as exc:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = str(exc)
            record.verification_result = {"error": str(exc)}
            record.empirical_success = False

        return record

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        return record.verification_result


class ExploitPluginAction(BaseAction):
    action_name = "exploit_plugin"
    action_type = "attack"

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
            record.failure_reason = f"Attack target '{target}' missing port specification."
            return record

        host, port_str = target.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Invalid port in '{target}'."
            return record

        if not context.config.is_target_host(host):
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = f"Host '{host}' is not in authorized TARGET_HOSTS."
            return record

        try:
            fingerprint = context.recon.scan(host)
            # Plugin dispatcher enforces plugin allowlist and target validation
            plugin_result = context.dispatcher.dispatch(fingerprint, port, context={}, cfg=context.config)
            record.completed_at = time.time()

            if plugin_result is None:
                record.success = False
                record.failure_reason = f"No authorized matching plugin for {target}."
                record.verification_result = {"plugin_found": False}
                record.empirical_success = False
            else:
                record.success = plugin_result.success
                record.verification_result = {
                    "plugin_found": True,
                    "exploit_success": plugin_result.success,
                    "flag_captured": bool(plugin_result.flag),
                    "notes": plugin_result.notes,
                }
                record.empirical_success = plugin_result.success

        except Exception as exc:
            record.completed_at = time.time()
            record.success = False
            record.failure_reason = str(exc)
            record.empirical_success = False

        return record

    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        return record.verification_result
