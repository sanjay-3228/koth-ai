"""Base classes for strictly registered actions and independent state verification."""
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ..config import Config
from ..defense.firewall import FirewallManager
from ..defense.monitor import ServiceMonitor
from ..defense.patcher import ServicePatcher
from ..attack.dispatcher import PluginDispatcher
from ..attack.recon import ReconScanner


@dataclass
class ActionContext:
    config: Config
    monitor: ServiceMonitor
    firewall: FirewallManager
    patcher: ServicePatcher
    recon: ReconScanner
    dispatcher: PluginDispatcher
    db: Any = None


@dataclass
class DryRunRecord:
    action_id: str
    action_type: str
    action_name: str
    target: str
    authorization_result: bool
    selected_model: str
    confidence: float
    would_execute: bool
    simulated_result: Dict[str, Any]
    simulated_verification: Dict[str, Any]
    empirical_success: bool
    latency: float
    timestamp: float

    def format_log(self) -> str:
        verif_summary = "simulated_up" if self.empirical_success else "simulated_down"
        if "verified_up" in self.simulated_verification:
            verif_summary = "simulated_up" if self.simulated_verification["verified_up"] else "simulated_down"
        elif "rule_active" in self.simulated_verification:
            verif_summary = "rule_active" if self.simulated_verification["rule_active"] else "rule_inactive"

        return (
            f"DRY_RUN:\n"
            f"{self.action_name}\n"
            f"target={self.target}\n"
            f"authorized={str(self.authorization_result).lower()}\n"
            f"would_execute={str(self.would_execute).lower()}\n"
            f"verification={verif_summary}\n"
            f"empirical_success={str(self.empirical_success).lower()}"
        )


@dataclass
class ActionExecutionRecord:
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: str = ""
    action_name: str = ""
    target: str = ""
    model_used: str = ""
    model_confidence: float = 1.0
    attempted: bool = True
    started_at: float = 0.0
    completed_at: float = 0.0
    success: bool = False
    failure_reason: Optional[str] = None
    verification_result: Dict[str, Any] = field(default_factory=dict)
    empirical_success: bool = False
    dry_run_record: Optional[DryRunRecord] = None

    def build_dry_run_record(self, authorized: bool = True) -> DryRunRecord:
        latency = (self.completed_at - self.started_at) if self.completed_at and self.started_at else 0.0
        rec = DryRunRecord(
            action_id=self.action_id,
            action_type=self.action_type,
            action_name=self.action_name,
            target=self.target,
            authorization_result=authorized,
            selected_model=self.model_used,
            confidence=self.model_confidence,
            would_execute=self.success and authorized,
            simulated_result={
                "status": "simulated",
                "success": self.success,
                "failure_reason": self.failure_reason,
            },
            simulated_verification=dict(self.verification_result),
            empirical_success=self.empirical_success,
            latency=latency,
            timestamp=self.completed_at or time.time(),
        )
        self.dry_run_record = rec
        return rec



class BaseAction(ABC):
    action_name: str = "base"
    action_type: str = "hold"

    @abstractmethod
    def execute(self, target: str, context: ActionContext, model_used: str = "", model_confidence: float = 1.0) -> ActionExecutionRecord:
        """Execute the registered action."""
        raise NotImplementedError

    @abstractmethod
    def verify(self, target: str, context: ActionContext, record: ActionExecutionRecord) -> Dict[str, Any]:
        """Independently verify the actual state after execution."""
        raise NotImplementedError
