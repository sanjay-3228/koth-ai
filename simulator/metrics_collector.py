"""Metrics collector for KOTH simulator and integration test harness.

Records:
- Latencies: detection, decision, action, verification, total recovery time
- Model counters: Flash calls, Pro calls, escalations, local-policy decisions
- Action counters: successful actions, failed actions, false actions
- Queue counters: queue wait time, critical task wait time
"""
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional


@dataclass
class ScenarioMetric:
    scenario_id: int
    name: str
    expected_behavior: str
    actual_behavior: str
    passed: bool
    detection_latency_ms: float = 0.0
    decision_latency_ms: float = 0.0
    action_latency_ms: float = 0.0
    verification_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    model_used: str = ""
    notes: str = ""


class MetricsCollector:
    def __init__(self):
        self.scenarios: List[ScenarioMetric] = []

        # Granular counters
        self.flash_calls: int = 0
        self.pro_calls: int = 0
        self.escalations: int = 0
        self.local_policy_decisions: int = 0

        self.successful_actions: int = 0
        self.failed_actions: int = 0
        self.false_actions: int = 0

        # Latency lists (in milliseconds)
        self.detection_latencies: List[float] = []
        self.decision_latencies: List[float] = []
        self.action_latencies: List[float] = []
        self.verification_latencies: List[float] = []
        self.recovery_times: List[float] = []

        self.queue_wait_times: List[float] = []
        self.critical_task_wait_times: List[float] = []

    def record_scenario(
        self,
        scenario_id: int,
        name: str,
        expected: str,
        actual: str,
        passed: bool,
        detection_ms: float = 0.0,
        decision_ms: float = 0.0,
        action_ms: float = 0.0,
        verification_ms: float = 0.0,
        model_used: str = "",
        notes: str = "",
    ) -> ScenarioMetric:
        total_ms = detection_ms + decision_ms + action_ms + verification_ms
        metric = ScenarioMetric(
            scenario_id=scenario_id,
            name=name,
            expected_behavior=expected,
            actual_behavior=actual,
            passed=passed,
            detection_latency_ms=round(detection_ms, 2),
            decision_latency_ms=round(decision_ms, 2),
            action_latency_ms=round(action_ms, 2),
            verification_latency_ms=round(verification_ms, 2),
            total_latency_ms=round(total_ms, 2),
            model_used=model_used,
            notes=notes,
        )
        self.scenarios.append(metric)

        if detection_ms > 0:
            self.detection_latencies.append(detection_ms)
        if decision_ms > 0:
            self.decision_latencies.append(decision_ms)
        if action_ms > 0:
            self.action_latencies.append(action_ms)
        if verification_ms > 0:
            self.verification_latencies.append(verification_ms)
        if total_ms > 0:
            self.recovery_times.append(total_ms)

        return metric

    def record_decision(self, model_used: str, confidence: float = 1.0, latency_ms: float = 0.0) -> None:
        if model_used == "local-policy":
            self.local_policy_decisions += 1
        elif any(k in model_used.lower() for k in ("pro", "super", "120b", "reasoning")):
            self.pro_calls += 1
        else:
            self.flash_calls += 1

        if latency_ms > 0:
            self.decision_latencies.append(latency_ms)

    def record_action_outcome(self, success: bool, empirical_success: bool, is_security_block: bool = False) -> None:
        if is_security_block:
            self.false_actions += 1
        elif success and empirical_success:
            self.successful_actions += 1
        else:
            self.failed_actions += 1

    def avg(self, lst: List[float]) -> float:
        return round(sum(lst) / len(lst), 2) if lst else 0.0

    def max_val(self, lst: List[float]) -> float:
        return round(max(lst), 2) if lst else 0.0

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_scenarios": len(self.scenarios),
            "passed_scenarios": sum(1 for s in self.scenarios if s.passed),
            "failed_scenarios": sum(1 for s in self.scenarios if not s.passed),
            "flash_calls": self.flash_calls,
            "pro_calls": self.pro_calls,
            "escalations": self.escalations,
            "local_policy_decisions": self.local_policy_decisions,
            "successful_actions": self.successful_actions,
            "failed_actions": self.failed_actions,
            "false_actions": self.false_actions,
            "avg_detection_latency_ms": self.avg(self.detection_latencies),
            "avg_decision_latency_ms": self.avg(self.decision_latencies),
            "avg_action_latency_ms": self.avg(self.action_latencies),
            "avg_verification_latency_ms": self.avg(self.verification_latencies),
            "avg_total_recovery_time_ms": self.avg(self.recovery_times),
            "max_recovery_time_ms": self.max_val(self.recovery_times),
            "avg_queue_wait_time_ms": self.avg(self.queue_wait_times),
            "avg_critical_task_wait_time_ms": self.avg(self.critical_task_wait_times),
        }
