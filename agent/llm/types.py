"""Typed definitions for the three-provider LLM architecture."""
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

# Strict validation pattern for host[:port]
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]+(?::\d{1,5})?$")

# Standardized actions recognized across providers and local policy
VALID_ACTIONS = {
    "recon",
    "exploit_plugin",
    "restart_service",
    "rate_limit_port",
    "block_source",
    "hold",
    # Backward compatibility aliases
    "defend",
    "attack",
}

VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "medium", "high", "critical"}


class ModelProviderType(str, Enum):
    LOCAL = "local"
    NVIDIA = "nvidia"
    GROQ = "groq"
    OPENROUTER = "openrouter"


@dataclass
class ModelDecision:
    """Strongly typed decision returned by LLM providers or local policy."""
    action: str = "hold"
    target: str = ""
    priority: str = "LOW"
    confidence: float = 0.0
    observation: str = ""
    reasoning_summary: str = ""
    provider: str = "local"
    model: str = ""
    latency_ms: float = 0.0
    request_id: str = ""
    fallback_level: int = 0
    parse_status: str = "SUCCESS"  # "SUCCESS", "FAILED", "SKIPPED"
    http_status: Optional[int] = 200
    needs_escalation: bool = False
    raw_response: Optional[str] = None
    diagnostics: Optional[Dict[str, Any]] = None

    # Duck-typing compatibility properties for Decision
    @property
    def action_type(self) -> str:
        """Map fine-grained action to coarse decision type (defend, attack, recon, hold)."""
        act = (self.action or "hold").lower()
        if act in ("restart_service", "rate_limit_port", "block_source", "defend"):
            return "defend"
        elif act in ("exploit_plugin", "attack"):
            return "attack"
        elif act in ("recon", "recon_scan", "nmap_scan"):
            return "recon"
        return "hold"

    @action_type.setter
    def action_type(self, val: str) -> None:
        val_lower = (val or "hold").lower()
        if val_lower in ("defend", "attack", "recon", "hold"):
            if self.action in ("hold", "", "defend", "attack", "recon"):
                self.action = val_lower

    @property
    def action_name(self) -> str:
        """Return concrete action identifier."""
        act = (self.action or "hold").lower()
        if act == "recon":
            return "recon_scan"
        elif act == "attack":
            return "exploit_plugin"
        elif act == "defend":
            return "restart_service"
        return self.action or "hold"

    @action_name.setter
    def action_name(self, val: str) -> None:
        self.action = val

    @property
    def reasoning(self) -> str:
        """Alias for reasoning_summary."""
        return self.reasoning_summary or self.observation

    @reasoning.setter
    def reasoning(self, val: str) -> None:
        self.reasoning_summary = val

    @property
    def model_used(self) -> str:
        """Alias for model."""
        return self.model or self.provider

    @model_used.setter
    def model_used(self, val: str) -> None:
        self.model = val

    @property
    def proposed_decision(self) -> str:
        """Alias for proposed_decision."""
        return self.action

    def sanitize(self) -> "ModelDecision":
        """Enforce strict allowlists and bounds to prevent arbitrary execution."""
        act_lower = (self.action or "hold").lower().strip()
        if act_lower not in VALID_ACTIONS:
            self.action = "hold"
            self.target = ""
        else:
            self.action = act_lower

        if self.target:
            self.target = self.target.strip()
            # Explicitly reject CIDRs and malformed syntax
            if "/" in self.target or not TARGET_PATTERN.fullmatch(self.target):
                self.target = ""
                self.action = "hold"
                self.reasoning_summary = f"Target validation failed; held safely. (Original: {self.reasoning_summary})"

        prio_upper = (self.priority or "LOW").upper().strip()
        if prio_upper not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            self.priority = "MEDIUM"
        else:
            self.priority = prio_upper

        try:
            val = float(self.confidence)
            if math.isnan(val) or math.isinf(val):
                self.confidence = 0.0
            else:
                self.confidence = max(0.0, min(1.0, val))
        except (ValueError, TypeError):
            self.confidence = 0.0

        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "priority": self.priority,
            "confidence": round(self.confidence, 3),
            "observation": self.observation,
            "reasoning_summary": self.reasoning_summary,
            "provider": self.provider,
            "model": self.model,
            "latency_ms": round(self.latency_ms, 2),
            "request_id": self.request_id,
            "fallback_level": self.fallback_level,
            "parse_status": self.parse_status,
            "http_status": self.http_status,
        }


@dataclass
class ProviderMetrics:
    """Metrics tracking for a single LLM provider."""
    provider_name: str
    model_id: str
    requests: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    parse_failures: int = 0
    latencies: List[float] = field(default_factory=list)

    def record(self, latency_ms: float, success: bool, timeout: bool = False, parse_failure: bool = False) -> None:
        self.requests += 1
        if success:
            self.successes += 1
        else:
            self.failures += 1
        if timeout:
            self.timeouts += 1
        if parse_failure:
            self.parse_failures += 1

        try:
            val = float(latency_ms)
            if val >= 0:
                self.latencies.append(val)
                if len(self.latencies) > 100:
                    self.latencies.pop(0)
        except (ValueError, TypeError):
            pass

    @property
    def avg_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        return sum(self.latencies) / len(self.latencies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "model": self.model_id,
            "requests": self.requests,
            "successes": self.successes,
            "failures": self.failures,
            "timeouts": self.timeouts,
            "parse_failures": self.parse_failures,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }
