"""Tiered Model Router implementing the 3-provider architecture:
  Local Policy -> NVIDIA Nemotron -> Groq GPT-OSS 120B -> OpenRouter GLM 5.3 Flash -> SAFE_HOLD
"""
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .parser import parse_model_response
from .providers.groq import GroqGptOssProvider
from .providers.nvidia import NvidiaNemotronProvider
from .providers.openrouter import OpenRouterGlmProvider
from .types import ModelDecision, ProviderMetrics
from ..config import Config, config as global_config
from ..logger import get_logger

logger = get_logger(__name__)

# Patterns used to strip sensitive information before sending prompts to models
SENSITIVE_PATTERNS = [
    re.compile(r"nvapi-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"gsk_[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"sk-or-v1-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"AIzaSy[A-Za-z0-9_-]{33}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"(?:password|passwd|secret|token|api_key)\s*[:=]\s*['\"][^\s'\"]+['\"]", re.IGNORECASE),
]


def sanitize_prompt_text(text: str) -> str:
    """Scrub potential credentials or secrets from text before sending to LLM providers."""
    if not text:
        return ""
    sanitized = text
    for pattern in SENSITIVE_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


class TieredModelRouter:
    """Hierarchical Model Router enforcing the strict escalation chain:
    Local Policy -> NVIDIA Nemotron -> Groq GPT-OSS 120B -> OpenRouter GLM 5.3 Flash -> SAFE_HOLD.
    """

    def __init__(self, cfg: Optional[Config] = None):
        self.config = cfg or global_config
        self.fast_provider = NvidiaNemotronProvider(
            api_key=self.config.nvidia_api_key or "",
            endpoint=self.config.nvidia_base_url or "https://integrate.api.nvidia.com/v1",
            model_id=self.config.nvidia_fast_model or "nvidia/nemotron-3.5-lightning-30b-a3b",
            timeout_seconds=self.config.llm_timeout_seconds,
            max_retries=self.config.llm_max_retries,
        )
        self.reasoning_provider = GroqGptOssProvider(
            api_key=self.config.groq_api_key or "",
            endpoint=self.config.groq_base_url or "https://api.groq.com/openai/v1",
            model_id=self.config.groq_reasoning_model or "openai/gpt-oss-120b",
            timeout_seconds=self.config.llm_timeout_seconds,
            max_retries=self.config.llm_max_retries,
        )
        self.specialist_provider = OpenRouterGlmProvider(
            api_key=self.config.openrouter_api_key or "",
            endpoint=self.config.openrouter_base_url or "https://openrouter.ai/api/v1",
            model_id=self.config.openrouter_specialist_model or "z-ai/glm-5.3-flash",
            timeout_seconds=self.config.llm_timeout_seconds,
            max_retries=self.config.llm_max_retries,
        )

        self.fast_threshold = self.config.fast_confidence_threshold
        self.reasoning_threshold = self.config.reasoning_confidence_threshold

        # Operational metrics
        self.total_decisions = 0
        self.local_policy_count = 0
        self.fast_count = 0
        self.reasoning_count = 0
        self.specialist_count = 0
        self.safe_hold_count = 0
        self.escalation_count = 0
        self.disagreement_count = 0
        self.db = None

    def _evaluate_local_policy(
        self,
        telemetry: Any,
        monitor_snapshot: Optional[Dict[str, Any]] = None,
    ) -> Optional[ModelDecision]:
        """Evaluate deterministic local policy before consulting external models."""
        # 1. Check file integrity tampering
        if monitor_snapshot and monitor_snapshot.get("tampered_files"):
            tampered = monitor_snapshot["tampered_files"]
            services = monitor_snapshot.get("services", [])
            target_str = ""
            if services:
                target_str = f"{services[0]['host']}:{services[0]['port']}"
            elif "host" in monitor_snapshot and "port" in monitor_snapshot:
                target_str = f"{monitor_snapshot['host']}:{monitor_snapshot['port']}"
            elif self.config.own_services:
                first = self.config.own_services[0].split(":")
                target_str = f"{first[0]}:{first[1]}" if len(first) >= 2 else self.config.own_services[0]

            logger.info("[router] Local policy: File tampering detected (%d file(s)); defensive rate-limiting.", len(tampered))
            return ModelDecision(
                action="rate_limit_port",
                target=target_str,
                priority="CRITICAL",
                confidence=1.0,
                observation=f"File tampering detected on {len(tampered)} files",
                reasoning_summary=f"Local policy: File tampering detected ({len(tampered)} file(s)); defensive rate-limiting.",
                provider="local",
                model="local-policy",
                fallback_level=0,
                parse_status="SUCCESS",
            )

        # 2. Check for single downed service in monitor_snapshot
        if monitor_snapshot:
            down = monitor_snapshot.get("down_services", [])
            if len(down) == 1:
                d = down[0]
                target_str = f"{d['host']}:{d['port']}"
                logger.info("[router] Local policy: Deterministic service restart for downed port %s.", d['port'])
                return ModelDecision(
                    action="restart_service",
                    target=target_str,
                    priority="HIGH",
                    confidence=1.0,
                    observation=f"Service {target_str} observed DOWN in snapshot",
                    reasoning_summary=f"Local policy: Deterministic service restart for downed port {d['port']}.",
                    provider="local",
                    model="local-policy",
                    fallback_level=0,
                    parse_status="SUCCESS",
                )

        # 3. Check telemetry if provided
        if telemetry is not None:
            raw = getattr(telemetry, "raw", {})
            if isinstance(raw, dict):
                if raw.get("stale") or raw.get("error") == "Scoreboard data is stale":
                    return ModelDecision(
                        action="hold",
                        target="",
                        priority="low",
                        confidence=1.0,
                        observation="Scoreboard telemetry stale",
                        reasoning_summary=f"Scoreboard telemetry is stale (>={self.config.stale_telemetry_threshold}s old); maintaining safe baseline hold.",
                        provider="local",
                        model="local-policy",
                        fallback_level=0,
                        parse_status="SUCCESS",
                    )
                if raw.get("error"):
                    return ModelDecision(
                        action="hold",
                        target="",
                        priority="low",
                        confidence=1.0,
                        observation=f"Scoreboard error: {raw.get('error')}",
                        reasoning_summary=f"Scoreboard unreachable ({raw.get('error')}); maintaining baseline defense.",
                        provider="local",
                        model="local-policy",
                        fallback_level=0,
                        parse_status="SUCCESS",
                    )

            # Check single downed own service in telemetry
            our_services = getattr(telemetry, "our_services", [])
            down_services = [s for s in our_services if not getattr(s, "up", True)]
            if len(down_services) == 1:
                svc = down_services[0]
                host = getattr(svc, "host", "")
                port = getattr(svc, "port", 0)
                target_str = f"{host}:{port}" if port else host
                logger.info("[router] Local policy: Deterministic service restart for downed port %s.", port)
                return ModelDecision(
                    action="restart_service",
                    target=target_str,
                    priority="HIGH",
                    confidence=1.0,
                    observation=f"Service {target_str} observed DOWN",
                    reasoning_summary=f"Local policy: Deterministic service restart for downed port {port}.",
                    provider="local",
                    model="local-policy",
                    fallback_level=0,
                    parse_status="SUCCESS",
                )

        return None

    def _build_sanitized_context(
        self,
        telemetry: Any,
        telemetry_summary: str,
        recent_actions: List[str],
        swarm_context: Optional[Dict[str, Any]] = None,
        disagreement_note: str = "",
    ) -> Dict[str, Any]:
        """Construct sanitized prompt dictionary with zero credential leaks."""
        swarm_ctx = swarm_context or {}
        return {
            "phase": swarm_ctx.get("phase", "HOLD"),
            "agent_id": swarm_ctx.get("agent_id", self.config.agent_id),
            "team_id": swarm_ctx.get("team_id", self.config.team_id),
            "round_id": swarm_ctx.get("round_id", 1),
            "phase_epoch": swarm_ctx.get("phase_epoch", 1),
            "authorized_targets": self.config.target_hosts,
            "own_services": self.config.own_services,
            "protected_hosts": self.config.protected_hosts,
            "allowed_actions": self.config.allowed_actions,
            "telemetry_summary": sanitize_prompt_text(telemetry_summary),
            "recent_actions": [sanitize_prompt_text(a) for a in recent_actions],
            "disagreement_note": sanitize_prompt_text(disagreement_note),
        }

    def execute_decision(
        self,
        telemetry: Any,
        telemetry_summary: str,
        recent_actions: List[str],
        brain: Any = None,
        monitor_snapshot: Optional[Dict[str, Any]] = None,
        swarm_context: Optional[Dict[str, Any]] = None,
    ) -> ModelDecision:
        """Route decision following the exact hierarchy:
        Local Policy -> Nemotron -> GPT-OSS 120B -> GLM 5.3 Flash -> SAFE_HOLD
        """
        self.total_decisions += 1

        # 1. Local Deterministic Policy check
        local_decision = self._evaluate_local_policy(telemetry, monitor_snapshot)
        if local_decision is not None:
            self.local_policy_count += 1
            logger.info("[router] Executed local-policy: %s", local_decision.reasoning_summary)
            self._log_decision_to_db(local_decision)
            return local_decision.sanitize()

        # Build clean sanitized context for LLM providers
        context = self._build_sanitized_context(
            telemetry=telemetry,
            telemetry_summary=telemetry_summary,
            recent_actions=recent_actions,
            swarm_context=swarm_context,
        )

        # Check for brain override (used by existing mock tests)
        if brain is not None and hasattr(brain, "decide"):
            mock_res = self._handle_legacy_brain(brain, telemetry_summary, recent_actions)
            if mock_res is not None:
                self._log_decision_to_db(mock_res)
                return mock_res.sanitize()

        # 2. Tier 1: Fast / Tactical - NVIDIA Nemotron
        fast_decision = self.fast_provider.generate_decision(context, fallback_level=1)
        fast_usable = (
            fast_decision.parse_status == "SUCCESS"
            and fast_decision.confidence >= self.fast_threshold
            and not fast_decision.needs_escalation
        )

        if fast_usable:
            self.fast_count += 1
            logger.info(
                "[router] [%s] %s target=%s priority=%s confidence=%.2f (%.0fms)",
                fast_decision.model,
                fast_decision.action,
                fast_decision.target,
                fast_decision.priority,
                fast_decision.confidence,
                fast_decision.latency_ms,
            )
            self._log_decision_to_db(fast_decision)
            return fast_decision.sanitize()

        # 3. Tier 2: Reasoning / Escalation - Groq GPT-OSS 120B
        self.escalation_count += 1
        logger.info(
            "[router] Escalating from Nemotron (conf=%.2f, parse=%s) to Groq GPT-OSS 120B",
            fast_decision.confidence,
            fast_decision.parse_status,
        )

        reasoning_decision = self.reasoning_provider.generate_decision(context, fallback_level=2)
        reasoning_usable = (
            reasoning_decision.parse_status == "SUCCESS"
            and reasoning_decision.confidence >= self.reasoning_threshold
        )

        # Check for tactical agreement between Nemotron and GPT-OSS
        is_disagreement = False
        if (
            fast_decision.parse_status == "SUCCESS"
            and reasoning_decision.parse_status == "SUCCESS"
            and fast_decision.action != reasoning_decision.action
        ):
            self.disagreement_count += 1
            is_disagreement = True
            logger.warning(
                "[router] Model disagreement detected: Nemotron=%s (%.2f) vs GPT-OSS=%s (%.2f)",
                fast_decision.action,
                fast_decision.confidence,
                reasoning_decision.action,
                reasoning_decision.confidence,
            )

        if reasoning_usable and not is_disagreement:
            self.reasoning_count += 1
            logger.info(
                "[router] [%s] %s target=%s priority=%s confidence=%.2f (%.0fms)",
                reasoning_decision.model,
                reasoning_decision.action,
                reasoning_decision.target,
                reasoning_decision.priority,
                reasoning_decision.confidence,
                reasoning_decision.latency_ms,
            )
            self._log_decision_to_db(reasoning_decision)
            return reasoning_decision.sanitize()

        # 4. Tier 3: Specialist / Final Escalation - OpenRouter GLM 5.3 Flash
        self.escalation_count += 1
        disagree_note = ""
        if is_disagreement:
            disagree_note = (
                f"Prior Tactical Model recommended: '{fast_decision.action}' (confidence: {fast_decision.confidence:.2f}). "
                f"Reasoning Model recommended: '{reasoning_decision.action}' (confidence: {reasoning_decision.confidence:.2f}). "
                f"Provide definitive tactical resolution strictly within authorized scope."
            )

        logger.info(
            "[router] Escalating to OpenRouter GLM 5.3 Flash (reasoning_conf=%.2f, disagreement=%s)",
            reasoning_decision.confidence,
            is_disagreement,
        )

        specialist_context = self._build_sanitized_context(
            telemetry=telemetry,
            telemetry_summary=telemetry_summary,
            recent_actions=recent_actions,
            swarm_context=swarm_context,
            disagreement_note=disagree_note,
        )

        specialist_decision = self.specialist_provider.generate_decision(specialist_context, fallback_level=3)

        if specialist_decision.parse_status == "SUCCESS" and specialist_decision.confidence >= 0.5:
            self.specialist_count += 1
            logger.info(
                "[router] [%s] %s target=%s priority=%s confidence=%.2f (%.0fms)",
                specialist_decision.model,
                specialist_decision.action,
                specialist_decision.target,
                specialist_decision.priority,
                specialist_decision.confidence,
                specialist_decision.latency_ms,
            )
            self._log_decision_to_db(specialist_decision)
            return specialist_decision.sanitize()

        # 5. Final Fallback: SAFE_HOLD
        self.safe_hold_count += 1
        logger.warning("[router] All model providers failed or returned low confidence; entering SAFE_HOLD.")
        safe_hold = ModelDecision(
            action="hold",
            target="",
            priority="LOW",
            confidence=0.0,
            observation="All providers failed or low confidence; entered safe hold.",
            reasoning_summary="All model providers unavailable or failed to produce authorized decision; safe hold.",
            provider="safe-fallback",
            model="safe-fallback",
            fallback_level=4,
            parse_status="FAILED",
        )
        self._log_decision_to_db(safe_hold)
        return safe_hold.sanitize()

    def _handle_legacy_brain(
        self,
        brain: Any,
        telemetry_summary: str,
        recent_actions: List[str],
    ) -> Optional[ModelDecision]:
        """Support test mock engines implementing the legacy .decide() interface."""
        try:
            # Check if brain has fast/reasoning model routing
            fast_m = getattr(self.config, "nvidia_fast_model", "nvidia/nemotron-3.5-lightning-30b-a3b")
            res = brain.decide(telemetry_summary, recent_actions, model=fast_m)
            if getattr(res, "confidence", 1.0) < self.fast_threshold or getattr(res, "needs_escalation", False):
                reason_m = getattr(self.config, "groq_reasoning_model", getattr(self.config, "nvidia_reasoning_model", "openai/gpt-oss-120b"))
                try:
                    res2 = brain.decide(telemetry_summary, recent_actions, model=reason_m)
                    if res2:
                        res = res2
                except Exception:
                    pass

            if res is not None:
                # Convert to ModelDecision
                return ModelDecision(
                    action=getattr(res, "action_type", "hold"),
                    target=getattr(res, "target", ""),
                    priority=getattr(res, "priority", "MEDIUM"),
                    confidence=getattr(res, "confidence", 1.0),
                    observation=getattr(res, "reasoning", ""),
                    reasoning_summary=getattr(res, "reasoning", ""),
                    provider="mock_brain",
                    model=getattr(res, "model_used", "mock"),
                    latency_ms=getattr(res, "latency_ms", 1.0),
                    fallback_level=1,
                    parse_status="SUCCESS",
                )
        except Exception as e:
            logger.warning("[router] Legacy brain error: %s", e)
        return None

    def _log_decision_to_db(self, decision: ModelDecision) -> None:
        """Persist decision metadata to DB if configured."""
        if self.db and hasattr(self.db, "record_model_call"):
            try:
                self.db.record_model_call(
                    model=decision.model,
                    reason=decision.reasoning_summary,
                    confidence=decision.confidence,
                    latency_ms=decision.latency_ms,
                    success=(decision.parse_status == "SUCCESS"),
                    fallback=(decision.fallback_level > 1),
                    escalation=(decision.fallback_level > 1),
                    provider=decision.provider,
                    fallback_level=decision.fallback_level,
                    parse_status=decision.parse_status,
                    request_id=decision.request_id,
                )
            except Exception:
                pass

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Aggregate metrics across providers for health probes and dashboards."""
        return {
            "total_decisions": self.total_decisions,
            "local_policy_decisions": self.local_policy_count,
            "fast_decisions": self.fast_count,
            "reasoning_decisions": self.reasoning_count,
            "specialist_decisions": self.specialist_count,
            "safe_hold_decisions": self.safe_hold_count,
            "escalations": self.escalation_count,
            "disagreements": self.disagreement_count,
            "providers": {
                "nvidia": self.fast_provider.metrics.to_dict(),
                "groq": self.reasoning_provider.metrics.to_dict(),
                "openrouter": self.specialist_provider.metrics.to_dict(),
            },
        }
