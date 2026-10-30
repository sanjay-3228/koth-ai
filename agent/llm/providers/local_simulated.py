"""
Local & Simulated Advisory LLM Provider for KOTH Swarm.

Provides a clean extension adapter for local / LAN LLMs (e.g. Ollama, vLLM, LM-Studio)
or pure simulated advisory recommendations during offline rehearsals.
Strictly advisory: no execution authority, no shell execution, no target choice authority.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from ..base import BaseLLMProvider
from ..types import ModelDecision, ProviderMetrics

logger = logging.getLogger("koth.llm.local")


class LocalAdvisoryProvider(BaseLLMProvider):
    """
    OpenAI-compatible adapter for local or private LAN LLM inference servers
    (Ollama, vLLM, LocalAI, LM Studio) without requiring external cloud API keys.
    """

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:11434/v1",
        model_id: str = "mistral",
        api_key: str = "local-key",
        timeout_seconds: float = 15.0,
        **kwargs,
    ):
        super().__init__(
            provider_name="local_advisory",
            endpoint=endpoint,
            model_id=model_id,
            api_key=api_key or "local-key",
            timeout_seconds=timeout_seconds,
            **kwargs,
        )


class SimulatedAdvisoryProvider:
    """
    Simulated Tactical Intelligence component for zero-credential offline rehearsals.
    Returns deterministic, safe tactical advice without network calls.
    """

    def __init__(self, provider_name: str = "simulated_advisory"):
        self.provider_name = provider_name
        self.metrics = ProviderMetrics(provider_name=provider_name, model_id="simulated-advisory")

    def decide(
        self,
        telemetry: Any,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ModelDecision:
        """Generate safe advisory recommendation based on current phase context."""
        ctx = context or {}
        phase = ctx.get("phase", "HOLD").upper()

        if phase == "ATTACK":
            target = ctx.get("target_host") or "10.254.254.11"
            return ModelDecision(
                action="recon",
                target=target,
                priority="HIGH",
                confidence=0.95,
                observation="Target service reachable; recon scan recommended",
                reasoning_summary="Authoritative ATTACK phase; probing service ports.",
                model=self.provider_name,
                latency_ms=1.5,
            )
        elif phase == "DEFENSE":
            target = ctx.get("target_host") or "10.254.254.101"
            return ModelDecision(
                action="restart_service",
                target=target,
                priority="HIGH",
                confidence=0.90,
                observation="Defended hill service requires integrity verification",
                reasoning_summary="Authoritative DEFENSE phase; auditing and hardening service.",
                model=self.provider_name,
                latency_ms=1.2,
            )
        else:
            return ModelDecision(
                action="hold",
                target="",
                priority="LOW",
                confidence=1.0,
                observation="Swarm in safe hold state",
                reasoning_summary="HOLD phase active; maintaining baseline state.",
                model=self.provider_name,
                latency_ms=0.5,
            )
