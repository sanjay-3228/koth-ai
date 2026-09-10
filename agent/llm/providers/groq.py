"""Groq GPT-OSS 120B Reasoning / Escalation Provider."""
from typing import Optional

from ..base import BaseLLMProvider


class GroqGptOssProvider(BaseLLMProvider):
    """Groq GPT-OSS 120B model layer for complex multi-step tactical reasoning and escalation."""

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://api.groq.com/openai/v1",
        model_id: str = "openai/gpt-oss-120b",
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        super().__init__(
            provider_name="groq",
            endpoint=endpoint,
            model_id=model_id,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
