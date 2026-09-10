"""OpenRouter GLM 5.3 Flash Specialist / Final Escalation Provider."""
from typing import Dict, Optional

from ..base import BaseLLMProvider


class OpenRouterGlmProvider(BaseLLMProvider):
    """OpenRouter GLM 5.3 Flash layer for specialist analysis, complex conflict resolution, and final escalation."""

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://openrouter.ai/api/v1",
        model_id: str = "z-ai/glm-5.3-flash",
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        super().__init__(
            provider_name="openrouter",
            endpoint=endpoint,
            model_id=model_id,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )

    def get_extra_headers(self) -> Dict[str, str]:
        """Add OpenRouter routing metadata."""
        return {
            "HTTP-Referer": "https://github.com/pwn-koth-agent",
            "X-Title": "PwnGrounds KOTH Agent",
        }
