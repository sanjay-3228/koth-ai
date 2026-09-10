"""NVIDIA Nemotron Fast / Tactical Provider."""
from typing import Optional

from ..base import BaseLLMProvider


class NvidiaNemotronProvider(BaseLLMProvider):
    """NVIDIA Nemotron model layer for fast tactical telemetry analysis and routine decisions."""

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://integrate.api.nvidia.com/v1",
        model_id: str = "nvidia/nemotron-3.5-lightning-30b-a3b",
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        super().__init__(
            provider_name="nvidia",
            endpoint=endpoint,
            model_id=model_id,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
