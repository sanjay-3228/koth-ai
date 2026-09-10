"""Three-provider LLM decision layer (NVIDIA Nemotron, Groq GPT-OSS, OpenRouter GLM)."""
from .base import BaseLLMProvider
from .parser import parse_model_response
from .providers.groq import GroqGptOssProvider
from .providers.nvidia import NvidiaNemotronProvider
from .providers.openrouter import OpenRouterGlmProvider
from .router import TieredModelRouter
from .types import ModelDecision, ModelProviderType, ProviderMetrics

__all__ = [
    "BaseLLMProvider",
    "ModelDecision",
    "ModelProviderType",
    "ProviderMetrics",
    "NvidiaNemotronProvider",
    "GroqGptOssProvider",
    "OpenRouterGlmProvider",
    "TieredModelRouter",
    "parse_model_response",
]
