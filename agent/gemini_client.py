"""Backwards-compatible wrapper module forwarding to agent.nvidia_client.

Preserves structured Decision object, schema validation, and decision engine interface.
"""

from .nvidia_client import (
    ADVISORY_DECISION_VALUES,
    DECISION_SCHEMA_PROMPT,
    FORBIDDEN_PROPOSAL_TERMS,
    RECON_DECISION_SCHEMA_PROMPT,
    TARGET_PATTERN,
    Decision,
    GeminiAPIError,
    GeminiQuotaError,
    NvidiaAPIError,
    NvidiaDecisionEngine,
    NvidiaQuotaError,
    NvidiaRateLimitError,
    extract_json_from_text,
    requests,
)

# Backwards compatible alias
class GeminiDecisionEngine(NvidiaDecisionEngine):
    """Backwards-compatible decision engine delegating to NvidiaDecisionEngine."""

    def _post_gemini(self, model: str, prompt: str, timeout: tuple = (10, 30)):
        """Compatibility helper for legacy test patches."""
        messages = [{"role": "user", "content": prompt}]
        resp, _ = self._post_nvidia(model, messages, timeout=timeout)
        return resp


__all__ = [
    "Decision",
    "GeminiDecisionEngine",
    "NvidiaDecisionEngine",
    "GeminiQuotaError",
    "GeminiAPIError",
    "NvidiaQuotaError",
    "NvidiaAPIError",
    "NvidiaRateLimitError",
    "ADVISORY_DECISION_VALUES",
    "FORBIDDEN_PROPOSAL_TERMS",
    "DECISION_SCHEMA_PROMPT",
    "RECON_DECISION_SCHEMA_PROMPT",
    "TARGET_PATTERN",
    "extract_json_from_text",
    "requests",
]