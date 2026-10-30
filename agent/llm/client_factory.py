"""Provider client factory for per-agent LLM instances supporting OpenAI, Anthropic,
Google Gemini, custom compatible endpoints, and local simulated adapters.
"""
import json
import time
from typing import Any, Dict, Optional, Tuple

import requests

from .agent_config import AgentLLMConfig, redact_secrets
from .parser import parse_model_response
from .types import ModelDecision
from ..logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are an advisory tactical assistant for a King-of-the-Hill defense and reconnaissance agent. You possess ZERO execution authority. Analyze the supplied telemetry and suggest an advisory action.

Respond ONLY with a valid JSON object matching this schema:
{
  "action": "recon" | "exploit_plugin" | "restart_service" | "rate_limit_port" | "block_source" | "hold",
  "target": "target-host-or-empty",
  "priority": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": <float 0.0 to 1.0>,
  "reasoning_summary": "<short reason>"
}
"""


class AgentLLMClient:
    """Dispatches advisory queries and safe connection tests based on an AgentLLMConfig."""

    def __init__(self, config: AgentLLMConfig, timeout_seconds: float = 10.0):
        self.config = config
        self.timeout_seconds = timeout_seconds

    def test_connection(self) -> Tuple[bool, str, float]:
        """Perform a benign connection probe without transmitting secrets, tokens, or flags.
        
        Returns (success, message, latency_ms).
        """
        if not self.config.enabled:
            return False, "Provider is disabled for this agent.", 0.0

        provider = self.config.provider.lower()
        if provider == "none":
            return False, "Provider is unconfigured (set to none).", 0.0

        if provider == "local_simulated":
            return True, "Local simulated provider connected successfully.", 0.5

        if not self.config.api_key and provider not in ("custom", "local_simulated"):
            return False, f"API key is required for provider '{provider}'.", 0.0

        start_time = time.time()
        try:
            if provider in ("openai", "custom"):
                return self._test_openai()
            elif provider == "anthropic":
                return self._test_anthropic()
            elif provider == "gemini":
                return self._test_gemini()
            else:
                return False, f"Unsupported provider '{provider}'.", 0.0
        except requests.Timeout:
            latency = (time.time() - start_time) * 1000.0
            return False, f"Connection timed out after {self.timeout_seconds:.1f}s.", latency
        except requests.ConnectionError as exc:
            latency = (time.time() - start_time) * 1000.0
            clean_err = redact_secrets(str(exc), [self.config.api_key])
            return False, f"Connection failed: {clean_err}", latency
        except Exception as exc:
            latency = (time.time() - start_time) * 1000.0
            clean_err = redact_secrets(str(exc), [self.config.api_key])
            return False, f"Error during connection test: {clean_err}", latency

    def _test_openai(self) -> Tuple[bool, str, float]:
        endpoint = self.config.endpoint.rstrip("/")
        if not endpoint.endswith("/chat/completions"):
            url = f"{endpoint}/chat/completions"
        else:
            url = endpoint

        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        payload = {
            "model": self.config.model_id or "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Respond with 'pong' only."}],
            "max_tokens": 8,
            "temperature": 0.0,
        }

        start = time.time()
        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        latency = (time.time() - start) * 1000.0

        if resp.status_code == 200:
            return True, f"Connected to OpenAI/Compatible endpoint ({resp.status_code} OK).", latency
        elif resp.status_code in (401, 403):
            return False, f"Authentication failed ({resp.status_code}): Invalid or unauthorized API key.", latency
        elif resp.status_code == 404:
            return False, f"Endpoint or model not found ({resp.status_code} 404). Check URL and model ID.", latency
        else:
            clean_text = redact_secrets(resp.text[:200], [self.config.api_key])
            return False, f"HTTP {resp.status_code}: {clean_text}", latency

    def _test_anthropic(self) -> Tuple[bool, str, float]:
        endpoint = self.config.endpoint.rstrip("/")
        if not endpoint.endswith("/messages"):
            url = f"{endpoint}/messages"
        else:
            url = endpoint

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.config.model_id or "claude-3-5-sonnet-20241022",
            "messages": [{"role": "user", "content": "Respond with 'pong' only."}],
            "max_tokens": 8,
        }

        start = time.time()
        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        latency = (time.time() - start) * 1000.0

        if resp.status_code == 200:
            return True, f"Connected to Anthropic API ({resp.status_code} OK).", latency
        elif resp.status_code in (401, 403):
            return False, f"Authentication failed ({resp.status_code}): Invalid Anthropic API key.", latency
        else:
            clean_text = redact_secrets(resp.text[:200], [self.config.api_key])
            return False, f"Anthropic HTTP {resp.status_code}: {clean_text}", latency

    def _test_gemini(self) -> Tuple[bool, str, float]:
        endpoint = self.config.endpoint.rstrip("/")
        model = self.config.model_id or "gemini-1.5-flash"
        url = f"{endpoint}/models/{model}:generateContent"

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.config.api_key,
        }
        payload = {
            "contents": [{"parts": [{"text": "Respond with 'pong' only."}]}],
            "generationConfig": {"maxOutputTokens": 8, "temperature": 0.0},
        }

        start = time.time()
        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        latency = (time.time() - start) * 1000.0

        if resp.status_code == 200:
            return True, f"Connected to Google Gemini API ({resp.status_code} OK).", latency
        elif resp.status_code in (400, 401, 403):
            clean_text = redact_secrets(resp.text[:200], [self.config.api_key])
            return False, f"Gemini API authentication/request failed ({resp.status_code}): {clean_text}", latency
        else:
            clean_text = redact_secrets(resp.text[:200], [self.config.api_key])
            return False, f"Gemini HTTP {resp.status_code}: {clean_text}", latency

    def query_advisory(self, telemetry_summary: str) -> Optional[ModelDecision]:
        """Query the configured LLM for an advisory decision.
        
        Strictly returns advisory recommendations.
        Falls back to None if unconfigured, disabled, or if query fails.
        """
        if not self.config.enabled or self.config.provider in ("none", ""):
            return None

        provider = self.config.provider.lower()
        scrubbed_telemetry = redact_secrets(telemetry_summary, [self.config.api_key])

        if provider == "local_simulated":
            # Fast rule-based simulated decision
            from .providers.local_simulated import SimulatedAdvisoryProvider
            sim = SimulatedAdvisoryProvider()
            raw_text, latency, _, _ = sim._post_chat_completion([])
            decision = parse_model_response(raw_text or "", model_id=self.config.model_id or "simulated")
            return decision

        try:
            if provider in ("openai", "custom"):
                return self._query_openai(scrubbed_telemetry)
            elif provider == "anthropic":
                return self._query_anthropic(scrubbed_telemetry)
            elif provider == "gemini":
                return self._query_gemini(scrubbed_telemetry)
        except Exception as exc:
            clean_err = redact_secrets(str(exc), [self.config.api_key])
            logger.warning(f"[{self.config.agent_id}] Advisory LLM query error: {clean_err}")
            return None

        return None

    def _query_openai(self, text: str) -> Optional[ModelDecision]:
        endpoint = self.config.endpoint.rstrip("/")
        url = endpoint if endpoint.endswith("/chat/completions") else f"{endpoint}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        payload = {
            "model": self.config.model_id or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            "max_tokens": 256,
            "temperature": 0.2,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return parse_model_response(content, model_id=self.config.model_id)
        return None

    def _query_anthropic(self, text: str) -> Optional[ModelDecision]:
        endpoint = self.config.endpoint.rstrip("/")
        url = endpoint if endpoint.endswith("/messages") else f"{endpoint}/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.config.model_id or "claude-3-5-sonnet-20241022",
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": text}],
            "max_tokens": 256,
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("content", [{}])[0].get("text", "")
            return parse_model_response(content, model_id=self.config.model_id)
        return None

    def _query_gemini(self, text: str) -> Optional[ModelDecision]:
        endpoint = self.config.endpoint.rstrip("/")
        model = self.config.model_id or "gemini-1.5-flash"
        url = f"{endpoint}/models/{model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.config.api_key,
        }
        payload = {
            "contents": [
                {"parts": [{"text": f"{SYSTEM_PROMPT}\n\nTelemetry:\n{text}"}]}
            ],
            "generationConfig": {"maxOutputTokens": 256, "temperature": 0.2},
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        if resp.status_code == 200:
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    content = parts[0].get("text", "")
                    return parse_model_response(content, model_id=self.config.model_id)
        return None

