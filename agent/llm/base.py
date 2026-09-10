"""Base Provider abstraction with circuit breaker, metrics, and OpenAI-compatible client."""
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests

from .parser import parse_model_response
from .types import ModelDecision, ProviderMetrics
from ..logger import get_logger

logger = get_logger(__name__)

SYSTEM_INSTRUCTION = """You are an advisory tactical intelligence component inside an authorized KOTH competition agent. You do not have execution authority. You must reason only over supplied telemetry and explicitly authorized competition scope. Return only a structured decision. Never invent credentials, targets, services, or authorization.

Respond ONLY with a valid JSON object matching exactly this schema:
{
  "action": "recon" | "exploit_plugin" | "restart_service" | "rate_limit_port" | "block_source" | "hold",
  "target": "authorized-target-or-empty",
  "priority": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": <float between 0.0 and 1.0>,
  "observation": "<short factual observation>",
  "reasoning_summary": "<short explanation>"
}

Strict Rules:
1. "action" must be one of: "recon", "exploit_plugin", "restart_service", "rate_limit_port", "block_source", "hold".
2. "target" must be an authorized host or host:port, or empty string. Never include subnets or CIDRs.
3. If phase is DEFENSE, prioritize defensive operations ("restart_service", "rate_limit_port", "block_source") for our own services.
4. If phase is ATTACK, consider "recon" or authorized "exploit_plugin" on authorized target hosts.
5. If phase is HOLD, return action "hold".
6. Do NOT output arbitrary shell commands or code payloads.
"""


class BaseLLMProvider:
    """Base class for OpenAI-compatible LLM providers."""

    def __init__(
        self,
        provider_name: str,
        endpoint: str,
        model_id: str,
        api_key: str,
        timeout_seconds: float = 30.0,
        max_retries: int = 1,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        self.provider_name = provider_name
        self.endpoint = endpoint.rstrip("/")
        self.model_id = model_id
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds

        self.failure_count = 0
        self.last_failure_time = 0.0
        self.metrics = ProviderMetrics(provider_name=provider_name, model_id=model_id)

    def is_configured(self) -> bool:
        """Check if an API key is present."""
        return bool(self.api_key and self.api_key.strip())

    def is_healthy(self) -> bool:
        """Check circuit breaker state."""
        if not self.is_configured():
            return False
        if self.failure_count >= self.failure_threshold:
            elapsed = time.time() - self.last_failure_time
            if elapsed < self.cooldown_seconds:
                return False
            # Cooldown passed; allow single trial probe
        return True

    def record_success(self) -> None:
        self.failure_count = 0

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()

    def get_extra_headers(self) -> Dict[str, str]:
        """Subclasses can override to add provider-specific headers (e.g. OpenRouter)."""
        return {}

    def _post_chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 512,
    ) -> Tuple[Optional[str], float, int, str]:
        """Post a chat completion request to the OpenAI-compatible endpoint.

        Returns (content_str, latency_ms, http_status, request_id).
        Never logs or leaks API keys.
        """
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        url = f"{self.endpoint}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        headers.update(self.get_extra_headers())

        payload = {
            "model": self.model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        retries = 0
        start_time = time.time()

        while retries <= self.max_retries:
            try:
                resp = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                latency_ms = (time.time() - start_time) * 1000.0

                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    content = ""
                    if choices:
                        msg = choices[0].get("message", {})
                        content = msg.get("content") or ""
                        if not content and msg.get("reasoning"):
                            content = msg.get("reasoning") or ""
                    self.record_success()
                    self.metrics.record(latency_ms=latency_ms, success=True)
                    return content, latency_ms, 200, request_id

                # Handle HTTP errors (rate limit 429, auth 401, 5xx server errors)
                logger.warning(
                    "[%s] API request failed with status %d (request_id=%s)",
                    self.provider_name,
                    resp.status_code,
                    request_id,
                )
                self.record_failure()
                self.metrics.record(
                    latency_ms=latency_ms,
                    success=False,
                    timeout=False,
                )
                return None, latency_ms, resp.status_code, request_id

            except requests.exceptions.Timeout:
                latency_ms = (time.time() - start_time) * 1000.0
                logger.warning(
                    "[%s] Timeout after %.1fs (request_id=%s, retry=%d/%d)",
                    self.provider_name,
                    self.timeout_seconds,
                    request_id,
                    retries,
                    self.max_retries,
                )
                retries += 1
                if retries > self.max_retries:
                    self.record_failure()
                    self.metrics.record(latency_ms=latency_ms, success=False, timeout=True)
                    return None, latency_ms, 408, request_id

            except Exception as e:
                latency_ms = (time.time() - start_time) * 1000.0
                # Do NOT print headers or key in logs
                logger.warning(
                    "[%s] Network/Connection error: %s (request_id=%s)",
                    self.provider_name,
                    type(e).__name__,
                    request_id,
                )
                retries += 1
                if retries > self.max_retries:
                    self.record_failure()
                    self.metrics.record(latency_ms=latency_ms, success=False)
                    return None, latency_ms, 503, request_id

        latency_ms = (time.time() - start_time) * 1000.0
        return None, latency_ms, 500, request_id

    def build_user_prompt(self, context: Dict[str, Any]) -> str:
        """Format sanitized context into a structured prompt."""
        phase = context.get("phase", "HOLD")
        agent_id = context.get("agent_id", "agent-01")
        team_id = context.get("team_id", "null_warriors")
        round_id = context.get("round_id", 1)
        epoch = context.get("phase_epoch", 1)
        allowed_actions = context.get("allowed_actions", [])
        authorized_targets = context.get("authorized_targets", [])
        own_services = context.get("own_services", [])
        protected_hosts = context.get("protected_hosts", [])
        telemetry_summary = context.get("telemetry_summary", "No telemetry available")
        recent_actions = context.get("recent_actions", [])
        disagreement_note = context.get("disagreement_note", "")

        prompt_lines = [
            f"=== OPERATIONAL CONTEXT ===",
            f"Authoritative Phase: {phase} (Round {round_id}, Epoch {epoch})",
            f"Agent Identity: {agent_id} (Team: {team_id})",
            f"Authorized Target Hosts: {authorized_targets}",
            f"Our Defended Services: {own_services}",
            f"Protected Hosts (DO NOT ATTACK): {protected_hosts}",
            f"Allowed Action Set: {allowed_actions}",
            "",
            f"=== TELEMETRY SUMMARY ===",
            telemetry_summary,
            "",
            f"=== RECENT ACTION LOG ===",
            "\n".join(recent_actions[-5:]) if recent_actions else "None",
        ]

        if disagreement_note:
            prompt_lines.append("")
            prompt_lines.append(f"=== ESCALATION CONTEXT ===")
            prompt_lines.append(disagreement_note)

        return "\n".join(prompt_lines)

    def generate_decision(
        self,
        context: Dict[str, Any],
        fallback_level: int = 1,
    ) -> ModelDecision:
        """Execute decision generation for this provider."""
        if not self.is_configured():
            return ModelDecision(
                action="hold",
                target="",
                priority="LOW",
                confidence=0.0,
                observation=f"{self.provider_name} is not configured (missing API key)",
                reasoning_summary=f"Missing {self.provider_name} API key",
                provider=self.provider_name,
                model=self.model_id,
                fallback_level=fallback_level,
                parse_status="SKIPPED",
                http_status=401,
            )

        if not self.is_healthy():
            return ModelDecision(
                action="hold",
                target="",
                priority="LOW",
                confidence=0.0,
                observation=f"{self.provider_name} circuit breaker open (cooling down)",
                reasoning_summary=f"{self.provider_name} is unhealthy; bypassed",
                provider=self.provider_name,
                model=self.model_id,
                fallback_level=fallback_level,
                parse_status="SKIPPED",
                http_status=503,
            )

        user_content = self.build_user_prompt(context)
        messages = [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_content},
        ]

        raw_content, latency_ms, http_status, req_id = self._post_chat_completion(messages)

        if raw_content is None:
            return ModelDecision(
                action="hold",
                target="",
                priority="LOW",
                confidence=0.0,
                observation=f"{self.provider_name} request failed (HTTP {http_status})",
                reasoning_summary=f"{self.provider_name} failed to return a response",
                provider=self.provider_name,
                model=self.model_id,
                latency_ms=latency_ms,
                request_id=req_id,
                fallback_level=fallback_level,
                parse_status="FAILED",
                http_status=http_status,
            )

        decision = parse_model_response(
            raw_text=raw_content,
            provider=self.provider_name,
            model=self.model_id,
            latency_ms=latency_ms,
            request_id=req_id,
            fallback_level=fallback_level,
            http_status=http_status,
        )

        if decision.parse_status == "FAILED":
            self.metrics.record(latency_ms=latency_ms, success=True, parse_failure=True)

        return decision
