"""Wraps NVIDIA NIM OpenAI-compatible API and forces structured JSON decisions with confidence scoring.

Strictly ADVISORY ONLY. Never executes shell commands, exploits, or network actions directly.
"""

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

import requests

from .config import config
from .logger import get_logger

logger = get_logger(__name__)

# Strict validation pattern for host[:port]
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]+(?::\d{1,5})?$")

# Configured model IDs
DEFAULT_FAST_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"
DEFAULT_REASONING_MODEL = "nvidia/nemotron-3-super-120b-a12b"
ALLOWED_MODELS = {DEFAULT_FAST_MODEL, DEFAULT_REASONING_MODEL}

ADVISORY_DECISION_VALUES = {
    "HOLD",
    "INVESTIGATE_SERVICE",
    "PRIORITIZE_HTTP",
    "PRIORITIZE_FTP",
    "PRIORITIZE_SSH",
    "NO_ACTION",
}

ALLOWED_ADVISORY_PRIORITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

FORBIDDEN_PROPOSAL_TERMS = {
    "attack",
    "exploit",
    "payload",
    "shell",
    "command",
    "bash",
    "cmd",
    "exec",
    "inject",
}


class NvidiaRateLimitError(Exception):
    """NVIDIA NIM API quota/rate-limit exhaustion (HTTP 429)."""

    def __init__(self, message: str, retry_after: float = 60.0):
        super().__init__(message)
        self.retry_after = retry_after


# Backwards compatibility alias
NvidiaQuotaError = NvidiaRateLimitError
GeminiQuotaError = NvidiaRateLimitError


class NvidiaAPIError(Exception):
    """NVIDIA NIM API authentication/model/HTTP failure."""


# Backwards compatibility alias
GeminiAPIError = NvidiaAPIError


DECISION_SCHEMA_PROMPT = """You are the strategic decision engine for a KOTH
(King of the Hill) attack/defense competition agent. You will be given the
current telemetry (our score, service health, competitor scores) and a log
of recent actions already taken.

Decide the SINGLE highest-priority next action. Respond with ONLY a JSON
object, no markdown fences, no preamble, matching exactly this shape:

{
  "action_type": "defend" | "attack" | "recon" | "hold",
  "target": "<host:port or empty string>",
  "priority": "critical" | "high" | "medium" | "low",
  "reasoning": "<one or two sentences>",
  "confidence": <float between 0.0 and 1.0>,
  "needs_escalation": <true | false>
}

Guidance:
- "defend": one of our services is down, degraded, or shows signs of tampering.
- "attack": use only when a recon result already indicates a known, specific
opportunity worth pursuing on a target we're authorized to test. You do not
choose or generate the exploit itself — you only flag that attacking is the
priority and against whom.
- "recon": we don't have enough information about a target yet.
- "hold": nothing urgent; keep monitoring.
- "confidence": estimate your confidence in this decision (0.0 to 1.0).
- "needs_escalation": set to true if the situation has high strategic ambiguity,
conflicting high-priority events, or multi-step risk requiring deep reasoning.
"""

RECON_DECISION_SCHEMA_PROMPT = """You are a strategic telemetry analysis advisor for an authorized security assessment agent.

You are STRICTLY ADVISORY ONLY.

You NEVER approve, initiate, or execute tests, exploits, shell commands, or payloads.

You must NEVER return "attack", "exploit", shell commands, payloads, or executable instructions.

Your role is solely to analyze already-collected structured telemetry and classify observations.

Allowed decision values (select exactly one):
- "HOLD": maintain safe hold; telemetry indicates baseline monitoring is optimal or host unreachable.
- "INVESTIGATE_SERVICE": telemetry shows services that require further passive observation.
- "PRIORITIZE_HTTP": HTTP service was observed and classified for prioritization.
- "PRIORITIZE_FTP": FTP service was observed and classified for prioritization.
- "PRIORITIZE_SSH": SSH service was observed and classified for prioritization.
- "NO_ACTION": no further analysis warranted or services do not warrant action.

Allowed priority values (select exactly one):
- "LOW"
- "MEDIUM"
- "HIGH"
- "CRITICAL"

Confidence must be a float between 0.0 and 1.0.

CRITICAL INSTRUCTION: You MUST return ONLY one raw JSON object.
Do NOT output any introductory text, thinking process, reasoning steps, conversational prose, or markdown code fences.
Do NOT say "Here's a thinking process" or explain your reasoning outside the JSON.
Your entire response must begin with '{' and end with '}'.

Expected structure:
{
  "decision": "HOLD",
  "priority": "LOW",
  "confidence": 0.82,
  "observation": "<one or two sentences classifying the telemetry observations>"
}
"""


@dataclass
class Decision:
    action_type: Literal["defend", "attack", "recon", "hold"]
    target: str
    priority: Literal["critical", "high", "medium", "low"]
    reasoning: str
    confidence: float = 1.0
    needs_escalation: bool = False
    model_used: str = ""
    latency_ms: float = 0.0
    api_latency_ms: float = 0.0
    proposed_decision: str = ""
    http_status: Optional[int] = 200
    diagnostics: Optional[Dict[str, Any]] = None

    def sanitize(self) -> "Decision":
        """Enforce strict allowlists and prevent shell injection."""
        valid_actions = {"defend", "attack", "recon", "hold"}

        if self.action_type not in valid_actions:
            logger.warning(
                "Invalid action_type '%s' from model; falling back to 'hold'",
                self.action_type,
            )
            self.action_type = "hold"
            self.target = ""

        # Validate target
        if self.target:
            self.target = self.target.strip()

        if self.target and not TARGET_PATTERN.fullmatch(self.target):
            logger.warning(
                "Potential malicious or malformed target '%s' rejected.",
                self.target,
            )
            self.target = ""
            self.action_type = "hold"
            self.reasoning = (
                "Target validation failed; holding safely. "
                f"(Original: {self.reasoning})"
            )

        valid_priorities = {"critical", "high", "medium", "low"}
        if self.priority not in valid_priorities:
            self.priority = "medium"

        try:
            self.confidence = max(
                0.0,
                min(1.0, float(self.confidence)),
            )
        except (ValueError, TypeError):
            self.confidence = 0.5

        return self


def validate_advisory_payload(data: Any) -> Dict[str, Any]:
    """Validate advisory payload strictly against required schema and enum values.

    Expected structure:
    {
      "decision": "HOLD",
      "priority": "LOW",
      "confidence": 0.82,
      "observation": "..."
    }
    """
    import math

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object, got {type(data).__name__}")

    # 1. Validate decision
    if "decision" not in data:
        raise ValueError("Missing required field 'decision'")
    raw_decision = data["decision"]
    if not isinstance(raw_decision, str) or not raw_decision.strip():
        raise ValueError(f"Invalid decision value: {raw_decision}")
    dec_upper = raw_decision.strip().upper()
    if dec_upper not in ADVISORY_DECISION_VALUES:
        raise ValueError(f"Invalid advisory decision enum value: '{raw_decision}'")

    # 2. Validate priority
    if "priority" not in data:
        raise ValueError("Missing required field 'priority'")
    raw_priority = data["priority"]
    if not isinstance(raw_priority, str) or not raw_priority.strip():
        raise ValueError(f"Invalid priority value: {raw_priority}")
    priority_str = raw_priority.strip().upper()
    if priority_str not in ALLOWED_ADVISORY_PRIORITIES:
        raise ValueError(f"Invalid advisory priority enum value: '{raw_priority}'")

    # 3. Validate confidence
    if "confidence" not in data:
        raise ValueError("Missing required field 'confidence'")
    raw_conf = data["confidence"]
    if raw_conf is None or isinstance(raw_conf, bool):
        raise ValueError(f"Invalid confidence value: {raw_conf}")
    try:
        conf_float = float(raw_conf)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid confidence value: {raw_conf}")
    if math.isnan(conf_float) or math.isinf(conf_float) or not (0.0 <= conf_float <= 1.0):
        raise ValueError(f"Confidence value out of range [0.0, 1.0]: {conf_float}")

    # 4. Validate observation (or reasoning for backward compatibility)
    raw_obs = data.get("observation") or data.get("reasoning")
    if raw_obs is None or not isinstance(raw_obs, str) or not raw_obs.strip():
        raise ValueError("Missing required field 'observation'")

    return {
        "decision": dec_upper,
        "priority": priority_str.lower(),
        "confidence": conf_float,
        "observation": raw_obs.strip(),
        "target": str(data.get("target", "")).strip(),
    }


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """Robustly extract and parse a JSON dictionary from an LLM response string."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Empty response text from model")

    # 1. Strip markdown code fences if present
    if "```" in text:
        matches = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        for block in reversed(matches):
            block = block.strip()
            if "{" in block and "}" in block:
                first_b = block.find("{")
                last_b = block.rfind("}")
                candidate = block[first_b : last_b + 1].strip()
                try:
                    data = json.loads(candidate)
                    if isinstance(data, dict):
                        return data
                except Exception:
                    pass

    # 2. Strip reasoning / thinking tags (<think>...</think>)
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", text).strip()

    # 3. Direct parse attempt on cleaned text
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 4. Balanced brace search to extract valid JSON objects even amidst reasoning/preamble
    for candidate in (cleaned, text):
        stack = []
        start = -1
        found_objs = []
        for i, ch in enumerate(candidate):
            if ch == "{":
                if not stack:
                    start = i
                stack.append(ch)
            elif ch == "}":
                if stack:
                    stack.pop()
                    if not stack and start != -1:
                        sub = candidate[start : i + 1]
                        try:
                            obj = json.loads(sub)
                            if isinstance(obj, dict):
                                found_objs.append(obj)
                        except Exception:
                            pass
                        start = -1
        if found_objs:
            # Prefer objects that contain schema indicator keys
            for obj in reversed(found_objs):
                if any(k in obj for k in ("decision", "action_type", "observation", "status")):
                    return obj
            return found_objs[-1]

    # 5. Outermost braces search
    for candidate in (cleaned, text):
        first_brace = candidate.find("{")
        last_brace = candidate.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            sub = candidate[first_brace : last_brace + 1].strip()
            try:
                data = json.loads(sub)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass

    raise ValueError(f"No valid JSON object found in response: {text[:200]}")


class NvidiaDecisionEngine:
    """Decision engine powered by NVIDIA NIM OpenAI-compatible API.

    Strictly ADVISORY ONLY. Never executes shell commands or arbitrary tools.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        fast_model: Optional[str] = None,
        reasoning_model: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = (
            api_key
            or config.nvidia_api_key
            or config.gemini_api_key
            or os.getenv("NVIDIA_API_KEY", "")
        )
        self.base_url = (
            base_url
            or config.nvidia_base_url
            or os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
        ).rstrip("/")

        self.fast_model = (
            fast_model
            or config.nvidia_fast_model
            or os.getenv("NVIDIA_FAST_MODEL", DEFAULT_FAST_MODEL)
        ).strip()

        self.reasoning_model = (
            reasoning_model
            or config.nvidia_reasoning_model
            or os.getenv("NVIDIA_REASONING_MODEL", DEFAULT_REASONING_MODEL)
        ).strip()

        raw_model = model or self.fast_model
        # Enforce that model is one of the configured models
        self.model = self._resolve_model(raw_model)

        self.quota_cooldown_until = 0.0
        self.last_error: Optional[str] = None
        self.last_http_status: Optional[int] = None
        self.last_api_latency_ms: float = 0.0

        # Detailed telemetry dictionary from most recent invocation
        self.last_telemetry: Dict[str, Any] = {}
        # Detailed diagnostics dictionary from most recent invocation
        self.last_diagnostics: Dict[str, Any] = {}

    def _resolve_model(self, model_name: Optional[str]) -> str:
        """Resolve model name ensuring only allowed configured models are used."""
        if not model_name:
            return self.fast_model

        name = model_name.strip()
        # Normalization for legacy / shorthand names
        if "pro" in name.lower() or "super" in name.lower() or "120b" in name.lower():
            return self.reasoning_model
        if "flash" in name.lower() or "lightning" in name.lower() or "30b" in name.lower():
            return self.fast_model

        # Only allow configured model IDs (Rule 9)
        if name in (self.fast_model, self.reasoning_model, DEFAULT_FAST_MODEL, DEFAULT_REASONING_MODEL):
            return name

        logger.warning(
            "Requested model '%s' not in configured allowlist; defaulting to configured fast model: %s",
            name,
            self.fast_model,
        )
        return self.fast_model

    def _cooldown_remaining(self) -> float:
        return max(0.0, self.quota_cooldown_until - time.time())

    def _extract_retry_after(self, response: requests.Response) -> float:
        default_retry = 60.0
        header_val = getattr(response, "headers", {}).get("Retry-After")
        if header_val:
            try:
                return max(1.0, float(header_val))
            except ValueError:
                pass

        try:
            data = response.json()
            err_msg = str(data.get("error", {}).get("message", ""))
            m = re.search(r"(\d+(?:\.\d+)?)\s*s", err_msg)
            if m:
                return max(1.0, float(m.group(1)))
        except Exception:
            pass

        return default_retry

    def _set_quota_cooldown(self, retry_after: float) -> None:
        cooldown = max(1.0, float(retry_after)) + 2.0
        self.quota_cooldown_until = time.time() + cooldown
        logger.warning("NVIDIA NIM quota cooldown enabled for %.1f seconds.", cooldown)

    def _check_quota_cooldown(self) -> Optional[Decision]:
        remaining = self._cooldown_remaining()
        if remaining <= 0:
            return None

        logger.warning(
            "NVIDIA NIM quota cooldown active: %.1fs remaining. Skipping API request.",
            remaining,
        )
        return Decision(
            action_type="hold",
            target="",
            priority="low",
            reasoning=(
                f"NVIDIA quota cooldown active for approximately {remaining:.0f}s; "
                "using deterministic fallback."
            ),
            confidence=0.0,
            needs_escalation=False,
            model_used="quota-cooldown",
            latency_ms=0.0,
            api_latency_ms=0.0,
            proposed_decision="HOLD",
            http_status=429,
        ).sanitize()

    def _post_nvidia(
        self,
        model: str,
        messages: List[Dict[str, str]],
        timeout: Tuple[int, int] = (10, 90),
        max_tokens: int = 2048,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> Tuple[requests.Response, float]:
        """Make an OpenAI-compatible chat completions request to NVIDIA NIM.

        Measures actual API wall-clock latency separately from local decision overhead.
        """
        remaining = self._cooldown_remaining()
        if remaining > 0:
            raise NvidiaRateLimitError(
                f"NVIDIA quota cooldown active for {remaining:.1f}s",
                retry_after=remaining,
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }

        # Request JSON object format when supported
        if response_format:
            payload["response_format"] = response_format
        else:
            payload["response_format"] = {"type": "json_object"}

        # Measure ACTUAL API wall-clock latency
        t0 = time.perf_counter()
        try:
            response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
            api_latency_ms = (time.perf_counter() - t0) * 1000.0
        except requests.Timeout as exc:
            api_latency_ms = (time.perf_counter() - t0) * 1000.0
            self.last_api_latency_ms = api_latency_ms
            self.last_http_status = None
            raise exc
        except requests.RequestException as exc:
            api_latency_ms = (time.perf_counter() - t0) * 1000.0
            self.last_api_latency_ms = api_latency_ms
            self.last_http_status = None
            raise exc

        self.last_api_latency_ms = api_latency_ms

        status_code = getattr(response, "status_code", 200)
        if isinstance(status_code, int):
            self.last_http_status = status_code
        else:
            status_code = 200
            self.last_http_status = 200

        # HTTP 429 Quota / Rate Limit
        if status_code == 429:
            retry_after = self._extract_retry_after(response)
            self._set_quota_cooldown(retry_after)
            self.last_error = f"RATE_LIMITED / HTTP 429; retry_after={retry_after:.1f}s"
            raise NvidiaRateLimitError(
                f"NVIDIA quota exhausted; retry after approximately {retry_after:.1f}s",
                retry_after=retry_after,
            )

        # HTTP 401/403 Authentication / Authorization
        if status_code in (401, 403):
            self.last_error = f"Authentication/permission failure: HTTP {status_code}"
            raise NvidiaAPIError(self.last_error)

        # HTTP 404 Model / Endpoint Not Found
        if status_code == 404:
            self.last_error = f"NVIDIA model or endpoint not found: {model} at {endpoint}"
            raise NvidiaAPIError(self.last_error)

        # Other HTTP 4xx / 5xx Errors
        if status_code >= 400:
            self.last_error = f"NVIDIA HTTP error {status_code}: {getattr(response, 'text', '')[:200]}"
            raise NvidiaAPIError(self.last_error)

        self.last_error = None
        return response, api_latency_ms

    def _extract_text_from_response(self, resp: requests.Response) -> str:
        """Extract response text supporting both OpenAI-compatible and Gemini mock formats."""
        try:
            data = resp.json()
        except Exception:
            return getattr(resp, "text", "") or ""

        # 1. OpenAI-compatible choices format (NVIDIA NIM)
        if "choices" in data and data["choices"]:
            choice = data["choices"][0]
            msg = choice.get("message", {})
            content = msg.get("content")
            if content is not None and str(content).strip():
                return str(content)
            # Check reasoning_content if content is empty
            reasoning = msg.get("reasoning_content")
            if reasoning is not None and str(reasoning).strip():
                return str(reasoning)
            return ""

        # 2. Gemini format (for test fixture compatibility)
        if "candidates" in data and data["candidates"]:
            cand = data["candidates"][0]
            parts = cand.get("content", {}).get("parts", [])
            for part in reversed(parts):
                p_text = part.get("text", "")
                if p_text and not part.get("thought", False) and "{" in p_text:
                    return p_text
            if parts and parts[0].get("text"):
                return parts[0]["text"]
            return ""

        return getattr(resp, "text", "") or ""

    def decide(
        self,
        telemetry_summary: str,
        recent_actions: List[str],
        model: Optional[str] = None,
    ) -> Decision:
        """Decide the single highest-priority next tactical action.

        Strictly advisory. Never executes actions.
        """
        cooldown_decision = self._check_quota_cooldown()
        if cooldown_decision is not None:
            return cooldown_decision

        target_model = self._resolve_model(model or self.model)
        prompt = (
            f"{DECISION_SCHEMA_PROMPT}\n\n"
            f"Current telemetry:\n{telemetry_summary}\n\n"
            f"Recent actions taken (most recent last):\n"
            + "\n".join(recent_actions[-10:])
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a strategic decision engine for an authorized security competition agent. "
                    "You are ADVISORY ONLY. Respond ONLY with a valid JSON object matching the required schema. "
                    "No preamble, no thinking tokens, no markdown fences."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        t_start = time.perf_counter()
        api_lat = 0.0
        response_length = 0
        parse_ok = False
        validation_ok = False

        try:
            resp, api_lat = self._post_nvidia(target_model, messages, timeout=(10, 90), max_tokens=2048)
            raw_text = self._extract_text_from_response(resp)
            response_length = len(raw_text)
            parsed = extract_json_from_text(raw_text)
            parse_ok = True

            if not isinstance(parsed, dict):
                raise TypeError(f"Expected JSON object, got {type(parsed).__name__}")

            required = {"action_type", "priority", "reasoning"}
            if not required.issubset(parsed.keys()):
                missing = required - set(parsed.keys())
                raise KeyError(f"Missing required schema fields: {missing}")

            allowed = {
                "action_type",
                "target",
                "priority",
                "reasoning",
                "confidence",
                "needs_escalation",
            }
            extra = set(parsed.keys()) - allowed
            if extra:
                raise TypeError(f"Unexpected extra fields in decision: {extra}")

            validation_ok = True
            total_lat = (time.perf_counter() - t_start) * 1000.0

            diagnostics = {
                "http_status": self.last_http_status or 200,
                "response_length": response_length,
                "parse_success": True,
                "validation_success": True,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics

            decision = Decision(
                action_type=parsed["action_type"],
                target=parsed.get("target", ""),
                priority=parsed["priority"],
                reasoning=parsed["reasoning"],
                confidence=float(parsed.get("confidence", 1.0)),
                needs_escalation=bool(parsed.get("needs_escalation", False)),
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                http_status=self.last_http_status or 200,
                diagnostics=diagnostics,
            ).sanitize()

            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=self.last_http_status or 200,
                success=True,
                timeout=False,
                rate_limit=False,
                malformed_response=False,
                confidence=decision.confidence,
                escalation=decision.needs_escalation,
                response_length=response_length,
                parse_success=True,
                validation_success=True,
            )
            return decision

        except NvidiaRateLimitError as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            logger.warning(
                "NVIDIA quota exhausted for %s. Using deterministic fallback. Retry after %.1fs.",
                target_model,
                exc.retry_after,
            )
            diagnostics = {
                "http_status": 429,
                "response_length": response_length,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=429,
                success=False,
                timeout=False,
                rate_limit=True,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=(
                    f"NVIDIA quota exhausted; deterministic fallback required. "
                    f"Cooldown approximately {exc.retry_after:.0f}s."
                ),
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=429,
                diagnostics=diagnostics,
            ).sanitize()

        except requests.Timeout as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            logger.warning("NVIDIA request to %s timed out: %s", target_model, exc)
            diagnostics = {
                "http_status": 408,
                "response_length": 0,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=None,
                success=False,
                timeout=True,
                rate_limit=False,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=0,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="NVIDIA request timed out; holding safely and allowing deterministic fallback.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=408,
                diagnostics=diagnostics,
            ).sanitize()

        except requests.RequestException as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            logger.warning("NVIDIA network request to %s failed: %s", target_model, exc)
            diagnostics = {
                "http_status": self.last_http_status,
                "response_length": response_length,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=self.last_http_status,
                success=False,
                timeout=False,
                rate_limit=False,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"NVIDIA network failure ({exc}); holding safely.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=self.last_http_status,
                diagnostics=diagnostics,
            ).sanitize()

        except Exception as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            logger.warning("NVIDIA request to %s failed (%s); holding safely.", target_model, exc)
            diagnostics = {
                "http_status": self.last_http_status,
                "response_length": response_length,
                "parse_success": parse_ok,
                "validation_success": validation_ok,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=self.last_http_status,
                success=False,
                timeout=False,
                rate_limit=False,
                malformed_response=True,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=parse_ok,
                validation_success=validation_ok,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"Failed to parse decision ({exc}); holding.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=self.last_http_status,
                diagnostics=diagnostics,
            ).sanitize()

    def decide_from_recon(
        self,
        recon_data: Dict[str, Any],
        model: Optional[str] = None,
    ) -> Decision:
        """Reason over already-collected structured recon telemetry.

        STRICTLY ADVISORY ONLY.
        NEVER executes network scans or shell commands.
        NEVER returns attack/exploit decisions.
        """
        cooldown_decision = self._check_quota_cooldown()
        if cooldown_decision is not None:
            return cooldown_decision

        target_model = self._resolve_model(model or self.model)
        prompt = (
            f"{RECON_DECISION_SCHEMA_PROMPT}\n\n"
            f"Already-collected structured reconnaissance telemetry:\n"
            f"{json.dumps(recon_data, indent=2)}"
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a strategic telemetry analysis advisor for an authorized security assessment agent. "
                    "You are STRICTLY ADVISORY ONLY. You NEVER approve, initiate, or execute tests, exploits, or shell commands. "
                    "You must output ONLY one raw valid JSON object matching the required schema. "
                    "Do NOT include any preamble, thinking process, reasoning steps, conversational prose, or markdown code fences. "
                    "Begin directly with '{' and end with '}'."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        t_start = time.perf_counter()
        api_lat = 0.0
        response_length = 0
        parse_ok = False
        validation_ok = False
        raw_text = ""
        http_status = None

        try:
            resp, api_lat = self._post_nvidia(
                target_model,
                messages,
                timeout=(10, 90),
                max_tokens=2048,
            )
            raw_status = getattr(resp, "status_code", 200)
            http_status = raw_status if isinstance(raw_status, int) else (self.last_http_status if isinstance(self.last_http_status, int) else 200)
            raw_text = self._extract_text_from_response(resp)
            response_length = len(raw_text)

            parsed = extract_json_from_text(raw_text)
            parse_ok = True

            validated = validate_advisory_payload(parsed)
            validation_ok = True

            raw_decision = validated["decision"]
            raw_priority = validated["priority"]
            confidence = validated["confidence"]
            raw_reasoning = validated["observation"]
            raw_target = validated["target"]

            # Strictly advisory: neutralize any forbidden proposal terms
            for forbidden in FORBIDDEN_PROPOSAL_TERMS:
                if forbidden in raw_decision.lower():
                    logger.warning("Forbidden term '%s' in model decision; forcing HOLD.", forbidden)
                    raw_decision = "HOLD"
                if forbidden in raw_target.lower():
                    logger.warning("Forbidden term '%s' in model target; neutralizing target.", forbidden)
                    raw_target = ""

            # Shell metacharacter protection
            if any(ch in raw_target for ch in (";", "|", "&", "`", "$", "(", ")", ">", "<", "\n", "\r")):
                logger.warning("Shell metacharacters detected in target '%s'; neutralizing.", raw_target)
                raw_target = ""

            if raw_target and not TARGET_PATTERN.fullmatch(raw_target):
                logger.warning("Potential malicious or malformed target '%s' rejected.", raw_target)
                raw_target = ""

            # Mandatory advisory constraint: action_type is ALWAYS 'hold'
            action_type = "hold"
            target = raw_target
            priority = raw_priority

            needs_esc = bool(parsed.get("needs_escalation", False))
            total_lat = (time.perf_counter() - t_start) * 1000.0

            diagnostics = {
                "http_status": http_status,
                "response_length": response_length,
                "parse_success": True,
                "validation_success": True,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics

            logger.info(
                "NVIDIA NIM Advisory Diagnostics: http_status=%s response_length=%d parse_success=%s validation_success=%s model_name=%s latency=%.2fms",
                diagnostics["http_status"],
                diagnostics["response_length"],
                diagnostics["parse_success"],
                diagnostics["validation_success"],
                diagnostics["model_name"],
                diagnostics["latency_ms"],
            )

            decision = Decision(
                action_type=action_type,
                target=target,
                priority=priority,
                reasoning=raw_reasoning,
                confidence=confidence,
                needs_escalation=needs_esc,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision=raw_decision,
                http_status=http_status,
                diagnostics=diagnostics,
            ).sanitize()

            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=http_status,
                success=True,
                timeout=False,
                rate_limit=False,
                malformed_response=False,
                confidence=decision.confidence,
                escalation=decision.needs_escalation,
                response_length=response_length,
                parse_success=True,
                validation_success=True,
            )
            return decision

        except NvidiaRateLimitError as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            diagnostics = {
                "http_status": 429,
                "response_length": response_length,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            logger.warning(
                "NVIDIA NIM Advisory Diagnostics: http_status=429 response_length=%d parse_success=False validation_success=False model_name=%s latency=%.2fms",
                response_length,
                target_model,
                round(api_lat, 2),
            )
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=429,
                success=False,
                timeout=False,
                rate_limit=True,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=(
                    f"NVIDIA quota exhausted during recon analysis; SAFE_HOLD enforced. "
                    f"Cooldown approximately {exc.retry_after:.0f}s."
                ),
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=429,
                diagnostics=diagnostics,
            ).sanitize()

        except requests.Timeout as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            diagnostics = {
                "http_status": 408,
                "response_length": 0,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            logger.warning(
                "NVIDIA NIM Advisory Diagnostics: http_status=408 response_length=0 parse_success=False validation_success=False model_name=%s latency=%.2fms",
                target_model,
                round(api_lat, 2),
            )
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=408,
                success=False,
                timeout=True,
                rate_limit=False,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=0,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"NVIDIA timeout ({exc}); SAFE_HOLD enforced.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=408,
                diagnostics=diagnostics,
            ).sanitize()

        except NvidiaAPIError as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            diag_status = self.last_http_status if isinstance(self.last_http_status, int) else 500
            diagnostics = {
                "http_status": diag_status,
                "response_length": response_length,
                "parse_success": False,
                "validation_success": False,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            logger.warning(
                "NVIDIA NIM Advisory Diagnostics: http_status=%s response_length=%d parse_success=False validation_success=False model_name=%s latency=%.2fms",
                diag_status,
                response_length,
                target_model,
                round(api_lat, 2),
            )
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=diag_status,
                success=False,
                timeout=False,
                rate_limit=False,
                malformed_response=False,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=False,
                validation_success=False,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"NVIDIA HTTP failure ({exc}); SAFE_HOLD enforced.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=diag_status,
                diagnostics=diagnostics,
            ).sanitize()

        except Exception as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            diag_status = http_status if isinstance(http_status, int) else (self.last_http_status if isinstance(self.last_http_status, int) else 200)
            diagnostics = {
                "http_status": diag_status,
                "response_length": response_length,
                "parse_success": parse_ok,
                "validation_success": validation_ok,
                "model_name": target_model,
                "latency": round(api_lat, 2),
                "latency_ms": round(api_lat, 2),
            }
            self.last_diagnostics = diagnostics
            logger.warning(
                "NVIDIA NIM Advisory Diagnostics: http_status=%s response_length=%d parse_success=%s validation_success=%s model_name=%s latency=%.2fms",
                diag_status,
                response_length,
                parse_ok,
                validation_ok,
                target_model,
                round(api_lat, 2),
            )
            logger.warning("NVIDIA recon analysis failed (%s); SAFE_HOLD enforced.", exc)
            self._record_telemetry(
                model=target_model,
                api_latency=api_lat,
                http_status=diag_status,
                success=False,
                timeout=False,
                rate_limit=False,
                malformed_response=not parse_ok or not validation_ok,
                confidence=0.0,
                escalation=False,
                response_length=response_length,
                parse_success=parse_ok,
                validation_success=validation_ok,
            )
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"NVIDIA advisory failure ({exc}); SAFE_HOLD enforced.",
                confidence=0.0,
                needs_escalation=False,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="HOLD",
                http_status=diag_status,
                diagnostics=diagnostics,
            ).sanitize()

    def analyze_test_result(
        self,
        test_result_data: Dict[str, Any],
        model: Optional[str] = None,
    ) -> Decision:
        """Advisory classification of structured controlled test results.

        Strictly advisory only. Does NOT approve, initiate, or execute tests.
        """
        cooldown_decision = self._check_quota_cooldown()
        if cooldown_decision is not None:
            return cooldown_decision

        target_model = self._resolve_model(model or self.model)
        prompt = (
            f"{RECON_DECISION_SCHEMA_PROMPT}\n\n"
            f"Already-collected controlled testing result telemetry:\n"
            f"{json.dumps(test_result_data, indent=2)}"
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a strategic telemetry analysis advisor. You are STRICTLY ADVISORY ONLY. "
                    "Classify observations in structured JSON."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        t_start = time.perf_counter()
        api_lat = 0.0

        try:
            resp, api_lat = self._post_nvidia(target_model, messages, timeout=(10, 90), max_tokens=2048)
            raw_text = self._extract_text_from_response(resp)
            parsed = extract_json_from_text(raw_text)

            if not isinstance(parsed, dict):
                raise TypeError(f"Expected JSON object, got {type(parsed).__name__}")

            raw_decision = str(parsed.get("decision", "NO_ACTION")).strip().upper()
            if raw_decision not in ADVISORY_DECISION_VALUES:
                raw_decision = "NO_ACTION"

            total_lat = (time.perf_counter() - t_start) * 1000.0

            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=str(
                    parsed.get("reasoning", f"Test result classification: {raw_decision}")
                ),
                confidence=float(parsed.get("confidence", 1.0)),
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision=raw_decision,
                http_status=self.last_http_status or 200,
            ).sanitize()

        except Exception as exc:
            total_lat = (time.perf_counter() - t_start) * 1000.0
            logger.warning("Advisory test result analysis failed: %s", exc)
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"Advisory test result analysis fallback ({exc}); holding.",
                confidence=0.0,
                model_used=target_model,
                latency_ms=total_lat,
                api_latency_ms=api_lat,
                proposed_decision="NO_ACTION",
                http_status=self.last_http_status,
            ).sanitize()

    def _record_telemetry(
        self,
        model: str,
        api_latency: float,
        http_status: Optional[int],
        success: bool,
        timeout: bool,
        rate_limit: bool,
        malformed_response: bool,
        confidence: float,
        escalation: bool,
        empirical_outcome: Optional[bool] = None,
        response_length: int = 0,
        parse_success: bool = True,
        validation_success: bool = True,
    ) -> None:
        """Store internal telemetry record for router and database persistence."""
        self.last_telemetry = {
            "model": model,
            "request_latency_ms": round(api_latency, 2),
            "http_status": http_status,
            "response_length": response_length,
            "parse_success": parse_success,
            "validation_success": validation_success,
            "success": success,
            "timeout": timeout,
            "rate_limit": rate_limit,
            "malformed_response": malformed_response,
            "confidence": round(confidence, 2),
            "escalation": escalation,
            "empirical_outcome": empirical_outcome,
        }

    # ------------------------------------------------------------------
    # HEALTH CHECK & SMOKE TEST
    # ------------------------------------------------------------------

    def health_check(self, model: Optional[str] = None) -> Dict[str, Any]:
        """Verify provider health without exposing the API key.

        Verifies:
          1. NVIDIA_API_KEY exists (never printed).
          2. Endpoint reachable.
          3. Configured model responds (HTTP 200).
          4. Structured JSON response can be parsed.
        """
        target_model = self._resolve_model(model or self.fast_model)
        result: Dict[str, Any] = {
            "healthy": False,
            "api_key_configured": bool(self.api_key),
            "endpoint_reachable": False,
            "model_responding": False,
            "json_parse_ok": False,
            "endpoint": self.base_url,
            "model": target_model,
            "api_latency_ms": 0.0,
            "http_status": None,
            "details": "",
        }

        if not self.api_key:
            result["details"] = "NVIDIA_API_KEY is not configured in environment or config"
            return result

        smoke_messages = [
            {"role": "user", "content": 'Return exactly: {"status":"ok"}'}
        ]

        try:
            resp, api_lat = self._post_nvidia(
                target_model,
                smoke_messages,
                timeout=(5, 20),
                max_tokens=256,
            )
            result["endpoint_reachable"] = True
            result["api_latency_ms"] = round(api_lat, 2)
            result["http_status"] = getattr(resp, "status_code", None)

            if result["http_status"] == 200:
                result["model_responding"] = True
                raw_text = self._extract_text_from_response(resp)
                parsed = extract_json_from_text(raw_text)
                if isinstance(parsed, dict) and parsed.get("status") == "ok":
                    result["json_parse_ok"] = True
                    result["healthy"] = True
                    result["details"] = "Health check passed: model returned valid structured JSON"
                else:
                    result["details"] = f"Model returned unexpected structure: {parsed}"
            else:
                result["details"] = f"NVIDIA API responded with HTTP {result['http_status']}"

        except requests.Timeout as exc:
            result["details"] = f"Endpoint timeout: {exc}"
        except NvidiaRateLimitError as exc:
            result["http_status"] = 429
            result["details"] = f"Rate limited: {exc}"
        except Exception as exc:
            result["details"] = f"Health check failed: {exc}"

        return result

    def smoke_test(self, model: Optional[str] = None) -> Dict[str, Any]:
        """Execute non-destructive NVIDIA smoke test asking only for {"status":"ok"}.

        DOES NOT execute any target actions.
        """
        target_model = self._resolve_model(model or self.fast_model)
        messages = [
            {"role": "user", "content": 'Return exactly: {"status":"ok"}'}
        ]

        t0 = time.perf_counter()
        resp, api_lat = self._post_nvidia(
            target_model,
            messages,
            timeout=(5, 20),
            max_tokens=256,
        )
        total_lat = (time.perf_counter() - t0) * 1000.0
        raw_text = self._extract_text_from_response(resp)
        parsed = extract_json_from_text(raw_text)

        status_ok = isinstance(parsed, dict) and parsed.get("status") == "ok"

        return {
            "success": status_ok,
            "model": target_model,
            "api_latency_ms": round(api_lat, 2),
            "total_latency_ms": round(total_lat, 2),
            "http_status": getattr(resp, "status_code", 200),
            "response_payload": parsed,
        }


# Backwards compatibility
GeminiDecisionEngine = NvidiaDecisionEngine


def main() -> None:
    """CLI entrypoint for NVIDIA NIM smoke testing and provider health verification."""
    import argparse

    parser = argparse.ArgumentParser(description="NVIDIA NIM Client Health and Smoke Test Utility")
    parser.add_argument("--smoke-test", action="store_true", help="Run NVIDIA smoke test")
    parser.add_argument("--health-check", action="store_true", help="Run NVIDIA provider health check")
    parser.add_argument("--model", type=str, default=None, help="Model to probe (fast or reasoning)")
    args = parser.parse_args()

    engine = NvidiaDecisionEngine()

    if args.health_check or not args.smoke_test:
        print("=== NVIDIA NIM Provider Health Check ===")
        health = engine.health_check(model=args.model)
        print(f"API Key Configured  : {health['api_key_configured']}")
        print(f"Endpoint Reachable : {health['endpoint_reachable']} ({health['endpoint']})")
        print(f"Model Responding   : {health['model_responding']} ({health['model']})")
        print(f"JSON Parse OK      : {health['json_parse_ok']}")
        print(f"Wall-Clock Latency : {health['api_latency_ms']} ms")
        print(f"HTTP Status        : {health['http_status']}")
        print(f"Overall Status     : {'HEALTHY' if health['healthy'] else 'UNHEALTHY'}")
        print(f"Details            : {health['details']}")

    if args.smoke_test:
        print("\n=== NVIDIA NIM Smoke Test ===")
        try:
            smoke = engine.smoke_test(model=args.model)
            print(f"Model Tested       : {smoke['model']}")
            print(f"HTTP Status        : {smoke['http_status']}")
            print(f"API Latency (wall) : {smoke['api_latency_ms']} ms")
            print(f"Total Latency      : {smoke['total_latency_ms']} ms")
            print(f"Parsed Response    : {json.dumps(smoke['response_payload'])}")
            print(f"Smoke Test Status  : {'PASSED' if smoke['success'] else 'FAILED'}")
            if not smoke["success"]:
                sys.exit(1)
        except Exception as exc:
            print(f"Smoke Test ERROR   : {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
