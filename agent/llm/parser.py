"""Robust JSON and Structured Decision Parser for Multi-Provider LLM outputs."""
import json
import re
from typing import Any, Dict, Optional, Tuple

from .types import ModelDecision, TARGET_PATTERN, VALID_ACTIONS, VALID_PRIORITIES


def strip_think_blocks(text: str) -> str:
    """Strip <think>...</think> reasoning blocks from text."""
    if not text:
        return ""
    return re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()


def extract_markdown_json(text: str) -> Optional[str]:
    """Extract JSON block from markdown code fences if present."""
    if not text:
        return None
    fence_pattern = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)
    matches = fence_pattern.findall(text)
    for candidate in matches:
        cand_strip = candidate.strip()
        if cand_strip.startswith("{") and cand_strip.endswith("}"):
            return cand_strip
    return None


def extract_balanced_json(text: str) -> Optional[str]:
    """Extract first substring with balanced curly braces starting with '{'."""
    if not text:
        return None
    start_idx = text.find("{")
    if start_idx == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for i in range(start_idx, len(text)):
        ch = text[i]

        if escape:
            escape = False
            continue

        if ch == "\\":
            escape = True
            continue

        if ch == '"':
            in_string = not in_string
            continue

        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start_idx : i + 1]

    return None


def parse_model_response(
    raw_text: str,
    provider: str = "",
    model: str = "",
    latency_ms: float = 0.0,
    request_id: str = "",
    fallback_level: int = 0,
    http_status: int = 200,
) -> ModelDecision:
    """Parse raw LLM completion text into a validated ModelDecision.

    Follows the strict 6-stage parsing order:
      1. direct JSON
      2. markdown code fences
      3. strip <think>...</think>
      4. balanced JSON extraction
      5. schema validation
      6. safe structured failure (action=hold, confidence=0.0, parse_status=FAILED)
    """
    if not raw_text or not isinstance(raw_text, str):
        return ModelDecision(
            action="hold",
            target="",
            priority="LOW",
            confidence=0.0,
            observation="Empty response received from provider",
            reasoning_summary="Parser failed: empty response",
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            request_id=request_id,
            fallback_level=fallback_level,
            parse_status="FAILED",
            http_status=http_status,
            raw_response=str(raw_text),
        )

    parsed_dict: Optional[Dict[str, Any]] = None
    cleaned = raw_text.strip()

    # 1. Try direct JSON
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            parsed_dict = data
    except Exception:
        pass

    # 2. Try markdown fence
    if parsed_dict is None:
        fence_content = extract_markdown_json(cleaned)
        if fence_content:
            try:
                data = json.loads(fence_content)
                if isinstance(data, dict):
                    parsed_dict = data
            except Exception:
                pass

    # 3. Strip <think>...</think> and retry
    if parsed_dict is None and ("<think>" in cleaned.lower()):
        no_think = strip_think_blocks(cleaned)
        try:
            data = json.loads(no_think)
            if isinstance(data, dict):
                parsed_dict = data
        except Exception:
            pass

        if parsed_dict is None:
            fence_content = extract_markdown_json(no_think)
            if fence_content:
                try:
                    data = json.loads(fence_content)
                    if isinstance(data, dict):
                        parsed_dict = data
                except Exception:
                    pass

    # 4. Balanced JSON object extraction
    if parsed_dict is None:
        no_think = strip_think_blocks(cleaned)
        balanced = extract_balanced_json(no_think) or extract_balanced_json(cleaned)
        if balanced:
            try:
                data = json.loads(balanced)
                if isinstance(data, dict):
                    parsed_dict = data
            except Exception:
                pass

    # 5. Schema validation
    if parsed_dict is not None and isinstance(parsed_dict, dict):
        try:
            # Extract action (accepts "action" or legacy "action_type" / "decision")
            action_val = parsed_dict.get("action") or parsed_dict.get("action_type") or parsed_dict.get("decision")
            if not action_val or not isinstance(action_val, str):
                raise ValueError("Missing or invalid 'action' field")

            action_clean = action_val.strip().lower()
            if action_clean not in VALID_ACTIONS:
                raise ValueError(f"Action '{action_clean}' not in recognized action set")

            target_val = str(parsed_dict.get("target") or "").strip()
            # If target has CIDR notation, reject
            if "/" in target_val:
                raise ValueError("Target contains prohibited CIDR notation")
            if target_val and not TARGET_PATTERN.fullmatch(target_val):
                raise ValueError(f"Target '{target_val}' failed syntax pattern")

            prio_val = str(parsed_dict.get("priority") or "MEDIUM").strip().upper()
            if prio_val not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                prio_val = "MEDIUM"

            raw_conf = parsed_dict.get("confidence", 0.5)
            try:
                conf_float = max(0.0, min(1.0, float(raw_conf)))
            except (ValueError, TypeError):
                conf_float = 0.5

            obs_val = str(parsed_dict.get("observation") or "").strip()
            reason_val = str(parsed_dict.get("reasoning_summary") or parsed_dict.get("reasoning") or "").strip()

            return ModelDecision(
                action=action_clean,
                target=target_val,
                priority=prio_val,
                confidence=conf_float,
                observation=obs_val,
                reasoning_summary=reason_val or obs_val,
                provider=provider,
                model=model,
                latency_ms=latency_ms,
                request_id=request_id,
                fallback_level=fallback_level,
                parse_status="SUCCESS",
                http_status=http_status,
                raw_response=raw_text,
            ).sanitize()

        except Exception as schema_err:
            return ModelDecision(
                action="hold",
                target="",
                priority="LOW",
                confidence=0.0,
                observation=f"Schema validation failed: {schema_err}",
                reasoning_summary=f"Parser rejected schema: {schema_err}",
                provider=provider,
                model=model,
                latency_ms=latency_ms,
                request_id=request_id,
                fallback_level=fallback_level,
                parse_status="FAILED",
                http_status=http_status,
                raw_response=raw_text,
            )

    # 6. Reject malformed output
    return ModelDecision(
        action="hold",
        target="",
        priority="LOW",
        confidence=0.0,
        observation="Failed to parse structured JSON from provider output",
        reasoning_summary="Parser failed: no valid JSON object found in response",
        provider=provider,
        model=model,
        latency_ms=latency_ms,
        request_id=request_id,
        fallback_level=fallback_level,
        parse_status="FAILED",
        http_status=http_status,
        raw_response=raw_text,
    )
