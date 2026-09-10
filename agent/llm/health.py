"""Diagnostic Health Check tool for LLM Providers.
Run via: python -m agent.llm.health
Tests availability, endpoint latency, and parse correctness without leaking secrets.
"""
import sys
import time
from typing import Dict, Any

from .providers.groq import GroqGptOssProvider
from .providers.nvidia import NvidiaNemotronProvider
from .providers.openrouter import OpenRouterGlmProvider
from ..config import Config, config as global_config

PROBE_MESSAGES = [
    {
        "role": "user",
        "content": 'Respond with ONLY a JSON object: {"action":"hold","target":"","priority":"LOW","confidence":1.0,"observation":"health_ok","reasoning_summary":"diagnostic probe"}',
    }
]


def check_provider(provider: Any) -> Dict[str, Any]:
    """Test a single provider's configuration, reachability, and parse capability."""
    configured = provider.is_configured()
    res: Dict[str, Any] = {
        "configured": "YES" if configured else "NO",
        "endpoint": provider.endpoint,
        "model": provider.model_id,
        "reachable": "NO",
        "latency_ms": "N/A",
        "parse": "FAIL",
    }

    if not configured:
        return res

    try:
        raw_content, latency_ms, status_code, req_id = provider._post_chat_completion(
            messages=PROBE_MESSAGES,
            max_tokens=512,
        )

        res["latency_ms"] = f"{latency_ms:.1f}ms"

        if status_code == 200 and raw_content:
            res["reachable"] = "YES"
            # Verify parsing
            from .parser import parse_model_response

            parsed = parse_model_response(
                raw_text=raw_content,
                provider=provider.provider_name,
                model=provider.model_id,
            )
            if parsed.parse_status == "SUCCESS":
                res["parse"] = "PASS"
            else:
                res["parse"] = f"FAIL (status={parsed.parse_status})"
        else:
            res["reachable"] = f"NO (HTTP {status_code})"

    except Exception as e:
        res["reachable"] = f"NO ({type(e).__name__})"

    return res


def run_health_check(cfg: Config = None) -> int:
    config = cfg or global_config
    print("=" * 60)
    print("LLM PROVIDER ARCHITECTURE DIAGNOSTIC REPORT")
    print("=" * 60)

    providers = [
        ("NVIDIA (Fast / Tactical)", NvidiaNemotronProvider(
            api_key=config.nvidia_api_key or "",
            endpoint=config.nvidia_base_url or "https://integrate.api.nvidia.com/v1",
            model_id=config.nvidia_fast_model or "nvidia/nemotron-3.5-lightning-30b-a3b",
            timeout_seconds=config.llm_timeout_seconds,
        )),
        ("Groq (Reasoning / Escalation)", GroqGptOssProvider(
            api_key=config.groq_api_key or "",
            endpoint=config.groq_base_url or "https://api.groq.com/openai/v1",
            model_id=config.groq_reasoning_model or "openai/gpt-oss-120b",
            timeout_seconds=config.llm_timeout_seconds,
        )),
        ("OpenRouter (Specialist / Escalation)", OpenRouterGlmProvider(
            api_key=config.openrouter_api_key or "",
            endpoint=config.openrouter_base_url or "https://openrouter.ai/api/v1",
            model_id=config.openrouter_specialist_model or "z-ai/glm-5.3-flash",
            timeout_seconds=config.llm_timeout_seconds,
        )),
    ]

    all_configured = True
    any_reachable = False

    for title, prov in providers:
        report = check_provider(prov)
        print(f"\n{title}:")
        print(f"  configured: {report['configured']}")
        print(f"  endpoint: {report['endpoint']}")
        print(f"  model: {report['model']}")
        print(f"  reachable: {report['reachable']}")
        print(f"  latency: {report['latency_ms']}")
        print(f"  parse: {report['parse']}")

        if report["configured"] != "YES":
            all_configured = False
        if report["reachable"] == "YES":
            any_reachable = True

    print("\n" + "=" * 60)
    if any_reachable:
        print("DIAGNOSTIC STATUS: Operational")
        return 0
    elif all_configured:
        print("DIAGNOSTIC STATUS: Configured, but provider endpoints unreachable")
        return 1
    else:
        print("DIAGNOSTIC STATUS: Unconfigured / Missing API keys")
        return 1


if __name__ == "__main__":
    sys.exit(run_health_check())
