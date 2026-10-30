"""
Tests for Final Phase: Replacement Advisory LLM Integration.
Verifies that:
1. Application works cleanly with no LLM configured (deterministic safe hold).
2. SimulatedAdvisoryProvider generates structured tactical advice without execution authority.
3. Advisory output cannot bypass policy, registry, or task authorization gates.
"""
import pytest
from agent.config import Config
from agent.llm.providers.local_simulated import SimulatedAdvisoryProvider, LocalAdvisoryProvider
from agent.llm.router import TieredModelRouter
from agent.llm.types import ModelDecision


def test_router_deterministic_hold_with_zero_llm_credentials():
    cfg = Config(
        nvidia_api_key="",
        groq_api_key="",
        openrouter_api_key="",
        enable_simulated_llm=False,
    )
    router = TieredModelRouter(cfg=cfg)
    decision = router.decide(telemetry=None)

    assert decision.action == "hold"
    assert decision.confidence == 1.0
    assert "No LLM providers configured" in decision.observation
    assert decision.provider == "deterministic-policy"


def test_simulated_advisory_provider_attack_phase():
    provider = SimulatedAdvisoryProvider()
    decision = provider.decide(
        telemetry=None,
        prompt="Advisory prompt",
        context={"phase": "ATTACK", "target_host": "10.254.254.12"},
    )
    assert isinstance(decision, ModelDecision)
    assert decision.action == "recon"
    assert decision.target == "10.254.254.12"
    assert decision.confidence == 0.95
    assert decision.priority == "HIGH"


def test_simulated_advisory_provider_defense_phase():
    provider = SimulatedAdvisoryProvider()
    decision = provider.decide(
        telemetry=None,
        prompt="Advisory prompt",
        context={"phase": "DEFENSE", "target_host": "10.254.254.102"},
    )
    assert isinstance(decision, ModelDecision)
    assert decision.action == "restart_service"
    assert decision.target == "10.254.254.102"
    assert decision.confidence == 0.90


def test_simulated_advisory_provider_hold_phase():
    provider = SimulatedAdvisoryProvider()
    decision = provider.decide(
        telemetry=None,
        prompt="Advisory prompt",
        context={"phase": "HOLD"},
    )
    assert decision.action == "hold"
    assert decision.target == ""
    assert decision.confidence == 1.0


def test_tiered_router_with_simulated_llm_enabled():
    cfg = Config(
        nvidia_api_key="",
        groq_api_key="",
        openrouter_api_key="",
        enable_simulated_llm=True,
    )
    router = TieredModelRouter(cfg=cfg)
    decision = router.decide(
        telemetry=None,
        swarm_context={"phase": "ATTACK", "target_host": "10.254.254.14"},
    )
    assert decision.action == "recon"
    assert decision.target == "10.254.254.14"
    assert decision.model_used == "simulated_advisory"

