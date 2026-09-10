# KOTH Agent

An autonomous agent for King-of-the-Hill style attack/defense competitions with 4-agent swarm coordination.

## Multi-Tiered Advisory Decision Engine

Decisions follow a strict hierarchical escalation chain:
1. **Local Deterministic Policy**: Instant resolution for known telemetry patterns, downed own services, and file tampering without LLM roundtrips.
2. **NVIDIA Nemotron (`nvidia/nemotron-3.5-lightning-30b-a3b`)**: FAST / Tactical tier for routine telemetry analysis, reconnaissance, and rapid prioritization.
3. **Groq GPT-OSS 120B (`openai/gpt-oss-120b`)**: REASONING tier for complex conflicts, multi-service outages, and low-confidence escalations.
4. **OpenRouter GLM 5.3 Flash (`z-ai/glm-5.3-flash`)**: SPECIALIST tier for complex strategic analysis, provider disagreement resolution, and final escalation.
5. **Deterministic SAFE HOLD**: Fail-safe fallback if all providers fail, timeout, or circuit breakers trip.

> **CRITICAL ARCHITECTURAL INVARIANT**:
> All LLM models are strictly **ADVISORY ONLY**. LLMs have ZERO direct execution authority and NO raw shell access. Every proposed action MUST pass through the deterministic 4-stage authorization gate:
> `Policy Authorization -> Registry Authorization -> Task Authorization -> Final Execution Gate`.

---

## Swarm Architecture

- **4 Identical Worker Agents**: `agent-01`, `agent-02`, `agent-03`, `agent-04`
- **One Coordinator**: Centralized phase management (`ATTACK`, `DEFENSE`, `HOLD`), task queue, lease allocation, and heartbeat tracking.
- **LAN / Wi-Fi Support**: Configurable private IP binding (`SWARM_BIND_HOST`, `SWARM_PORT`), per-agent credential verification, and mutual TLS encryption.
- **Execution-Time Phase Fence**: Tasks belonging to previous epochs or mismatched phases are deterministically blocked at execution time.

---

## Structure

```
koth-agent/
  agent/
    main.py              # Orchestration loop (the "tick")
    config.py            # Environment & config loading, safety gates, profile management
    model_router.py      # Multi-tier router integration and metrics tracking
    db.py                # SQLite persistence for telemetry, actions, and model calls
    logger.py            # Structured millisecond-timestamped logging
    dashboard.py         # Local Flask web dashboard and status API
    telemetry.py         # Scoreboard polling and telemetry normalization
    llm/
      types.py           # ModelDecision, ProviderMetrics, and provider type definitions
      parser.py          # 6-stage JSON/markdown/<think> parsing engine
      base.py            # BaseLLMProvider with circuit breakers, retries, and metrics
      providers/
        nvidia.py        # NVIDIA Nemotron provider
        groq.py          # Groq GPT-OSS 120B provider
        openrouter.py    # OpenRouter GLM 5.3 Flash provider
      router.py          # TieredModelRouter escalation engine
      health.py          # Diagnostic CLI command for provider health checks
    security/
      policy.py          # Deterministic security policy and boundary enforcement
      execution_gate.py  # FinalExecutionGate 4-stage authorization chain
    swarm/
      coordinator.py     # SwarmCoordinator server and RBAC endpoints
      client.py          # HTTP SwarmClient with TLS and fail-safe degraded mode
      models.py          # Swarm data models (Phase, Task, Lease, AgentRole)
    defense/
      monitor.py         # Service health checks and file integrity monitoring
      firewall.py        # Host firewall rule generation
      patcher.py         # Service restart and automated rollback
    attack/
      recon.py           # Port scanner and service fingerprinting
      plugin_interface.py# ExploitPlugin contract
      dispatcher.py      # Allowlisted exploit plugin execution
  tests/                 # Comprehensive unit & integration test suite (290 tests)
  requirements.txt
```

---

## Setup & Configuration

```bash
# 1. Install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure environment (copy template)
cp .env.example .env
# Fill in your API keys in .env:
# NVIDIA_API_KEY=...
# GROQ_API_KEY=...
# OPENROUTER_API_KEY=...

# 3. Verify provider connectivity & health
python -m agent.llm.health

# 4. Run the full test suite
pytest -v

# 5. Build clean release package (automated secret scanning)
python scripts/package_release.py
```

---

## Safety & Compliance

This agent is built strictly for authorized use against infrastructure you own or designated targets within authorized competition rules of engagement. Arbitrary scanning, unconfigured targets, and raw command injection are strictly blocked by deterministic gates.
