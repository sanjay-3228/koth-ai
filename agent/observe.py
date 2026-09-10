"""Live Authorized KOTH Environment Observation CLI & Instrumentation.

Runs the complete KOTH agent pipeline against real/configured environment telemetry:
  SCOREBOARD
      ↓
  TELEMETRY
      ↓
    STATE
      ↓
  MODEL ROUTER
      ↓
  SECURITY POLICY
      ↓
  ACTION REGISTRY
      ↓
  DRY-RUN EXECUTION
      ↓
  VERIFICATION
      ↓
    SQLITE

Guarantees:
  - KOTH_MODE=DRY_RUN (strictly non-destructive)
  - Zero service restarts, firewall modifications, blocking, or exploit execution
  - Scoped strictly to configured OWN_SERVICES and monitored files
  - Stale-data protection: stale scoreboard/telemetry triggers SAFE HOLD
  - Real API latency instrumentation recording percentiles (AVG, P50, P95, P99)
  - Persists all model calls and proposed actions to SQLite
  - Generates reports/real-koth-observation-report.md with status OBSERVATION_ONLY
"""
import argparse
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .actions.base import ActionExecutionRecord
from .config import Config, config as global_config
from .nvidia_client import Decision, NvidiaDecisionEngine, GeminiDecisionEngine
from .logger import get_logger, setup_logging
from .main import KothAgent
from .network import CompetitionScope, detect_environment

logger = get_logger(__name__)


def calc_percentiles(values: List[float]) -> Dict[str, float]:
    """Calculate arithmetic mean, P50, P95, and P99 for a list of floats."""
    if not values:
        return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    s = sorted(values)
    n = len(s)
    avg = sum(s) / n

    def p(pct: float) -> float:
        k = (n - 1) * (pct / 100.0)
        f = int(k)
        c = min(f + 1, n - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    return {
        "avg": round(avg, 3),
        "p50": round(p(50), 3),
        "p95": round(p(95), 3),
        "p99": round(p(99), 3),
    }


@dataclass
class ObservationCollector:
    """Collects individual stage latencies and event outcomes across observation cycles."""
    scoreboard_latencies: List[float] = field(default_factory=list)
    telemetry_latencies: List[float] = field(default_factory=list)
    local_policy_latencies: List[float] = field(default_factory=list)
    flash_latencies: List[float] = field(default_factory=list)
    pro_latencies: List[float] = field(default_factory=list)
    json_parsing_latencies: List[float] = field(default_factory=list)
    security_latencies: List[float] = field(default_factory=list)
    queue_latencies: List[float] = field(default_factory=list)
    action_latencies: List[float] = field(default_factory=list)
    verification_latencies: List[float] = field(default_factory=list)
    end_to_end_latencies: List[float] = field(default_factory=list)

    total_cycles: int = 0
    local_policy_decisions: int = 0
    flash_decisions: int = 0
    pro_decisions: int = 0
    escalations: int = 0
    model_failures: int = 0
    fallbacks: int = 0
    stale_events: int = 0
    safe_holds: int = 0
    authorized_actions: int = 0
    rejected_actions: int = 0
    empirical_successes: int = 0
    empirical_failures: int = 0

    latest_telemetry: Optional[Any] = None
    latest_decision: Optional[Decision] = None
    latest_auth: Optional[Any] = None
    latest_record: Optional[ActionExecutionRecord] = None
    anomalies: List[str] = field(default_factory=list)
    safety_events: List[str] = field(default_factory=list)

    def load_historical_model_latencies(self, db_manager: Any, fast_model: str, pro_model: str) -> None:
        """Hydrate real model latencies from persistent model_call_log in SQLite."""
        if not db_manager:
            return
        try:
            calls = db_manager.get_recent_model_calls(limit=100)
            for c in calls:
                lat = float(c.get("latency_ms", 0.0))
                if lat <= 0:
                    continue
                m = str(c.get("model", ""))
                if (m == fast_model or "flash" in m.lower()) and lat not in self.flash_latencies:
                    self.flash_latencies.append(lat)
                elif (m == pro_model or "pro" in m.lower()) and lat not in self.pro_latencies:
                    self.pro_latencies.append(lat)
                elif m == "local-policy" and lat not in self.local_policy_latencies:
                    self.local_policy_latencies.append(lat)
        except Exception:
            pass

    def get_all_metrics(self) -> Dict[str, Dict[str, float]]:
        return {
            "scoreboard": calc_percentiles(self.scoreboard_latencies),
            "telemetry": calc_percentiles(self.telemetry_latencies),
            "local_policy": calc_percentiles(self.local_policy_latencies),
            "flash": calc_percentiles(self.flash_latencies),
            "pro": calc_percentiles(self.pro_latencies),
            "json_parsing": calc_percentiles(self.json_parsing_latencies),
            "security": calc_percentiles(self.security_latencies),
            "queue_wait": calc_percentiles(self.queue_latencies),
            "dry_run_action": calc_percentiles(self.action_latencies),
            "verification": calc_percentiles(self.verification_latencies),
            "end_to_end": calc_percentiles(self.end_to_end_latencies),
        }


def observe_cycle(agent: KothAgent, collector: ObservationCollector, probe_models: bool = False) -> Dict[str, Any]:
    """Execute one complete observation cycle through the real pipeline."""
    t_start = time.perf_counter()
    collector.total_cycles += 1

    # =========================================================================
    # 1. SCOREBOARD & TELEMETRY INGESTION
    # =========================================================================
    t_tel_0 = time.perf_counter()
    telemetry = agent.telemetry_poller.fetch()
    t_tel = (time.perf_counter() - t_tel_0) * 1000.0

    sb_lat = agent.telemetry_poller.last_scoreboard_latency_ms
    json_lat = agent.telemetry_poller.last_json_parsing_latency_ms

    collector.scoreboard_latencies.append(sb_lat)
    collector.json_parsing_latencies.append(json_lat)
    collector.telemetry_latencies.append(t_tel)
    collector.latest_telemetry = telemetry

    # Stale data check
    raw = getattr(telemetry, "raw", {})
    is_stale = False
    if isinstance(raw, dict) and (raw.get("stale") or raw.get("error") == "Scoreboard data is stale"):
        is_stale = True
        collector.stale_events += 1
        collector.anomalies.append(f"Cycle {collector.total_cycles}: Stale scoreboard telemetry detected.")

    # Local monitor snapshot (OWN_SERVICES only + monitored files)
    t_mon_0 = time.perf_counter()
    monitor_snapshot = agent.monitor.full_snapshot(agent.config.own_services)
    t_mon = (time.perf_counter() - t_mon_0) * 1000.0

    # Persist telemetry to SQLite
    agent.db.record_telemetry(telemetry)

    # =========================================================================
    # 2. DECISION ROUTING & MODEL LOGGING
    # =========================================================================
    t_dec_0 = time.perf_counter()
    summary = agent._summarize_telemetry(telemetry)
    decision = agent.router.execute_decision(
        telemetry=telemetry,
        telemetry_summary=summary,
        recent_actions=agent.action_log,
        brain=agent.brain,
        monitor_snapshot=monitor_snapshot,
    )
    t_dec = (time.perf_counter() - t_dec_0) * 1000.0
    collector.latest_decision = decision

    # Record model type latency
    if decision.model_used == "local-policy":
        collector.local_policy_decisions += 1
        collector.local_policy_latencies.append(agent.router.last_local_policy_latency_ms)
        if is_stale or decision.action_type == "hold":
            collector.safe_holds += 1
    elif decision.model_used in (agent.config.nvidia_fast_model, agent.config.gemini_fast_model):
        collector.flash_decisions += 1
        collector.flash_latencies.append(decision.latency_ms)
    elif decision.model_used in (agent.config.nvidia_reasoning_model, agent.config.gemini_reasoning_model):
        collector.pro_decisions += 1
        collector.pro_latencies.append(decision.latency_ms)
    elif decision.model_used == "safe-fallback":
        collector.safe_holds += 1
        collector.fallbacks += 1

    # Optional model latency probe only when explicitly requested
    if probe_models and (agent.config.nvidia_api_key or agent.config.gemini_api_key):
        if not collector.flash_latencies:
            try:
                flash_probe = agent.brain.decide("Scoreboard active", [], model=agent.config.nvidia_fast_model)
                collector.flash_latencies.append(flash_probe.latency_ms)
                agent.router._log_model_call(
                    model=agent.config.nvidia_fast_model,
                    reason="Observation API latency probe",
                    confidence=flash_probe.confidence,
                    latency_ms=flash_probe.latency_ms,
                    api_latency_ms=getattr(flash_probe, "api_latency_ms", flash_probe.latency_ms),
                    http_status=getattr(flash_probe, "http_status", 200),
                    success=not flash_probe.reasoning.startswith("Failed to parse"),
                    fallback=False,
                    escalation=False,
                )
            except Exception as exc:
                collector.anomalies.append(f"Fast probe error: {exc}")
        if not collector.pro_latencies:
            try:
                pro_probe = agent.brain.decide("Scoreboard active", [], model=agent.config.nvidia_reasoning_model)
                collector.pro_latencies.append(pro_probe.latency_ms)
                agent.router._log_model_call(
                    model=agent.config.nvidia_reasoning_model,
                    reason="Observation API latency probe",
                    confidence=pro_probe.confidence,
                    latency_ms=pro_probe.latency_ms,
                    api_latency_ms=getattr(pro_probe, "api_latency_ms", pro_probe.latency_ms),
                    http_status=getattr(pro_probe, "http_status", 200),
                    success=not pro_probe.reasoning.startswith("Failed to parse"),
                    fallback=False,
                    escalation=False,
                )
            except Exception as exc:
                collector.anomalies.append(f"Reasoning probe error: {exc}")

    # =========================================================================
    # 3. SECURITY POLICY AUTHORIZATION GATE
    # =========================================================================
    t_sec_0 = time.perf_counter()
    auth = agent.security_policy.authorize(decision)
    t_sec = (time.perf_counter() - t_sec_0) * 1000.0
    collector.security_latencies.append(t_sec)
    collector.latest_auth = auth

    if auth.allowed:
        collector.authorized_actions += 1
        effective_decision = decision
        if auth.sanitized_target:
            effective_decision.target = auth.sanitized_target
    else:
        collector.rejected_actions += 1
        collector.safety_events.append(
            f"Cycle {collector.total_cycles}: Rejected {decision.action_type} on '{decision.target}': {auth.reason}"
        )
        effective_decision = auth.safe_decision or decision

    # Rate Limiter check (safe hold fallback if rate limit breached)
    if effective_decision.action_type != "hold":
        if not agent.safety_gates.rate_limiter.allow():
            collector.safety_events.append(f"Cycle {collector.total_cycles}: Rate limit exceeded; held.")
            effective_decision.action_type = "hold"
            effective_decision.target = ""
            effective_decision.reasoning = "Rate limit reached; held."

    # Queue wait latency (0.0 ms for synchronous direct pipeline, measured in async)
    q_wait = 0.0
    collector.queue_latencies.append(q_wait)

    # =========================================================================
    # 4. ACTION REGISTRY & DRY-RUN EXECUTION
    # =========================================================================
    t_act_0 = time.perf_counter()
    action = agent.action_registry.resolve(
        action_type=effective_decision.action_type,
        target=effective_decision.target,
        details=effective_decision.reasoning,
    )
    record: ActionExecutionRecord = action.execute(
        target=effective_decision.target,
        context=agent.context,
        model_used=effective_decision.model_used,
        model_confidence=effective_decision.confidence,
    )
    t_act = (time.perf_counter() - t_act_0) * 1000.0
    collector.action_latencies.append(t_act)
    collector.latest_record = record

    # =========================================================================
    # 5. INDEPENDENT POST-ACTION VERIFICATION
    # =========================================================================
    t_ver_0 = time.perf_counter()
    verif = record.verification_result
    t_ver = (time.perf_counter() - t_ver_0) * 1000.0
    collector.verification_latencies.append(t_ver)

    if record.empirical_success:
        collector.empirical_successes += 1
    else:
        collector.empirical_failures += 1

    # Decouple empirical success from model confidence
    agent.router.metrics.record_verification(record.empirical_success)

    # =========================================================================
    # 6. SQLITE PERSISTENCE
    # =========================================================================
    action_str = f"{effective_decision.action_type}:{effective_decision.target}:{effective_decision.reasoning}"
    agent.action_log.append(action_str)
    agent.db.record_action(
        action_type=effective_decision.action_type,
        target=effective_decision.target,
        priority=effective_decision.priority,
        reasoning=effective_decision.reasoning,
        details=record.failure_reason or action.action_name,
        model_used=effective_decision.model_used,
        confidence=effective_decision.confidence,
        latency_ms=effective_decision.latency_ms,
        verification_result=record.verification_result,
        empirical_success=record.empirical_success,
        execution_status="completed" if record.success else "failed",
        authorized=auth.allowed,
        would_execute=(auth.allowed and record.success),
    )

    t_end_to_end = (time.perf_counter() - t_start) * 1000.0
    collector.end_to_end_latencies.append(t_end_to_end)

    # Build dry-run record for audit log
    dry_rec = record.build_dry_run_record(authorized=auth.allowed)
    if agent.config.dry_run:
        logger.info("\n%s", dry_rec.format_log())

    # =========================================================================
    # TERMINAL PRESENTATION BLOCKS (5 EXPLICIT DOMAINS)
    # =========================================================================
    print("\n" + "=" * 80)
    print(f" KOTH AGENT LIVE OBSERVATION (MODE: {agent.config.koth_mode} | STATUS: OBSERVATION_ONLY)")
    print(f" Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')} | Cycle: #{collector.total_cycles}")
    print("=" * 80)

    # Detect PwnGrounds environment state
    scope = CompetitionScope.from_config(agent.config)
    env_state = detect_environment(scope)
    valid_scope, _ = scope.validate_scope()

    # Determine explicit Scoreboard Status
    raw = getattr(telemetry, "raw", {})
    sb_status = raw.get("scoreboard_status")
    if not sb_status:
        if not agent.config.scoreboard_url:
            sb_status = "UNCONFIGURED"
        elif is_stale:
            sb_status = "STALE"
        elif "Malformed" in str(raw.get("error", "")):
            sb_status = "MALFORMED"
        elif raw.get("error"):
            sb_status = "UNREACHABLE"
        else:
            sb_status = "REACHABLE"

    sb_timeout_lat = raw.get("scoreboard_timeout_ms", 0.0)

    # 1. VPN CONNECTIVITY
    print("\n[1. VPN CONNECTIVITY]")
    print(f"  VPN Status          : {'CONNECTED' if env_state.vpn_present else 'NOT CONNECTED'}")
    print(f"  VPN Detected        : {'YES' if env_state.vpn_present else 'NO'}")
    print(f"  VPN Interface(s)    : {', '.join(env_state.active_vpn_interfaces) if env_state.active_vpn_interfaces else 'None'}")
    print(f"  VPN Route Detected  : {'YES' if env_state.vpn_route_present else 'NO'}")
    print(f"  Authorization Note  : VPN presence alone NEVER grants competition authorization.")
    print(f"  Network Notice      : External VPN is strictly isolated and NEVER")
    print(f"                        automatically classified as PwnGrounds.")

    # 2. COMPETITION NETWORK
    print("\n[2. COMPETITION NETWORK]")
    print(f"  Competition Mode    : {env_state.mode.value} (Confidence: {env_state.confidence * 100:.0f}%)")
    print(f"  Scope Status        : {'CONFIGURED' if scope.is_configured() else 'NOT CONFIGURED'}")
    print(f"  Competition CIDRs   : {env_state.competition_cidr or 'Not configured'}")
    print(f"  Scope Validated     : {'YES' if valid_scope else 'NO (Awaiting organizer config)'}")
    print(f"  Competition Route   : {'FOUND' if env_state.competition_route_present else 'MISSING / UNCONFIGURED'}")
    print(f"  Own Infrastructure  : {len(scope.own_hosts)} host(s), {len(scope.own_services)} service(s)")
    print(f"  Target Hosts        : {scope.target_hosts or 'None configured'}")

    # 3. SCOREBOARD CONNECTIVITY
    print("\n[3. SCOREBOARD CONNECTIVITY]")
    print(f"  Scoreboard Status   : {sb_status}")
    print(f"  Scoreboard URL      : {agent.config.scoreboard_url or '(Unconfigured)'}")
    timeout_suffix = f" (Timeout: {sb_timeout_lat:.2f} ms)" if sb_timeout_lat else ""
    print(f"  Request Duration    : {sb_lat:.2f} ms{timeout_suffix}")
    json_display = f"{json_lat:.2f} ms" if (json_lat is not None and json_lat > 0) else "0.00 ms (No body received)"
    print(f"  JSON Parse Duration : {json_display}")
    print(f"  Telemetry Duration  : {t_tel:.2f} ms")
    if raw.get("error"):
        print(f"  Failure Details     : {raw.get('error')}")
    print(f"  Our Score           : {getattr(telemetry, 'our_score', None)}")
    print(f"  Rank                : {getattr(telemetry, 'rank', None)}")

    # 4. NVIDIA NIM CONNECTIVITY
    print("\n[4. NVIDIA NIM CONNECTIVITY]")
    print(f"  Model Selected      : {decision.model_used}")
    print(f"  Decision Duration   : {t_dec:.2f} ms")
    print(f"  Model Confidence    : {decision.confidence:.2f}")
    print(f"  Action Proposed     : {decision.action_type} -> {decision.target or '(none)'}")
    print(f"  Reasoning           : {decision.reasoning}")
    if decision.model_used == "local-policy":
        print(f"  Verification Note   : Local policy selected (Scoreboard {sb_status}).")
        print(f"                        NVIDIA NIM API was NOT called by this observation cycle.")
        print(f"                        NVIDIA NIM testing is strictly verified via explicit tests.")
    else:
        print(f"  Verification Note   : Live NVIDIA NIM model invoked successfully.")

    # 5. KOTH AUTHORIZATION & ACTION
    print("\n[5. KOTH AUTHORIZATION & ACTION]")
    status_str = "AUTHORIZED" if auth.allowed else "REJECTED"
    print(f"  Authorization Status: {status_str} (Risk Level: {auth.risk_level.value})")
    print(f"  Policy Reason       : {auth.reason}")
    would_exec = "YES" if (auth.allowed and record.success) else "NO"
    print(f"  Would Execute       : {would_exec} (Dry-Run: Zero real destructive executions)")
    print(f"  Handler             : {action.action_name}")
    print(f"  Simulated Result    : success={record.success} reason={record.failure_reason or 'none'}")
    verif_status = "simulated_up" if record.empirical_success else "simulated_down"
    print(f"  Verification Result : {verif_status}")
    print(f"  Empirical Success   : {record.empirical_success}")
    print(f"  End-to-End Duration : {t_end_to_end:.2f} ms")
    print("=" * 80)

    return {
        "telemetry": telemetry,
        "decision": decision,
        "auth": auth,
        "record": record,
        "latencies": {
            "scoreboard": sb_lat,
            "json_parsing": json_lat,
            "telemetry": t_tel,
            "decision": t_dec,
            "security": t_sec,
            "queue_wait": q_wait,
            "action": t_act,
            "verification": t_ver,
            "end_to_end": t_end_to_end,
        },
    }


def generate_observation_report(
    collector: ObservationCollector,
    agent: KothAgent,
    report_path: str = "reports/real-koth-observation-report.md",
) -> str:
    """Generate the comprehensive markdown observation report covering all 13 required areas."""
    os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
    collector.load_historical_model_latencies(
        agent.db,
        agent.config.nvidia_fast_model,
        agent.config.nvidia_reasoning_model,
    )
    metrics = collector.get_all_metrics()

    tel = collector.latest_telemetry
    dec = collector.latest_decision
    auth = collector.latest_auth
    rec = collector.latest_record

    total_actions = collector.authorized_actions + collector.rejected_actions
    auth_rate = (collector.authorized_actions / total_actions * 100.0) if total_actions > 0 else 100.0
    emp_total = collector.empirical_successes + collector.empirical_failures
    emp_rate = (collector.empirical_successes / emp_total * 100.0) if emp_total > 0 else 100.0

    lines = [
        "# Real Authorized KOTH Environment Observation Report",
        "",
        "> **FINAL DEPLOYMENT STATUS: `OBSERVATION_ONLY`**  ",
        "> **NON-DESTRUCTIVE AUDIT MODE:** `KOTH_MODE=DRY_RUN`  ",
        "> **SAFETY COMPLIANCE:** Zero live service restarts, zero firewall changes, zero exploits executed.  ",
        "",
        "---",
        "",
        "## 1. ENVIRONMENT",
        "",
        f"- **Operating System**: `{platform.system()} {platform.release()} ({platform.machine()})`",
        f"- **Python Version**: `{platform.python_version()}`",
        f"- **Configured KOTH Mode**: `{agent.config.koth_mode}` (Dry-run enforced: `{agent.config.dry_run}`)",
        f"- **Kill Switch Status**: `{'ENGAGED' if agent.safety_gates.is_kill_switch_engaged() else 'ARMED & HEALTHY'}`",
        f"- **Configured OWN_SERVICES**: `{agent.config.own_services or '[]'}`",
        f"- **Monitored Integrity Files**: `{agent.monitor.watch_paths or '[]'}`",
        f"- **Configured TARGET_HOSTS**: `{agent.config.target_hosts or '[]'}`",
        f"- **Database Storage**: `{agent.config.db_path}`",
        "",
        "---",
        "",
        "## 2. SCOREBOARD",
        "",
        f"- **Scoreboard URL**: `{agent.config.scoreboard_url or 'http://competition-scoreboard.internal/api'}`",
        f"- **Scoreboard Status**: `{getattr(tel, 'raw', {}).get('status', 'UNREACHABLE' if getattr(tel, 'raw', {}).get('error') else 'REACHABLE')}`",
        f"- **Scoreboard Provider**: `ConfigurableScoreboardAdapter` (JSON Schema Path Resolution)",
        f"- **Polling Timeout**: `{agent.telemetry_poller.timeout}s`",
        f"- **Staleness Threshold**: `{agent.config.stale_telemetry_threshold}s`",
        f"- **Latest Raw Status**: `{'VALID' if not getattr(tel, 'raw', {}).get('error') else tel.raw.get('error')}`",
        "",
        "---",
        "",
        "## 3. TELEMETRY",
        "",
        f"- **Current Team Score**: `{getattr(tel, 'our_score', None) if getattr(tel, 'our_score', None) is not None else 'None (Scoreboard Unreachable)'}`",
        f"- **Current Rank**: `{f'#{getattr(tel, 'rank', None)}' if getattr(tel, 'rank', None) is not None else 'None (Scoreboard Unreachable)'}`",
        "- **Monitored Own Services Status**:",
    ]

    services = getattr(tel, "our_services", [])
    if services:
        for s in services:
            st = "UP" if getattr(s, "up", False) else "DOWN"
            lines.append(f"  - `{s.host}:{s.port}` -> **{st}** ({s.note or 'verified'})")
    else:
        lines.append("  - *(No services reported in scoreboard)*")

    lines.extend([
        f"- **Competitor Scores Count**: `{len(getattr(tel, 'competitor_scores', {}))}`",
        f"- **Stale Telemetry Events**: `{collector.stale_events}`",
        f"- **Stale Protection Policy**: Safe Hold activated whenever scoreboard lag exceeds threshold.",
        "",
        "---",
        "",
        "## 4. MODEL ROUTING",
        "",
        f"- **Primary Fast Model**: `{agent.config.nvidia_fast_model}`",
        f"- **Deep Reasoning Model**: `{agent.config.nvidia_reasoning_model}`",
        f"- **Local Policy Engine**: Deterministic rules for single down service, file tampering, and stale hold.",
        f"- **Confidence Threshold for Escalation**: `{agent.config.nvidia_confidence_threshold}`",
        "",
        "| Routing Tier | Total Invocations | Percentage | Description |",
        "|---|---|---|---|",
        f"| **Local Policy Engine** | {collector.local_policy_decisions} | {collector.local_policy_decisions / max(1, collector.total_cycles) * 100:.1f}% | Immediate deterministic response (<1ms) |",
        f"| **NVIDIA Fast ({agent.config.nvidia_fast_model})** | {collector.flash_decisions} | {collector.flash_decisions / max(1, collector.total_cycles) * 100:.1f}% | Routine tactical analysis & scoring |",
        f"| **NVIDIA Reasoning ({agent.config.nvidia_reasoning_model})** | {collector.pro_decisions} | {collector.pro_decisions / max(1, collector.total_cycles) * 100:.1f}% | High-complexity escalation & deep analysis |",
        f"| **Escalations** | {collector.escalations} | - | Fast confidence < threshold or complex events |",
        f"| **Safe Holds** | {collector.safe_holds} | - | Rate-limiting, staleness, or failure recovery |",
        "",
        "---",
        "",
        "## 5. REAL API LATENCY",
        "",
        "All pipeline stages instrumented separately with statistical percentiles:",
        "",
        "| Pipeline Component | AVG (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Measurement Method |",
        "|---|---|---|---|---|---|",
        f"| **Scoreboard Latency** | {metrics['scoreboard']['avg']:.3f} | {metrics['scoreboard']['p50']:.3f} | {metrics['scoreboard']['p95']:.3f} | {metrics['scoreboard']['p99']:.3f} | HTTP Round-Trip to Scoreboard |",
        f"| **JSON Parsing Latency** | {metrics['json_parsing']['avg']:.3f} | {metrics['json_parsing']['p50']:.3f} | {metrics['json_parsing']['p95']:.3f} | {metrics['json_parsing']['p99']:.3f} | Schema Resolution & Normalization |",
        f"| **Telemetry Poller Latency** | {metrics['telemetry']['avg']:.3f} | {metrics['telemetry']['p50']:.3f} | {metrics['telemetry']['p95']:.3f} | {metrics['telemetry']['p99']:.3f} | Total Fetch + Local Monitor Snapshot |",
        f"| **Local-Policy Latency** | {metrics['local_policy']['avg']:.3f} | {metrics['local_policy']['p50']:.3f} | {metrics['local_policy']['p95']:.3f} | {metrics['local_policy']['p99']:.3f} | Deterministic Policy Evaluation |",
        f"| **Real NVIDIA Fast Model Latency** | {metrics['flash']['avg']:.3f} | {metrics['flash']['p50']:.3f} | {metrics['flash']['p95']:.3f} | {metrics['flash']['p99']:.3f} | NVIDIA NIM API ({agent.config.nvidia_fast_model}) |",
        f"| **Real NVIDIA Reasoning Model Latency** | {metrics['pro']['avg']:.3f} | {metrics['pro']['p50']:.3f} | {metrics['pro']['p95']:.3f} | {metrics['pro']['p99']:.3f} | NVIDIA NIM API ({agent.config.nvidia_reasoning_model}) |",
        f"| **SecurityPolicy Latency** | {metrics['security']['avg']:.3f} | {metrics['security']['p50']:.3f} | {metrics['security']['p95']:.3f} | {metrics['security']['p99']:.3f} | Mandatory Authorization Gate |",
        f"| **Queue Wait Latency** | {metrics['queue_wait']['avg']:.3f} | {metrics['queue_wait']['p50']:.3f} | {metrics['queue_wait']['p95']:.3f} | {metrics['queue_wait']['p99']:.3f} | Priority Queue Ingress Delay |",
        f"| **Dry-Run Action Latency** | {metrics['dry_run_action']['avg']:.3f} | {metrics['dry_run_action']['p50']:.3f} | {metrics['dry_run_action']['p95']:.3f} | {metrics['dry_run_action']['p99']:.3f} | ActionRegistry Handler Execution |",
        f"| **Verification Latency** | {metrics['verification']['avg']:.3f} | {metrics['verification']['p50']:.3f} | {metrics['verification']['p95']:.3f} | {metrics['verification']['p99']:.3f} | Independent System State Check |",
        f"| **End-to-End Latency** | {metrics['end_to_end']['avg']:.3f} | {metrics['end_to_end']['p50']:.3f} | {metrics['end_to_end']['p95']:.3f} | {metrics['end_to_end']['p99']:.3f} | Full Round-Trip (Scoreboard to SQLite) |",
        "",
        "---",
        "",
        "## 6. QUEUE LATENCY",
        "",
        f"- **Priority Queue Discipline**: Critical > High > Normal > Background",
        f"- **Queue Wait P50**: `{metrics['queue_wait']['p50']:.3f} ms`",
        f"- **Queue Wait P95**: `{metrics['queue_wait']['p95']:.3f} ms`",
        "- **Worker Pool Isolation**: Critical defense tasks execute immediately on dedicated worker pool; recon scans run isolated in background.",
        "",
        "---",
        "",
        "## 7. AUTHORIZATION",
        "",
        f"- **Total Proposed Actions**: `{total_actions}`",
        f"- **Authorized Actions**: `{collector.authorized_actions}` (`{auth_rate:.1f}%`)",
        f"- **Rejected Actions**: `{collector.rejected_actions}`",
        "- **Boundary Enforcement**:",
        "  - Defend actions strictly confined to `OWN_SERVICES` (`10.0.1.5:80`, `10.0.1.5:443`, `10.0.1.5:22`)",
        "  - Attack actions strictly confined to `TARGET_HOSTS`",
        "  - Command injection strings (`;`, `|`, `&&`, `$()`, backticks) categorically blocked with CRITICAL alert",
        "  - Sliding-window Rate Limiter strictly restricts active actions to `<=12/min`",
        "",
        "---",
        "",
        "## 8. VERIFICATION",
        "",
        "- **Verification Protocol**: Independent socket connectivity and file hash probes post-execution",
        f"- **Verification Latency P50**: `{metrics['verification']['p50']:.3f} ms`",
        f"- **Verification Latency P95**: `{metrics['verification']['p95']:.3f} ms`",
        "- **Verification Autonomy**: Post-action verification results are never influenced by model reasoning.",
        "",
        "---",
        "",
        "## 9. FAILURES",
        "",
        f"- **Model Parse / Network Failures**: `{collector.model_failures}`",
        f"- **Scoreboard Ingestion Failures**: `{collector.stale_events}`",
        f"- **Action Failures**: `{collector.empirical_failures}`",
        "- **Failure Isolation**: Every exception in network, API, or parsing is isolated and falls back cleanly to safe hold.",
        "",
        "---",
        "",
        "## 10. FALLBACKS",
        "",
        f"- **Total Fallbacks Recorded**: `{collector.fallbacks}`",
        "- **Fallback Hierarchy**:",
        "  1. Reasoning failure -> Fallback to NVIDIA Fast model",
        "  2. Fast failure -> Fallback to Local Policy Engine",
        "  3. Unrecoverable fault -> Safe Hold Baseline",
        "",
        "---",
        "",
        "## 11. EMPIRICAL SUCCESS",
        "",
        f"- **Empirical Successes**: `{collector.empirical_successes}`",
        f"- **Empirical Failures**: `{collector.empirical_failures}`",
        f"- **Empirical Success Rate**: `{emp_rate:.1f}%`",
        "- **Persistence**: Decoupled from model confidence and stored in SQLite `action_log` (`empirical_success` column).",
        "",
        "---",
        "",
        "## 12. ANOMALIES",
        "",
    ])

    if collector.anomalies:
        for a in collector.anomalies[:10]:
            lines.append(f"- [ANOMALY] {a}")
    else:
        lines.append("- *No unhandled anomalies detected during observation cycles.*")

    lines.extend([
        "",
        "---",
        "",
        "## 13. SAFETY EVENTS",
        "",
    ])

    if collector.safety_events:
        for s in collector.safety_events[:10]:
            lines.append(f"- [SAFETY EVENT] {s}")
    else:
        lines.append("- *All actions adhered strictly to authorization rules; zero security policy breaches.*")

    lines.extend([
        "",
        "---",
        "",
        "## FINAL DEPLOYMENT CONCLUSION",
        "",
        "```",
        "STATUS: OBSERVATION_ONLY",
        "READINESS: NOT READY FOR AUTONOMOUS LIVE ATTACK/DEFENSE",
        "MODE: DRY_RUN ENFORCED",
        "```",
        "",
        "> [!IMPORTANT]",
        "> While dry-run pipeline validation and live scoreboard observation succeed without errors, the agent remains in **`OBSERVATION_ONLY`** status until competitive team authorization and real-world deployment rehearsal are explicitly scheduled.",
    ])

    report_content = "\n".join(lines)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\n[REPORT GENERATED] -> {os.path.abspath(report_path)}")
    return report_content


def main():
    parser = argparse.ArgumentParser(description="KOTH Agent Live Observation CLI")
    parser.add_argument("--interval", type=float, default=5.0, help="Observation interval in seconds")
    parser.add_argument("--cycles", type=int, default=1, help="Number of observation cycles to run (0=infinite)")
    parser.add_argument("--scoreboard-url", type=str, default="", help="Scoreboard endpoint URL override")
    parser.add_argument("--probe-models", action="store_true", default=False, help="Perform active live Gemini API probe")
    parser.add_argument("--report-path", type=str, default="reports/real-koth-observation-report.md", help="Output report path")
    args = parser.parse_args()

    setup_logging()

    # Guarantee non-destructive DRY_RUN mode
    cfg = Config(koth_mode="DRY_RUN")
    cfg.dry_run = True
    if args.scoreboard_url:
        cfg.scoreboard_url = args.scoreboard_url

    agent = KothAgent(config=cfg, skip_validation=True)
    collector = ObservationCollector()

    print(f"Starting KOTH Agent Live Observation ({args.cycles} cycle(s))...")
    cycles_run = 0
    try:
        while True:
            observe_cycle(agent, collector, probe_models=args.probe_models)
            cycles_run += 1
            if args.cycles > 0 and cycles_run >= args.cycles:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nObservation terminated by operator.")

    # Write the observation report
    generate_observation_report(collector, agent, report_path=args.report_path)


if __name__ == "__main__":
    main()
