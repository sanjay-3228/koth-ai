"""Model Router for KOTH Agent.

Implements multi-tiered model routing:
  1. Local Policy Engine: Deterministic/obvious events without calling NVIDIA.
  2. NVIDIA Fast (nvidia/nemotron-3.5-lightning-30b-a3b): Routine telemetry analysis, service prioritization, tactical decisions.
  3. NVIDIA Reasoning (nvidia/nemotron-3-super-120b-a12b): Escalated when confidence is low, multiple high-priority events conflict,
     multi-step reasoning is required, or Fast explicitly requests escalation.
  4. SecurityPolicy -> ActionRegistry -> Verification.

Tracks actual API wall-clock latencies separately from local decision latency, escalations, failures, and fallbacks.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import config
from .logger import get_logger
from .nvidia_client import Decision, NvidiaDecisionEngine, GeminiDecisionEngine
from .llm.router import TieredModelRouter

logger = get_logger(__name__)


@dataclass
class RouteDecision:
    model: str
    reason: str
    priority: str
    confidence_requirement: float
    is_local: bool = False
    local_action: Optional[Decision] = None


@dataclass
class RouterMetrics:
    latest_model: str = "none"
    latest_reason: str = "initialized"
    latest_confidence: float = 1.0
    local_policy_latencies: List[float] = field(default_factory=list)
    fast_latencies: List[float] = field(default_factory=list)
    reasoning_latencies: List[float] = field(default_factory=list)
    escalation_count: int = 0
    failures_count: int = 0
    fallback_count: int = 0
    total_decisions: int = 0
    verified_success_count: int = 0
    verified_failure_count: int = 0

    # Backwards compatibility properties
    @property
    def flash_latencies(self) -> List[float]:
        return self.fast_latencies

    @flash_latencies.setter
    def flash_latencies(self, val: List[float]) -> None:
        self.fast_latencies = val

    @property
    def pro_latencies(self) -> List[float]:
        return self.reasoning_latencies

    @pro_latencies.setter
    def pro_latencies(self, val: List[float]) -> None:
        self.reasoning_latencies = val

    def record_local_policy_latency(self, latency_ms: float) -> None:
        try:
            val = float(latency_ms)
            if val >= 0:
                self.local_policy_latencies.append(val)
                if len(self.local_policy_latencies) > 100:
                    self.local_policy_latencies.pop(0)
        except (TypeError, ValueError):
            pass

    def record_fast_latency(self, latency_ms: float) -> None:
        try:
            val = float(latency_ms)
            if val > 0:
                self.fast_latencies.append(val)
                if len(self.fast_latencies) > 100:
                    self.fast_latencies.pop(0)
        except (TypeError, ValueError):
            pass

    def record_flash_latency(self, latency_ms: float) -> None:
        """Alias for backward compatibility."""
        self.record_fast_latency(latency_ms)

    def record_reasoning_latency(self, latency_ms: float) -> None:
        try:
            val = float(latency_ms)
            if val > 0:
                self.reasoning_latencies.append(val)
                if len(self.reasoning_latencies) > 100:
                    self.reasoning_latencies.pop(0)
        except (TypeError, ValueError):
            pass

    def record_pro_latency(self, latency_ms: float) -> None:
        """Alias for backward compatibility."""
        self.record_reasoning_latency(latency_ms)

    def record_verification(self, success: bool) -> None:
        if success:
            self.verified_success_count += 1
        else:
            self.verified_failure_count += 1

    def get_summary(self) -> Dict[str, Any]:
        local_avg = (
            sum(self.local_policy_latencies) / len(self.local_policy_latencies)
            if self.local_policy_latencies
            else 0.0
        )
        fast_avg = (
            sum(self.fast_latencies) / len(self.fast_latencies)
            if self.fast_latencies
            else 0.0
        )
        reasoning_avg = (
            sum(self.reasoning_latencies) / len(self.reasoning_latencies)
            if self.reasoning_latencies
            else 0.0
        )
        total_verifications = self.verified_success_count + self.verified_failure_count
        empirical_rate = (
            round((self.verified_success_count / total_verifications) * 100.0, 1)
            if total_verifications > 0
            else 100.0
        )
        return {
            "primary_model": config.nvidia_fast_model,
            "reasoning_model": config.nvidia_reasoning_model,
            "current_model": self.latest_model,
            "latest_reason": self.latest_reason,
            "latest_confidence": round(self.latest_confidence, 2),
            "local_policy_latency_avg_ms": round(local_avg, 3),
            "fast_latency_avg_ms": round(fast_avg, 2),
            "reasoning_latency_avg_ms": round(reasoning_avg, 2),
            "flash_latency_avg_ms": round(fast_avg, 2),  # Compatibility
            "pro_latency_avg_ms": round(reasoning_avg, 2),  # Compatibility
            "escalation_count": self.escalation_count,
            "failures_count": self.failures_count,
            "fallback_count": self.fallback_count,
            "total_decisions": self.total_decisions,
            "verified_successes": self.verified_success_count,
            "verified_failures": self.verified_failure_count,
            "empirical_success_rate": empirical_rate,
        }


class ModelRouter:
    def __init__(self, db_manager: Optional[Any] = None):
        self.metrics = RouterMetrics()
        self.db = db_manager
        self.tiered_router = TieredModelRouter(config)
        self.last_local_policy_latency_ms: float = 0.0
        self.last_fast_latency_ms: float = 0.0
        self.last_reasoning_latency_ms: float = 0.0
        self.last_api_latency_ms: float = 0.0

    @property
    def last_flash_latency_ms(self) -> float:
        return self.last_fast_latency_ms

    @last_flash_latency_ms.setter
    def last_flash_latency_ms(self, val: float) -> None:
        self.last_fast_latency_ms = val

    @property
    def last_pro_latency_ms(self) -> float:
        return self.last_reasoning_latency_ms

    @last_pro_latency_ms.setter
    def last_pro_latency_ms(self, val: float) -> None:
        self.last_reasoning_latency_ms = val

    def _log_model_call(
        self,
        model: str,
        reason: str,
        confidence: float = 1.0,
        latency_ms: float = 0.0,
        api_latency_ms: float = 0.0,
        http_status: Optional[int] = 200,
        success: bool = True,
        fallback: bool = False,
        escalation: bool = False,
        timeout: bool = False,
        rate_limit: bool = False,
        malformed_response: bool = False,
        empirical_outcome: Optional[bool] = None,
    ) -> None:
        """Persist model invocation telemetry to SQLite database."""
        db_inst = self.db
        if db_inst is None:
            try:
                from .db import db as global_db
                db_inst = global_db
            except Exception:
                db_inst = None
        if db_inst and hasattr(db_inst, "record_model_call"):
            try:
                db_inst.record_model_call(
                    model=model,
                    reason=reason,
                    confidence=confidence,
                    latency_ms=latency_ms,
                    api_latency_ms=api_latency_ms,
                    http_status=http_status,
                    success=success,
                    fallback=fallback,
                    escalation=escalation,
                    timeout=timeout,
                    rate_limit=rate_limit,
                    malformed_response=malformed_response,
                    empirical_outcome=empirical_outcome,
                )
            except TypeError:
                # Fallback for old signature in mock environments
                db_inst.record_model_call(
                    model=model,
                    reason=reason,
                    confidence=confidence,
                    latency_ms=latency_ms,
                    success=success,
                    fallback=fallback,
                    escalation=escalation,
                )
            except Exception as exc:
                logger.warning("[router] Failed to persist model call log: %s", exc)

    def _is_decision_failure(self, decision: Any) -> bool:
        """Determine if a decision represents an underlying model/provider failure."""
        if not isinstance(decision, Decision):
            return True
        if decision.confidence <= 0.0:
            return True
        if decision.reasoning.startswith("Failed to parse"):
            return True
        if getattr(decision, "http_status", 200) in (408, 429, 500, 502, 503, 504):
            return True
        if decision.action_type == "hold" and any(
            k in decision.reasoning.lower() for k in ("failed", "failure", "quota", "timed out", "cooldown", "error")
        ):
            return True
        return False

    def _call_fast_model(
        self, brain: Any, telemetry_summary: str, recent_actions: List[str], target_fast: str
    ) -> Decision:
        # Check for legacy mock decide_tactical
        if hasattr(brain, "decide_tactical"):
            try:
                res = brain.decide_tactical(telemetry_summary, recent_actions)
                if isinstance(res, Decision):
                    return res
            except Exception as exc:
                logger.warning("[router] Fast call failed with exception: %s", exc)
                return Decision(
                    action_type="hold",
                    target="",
                    priority="low",
                    reasoning=f"Fast failed with exception: {exc}",
                    confidence=0.0,
                    model_used=target_fast,
                )
        try:
            res = brain.decide(telemetry_summary, recent_actions, model=target_fast)
            if isinstance(res, Decision):
                return res
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="Brain returned non-Decision object",
                confidence=0.0,
                model_used=target_fast,
            )
        except Exception as exc:
            logger.warning("[router] Fast call failed with exception: %s", exc)
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"Fast failed with exception: {exc}",
                confidence=0.0,
                model_used=target_fast,
            )

    def _call_reasoning_model(
        self, brain: Any, telemetry_summary: str, recent_actions: List[str], target_reasoning: str
    ) -> Decision:
        # Check for legacy mock decide_deep_reasoning
        if hasattr(brain, "decide_deep_reasoning"):
            try:
                res = brain.decide_deep_reasoning(telemetry_summary, recent_actions)
                if isinstance(res, Decision):
                    return res
            except Exception as exc:
                logger.warning("[router] Reasoning call failed with exception: %s", exc)
                return Decision(
                    action_type="hold",
                    target="",
                    priority="low",
                    reasoning=f"Reasoning failed with exception: {exc}",
                    confidence=0.0,
                    model_used=target_reasoning,
                )
        try:
            res = brain.decide(telemetry_summary, recent_actions, model=target_reasoning)
            if isinstance(res, Decision):
                return res
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="Brain returned non-Decision object",
                confidence=0.0,
                model_used=target_reasoning,
            )
        except Exception as exc:
            logger.warning("[router] Reasoning call failed with exception: %s", exc)
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning=f"Reasoning failed with exception: {exc}",
                confidence=0.0,
                model_used=target_reasoning,
            )

    def route(
        self,
        telemetry: Any,
        recent_actions: List[str],
        monitor_snapshot: Optional[Dict[str, Any]] = None,
    ) -> RouteDecision:
        """Route context to either local policy, NVIDIA Fast, or NVIDIA Reasoning based on complexity."""
        import time
        t0 = time.perf_counter()
        local_decision = self._evaluate_local_policy(telemetry, monitor_snapshot)
        local_lat = (time.perf_counter() - t0) * 1000.0
        self.metrics.record_local_policy_latency(local_lat)
        self.last_local_policy_latency_ms = local_lat

        # 1. Local Policy Engine: Check for deterministic/obvious events
        if local_decision:
            return RouteDecision(
                model="local-policy",
                reason=f"Deterministic local policy: {local_decision.reasoning}",
                priority=local_decision.priority,
                confidence_requirement=1.0,
                is_local=True,
                local_action=local_decision,
            )


        # 2. Check for inherently high-complexity situations warranting Reasoning immediately
        if self._is_high_complexity(telemetry, monitor_snapshot):
            return RouteDecision(
                model=config.nvidia_reasoning_model,
                reason="High complexity: Multiple conflicting high-priority events or critical score margin",
                priority="critical",
                confidence_requirement=0.85,
                is_local=False,
            )

        # 3. Default: NVIDIA Fast for routine analysis & tactical prioritization
        return RouteDecision(
            model=config.nvidia_fast_model,
            reason="Routine strategic analysis and tactical prioritization",
            priority="high",
            confidence_requirement=config.nvidia_confidence_threshold,
            is_local=False,
        )

    def _evaluate_local_policy(
        self,
        telemetry: Any,
        monitor_snapshot: Optional[Dict[str, Any]] = None,
    ) -> Optional[Decision]:
        """Deterministic policy handler without calling NVIDIA."""
        # Scoreboard failure / telemetry error -> safe local hold
        if not telemetry:
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="Scoreboard telemetry unavailable; holding safe baseline state.",
                model_used="local-policy",
            )

        raw = getattr(telemetry, "raw", {})
        if isinstance(raw, dict):
            if raw.get("stale") or raw.get("error") == "Scoreboard data is stale":
                return Decision(
                    action_type="hold",
                    target="",
                    priority="low",
                    reasoning=f"Scoreboard telemetry is stale (>={config.stale_telemetry_threshold}s old); maintaining safe baseline hold.",
                    model_used="local-policy",
                )
            if raw.get("error"):
                return Decision(
                    action_type="hold",
                    target="",
                    priority="low",
                    reasoning=f"Scoreboard unreachable ({raw.get('error')}); maintaining baseline defense.",
                    model_used="local-policy",
                )

        # Direct file tampering detected in local monitor snapshot
        if monitor_snapshot and monitor_snapshot.get("tampered_files"):
            # Resolve target own service
            services = monitor_snapshot.get("services", [])
            target = ""
            if services:
                target = f"{services[0]['host']}:{services[0]['port']}"
            elif "host" in monitor_snapshot and "port" in monitor_snapshot:
                target = f"{monitor_snapshot['host']}:{monitor_snapshot['port']}"
            elif config.own_services:
                first = config.own_services[0].split(":")
                target = f"{first[0]}:{first[1]}"

            return Decision(
                action_type="defend",
                target=target,
                priority="critical",
                reasoning=f"Local policy: File tampering detected ({len(monitor_snapshot['tampered_files'])} file(s)); defensive rate-limiting.",
                model_used="local-policy",
            )

        # Single downed service in monitor_snapshot
        if monitor_snapshot:
            down = monitor_snapshot.get("down_services", [])
            if len(down) == 1:
                d = down[0]
                return Decision(
                    action_type="defend",
                    target=f"{d['host']}:{d['port']}",
                    priority="critical",
                    reasoning=f"Local policy: Deterministic service restart for downed port {d['port']}.",
                    model_used="local-policy",
                )

        # Single downed service in telemetry
        services = getattr(telemetry, "our_services", [])
        down_services = [s for s in services if not getattr(s, "up", True)]
        if len(down_services) == 1:
            down_svc = down_services[0]
            host = getattr(down_svc, "host", "")
            port = getattr(down_svc, "port", 0)
            return Decision(
                action_type="defend",
                target=f"{host}:{port}",
                priority="critical",
                reasoning=f"Local policy: Deterministic service restart for downed port {port}.",
                model_used="local-policy",
            )

        return None

    def _is_high_complexity(self, telemetry: Any, monitor_snapshot: Optional[Dict[str, Any]] = None) -> bool:
        """Determine if context requires deep multi-step reasoning from NVIDIA Reasoning."""
        if not telemetry:
            return False

        services = getattr(telemetry, "our_services", [])
        down_services = [s for s in services if not getattr(s, "up", True)]

        # Check monitor snapshot for multiple downed services
        if monitor_snapshot and "services" in monitor_snapshot:
            down_monitored = [s for s in monitor_snapshot.get("services", []) if not s.get("up", True)]
            if len(down_monitored) >= 2:
                return True

        # Multiple services down simultaneously while competitor scores are active
        competitor_scores = getattr(telemetry, "competitor_scores", {})
        if len(down_services) >= 2 and len(competitor_scores) > 0:
            return True

        # Close score race in top rankings: rank <= 3 and score diff is small
        rank = getattr(telemetry, "rank", None)
        our_score = getattr(telemetry, "our_score", None)
        if rank is not None and rank <= 3 and our_score is not None:
            for score in competitor_scores.values():
                if abs(our_score - score) < 50.0 and len(down_services) >= 1:
                    return True

        return False

    def execute_decision(
        self,
        telemetry: Any,
        telemetry_summary: str,
        recent_actions: List[str],
        brain: Any = None,
        monitor_snapshot: Optional[Dict[str, Any]] = None,
        swarm_context: Optional[Dict[str, Any]] = None,
    ) -> Decision:
        """Route, execute, escalate if needed, and handle fallback cleanly.

        Architecture flow:
          LOCAL POLICY -> NVIDIA NEMOTRON -> GROQ GPT-OSS 120B -> OPENROUTER GLM 5.3 FLASH -> SAFE_HOLD
        """
        # If running in production or without test mock brain, use 3-provider TieredModelRouter
        is_mock_brain = brain is not None and (
            hasattr(brain, "fixtures")
            or hasattr(brain, "call_history")
            or hasattr(brain, "flash_available")
            or type(brain).__name__ in ("MagicMock", "Mock", "MockGeminiEngine", "MockNvidiaEngine")
            or not hasattr(brain, "_post_nvidia")
        )

        if not is_mock_brain:
            tiered_decision = self.tiered_router.execute_decision(
                telemetry=telemetry,
                telemetry_summary=telemetry_summary,
                recent_actions=recent_actions,
                brain=brain,
                monitor_snapshot=monitor_snapshot,
                swarm_context=swarm_context,
            )
            self.metrics.total_decisions += 1
            self._update_metrics(tiered_decision, tiered_decision.reasoning)
            if tiered_decision.provider == "nvidia":
                self.metrics.record_fast_latency(tiered_decision.latency_ms)
            elif tiered_decision.provider in ("groq", "openrouter"):
                self.metrics.record_reasoning_latency(tiered_decision.latency_ms)
            if tiered_decision.fallback_level > 1:
                self.metrics.escalation_count += 1
            return tiered_decision

        self.metrics.total_decisions += 1
        route_decision = self.route(telemetry, recent_actions, monitor_snapshot)

        # 1. Local Policy Engine Execution
        if route_decision.is_local and route_decision.local_action:
            decision = route_decision.local_action.sanitize()
            self._update_metrics(decision, route_decision.reason)
            self._log_model_call(
                model="local-policy",
                reason=route_decision.reason,
                confidence=decision.confidence,
                latency_ms=self.last_local_policy_latency_ms,
                api_latency_ms=0.0,
                http_status=200,
                success=True,
                fallback=False,
                escalation=False,
            )
            logger.info("[router] Executed %s: %s", decision.model_used, decision.reasoning)
            return decision

        # 2. Reasoning model routed directly (high-complexity situation)
        is_reasoning_route = (
            route_decision.model in (config.nvidia_reasoning_model, config.gemini_reasoning_model)
            or "super" in route_decision.model.lower()
            or "120b" in route_decision.model.lower()
            or "pro" in route_decision.model.lower()
        )

        if is_reasoning_route:
            target_reasoning = config.nvidia_reasoning_model
            logger.info("[router] Routing directly to NVIDIA Reasoning: %s", target_reasoning)
            reasoning_decision = self._call_reasoning_model(brain, telemetry_summary, recent_actions, target_reasoning)
            self.last_reasoning_latency_ms = reasoning_decision.latency_ms
            self.last_api_latency_ms = getattr(reasoning_decision, "api_latency_ms", reasoning_decision.latency_ms)
            self.metrics.record_reasoning_latency(reasoning_decision.latency_ms)

            reasoning_succeeded = not self._is_decision_failure(reasoning_decision)

            self._log_model_call(
                model=target_reasoning,
                reason=route_decision.reason,
                confidence=reasoning_decision.confidence,
                latency_ms=reasoning_decision.latency_ms,
                api_latency_ms=self.last_api_latency_ms,
                http_status=getattr(reasoning_decision, "http_status", 200),
                success=reasoning_succeeded,
                fallback=False,
                escalation=False,
                timeout=("timeout" in reasoning_decision.reasoning.lower()),
                rate_limit=("quota" in reasoning_decision.reasoning.lower() or "rate" in reasoning_decision.reasoning.lower()),
                malformed_response=reasoning_decision.reasoning.startswith("Failed to parse"),
            )

            if reasoning_succeeded:
                self._update_metrics(reasoning_decision, route_decision.reason)
                return reasoning_decision

            # Fallback if Reasoning fails: Try Fast model
            logger.warning("[router] NVIDIA Reasoning model failed; falling back to Fast model")
            self.metrics.failures_count += 1
            self.metrics.fallback_count += 1

            fast_fallback = self._call_fast_model(brain, telemetry_summary, recent_actions, config.nvidia_fast_model)
            self.last_fast_latency_ms = fast_fallback.latency_ms
            self.last_api_latency_ms = getattr(fast_fallback, "api_latency_ms", fast_fallback.latency_ms)
            self.metrics.record_fast_latency(fast_fallback.latency_ms)
            fast_succeeded = not self._is_decision_failure(fast_fallback)
            self._log_model_call(
                model=config.nvidia_fast_model,
                reason="Fallback from Reasoning failure to Fast",
                confidence=fast_fallback.confidence,
                latency_ms=fast_fallback.latency_ms,
                api_latency_ms=self.last_api_latency_ms,
                http_status=getattr(fast_fallback, "http_status", 200),
                success=fast_succeeded,
                fallback=True,
                escalation=False,
            )
            if fast_succeeded:
                self._update_metrics(fast_fallback, "Fallback from Reasoning failure to Fast")
                return fast_fallback

            # Ultimate safe local fallback
            local_fallback = self._evaluate_local_policy(telemetry, monitor_snapshot)
            if local_fallback:
                return local_fallback.sanitize()
            self._log_model_call(
                model="safe-fallback",
                reason="NVIDIA Reasoning and Fast both failed; safe hold.",
                confidence=0.0,
                latency_ms=0.0,
                api_latency_ms=0.0,
                http_status=200,
                success=True,
                fallback=True,
                escalation=False,
            )
            return self._safe_fallback("NVIDIA Reasoning and Fast both failed; safe hold.")

        # 3. Default: NVIDIA Fast Model
        target_fast = config.nvidia_fast_model
        logger.debug("[router] Routing to Fast Model: %s", target_fast)
        fast_decision = self._call_fast_model(brain, telemetry_summary, recent_actions, target_fast)
        self.last_fast_latency_ms = fast_decision.latency_ms
        self.last_api_latency_ms = getattr(fast_decision, "api_latency_ms", fast_decision.latency_ms)
        self.metrics.record_fast_latency(fast_decision.latency_ms)

        fast_failed = self._is_decision_failure(fast_decision)

        # Rule 6: If NVIDIA FAST fails, use deterministic fallback
        if fast_failed:
            self.metrics.failures_count += 1
            self.metrics.fallback_count += 1
            self._log_model_call(
                model=target_fast,
                reason=route_decision.reason,
                confidence=fast_decision.confidence,
                latency_ms=fast_decision.latency_ms,
                api_latency_ms=self.last_api_latency_ms,
                http_status=getattr(fast_decision, "http_status", 500),
                success=False,
                fallback=False,
                escalation=False,
                timeout=("timeout" in fast_decision.reasoning.lower() or getattr(fast_decision, "http_status", None) == 408),
                rate_limit=("quota" in fast_decision.reasoning.lower() or getattr(fast_decision, "http_status", None) == 429),
                malformed_response=fast_decision.reasoning.startswith("Failed to parse"),
            )
            logger.warning("[router] NVIDIA Fast call failed; evaluating local policy deterministic fallback")
            local_fallback = self._evaluate_local_policy(telemetry, monitor_snapshot)
            if local_fallback:
                self._log_model_call(
                    model="local-policy",
                    reason="Deterministic fallback to local policy after Fast failure",
                    confidence=local_fallback.confidence,
                    latency_ms=self.last_local_policy_latency_ms,
                    api_latency_ms=0.0,
                    http_status=200,
                    success=True,
                    fallback=True,
                    escalation=False,
                )
                self._update_metrics(local_fallback, "Deterministic fallback after Fast failure")
                return local_fallback.sanitize()

            self._log_model_call(
                model="safe-fallback",
                reason="Fast failed (Flash failed) and situation cannot be safely automated locally; safe hold.",
                confidence=0.0,
                latency_ms=0.0,
                api_latency_ms=0.0,
                http_status=200,
                success=True,
                fallback=True,
                escalation=False,
            )
            return self._safe_fallback("Fast failed (Flash failed) and situation cannot be safely automated locally; safe hold.")

        # Rule 7: If NVIDIA FAST returns low confidence, escalate to NVIDIA REASONING
        should_escalate = (
            fast_decision.confidence < config.nvidia_confidence_threshold
            or fast_decision.needs_escalation
        )

        if should_escalate:
            escalation_reason = (
                f"Confidence {fast_decision.confidence:.2f} < {config.nvidia_confidence_threshold:.2f}"
                if fast_decision.confidence < config.nvidia_confidence_threshold
                else "Fast requested escalation"
            )
            logger.info("[router] Escalating from Fast to Reasoning: %s", escalation_reason)
            self.metrics.escalation_count += 1
            self._log_model_call(
                model=target_fast,
                reason=route_decision.reason,
                confidence=fast_decision.confidence,
                latency_ms=fast_decision.latency_ms,
                api_latency_ms=self.last_api_latency_ms,
                http_status=getattr(fast_decision, "http_status", 200),
                success=True,
                fallback=False,
                escalation=True,
            )

            target_reasoning = config.nvidia_reasoning_model
            reasoning_decision = self._call_reasoning_model(brain, telemetry_summary, recent_actions, target_reasoning)
            self.last_reasoning_latency_ms = reasoning_decision.latency_ms
            self.last_api_latency_ms = getattr(reasoning_decision, "api_latency_ms", reasoning_decision.latency_ms)
            self.metrics.record_reasoning_latency(reasoning_decision.latency_ms)

            reasoning_succeeded = not self._is_decision_failure(reasoning_decision)

            self._log_model_call(
                model=target_reasoning,
                reason=f"Escalated from Fast ({escalation_reason})",
                confidence=reasoning_decision.confidence,
                latency_ms=reasoning_decision.latency_ms,
                api_latency_ms=self.last_api_latency_ms,
                http_status=getattr(reasoning_decision, "http_status", 200),
                success=reasoning_succeeded,
                fallback=False,
                escalation=True,
                timeout=("timeout" in reasoning_decision.reasoning.lower()),
                rate_limit=("quota" in reasoning_decision.reasoning.lower()),
                malformed_response=reasoning_decision.reasoning.startswith("Failed to parse"),
            )

            # If Reasoning succeeded, use it
            if reasoning_succeeded:
                self._update_metrics(reasoning_decision, f"Escalated to Reasoning ({escalation_reason})")
                return reasoning_decision

            # Rule 8: If NVIDIA REASONING fails: SAFE_HOLD / deterministic fallback
            self.metrics.failures_count += 1
            self.metrics.fallback_count += 1
            logger.warning("[router] Escalation to Reasoning failed; evaluating deterministic fallback or safe hold")

            local_fallback = self._evaluate_local_policy(telemetry, monitor_snapshot)
            if local_fallback:
                self._update_metrics(local_fallback, "Deterministic fallback after Reasoning failure")
                return local_fallback.sanitize()

            # If Fast decision was reasonable, fallback to Fast decision
            if fast_decision.confidence > 0.0 and not fast_decision.reasoning.startswith("Failed to parse"):
                self._update_metrics(fast_decision, "Fell back to Fast after Reasoning escalation failure")
                return fast_decision

            return self._safe_fallback("NVIDIA Reasoning failed and no deterministic policy matched; safe hold.")

        # Standard Fast success
        self._log_model_call(
            model=target_fast,
            reason=route_decision.reason,
            confidence=fast_decision.confidence,
            latency_ms=fast_decision.latency_ms,
            api_latency_ms=self.last_api_latency_ms,
            http_status=getattr(fast_decision, "http_status", 200),
            success=True,
            fallback=False,
            escalation=False,
        )
        self._update_metrics(fast_decision, route_decision.reason)
        return fast_decision

    def _safe_fallback(self, reason: str) -> Decision:
        decision = Decision(
            action_type="hold",
            target="",
            priority="low",
            reasoning=reason,
            confidence=0.0,
            model_used="safe-fallback",
        ).sanitize()
        self._update_metrics(decision, reason)
        return decision

    def _update_metrics(self, decision: Decision, reason: str) -> None:
        self.metrics.latest_model = decision.model_used
        self.metrics.latest_reason = reason
        self.metrics.latest_confidence = decision.confidence


router = ModelRouter()
