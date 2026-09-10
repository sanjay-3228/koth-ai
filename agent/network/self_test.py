"""PwnGrounds Network & Environment Read-Only Self-Test CLI.

Usage:
    python -m agent.network.self_test

Strictly read-only:
  - Does NOT alter routing tables
  - Does NOT connect or disconnect VPN tunnels
  - Does NOT modify network interfaces
  - Does NOT send attack or defense commands
"""
import sys
import requests

from ..config import config
from ..logger import get_logger
from .competition_scope import CompetitionScope, detect_environment
from .detector import NetworkDetector
from .models import EnvironmentMode, VpnStatus
from .state_machine import StartupSafetyStateMachine
from .vpn import VpnDetector

logger = get_logger(__name__)


def run_self_test() -> int:
    print("=" * 75)
    print("        PWNGROUNDS NETWORK & ENVIRONMENT READ-ONLY SELF-TEST")
    print("=" * 75)

    detector = NetworkDetector()
    scope = CompetitionScope.from_config(config)
    interfaces = detector.get_interfaces()
    routes = detector.get_routes()
    env_state = detect_environment(scope, detector)

    # --------------------------------------------------------------------------
    # 1. VPN CONNECTIVITY
    # --------------------------------------------------------------------------
    print("\n[1] VPN CONNECTIVITY:")
    print("-" * 75)
    vpn_status, active_vpns = VpnDetector.detect_vpn_status(interfaces)
    vpn_names = [v.name for v in active_vpns]

    print(f"  * VPN Status                 : {vpn_status.value}")
    print(f"  * VPN Detected               : {'YES' if vpn_status == VpnStatus.CONNECTED else 'NO'}")
    print(f"  * Active VPN Interface(s)    : {', '.join(vpn_names) if vpn_names else 'None'}")
    print(f"  * VPN Route Detected         : {'YES' if env_state.vpn_route_present else 'NO'}")
    print("  * Authorization Boundary     : VPN presence alone NEVER grants competition authorization.")
    print("  * Network Notice             : External VPN connections are strictly isolated")
    print("                                 and NEVER automatically classified as PwnGrounds.")

    # --------------------------------------------------------------------------
    # 2. COMPETITION NETWORK & SCOPE
    # --------------------------------------------------------------------------
    print("\n[2] COMPETITION NETWORK & SCOPE:")
    print("-" * 75)
    valid_scope, scope_reason = scope.validate_scope()
    print(f"  * Configured Mode (PWN_MODE) : {scope.mode}")
    print(f"  * Competition Scope Status   : {'CONFIGURED' if scope.is_configured() else 'NOT CONFIGURED'}")
    print(f"  * Competition CIDRs          : {[str(c) for c in scope.competition_cidrs] or 'NOT CONFIGURED'}")
    print(f"  * Scope Validation Check     : {'VALID' if valid_scope else 'INVALID'} ({scope_reason})")
    print(f"  * Environment Mode           : {env_state.mode.value}")
    print(f"  * Competition Route Present  : {'YES' if env_state.competition_route_present else 'NO (MISSING / UNCONFIGURED)'}")
    print(f"  * Classification Details     : {env_state.details}")
    print(f"  * Own Hosts / Services       : {len(scope.own_hosts)} host(s), {len(scope.own_services)} service(s)")
    print(f"  * Target Hosts               : {scope.target_hosts or 'None configured'}")

    # --------------------------------------------------------------------------
    # 3. SCOREBOARD CONNECTIVITY
    # --------------------------------------------------------------------------
    print("\n[3] SCOREBOARD CONNECTIVITY:")
    print("-" * 75)
    sb_status = "UNCONFIGURED"
    sb_latency_ms = 0.0
    sb_err = None

    if not scope.scoreboard_url:
        print("  * Scoreboard Status          : UNCONFIGURED (No URL provided)")
    else:
        print(f"  * Scoreboard URL             : {scope.scoreboard_url}")
        try:
            resp = requests.get(scope.scoreboard_url, timeout=5)
            sb_latency_ms = resp.elapsed.total_seconds() * 1000.0
            if resp.status_code == 200:
                sb_status = "REACHABLE"
                print(f"  * Scoreboard Status          : REACHABLE (HTTP {resp.status_code}, {sb_latency_ms:.1f}ms)")
            else:
                sb_status = "UNREACHABLE"
                print(f"  * Scoreboard Status          : UNREACHABLE (HTTP {resp.status_code}, {sb_latency_ms:.1f}ms)")
        except requests.Timeout:
            sb_status = "UNREACHABLE"
            print("  * Scoreboard Status          : UNREACHABLE (Connection Timed Out)")
        except requests.RequestException as exc:
            sb_status = "UNREACHABLE"
            print(f"  * Scoreboard Status          : UNREACHABLE (Connection Failed: {exc})")

    # --------------------------------------------------------------------------
    # 4. GEMINI CONNECTIVITY
    # --------------------------------------------------------------------------
    print("\n[4] GEMINI CONNECTIVITY:")
    print("-" * 75)
    print(f"  * Fast Reasoning Model       : {config.gemini_fast_model}")
    print(f"  * Deep Reasoning Model       : {config.gemini_reasoning_model}")
    print(f"  * API Key Configured         : {'YES' if bool(config.gemini_api_key) else 'NO'}")
    print("  * Decoupling Guarantee       : Gemini API testing is strictly decoupled from scoreboard")
    print("                                 telemetry. Local-policy safe hold handles scoreboard faults.")

    # --------------------------------------------------------------------------
    # 5. KOTH AUTHORIZATION & STATE MACHINE
    # --------------------------------------------------------------------------
    print("\n[5] KOTH AUTHORIZATION:")
    print("-" * 75)
    sm = StartupSafetyStateMachine(cfg=config, detector=detector, scope=scope)
    final_state = sm.run_startup_sequence()
    for res in sm.history:
        status_sym = "[PASS]" if res.success else "[FAIL]"
        print(f"  * {res.step_name:<28} {status_sym} - {res.message}")
    print(f"  * Final State Machine State  : {final_state.value}")
    print(f"  * Action Execution Allowed   : {'YES' if sm.can_execute_actions() else 'NO (Safe Hold Enforced)'}")

    # --------------------------------------------------------------------------
    # READINESS SUMMARY
    # --------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print("                             READINESS SUMMARY")
    print("=" * 75)
    print(f"  VPN Status                   : {vpn_status.value}")
    print(f"  Competition Network Scope    : {'CONFIGURED' if scope.is_configured() else 'NOT CONFIGURED'}")
    print(f"  Competition Route Present    : {'YES' if env_state.competition_route_present else 'NO'}")
    print(f"  Scoreboard Reachability      : {sb_status}")
    print(f"  Operating Mode               : {config.koth_mode} (OBSERVATION_ONLY={config.observation_only})")
    print(f"  Live Operations Authorized   : NO (Safely Guarded)")
    print("-" * 75)
    print("  IMPORTANT NOTICE: Do NOT claim PwnGrounds readiness from unconfigured external VPN.")
    print("  External VPN connectivity does not authorize or configure competition scope.")
    print("=" * 75)

    return 0


if __name__ == "__main__":
    sys.exit(run_self_test())
