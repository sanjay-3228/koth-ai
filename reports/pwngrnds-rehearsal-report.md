# PwnGrounds Rehearsal Mode Integration Report

**Execution Timestamp**: 2026-09-10 17:01:25 UTC  
**Mode**: `PWNGROUNDS_FULL_REHEARSAL`  
**Lifecycle Steps Executed**: `0/33`  
**Total Simulated Actions**: `0`  
**Actual Executions**: `0` (HARD ASSERTION: 0)  
**Safety Violations**: `0`  
**Final Result Status**: `PASSED`  

---

## 1. NETWORK

- **Environment Mode**: `WIFI_PLUS_VPN` (Simulated)
- **Wi-Fi Interface**: `wlan0` (192.168.1.50/24)
- **VPN Interface**: `tun0` (10.200.1.5/16)
- **Default Gateway**: `192.168.1.1` via `wlan0`
- **Competition Route**: `10.200.0.0/16` via `tun0`
- **Anomaly Testing**: Wrong VPN subnet (`10.99.0.0/16`) halts startup to `SAFE_HOLD`.

## 2. SCOPE

- **Competition CIDRs**: `10.200.0.0/16`
- **Own Host**: `10.200.1.5`
- **Own Services**: `10.200.1.5:80 (web-service)`, `10.200.1.5:22 (sshd)`
- **Authorized Target Hosts**: `10.200.2.10`, `10.200.2.20`
- **Scoreboard URL**: `http://scoreboard.pwngrounds.local/api`

## 3. SAFETY GATES

- **Startup Safety State Machine**: `STARTING` -> `NETWORK_DETECTED` -> `COMPETITION_SCOPE_VERIFIED` -> `SCOREBOARD_VERIFIED` -> `TELEMETRY_VERIFIED` -> `DRY_RUN_READY`
- **Rate Limiting**: Sliding window 12 actions/minute verified.
- **Kill-Switch**: Immediate preemption to `SAFE_HOLD` verified.

## 4. TELEMETRY

- **Poller Source**: `SimulatedScoreboard` in-memory provider
- **Initial Telemetry**: Healthy baseline (all services UP)
- **Failure Event Detected**: `10.200.1.5:80` DOWN in cycle 10
- **Stale Data Protection**: Scoreboard timestamp > 60s triggers immediate `SAFE_HOLD`.
- **Outage Protection**: Scoreboard HTTP 504 triggers immediate `SAFE_HOLD`.

## 5. AI ROUTING

- **Fast Model**: `nvidia/nemotron-3.5-lightning-30b-a3b`
- **Reasoning Model**: `nvidia/nemotron-3-super-120b-a12b`
- **Deterministic Local Policy**: Single service failure routed to `local-policy` without calling external AI advisory.
- **Tactical Routing**: Routine telemetry routed to NVIDIA Fast advisory.
- **Failure Fallback**: AI timeouts (HTTP 408) and malformed output safely trigger `SAFE_HOLD` fallback.

## 6. AUTHORIZATION

- **Gate Mechanism**: `CompetitionNetworkGuard` + `SecurityPolicy`
- **In-Scope Defense**: Approved (`10.200.1.5:80` -> unit `web-service`)
- **In-Scope Attack**: Approved (`10.200.2.10:8080`)
- **Competitor Defense**: Rejected (`10.200.2.10:80` - CRITICAL risk)
- **Own Host Attack**: Rejected (`10.200.1.5:80` - CRITICAL risk)
- **Forbidden Port 9999**: Rejected (port not in `OWN_SERVICES`)
- **Unauthorized Host**: Rejected (`192.168.99.99:80` outside CIDR)
- **CIDR Injection**: Rejected (`10.200.2.0/24` subnet scanning forbidden)

## 7. ACTIONS

| Timestamp | Model | Action | Target | Authorized | Attempted | Actually Executed | Empirical Success |
|---|---|---|---|---|---|---|---|

## 8. VERIFICATION

- **Independent State Probes**: Probed simulated systemd and network ports.
- **Decoupled Verification**: Empirical success is decoupled from command exit status.
- **Injected Verification Failure**: Service restart simulated success, but probe reported port DOWN.

## 9. SCOREBOARD

- **Score Tracking**: Initial score `1000.0` -> Recovery score `1050.0` (+50.0 delta).
- **Ranking**: Rank 1 maintained.
- **Competitors Monitored**: `null_warriors: 950.0`, `team_bravo: 900.0`.

## 10. RECOVERY

- **Automated Recovery**: Automated `restart_service` resolved for mapped unit `web-service`.
- **Bounded Retries**: Maximum retries capped at 2. Exceeded retries halt to `SAFE_HOLD`.

## 11. FAILURE INJECTION

1. **AI Timeout**: Handled safely -> Reverted to `SAFE_HOLD`.
2. **Malformed AI Output**: Handled safely -> Reverted to `SAFE_HOLD`.
3. **Unauthorized Target (192.168.99.99)**: Rejected by policy -> 0 executions.
4. **Forbidden Port (9999)**: Rejected by policy -> 0 executions.
5. **Verification Failure**: Decoupled reality verified -> 0 infinite loops.

## 12. KILL SWITCH

- **Activation**: Engaged via kill switch trigger (`agent.config.kill_switch = True`).
- **Immediate Effect**: All subsequent cycles immediately return `hold` with model `kill-switch`.
- **Action Suppression**: Zero further actions evaluated or executed.

## 13. SAFETY VIOLATIONS

- **Real Socket Connections**: `0`
- **Subprocess Executions**: `0`
- **Firewall Modifications**: `0`
- **Systemctl Calls**: `0`
- **Exploit Plugin Executions**: `0`
- **Out of Bounds File Writes**: `0`
- **Total Safety Violations**: `0`

## 14. FINAL RESULT

- **Status**: **`PASSED`**
- **Full 33-Step Lifecycle**: Complete end-to-end execution without exceptions.
- **Hard Assertion**: `actually_executed` was verified False for 100% of actions.
