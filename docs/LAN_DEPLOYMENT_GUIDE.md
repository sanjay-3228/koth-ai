# PwnGrounds 4-Agent Swarm: Private LAN Deployment & Rehearsal Guide

This guide details how to deploy, configure, and operate the **koth-agent 4-agent swarm** across four physical or virtual machines on an isolated private Local Area Network (LAN).

---

## 1. Architectural Overview & Privilege Separation

The swarm architecture strictly separates execution roles and permissions:
- **Authoritative Coordinator Process**: Lightweight REST service managing authoritative phase state, exclusive task leases, heartbeat monitoring, and zero-credential shared intelligence.
- **Dedicated Operator Identity (`OPERATOR_TOKEN`)**: Only requests bearing the `OPERATOR_TOKEN` can advance phases, trigger the global kill switch, or shut down the coordinator. Workers are strictly forbidden from performing operator actions.
- **Four Independent Worker Agent Processes**:
  - `agent-01` (Team Member 1)
  - `agent-02` (Team Member 2)
  - `agent-03` (Team Member 3)
  - `agent-04` (Team Member 4)
- **Per-Agent Cryptographic Authentication**:
  - Each worker presents a per-agent credential (either HMAC-derived from `SWARM_AUTH_TOKEN:agent_id` or configured individually via `--agent-token`).
  - Mismatched credentials (e.g. `credential(agent-02)` with `agent_id(agent-03)`) are authoritatively rejected (`403 Forbidden`).
  - Registration issues an ephemeral `AgentSession` with TTL. Duplicate active registrations are rejected (`409 Conflict`).
- **TLS / HTTPS Transport**: Secure transport can be enabled via `--ssl-cert` and `--ssl-key`. Clients verify certificates with `--ca-cert` with zero silent downgrades.
- **Privacy-Preserving Health Probe (`/healthz`)**: A minimal, unauthenticated probe exposing strictly 6 safe operational fields without leaking credentials, model keys, or internal targets.

```
                    [ Private LAN / Mobile Hotspot / Radmin VPN ]
                                       |
                      +---------------------------------+
                      |  Swarm Coordinator              |
                      |  IP: <COORDINATOR_LAN_IP>:5000  |
                      |  Profile: LAN_REHEARSAL         |
                      |  RBAC: Operator vs Worker       |
                      +---------------------------------+
                                       |
           +-------------------+-------+-------+-------------------+
           |                   |               |                   |
           v                   v               v                   v
+-------------------+ +-------------------+ +-------------------+ +-------------------+
| Machine 1         | | Machine 2         | | Machine 3         | | Machine 4         |
| agent-01 (Sanjay) | | agent-02 (Prachi) | | agent-03 (Aman)   | | agent-04(Akshitha)|
| Token: 1000       | | Token: 1001       | | Token: 1002       | | Token: 1003       |
+-------------------+ +-------------------+ +-------------------+ +-------------------+
```

---

## 2. Binding Rules & Zero-Exposure Safety

To eliminate unintentional public exposure or misconfigured targets:

1. **`0.0.0.0` is strictly rejected**: The coordinator will **never** automatically expose itself to all interfaces (`0.0.0.0`). Attempting to bind to `0.0.0.0` results in an immediate startup error.
2. **`127.0.0.1` is rejected in `LAN_REHEARSAL`**: In LAN rehearsal mode, `SWARM_BIND_HOST` must be explicitly configured with a private LAN IP (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`). Binding to `127.0.0.1` is only permitted in `LOCAL_REHEARSAL`.
3. **Deterministic Action Policy (`allowed_actions`)**: Actions requested outside `Config.allowed_actions` are strictly rejected by both `SecurityPolicy` and `ActionRegistry`.
4. **Non-Routable Rehearsal Targets**: Rehearsal targets are strictly confined to dummy private subnets (`10.254.254.11-14` for targets, `10.254.254.101-104` for own infrastructure).
5. **Enforced Dry-Run**: `DRY_RUN=True` and `OBSERVATION_ONLY=True` remain enforced for all rehearsals.

---

## 3. Pre-Flight Setup

> [!WARNING]
> **OBSOLETE ARCHITECTURE NOTICE (Stage 3 Shared Token)**:
> In earlier prototypes (Stage 3), a single shared `SWARM_AUTH_TOKEN` was used across all nodes.
> **DO NOT USE A SINGLE SHARED SECRET FOR LAN DEPLOYMENT.**
> A single shared secret allows any compromised worker machine to forge requests on behalf of other agents.
> Stage 4 strictly enforces **Per-Agent Distinct Identity**:
> - Each agent (`agent-01`, `agent-02`, `agent-03`, `agent-04`) is provisioned with a **unique, independent secret token**.
> - The Operator has a separate, highly privileged **`OPERATOR_TOKEN`**.
> - The Coordinator validates `agent_id` strictly against its authorized token mapping (`--agent-tokens`). Cross-agent credential use is rejected with `403 Forbidden`.

### Step A: Configure Roster Tokens
The team uses the provisioned roster:
- `agent-01` (Sanjay) → `1000`
- `agent-02` (Prachi) → `1001`
- `agent-03` (Aman) → `1002`
- `agent-04` (Akshitha) → `1003`

Default roster environment variable:
```bash
SWARM_AGENT_TOKENS="agent-01:1000,agent-02:1001,agent-03:1002,agent-04:1003"
```
Generate an Operator Token:
```bash
python -c "import secrets; print('SWARM_OPERATOR_TOKEN=' + secrets.token_hex(24))"
```

*(Note: Legacy fallback `--auth-token <SECRET>` is only retained for backwards compatibility in single-host test fixtures and MUST NOT be used in LAN operations).*

### Step B: Coordinator Machine Firewall Configuration
On the machine hosting the coordinator (e.g. `192.168.1.101`):

#### On Linux (ufw):
```bash
sudo ufw allow from 192.168.1.0/24 to any port 5000 proto tcp comment "KOTH Swarm Coordinator"
```

#### On Windows (PowerShell as Administrator):
```powershell
New-NetFirewallRule -DisplayName "KOTH Swarm Coordinator Port 5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow -RemoteAddress 192.168.1.0/24
```

---

## 4. Step-by-Step Launch Sequence

### Step 1: Launch Authoritative Coordinator
On the Coordinator machine:

```powershell
python -m agent.swarm.coordinator_server `
  --host "<COORDINATOR_BIND_HOST>" `
  --port 5000 `
  --profile LAN_REHEARSAL `
  --operator-token "<OPERATOR_TOKEN>" `
  --agent-tokens "agent-01:1000,agent-02:1001,agent-03:1002,agent-04:1003"
```

*(Optional: Add `--use-tls --ssl-cert cert.pem --ssl-key key.pem` for HTTPS).*

**Expected Coordinator Startup Output**:
```text
[INFO] [COORDINATOR] Swarm Coordinator initialized: team=null_warriors profile=LAN_REHEARSAL auth_enabled=True targets=4 own_hosts=4
[INFO] [COORDINATOR] Starting Swarm Coordinator REST API on http://192.168.1.101:5000
```

### Step 2: Verify Coordinator Health Probe
From any machine on the LAN/VPN, verify the minimal `/healthz` probe:
```bash
curl -s http://<COORDINATOR_LAN_IP>:5000/healthz
```

**Expected JSON Response** (strictly 6 fields, zero secrets):
```json
{
  "service_status": "ok",
  "team_id": "null_warriors",
  "phase": "HOLD",
  "round": 1,
  "phase_epoch": 1,
  "registered_agent_count": 0
}
```

### Step 3: Launch Worker Agents

#### Machine 1 (Agent 01 - Sanjay):
```powershell
python -m agent.koth_controller `
  --agent-id agent-01 `
  --team-id null_warriors `
  --coordinator-url https://<COORDINATOR_LAN_IP>:5000 `
  --agent-token 1000 `
  --profile LAN_REHEARSAL `
  --worker
```

#### Machine 2 (Agent 02 - Prachi):
```powershell
python -m agent.koth_controller `
  --agent-id agent-02 `
  --team-id null_warriors `
  --coordinator-url https://<COORDINATOR_LAN_IP>:5000 `
  --agent-token 1001 `
  --profile LAN_REHEARSAL `
  --worker
```

#### Machine 3 (Agent 03 - Aman):
```powershell
python -m agent.koth_controller `
  --agent-id agent-03 `
  --team-id null_warriors `
  --coordinator-url https://<COORDINATOR_LAN_IP>:5000 `
  --agent-token 1002 `
  --profile LAN_REHEARSAL `
  --worker
```

#### Machine 4 (Agent 04 - Akshitha):
```powershell
python -m agent.koth_controller `
  --agent-id agent-04 `
  --team-id null_warriors `
  --coordinator-url https://<COORDINATOR_LAN_IP>:5000 `
  --agent-token 1003 `
  --profile LAN_REHEARSAL `
  --worker
```

### Step 4: Verify 4-Agent Cluster Status
Query `/healthz`:
```bash
curl -s https://<COORDINATOR_LAN_IP>:5000/healthz
```
Expected: `"registered_agent_count": 4`.

Query full authenticated swarm status (Operator token):
```bash
curl -s -H "X-Operator-Token: <OPERATOR_TOKEN>" \
  https://<COORDINATOR_LAN_IP>:5000/api/swarm/status
```

---

## 5. Phase Transitions (Operator Only)

Workers attempting to call phase advancement endpoints will receive `403 Forbidden`. Only the Operator can advance phases:

### Advance to ATTACK (Round 1)
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  -H "X-Operator-Token: <OPERATOR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"phase": "ATTACK", "round_id": 1}'
```
- Workers automatically detect the epoch increment on their next heartbeat.
- All 4 agents claim distinct targets from `10.254.254.11-14` with zero target collisions.
- Progress is logged in real-time: `[agent-0X] phase=ATTACK epoch=2`.

### Advance to DEFENSE (Round 1)
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  -H "X-Operator-Token: <OPERATOR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"phase": "DEFENSE", "round_id": 1}'
```
- In-flight attack work is dropped immediately.
- Agents claim defense tasks for defended infrastructure (`10.254.254.101-104`).

### Return to HOLD
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  -H "X-Operator-Token: <OPERATOR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"phase": "HOLD"}'
```
- All agents revert to safe hold standby mode.

---


## 5A. Swarm usernames and status dashboard

The coordinator can display a friendly username for each worker in the same Admin Command Console:

| Agent | Username |
|---|---|
| agent-01 | sanjay |
| agent-02 | prachi |
| agent-03 | aman |
| agent-04 | akshitha |

The `/admin` console shows connection state, agent status, current phase, current task type, target, task status, and last heartbeat for all four agents.

For **LOCAL_REHEARSAL only**, username-only login can be enabled so a worker can start with its username instead of manually entering a token. The coordinator maps the username to the authorized agent ID and issues a temporary session. This mode is deliberately restricted to `127.0.0.1`; live LAN deployments must continue using provisioned agent credentials.

Example local coordinator:

```bash
python -m agent.swarm.coordinator_server \
  --profile LOCAL_REHEARSAL \
  --host 127.0.0.1 \
  --port 5000 \
  --operator-token test-admin-123 \
  --enable-username-login
```

Example worker login:

```bash
python -m agent.koth_controller --profile LOCAL_REHEARSAL --swarm --worker \
  --coordinator-url http://127.0.0.1:5000 --username sanjay
```

## 6. Emergency Kill Switch (Operator Only)

In the event of an unexpected competition condition or operator abort command:

```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/kill-switch \
  -H "X-Operator-Token: <OPERATOR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Manual operator abort"}'
```

- Coordinator immediately revokes all active leases and enters emergency kill state.
- All 4 worker agents transition to `SAFE_HOLD` within 1 poll interval.
- All subsequent task requests are rejected.

---

## 7. Packaging Clean Release

Before sharing the repository or deploying to competition laptops, build a clean distribution bundle:

```bash
python scripts/package_release.py
```
This automatically produces `dist/koth-agent-release.zip`, which:
- Excludes `.env`, `.git/`, `__pycache__/`, `*.pyc`, `*.db`, `reports/`, `Zone.Identifier`, real flags, and temp files.
- Has been verified by `tests/test_clean_release.py` against secret pattern scanners (API keys, tokens, private keys).

---

## 8. Troubleshooting Matrix

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **`ValueError: Coordinator server cannot be automatically exposed to 0.0.0.0`** | Attempted to pass `0.0.0.0` as host. | Specify your machine's exact private LAN/VPN IP (e.g. `<COORDINATOR_LAN_IP>`). |
| **`ValueError: In LAN_REHEARSAL profile, coordinator host must NOT be 127.0.0.1`** | Attempted to use loopback in LAN mode. | Provide the machine's private LAN IP, or use `--profile LOCAL_REHEARSAL`. |
| **HTTP 401 Unauthorized: Invalid or missing session token** | Session expired, coordinator restarted, or token missing. | Worker will automatically re-register; verify coordinator did not restart without workers restarting. |
| **HTTP 403 Forbidden: Worker role cannot advance phase / trigger kill-switch** | Worker token used instead of Operator token on privileged endpoint. | Use `X-Operator-Token: <OPERATOR_TOKEN>` for phase transitions and kill switch. |
| **HTTP 403 Forbidden: Credential does not match requested agent_id** | Worker attempted to register with another agent's credential. | Ensure each worker's `--agent-id` matches its configured or HMAC-derived token. |
| **HTTP 409 Conflict: Agent already has an active session** | Another process is currently running with the same `agent_id`. | Terminate the rogue or duplicate process before launching the worker. |
| **Connection Refused / Timeout** | Host firewall blocking port 5000 or wrong IP. | Ensure inbound port 5000 is allowed from LAN subnet; verify IP with `ipconfig` / `ip a`. |



## Manual operator phase control

For live competitions where no scoreboard API is provided, the coordinator uses the existing PhaseProvider/PhaseManager architecture with an operator-controlled provider. The authorized operator controls the team phase from the coordinator admin console:

1. Start the coordinator with `SWARM_OPERATOR_TOKEN` configured.
2. Open `https://<coordinator-private-lan-ip>:<port>/admin`.
3. Enter the operator token in the browser.
4. Use **ATTACK**, **DEFENSE**, or **HOLD**.
5. The coordinator increments the phase epoch and invalidates old-phase leases/tasks through the existing PhaseManager transition handler.

Worker agents cannot advance the phase. Their authenticated role is `WORKER`; phase changes require `OPERATOR`. The operator token is kept in browser session storage and is not embedded in the page source.
