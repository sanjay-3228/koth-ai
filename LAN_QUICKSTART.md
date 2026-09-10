# KOTH Swarm Dynamic Network Quickstart (`null_warriors`)

This guide explains how to discover network IPs, generate dynamic TLS certificates, and start the authenticated, TLS-encrypted **4-agent swarm** across any environment without hardcoded IP addresses:
- **Mobile Hotspot / Event LAN** (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`)
- **Radmin VPN** (`26.x.x.x`)
- **Authorized Private Competition Networks**

---

## 1. Team & Roster Configuration

- **Team Name**: `null_warriors` (`TEAM_ID=null_warriors`)
- **4-Agent Roster**:
  - **Agent-01 (Sanjay)** → Token: `1000` (Coordinator / Operator Host)
  - **Agent-02 (Prachi)** → Token: `1001` (Worker)
  - **Agent-03 (Aman)** → Token: `1002` (Worker)
  - **Agent-04 (Akshitha)** → Token: `1003` (Worker)

> [!IMPORTANT]
> **Coordinator Authority**: All workers connect to the coordinator. An arbitrary client cannot register merely by knowing a token; it must belong to the authorized roster (`agent-01` through `agent-04`) with its exact matching token. Secret tokens are never printed in logs or displayed in dashboards.

---

## 2. Manual IP Discovery Workflow

Network addresses must be discovered at deployment time. **Do NOT assume or hardcode any IP address.**

### A. Windows Host (Coordinator or Worker)
Open PowerShell or Command Prompt:
```powershell
ipconfig
```
- **Wi-Fi / Ethernet LAN**: Look under `Wireless LAN adapter Wi-Fi` or `Ethernet adapter` for the IPv4 Address (e.g. `192.168.1.X`, `10.X.X.X`).
- **Radmin VPN**: Look under `Ethernet adapter Radmin VPN` for the IPv4 Address (starts with `26.X.X.X`).

### B. Linux / WSL Host
Open bash terminal:
```bash
hostname -I
```
or for full interface details:
```bash
ip addr
```
- **WSL NAT Internal IP**: In WSL, check `eth0` (e.g. `172.X.X.X`). This is the WSL bind address (`COORDINATOR_BIND_HOST`).
- **Native Linux Host**: Check `wlan0`, `eth0`, or VPN adapter `radmin0`.

---

## 3. Network Architecture (WSL NAT & Portproxy)

When hosting the coordinator on Windows inside WSL:
```text
┌─────────────────────────────────────────────────────────────┐
│ Coordinator Machine (Windows Host)                          │
│ Reachable LAN/VPN IP: <COORDINATOR_LAN_IP>                  │
│                                                             │
│   Windows Firewall allows TCP 5000                          │
│   Windows Portproxy:                                        │
│     <COORDINATOR_LAN_IP>:5000 -> <COORDINATOR_BIND_HOST>:5000 │
│                                                             │
│   ┌───────────────────────────────────────────────────────┐ │
│   │ Coordinator Kali / WSL (<COORDINATOR_BIND_HOST>)      │ │
│   │   Coordinator Process binds to: <COORDINATOR_BIND_HOST>│
│   │   Cert SAN includes: <COORDINATOR_LAN_IP>             │ │
│   └───────────────────────────────────────────────────────┘ │
└──────────────────────────────▲──────────────────────────────┘
                               │
               LAN / Mobile Hotspot / Radmin VPN
                               │
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
┌──────▼──────┐         ┌──────▼──────┐         ┌──────▼──────┐
│   Agent-02  │         │   Agent-03  │         │   Agent-04  │
│   (Prachi)  │         │    (Aman)   │         │  (Akshitha) │
│ Token: 1001 │         │ Token: 1002 │         │ Token: 1003 │
└─────────────┘         └─────────────┘         └─────────────┘
```

Distinguish these two addresses:
- **`COORDINATOR_LAN_IP`**: The address workers use across the network to reach the coordinator (Windows LAN IP or Radmin VPN IP).
- **`COORDINATOR_BIND_HOST`**: The local interface where the coordinator process listens (`<WSL_IP>` under WSL NAT, or identical to `COORDINATOR_LAN_IP` on bare metal / native Windows / native Linux).

---

## 4. Coordinator Setup (Agent-01)

### Step 4.1: Windows Port Forwarding (WSL NAT only)
On the Windows host, open PowerShell as **Administrator**:
```powershell
.\scripts\Setup-PortProxy.ps1 -CoordinatorLanIp "<COORDINATOR_LAN_IP>" -CoordinatorBindHost "<WSL_BIND_IP>"
```
*(If run without arguments, the script interactively prompts for the IPs).*

To configure manually via `netsh`:
```powershell
netsh interface portproxy add v4tov4 listenaddress=<COORDINATOR_LAN_IP> listenport=5000 connectaddress=<WSL_BIND_IP> connectport=5000
New-NetFirewallRule -DisplayName "KOTH-Swarm-Coordinator" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

### Step 4.2: Generate Dynamic TLS Certificates
Inside the Coordinator terminal (WSL or Linux):
```bash
python3 scripts/generate_swarm_certs.py "<COORDINATOR_LAN_IP>,<WSL_BIND_IP>" certs/
```
*(Or run `python3 scripts/generate_swarm_certs.py` without arguments for interactive prompt).*

> [!CAUTION]
> **CRITICAL TLS DISTRIBUTION RULE**:
> - Distribute **ONLY** `certs/ca.crt` to Worker machines.
> - **NEVER** share `ca.key` or `server.key` with workers.

### Step 4.3: Start the Swarm Coordinator

#### On Linux / WSL:
```bash
export COORDINATOR_LAN_IP="<COORDINATOR_LAN_IP>"
export COORDINATOR_BIND_HOST="<WSL_BIND_IP>"
export SWARM_AUTH_TOKEN="null_warriors_lan_secret_2026"
export SWARM_OPERATOR_TOKEN="null_warriors_operator_root_2026"

./scripts/start_coordinator_lan.sh
```
*(If `COORDINATOR_LAN_IP` is unset, the launcher will prompt interactively: `Enter coordinator IP: `).*

#### On Windows PowerShell (Native):
```powershell
$env:SWARM_AUTH_TOKEN = "null_warriors_lan_secret_2026"
$env:SWARM_OPERATOR_TOKEN = "null_warriors_operator_root_2026"

.\scripts\Start-CoordinatorLan.ps1 -CoordinatorLanIp "<COORDINATOR_LAN_IP>"
```

### Step 4.4: Verify Coordinator Health Probe
```bash
curl --cacert certs/ca.crt https://<COORDINATOR_LAN_IP>:5000/healthz
```
Expected response:
```json
{"phase":"HOLD","phase_epoch":1,"registered_agent_count":0,"round":1,"service_status":"ok","team_id":"null_warriors"}
```

---

## 5. Worker Setup (Agent-02, Agent-03, Agent-04)

On each worker machine:
1. Receive `certs/ca.crt` from Agent-01 and place in `certs/ca.crt`.
2. Ensure network reachability to `https://<COORDINATOR_LAN_IP>:5000`.

### Start Agent-02 (Prachi)
```bash
export COORDINATOR_LAN_IP="<COORDINATOR_LAN_IP>"
export AGENT_ID="agent-02"
export AGENT_TOKEN="1001"
export SWARM_AUTH_TOKEN="null_warriors_lan_secret_2026"

./scripts/start_worker_lan.sh
```
*PowerShell equivalent:*
```powershell
.\scripts\Start-WorkerLan.ps1 -CoordinatorLanIp "<COORDINATOR_LAN_IP>" -AgentId agent-02 -AgentToken 1001 -AuthToken "null_warriors_lan_secret_2026"
```

### Start Agent-03 (Aman)
```bash
export COORDINATOR_LAN_IP="<COORDINATOR_LAN_IP>"
export AGENT_ID="agent-03"
export AGENT_TOKEN="1002"
export SWARM_AUTH_TOKEN="null_warriors_lan_secret_2026"

./scripts/start_worker_lan.sh
```
*PowerShell equivalent:*
```powershell
.\scripts\Start-WorkerLan.ps1 -CoordinatorLanIp "<COORDINATOR_LAN_IP>" -AgentId agent-03 -AgentToken 1002 -AuthToken "null_warriors_lan_secret_2026"
```

### Start Agent-04 (Akshitha)
```bash
export COORDINATOR_LAN_IP="<COORDINATOR_LAN_IP>"
export AGENT_ID="agent-04"
export AGENT_TOKEN="1003"
export SWARM_AUTH_TOKEN="null_warriors_lan_secret_2026"

./scripts/start_worker_lan.sh
```
*PowerShell equivalent:*
```powershell
.\scripts\Start-WorkerLan.ps1 -CoordinatorLanIp "<COORDINATOR_LAN_IP>" -AgentId agent-04 -AgentToken 1003 -AuthToken "null_warriors_lan_secret_2026"
```

### Worker Startup Output
Workers output the startup banner and registration line:
```text
Team: null_warriors
Agent: agent-02
Coordinator: https://<COORDINATOR_LAN_IP>:5000
TLS: enabled
Phase: HOLD
Registering with coordinator at https://<COORDINATOR_LAN_IP>:5000
```
*(Tokens are never displayed or leaked).*

---

## 6. Operator Phase Management & Emergency Controls

The human operator controls the competition phase using `SWARM_OPERATOR_TOKEN` from Agent-01:

### Advance to ATTACK Phase:
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  --cacert certs/ca.crt \
  -H "X-Operator-Token: null_warriors_operator_root_2026" \
  -H "Content-Type: application/json" \
  -d '{"phase":"ATTACK","round_id":1}'
```

### Advance to DEFENSE Phase (Phase Fence active):
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  --cacert certs/ca.crt \
  -H "X-Operator-Token: null_warriors_operator_root_2026" \
  -H "Content-Type: application/json" \
  -d '{"phase":"DEFENSE","round_id":1}'
```

### Return to Safe HOLD:
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/phase/advance \
  --cacert certs/ca.crt \
  -H "X-Operator-Token: null_warriors_operator_root_2026" \
  -H "Content-Type: application/json" \
  -d '{"phase":"HOLD","round_id":1}'
```

### Emergency Kill Switch (Halts all workers instantly):
```bash
curl -X POST https://<COORDINATOR_LAN_IP>:5000/api/swarm/kill-switch \
  --cacert certs/ca.crt \
  -H "X-Operator-Token: null_warriors_operator_root_2026" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Operator emergency stop"}'
```

---

## 7. Troubleshooting & Verification

1. **Verify Windows Portproxy**:
   ```powershell
   netsh interface portproxy show all
   ```
2. **Test TCP Connectivity from Worker**:
   ```powershell
   Test-NetConnection <COORDINATOR_LAN_IP> -Port 5000
   ```
3. **Verify TLS SAN on Certificate**:
   ```bash
   openssl x509 -in certs/server.crt -text -noout | grep -A 1 "Subject Alternative Name"
   ```
   *Must match the exact operator-entered `<COORDINATOR_LAN_IP>`.*
