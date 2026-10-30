# KOTH Command — Five-PC LAN Deployment Architecture & Operations Guide

## 1. System Architecture Overview

This deployment model distributes the cybersecurity competition operations across **five separate physical Windows PCs** on a dedicated local area network (LAN) or private virtual network:

```
                            +-------------------------------------------+
                            |            CENTRAL SERVER PC              |
                            |  - KOTH Command Desktop Operations Center |
                            |  - Authoritative Swarm Coordinator Server |
                            |  - SQLite Persistence (koth_swarm.db)     |
                            |  - Competition & Hill State Management    |
                            |  - IP: 192.168.1.50 : 5000 (TCP)          |
                            +---------------------+---------------------+
                                                  |
                               +------------------+------------------+
                               |    Encrypted LAN REST Transport     |
                               |  (Authenticated Session / Tokens)   |
                               +------------------+------------------+
                                                  |
         +--------------------+-------------------+-------------------+--------------------+
         |                    |                                       |                    |
         v                    v                                       v                    v
+------------------+ +------------------+                   +------------------+ +------------------+
|   AGENT PC 1     | |   AGENT PC 2     |                   |   AGENT PC 3     | |   AGENT PC 4     |
| Role: Leader     | | Role: Specialist |                   | Role: Specialist | | Role: Specialist |
| Agent: agent-01  | | Agent: agent-02  |                   | Agent: agent-03  | | Agent: agent-04  |
| Focus: Hill 1    | | Focus: Hill 2    |                   | Focus: Hill 3    | | Focus: Hill 4    |
| (Coordination)   | | (Reconnaissance) |                   | (Exploitation)   | | (Defense/Patch)  |
| Worker Exe       | | Worker Exe       |                   | Worker Exe       | | Worker Exe       |
+------------------+ +------------------+                   +------------------+ +------------------+
```

### Core Design Rules
1. **Centralized SQLite Persistence**: The SQLite database (`koth_swarm.db`) exists **strictly on the Central PC**. Remote agents communicate exclusively over authenticated HTTP/HTTPS APIs; they never access the database file directly.
2. **Independent Agent Identity & Authentication**: Each of the four agents has an isolated identity (`agent-01`, `agent-02`, `agent-03`, `agent-04`) with dedicated credentials. Cross-agent impersonation is cryptographically rejected.
3. **Fail-Safe Disconnect Handling**: If an agent loses connection to the Central PC, it enters `SAFE_DEGRADED` (HOLD) mode to avoid uncoordinated actions, automatically attempting reconnection every 2 seconds.
4. **Lease Reaping & Work Reallocation**: If a leased agent drops offline, the central coordinator reaps its expired lease and returns the task to `PENDING`, allowing the Leader or another specialist to claim it without duplicate execution.

---

## 2. Central PC Server Configuration

The Central PC runs the **KOTH Command Desktop Application** and the authoritative **KOTH Swarm Coordinator Server**.

### A. Network Interface & IP Identification
Open PowerShell on the Central PC:
```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" -or $_.InterfaceAlias -like "*Ethernet*" } | Select-Object IPAddress, InterfaceAlias
```
*Note the Central PC's LAN IP address (e.g. `192.168.1.50`).*

### B. Windows Firewall Configuration (Minimum Required Access)
Configure Windows Firewall to permit inbound TCP connections on port 5000 **strictly from the local subnet**. Do not disable Windows Firewall.

Run PowerShell as Administrator on the Central PC:
```powershell
# 1. Ensure private profile is active on your LAN network connection
Get-NetConnectionProfile

# 2. Add inbound firewall rule restricted to local subnet
New-NetFirewallRule -DisplayName "KOTH Command Central Coordinator" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 5000 `
    -RemoteAddress LocalSubnet `
    -Profile Private, Domain
```

### C. Starting the Central PC Backend
When launching the **KOTH Command Desktop Application** on the Central PC:
- The Electron main process checks if port 5000 is running.
- If inactive, it launches `resources\backend\koth-coordinator.exe` bound to `0.0.0.0:5000`.
- The database is located at `%APPDATA%\KOTH Command\koth_swarm.db`.
- The Central Server LAN IP and port are displayed in the **Central Coordinator Server** banner at the top of the **Agent Monitoring** panel in the desktop application.

---

## 3. Four Remote Agent PCs Setup & Enrollment

Each of the four separate Windows PCs runs the standalone **KOTH Agent Worker** client.

### Distributed Worker Package Deliverable
The agent worker package is available at:
```text
dist-installer\KOTH-Agent-Worker-v1.0.0-win-x64.zip (13.9 MB)
```
Extract this package to each agent PC:
- `koth-agent-worker.exe` (13.5 MB standalone executable)
- `enroll_agent.bat` (1-click interactive enrollment wizard)
- `run_agent.bat` (launcher for configured agent)
- `README.txt`

### Enrollment Method A: Interactive Enrollment Wizard (Recommended)
On the remote agent PC:
1. Double-click `enroll_agent.bat` (or run `koth-agent-worker.exe --enroll`).
2. **Central Server URL**: Enter the Central PC's address:
   ```text
   http://192.168.1.50:5000
   ```
3. **Select Agent Seat**:
   - PC 1: Choose `1` for `agent-01` (Leader / Coordinator — Hill 1)
   - PC 2: Choose `2` for `agent-02` (Reconnaissance Specialist — Hill 2)
   - PC 3: Choose `3` for `agent-03` (Exploitation Specialist — Hill 3)
   - PC 4: Choose `4` for `agent-04` (Defense & Hardening Specialist — Hill 4)
4. **Authentication**:
   - Enter your teammate username & password (e.g. `bob_recon` / `Password123!`).
   - The worker authenticates against `/api/team/login`, acquires an exclusive session token, and saves the configuration to `%APPDATA%\KOTH Agent Worker\agent_config.json`.
5. The worker immediately starts sending live heartbeats and begins polling for authorized tasks.

### Enrollment Method B: Automated Command-Line Execution
Run directly via PowerShell or batch script:

#### PC 1 (Agent 01 — Team Leader):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-01 --username "alice_leader" --password "Password123!"
```

#### PC 2 (Agent 02 — Reconnaissance Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-02 --username "bob_recon" --password "Password123!"
```

#### PC 3 (Agent 03 — Exploitation Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-03 --username "charlie_exploit" --password "Password123!"
```

#### PC 4 (Agent 04 — Defense Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-04 --username "diana_defender" --password "Password123!"
```

---

## 4. HTTPS / TLS Configuration (Optional Managed Security)

To enable encrypted communication over the LAN:

1. On the Central PC, generate Root CA and Server certificates with Subject Alternative Names for your LAN IP:
   ```powershell
   python scripts\generate_lan_cert.py "192.168.1.50"
   ```
   *Generated in `certs\`: `ca.crt`, `server.crt`, `server.key`.*
2. Start coordinator on Central PC with TLS flags:
   ```powershell
   koth-coordinator.exe --host 0.0.0.0 --port 5000 --use-tls --ssl-cert certs\server.crt --ssl-key certs\server.key
   ```
3. Copy `ca.crt` to the four Agent PCs.
4. Run agent workers with TLS verification:
   ```powershell
   koth-agent-worker.exe --coordinator-url "https://192.168.1.50:5000" --ca-cert ca.crt --agent-id agent-02
   ```

---

## 5. Five-PC Deployment Verification Procedure

Execute this 8-step verification checklist to validate the 5-PC LAN deployment:

| Test ID | Scenario | Verification Action | Expected Outcome | Pass/Fail |
|---|---|---|---|---|
| **V-01** | **Central API Reachability** | From PC 2, run: `Invoke-RestMethod http://192.168.1.50:5000/healthz` | HTTP 200 returned with team ID and current phase (`HOLD`). | [ ] |
| **V-02** | **Four-Agent Registration** | Start agent workers on PC 1, PC 2, PC 3, PC 4 | Desktop UI on Central PC shows **Connected Agents: 4/4** with green badges. | [ ] |
| **V-03** | **Real Telemetry Stream** | Inspect **Agent Monitoring** on Central PC | Real CPU% and RAM% update live every 3 seconds for all 4 PCs. | [ ] |
| **V-04** | **Phase Synchronization** | Leader on Central PC changes phase: `HOLD -> ATTACK` | All 4 remote PC worker consoles log phase transition to `ATTACK` within 1 second. | [ ] |
| **V-05** | **Agent Disconnect (Drop)** | Unplug network cable or close terminal on PC 2 (`agent-02`) | Central PC marks Agent 02 **STALE** after 10s and **OFFLINE** after 15s. | [ ] |
| **V-06** | **Lease Expiration & Reassignment** | Agent 02 held a leased task before disconnect | Central coordinator reaps lease, resets task to `PENDING`. PC 3 (`agent-03`) claims it. | [ ] |
| **V-07** | **Anti-Collision & No Duplicate** | Both Agent 03 and Agent 04 request work on same hill | Coordinator grants exclusive lease to Agent 03; rejects duplicate execution by Agent 04. | [ ] |
| **V-08** | **Auto-Reconnect & Recovery** | Reconnect network cable on PC 2 (`agent-02`) | Agent 02 worker automatically re-registers, resynchronizes phase, and resumes tasks. | [ ] |

