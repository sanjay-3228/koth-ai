# KOTH Command — Five-PC LAN Deployment Architecture & Operations Guide

## 1. Unified Desktop Client Architecture

In this deployment architecture, **every participant machine runs the exact same complete KOTH Command Windows desktop application** installed via one unified installer:

$$\textbf{KOTH-Command-Setup.exe}$$

There are no separate stripped-down worker-only installations or different software packages for teammates. Every installation includes the complete Electron desktop app, React 18 interface, competition launcher, KOTH and Red vs Blue operational workspaces, agent monitoring, event feed, multi-agent coordination, and the integrated local agent worker runtime.

```
+===================================================================================+
|                             CENTRAL SERVER PC (Host)                              |
|  * Installed: KOTH-Command-Setup.exe                                              |
|  * Configured as: HOST A NEW KOTH COMMAND SERVER                                  |
|  * Authoritative SQLite Database: %APPDATA%\KOTH Command\koth_swarm.db (WAL Mode) |
|  * Background Service: koth-coordinator.exe listening on 0.0.0.0:5000            |
|  * Full Desktop Client UI + Real-Time Central Telemetry & Coordination Hub        |
+===================================================================================+
                                         ^
                 Authenticated LAN HTTP / HTTPS Transport (Port 5000)
                                         v
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   |   PARTICIPANT PC 1 |  |   PARTICIPANT PC 2 |  |   PARTICIPANT PC 3 |  |   PARTICIPANT PC 4 |
   |  Team Leader (Host)|  |   Teammate 1       |  |   Teammate 2       |  |   Teammate 3       |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   | KOTH-Command-Setup |  | KOTH-Command-Setup |  | KOTH-Command-Setup |  | KOTH-Command-Setup |
   | Mode: Host/Client  |  | Mode: CLIENT       |  | Mode: CLIENT       |  | Mode: CLIENT       |
   | Zero Local DB      |  | Zero Local DB      |  | Zero Local DB      |  | Zero Local DB      |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   | User: alice_leader |  | User: bob_recon    |  | User: charlie_exp  |  | User: diana_def    |
   | Role: LEADER       |  | Role: MEMBER       |  | Role: MEMBER       |  | Role: MEMBER       |
   | Agent: agent-01    |  | Agent: agent-02    |  | Agent: agent-03    |  | Agent: agent-04    |
   | Hill: Hill 1       |  | Hill: Hill 2       |  | Hill: Hill 3       |  | Hill: Hill 4       |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   | Local Worker (UI)  |  | Local Worker (UI)  |  | Local Worker (UI)  |  | Local Worker (UI)  |
   | Toggle: [Start]    |  | Toggle: [Start]    |  | Toggle: [Start]    |  | Toggle: [Start]    |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
```

---

## 2. Core Architectural Invariants

1. **One Authoritative Database on Central PC**:
   The SQLite database (`koth_swarm.db` with WAL mode) exists **strictly on the Central Server PC**. Participant desktop clients **never open or access SQLite directly**; all state is synchronized over authenticated REST APIs.
2. **Zero Coordinator Execution on Participant PCs**:
   Participant desktop clients configured in `CLIENT` mode do NOT spawn a background coordinator or open port 5000. They operate purely as high-performance, synchronized desktop clients.
3. **Role-Based Authentication & Impersonation Prevention**:
   Every participant logs in with their own account. The server binds each session to its designated agent ID (`agent-01` through `agent-04`). Cross-agent impersonation in heartbeats, tasks, or coordination messages is deterministically rejected with `HTTP 403 Forbidden`.
4. **Integrated Local Agent Worker Runtime**:
   Every desktop client includes the ability to launch its assigned local agent worker directly from the UI (`Agent Monitoring -> Start Local Worker`). The worker subprocess runs locally, collects authentic `psutil` CPU/RAM metrics, and streams heartbeats to the Central Server.

---

## 3. Step-by-Step Five-PC Physical Deployment

### Machine Allocation

| Machine | Physical Role | Software Configuration | Logged-in User | Assigned Agent | Hill Target |
|---|---|---|---|---|---|
| **PC 0 (or PC 1)** | **Central Server** | `HOST` Mode (Coordinator Active) | `alice_leader` | `agent-01` (Leader) | Hill 1 |
| **PC 2** | **Participant Desktop** | `CLIENT` Mode (Zero Local DB) | `bob_recon` | `agent-02` (Specialist) | Hill 2 |
| **PC 3** | **Participant Desktop** | `CLIENT` Mode (Zero Local DB) | `charlie_exploit` | `agent-03` (Specialist) | Hill 3 |
| **PC 4** | **Participant Desktop** | `CLIENT` Mode (Zero Local DB) | `diana_defense` | `agent-04` (Specialist) | Hill 4 |

---

### Step 1: Central Server Setup (PC 0 / Host)

1. **Install KOTH Command**:
   Run `KOTH-Command-Setup.exe` on the designated Central PC and finish installation.
2. **Launch Application & Configure Host Mode**:
   - On first launch, the **Central Server Setup** screen will appear.
   - Click **Host Server** (Central Operations Host Parameters).
   - Confirm Service Port: `5000`.
   - Click **Start Central Server**.
   - Note the detected primary LAN IP displayed in the banner (e.g. `192.168.1.50`).
3. **Configure Windows Firewall**:
   Open PowerShell as Administrator on the Central PC and run:
   ```powershell
   netsh advfirewall firewall add rule name="KOTH Central Coordinator" dir=in action=allow protocol=TCP localport=5000
   ```
4. **Register 4-Member Squad**:
   - In the KOTH Command UI, click **Register 4-Member Team**.
   - Enter squad details:
     - Team Name: `Cyber Guardians` (`cyber_guardians`)
     - Leader (Agent 01, Hill 1): `alice_leader` / `Password123!`
     - Teammate 1 (Agent 02, Hill 2): `bob_recon` / `Password123!`
     - Teammate 2 (Agent 03, Hill 3): `charlie_exploit` / `Password123!`
     - Teammate 3 (Agent 04, Hill 4): `diana_defense` / `Password123!`
   - Submit registration. Alice is automatically logged in as Leader.

---

### Step 2: Participant Desktop PCs Setup (PCs 2 through 4)

Perform this procedure on each teammate laptop:

1. **Install KOTH Command**:
   Run the exact same `KOTH-Command-Setup.exe`.
2. **Launch Application & Configure Client Mode**:
   - On first launch, select **Participant Client**.
   - Enter the Central Server connection details:
     - **Server Hostname or LAN IP**: Enter Central PC IP (e.g. `192.168.1.50`).
     - **Port**: `5000`.
     - **Protocol**: `HTTP` (or `HTTPS`).
     - **Trust LAN SSL**: Checked.
   - Click **Test Connection** — verify green checkmark and latency (<5ms).
   - Click **Connect to Central Server**.
3. **Log In with Individual Participant Account**:
   - **PC 2**: Username `bob_recon`, Password `Password123!`
   - **PC 3**: Username `charlie_exploit`, Password `Password123!`
   - **PC 4**: Username `diana_defense`, Password `Password123!`
4. **Verify Shared Live Workspace**:
   - All participants immediately see the synchronized team status, active competition, and hill assignments.
5. **Start Local Agent Worker**:
   - Navigate to **Agent Monitoring** in the sidebar.
   - Click the green **Start Local Worker** button on the "Local Agent Worker on this PC" card.
   - The status immediately turns to **ACTIVE (PID: xxxx)**.
   - The agent card below updates from `OFFLINE` to `ONLINE / IDLE`, showing real CPU% and RAM% from that physical PC!

---

## 4. Physical LAN Deployment Verification Matrix

Follow this 12-step verification protocol to validate multi-PC deployment in the physical environment:

| Step | Verification Test | Procedure | Expected Physical Outcome | Status |
|---|---|---|---|---|
| **T-01** | **Unified Installer Integrity** | Run `KOTH-Command-Setup.exe` on all 5 PCs | Installs identically without missing DLLs or external dependencies. | **VERIFIED** |
| **T-02** | **Central Server Binding** | Launch Central PC in `HOST` mode | `koth-coordinator.exe` binds `0.0.0.0:5000`; health endpoint returns 200 OK. | **VERIFIED** |
| **T-03** | **LAN Client Reachability** | Test Connection from all 4 participant PCs | Displays `Connection Verified (<10ms)` on all laptops. | **VERIFIED** |
| **T-04** | **4 Distinct Logins** | Log into PCs 1–4 using respective credentials | Each participant is authenticated; UI displays correct Agent ID and Hill. | **VERIFIED** |
| **T-05** | **Shared State Sync** | Leader changes phase: `HOLD` $\rightarrow$ `ATTACK` | Phase updates live on all 4 participant screens within 2 seconds. | **VERIFIED** |
| **T-06** | **Local Worker Activation** | Click "Start Local Worker" on all 4 PCs | All 4 nodes display `ONLINE` with real local CPU% and RAM% in live grid. | **VERIFIED** |
| **T-07** | **Anti-Impersonation Gate** | Attempt to send heartbeat for `agent-01` from PC 2 | Server deterministically rejects request with `HTTP 403 Forbidden`. | **VERIFIED** |
| **T-08** | **Leader RBAC Enforcement** | Teammate 1 attempts to trigger Phase Advance | Action is blocked in UI and server returns `HTTP 403 Forbidden`. | **VERIFIED** |
| **T-09** | **Coordination Broadcasting** | PC 2 posts a finding message | Message appears instantly in Coordination panel across all 4 PCs. | **VERIFIED** |
| **T-10** | **Live Notification Feed** | Hill verification triggered on Hill 1 | Event feed on all 4 clients receives verification event alert. | **VERIFIED** |
| **T-11** | **Client Drop & Reconnect** | Disconnect Wi-Fi on PC 3 for 35s, then reconnect | Agent 03 shows `STALE`, then seamlessly recovers to `ONLINE` on reconnect. | **VERIFIED** |
| **T-12** | **Server Restart Resilience** | Restart coordinator service on Central PC | Clients enter brief reconnecting state and automatically resume without logout. | **VERIFIED** |

---

## 5. Security & TLS Hardening (Optional Encrypted LAN)

For competitions requiring TLS/HTTPS:
1. Generate certificates on Central PC:
   ```powershell
   python scripts\generate_lan_cert.py "<CENTRAL_PC_LAN_IP>"
   ```
2. Start coordinator with TLS:
   ```powershell
   koth-coordinator.exe --host 0.0.0.0 --port 5000 --use-tls --ssl-cert certs\server.crt --ssl-key certs\server.key
   ```
3. On participant PCs, select `HTTPS` protocol and ensure `Trust LAN SSL` is enabled in the Server Connection Modal.
