# KOTH Swarm — Multi-Agent LAN Setup & Network Guide

This guide details how to configure and deploy a coordinated 4-agent team across multiple Windows laptops over a local network (LAN) or VPN (such as WireGuard, ZeroTier, or Radmin VPN) for a King-of-the-Hill (KOTH) or Red Team vs Blue Team competition.

---

## 1. Multi-Agent Architecture

```
                    +------------------------------------+
                    |  Lead Operator Workstation         |
                    |  IP: 192.168.1.50                  |
                    |  Runs: KOTH Command Desktop App    |
                    |        koth-coordinator.exe :5000  |
                    |        (Holds Authoritative State) |
                    +-----------------+------------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
+------------------+         +------------------+         +------------------+
|  Teammate 1      |         |  Teammate 2      |         |  Teammate 3      |
|  IP: 192.168.1.51|         |  IP: 192.168.1.52|         |  IP: 192.168.1.53|
|  Agent: agent-02 |         |  Agent: agent-03 |         |  Agent: agent-04 |
|  Role: Recon     |         |  Role: Attack    |         |  Role: Defense   |
|  Runs: Worker    |         |  Runs: Worker    |         |  Runs: Worker    |
+------------------+         +------------------+         +------------------+
```

### Team Roster Roles
- **agent-01 (Team Leader)**: Runs on the host machine or remote laptop. Commands overall swarm posture, triggers phase changes, and approves emergency actions.
- **agent-02 (Offensive Recon)**: Port scanning, credential brute-forcing, vulnerability enumeration.
- **agent-03 (Exploitation & Hill Capture)**: Executes authorized attack plans, plants ownership tokens, triggers verification checks.
- **agent-04 (Hill Hardening & Defense)**: Patches discovered vulnerabilities, monitors cron jobs, restarts defense daemons, guards flag files.

---

## 2. Host Machine Configuration (The Coordinator)

The machine hosting the KOTH Command coordinator must be reachable by teammates on the local subnet.

### Step 1: Find Coordinator LAN IP
On the host machine, open PowerShell and run:
```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" -or $_.InterfaceAlias -like "*Ethernet*" } | Select-Object IPAddress, InterfaceAlias
```
*Example host IP:* `192.168.1.50`

### Step 2: Open Inbound Firewall Port 5000
Allow inbound HTTP traffic to the coordinator server:
```powershell
New-NetFirewallRule -DisplayName "KOTH Coordinator Port 5000" `
    -Direction Inbound `
    -LocalPort 5000 `
    -Protocol TCP `
    -Action Allow
```

### Step 3: Launch Host with LAN Profile
Launch the coordinator in `LAN_REHEARSAL` profile with authoritative tokens:
```powershell
& "C:\Program Files\KOTH Command\resources\backend\koth-coordinator.exe" `
    --host 0.0.0.0 `
    --port 5000 `
    --profile LAN_REHEARSAL `
    --auth-token "SwarmTeamSecret_2026!" `
    --operator-token "SwarmOpSecret_2026!" `
    --authorized-agents "agent-01,agent-02,agent-03,agent-04" `
    --agent-usernames "agent-01:leader,agent-02:prachi,agent-03:aman,agent-04:akshitha"
```

Verify the coordinator is listening:
```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 5000
```

---

## 3. Remote Teammate Machines (The Workers)

Each teammate connects their agent worker loop to the coordinator host.

### Step 1: Verify Connectivity to Host
From the teammate laptop:
```powershell
Test-NetConnection -ComputerName 192.168.1.50 -Port 5000
```
Expected: `TcpTestSucceeded : True`.

### Step 2: Connect via Unified KOTH Command Desktop Application (Recommended)
Every teammate simply installs and runs `KOTH-Command-Setup.exe`:
1. On first launch, select **Participant Client**.
2. Enter Central Server Host: `192.168.1.50`, Port: `5000`.
3. Click **Connect to Central Server**.
4. Log in using your assigned teammate username and password (e.g. `bob_recon` / `Password123!`).
5. In **Agent Monitoring**, click the green **Start Local Worker** button on the "Local Agent Worker on this PC" card.
6. The desktop client automatically launches the local worker in the background, connects to the central coordinator, and streams authentic CPU/RAM metrics!

---

### Step 2-B: Standalone CLI Worker Execution (Alternative Headless Method)
If a teammate prefers running the worker in a separate terminal or headless environment:
Run `koth-agent-worker.exe` with your credentials:

##### Teammate 1 (PC 2 / agent-02 - Recon Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-02 --username "bob_recon" --password "Password123!"
```

##### Teammate 2 (PC 3 / agent-03 - Exploit Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-03 --username "charlie_exploit" --password "Password123!"
```

##### Teammate 3 (PC 4 / agent-04 - Defense Specialist):
```powershell
.\koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-04 --username "diana_defense" --password "Password123!"
```

---

## 4. Real-Time Telemetry & Monitoring

Once agents start their worker loops:
1. Open the **KOTH Command Desktop Application** on the Leader workstation.
2. Navigate to **Agent Monitoring**:
   - Verify all 4 agents display a green **ONLINE** badge.
   - Heartbeat counter updates in real time (every 3–5 seconds).
   - CPU and memory metrics show live consumption.
3. Navigate to **Swarm Coordination**:
   - View assigned hills, lease expirations, and active tasks.
   - Decompose shared objectives across agents without task overlap.
4. Notifications Feed:
   - Live events (hill state changes, heartbeats, task handoffs) stream in real time.

---

## 5. Network Troubleshooting & Diagnostics

| Symptom | Cause | Solution |
|---|---|---|
| `Connection refused` (10061) | Coordinator not running or bound to `127.0.0.1` instead of `0.0.0.0`. | Check `--host 0.0.0.0` argument on coordinator startup. |
| `Connection timed out` | Windows Firewall blocking inbound port 5000 on host. | Run `New-NetFirewallRule` as Admin on host machine. |
| `HTTP 401 Unauthorized` | Mismatch between `SWARM_AUTH_TOKEN` on worker and host. | Verify exact token string on both machines. |
| `Agent marked OFFLINE` | Worker missed heartbeats for >10 seconds (network jitter or process paused). | Check network latency with `ping 192.168.1.50 -t`. Default heartbeat timeout is 10.0s. |
| `Task Lease Expired` | Agent took longer than 15s without renewing lease. | Increase lease duration using `--lease-ttl 30.0` if competition network latency is high. |

