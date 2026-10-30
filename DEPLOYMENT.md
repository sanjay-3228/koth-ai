# KOTH Command — Production Deployment & Operations Guide

## 1. System Overview

**KOTH Command** is an enterprise desktop operations platform for cyber defense and offensive security teams participating in King-of-the-Hill (KOTH) and Red Team vs Blue Team competitions.

The platform consists of two integrated components:
1. **Frontend Operations Center**: An Electron 28 / React 18 / Vite light-themed desktop application providing real-time telemetry, 4-step competition creation, live hill defense/attack portals, notifications, and multi-agent coordination.
2. **Authoritative Coordinator**: A standalone Python-based binary (`koth-coordinator.exe`) providing REST APIs, SQLite state persistence, heartbeat tracking, lease management, RBAC, and competition state machines.

---

## 2. System Requirements

### Hardware Requirements
- **Operating System**: Windows 10 (64-bit) or Windows 11 (64-bit), Build 19041+.
- **Processor**: Dual-Core x86_64 CPU (2.0 GHz or higher).
- **RAM**: Minimum 4 GB (8 GB recommended when running local agent workers).
- **Disk Space**: 500 MB free for installation, binaries, and local SQLite database.

### Network Requirements
- **Local Port 5000 (TCP)**: Used by the authoritative coordinator REST API.
- **Local Port 3000 (TCP)**: (Development mode only) Vite dev server.
- **Inbound Firewall**: If remote team agents on the LAN connect to this coordinator, Windows Firewall must allow inbound TCP connections on port 5000.

---

## 3. Installation Guide

### Option A: Windows Installer (Standard Production Deployment)

1. Obtain the installer executable:
   ```text
   KOTH-Command-Setup.exe
   ```
2. Double-click `KOTH-Command-Setup.exe`.
3. Follow the setup wizard:
   - Choose the destination folder (default: `%LOCALAPPDATA%\Programs\koth-command`).
   - Choose whether to create Desktop and Start Menu shortcuts.
   - Click **Install**.
4. Once completed, check **Run KOTH Command** and click **Finish**.

### Installation Layout on Windows
- **Application Binaries**:
  `%LOCALAPPDATA%\Programs\koth-command\`
  - `KOTH Command.exe`: Main Electron desktop launcher.
  - `resources\backend\koth-coordinator.exe`: Packaged coordinator engine (only executed when configured as Host).
  - `resources\worker\koth-agent-worker.exe`: Packaged agent worker runtime (spawned when local worker is started).
  - `resources\app.asar`: Packaged React frontend assets.
- **Client Configuration**:
  `%APPDATA%\KOTH Command\client_config.json`: Stores whether the machine is Host or Client, target server LAN IP, port, and TLS preferences.
- **Persistent Storage (Host Only)**:
  `%APPDATA%\KOTH Command\`
  - `koth_swarm.db`: Authoritative SQLite database (persists across application updates).
  - `koth_swarm.db-wal` / `koth_swarm.db-shm`: SQLite Write-Ahead Log files.
- **Runtime Logs**:
  `%APPDATA%\KOTH Command\logs\`
  - `coordinator.log`: Output from the authoritative coordinator engine (Host mode).
  - `local_worker_<agent_id>.log`: Output from the integrated local agent worker.

---

## 4. First-Launch Configuration: Host vs Client Mode

On first launch, the desktop application displays the **Central Server Setup Wizard**:

### Mode 1: Host Central Server (Designated Central PC)
- Select **Host Server**.
- The Electron main process launches the bundled `koth-coordinator.exe` bound to `0.0.0.0:5000` with the central SQLite database.
- The UI displays the Central PC's detected LAN IP (e.g. `192.168.1.50`).
- Teammate desktop clients across the LAN connect to this address.

### Mode 2: Connect to Central Server (Participant Desktop Client PCs)
- Select **Participant Client**.
- Enter:
  - **Server Hostname or LAN IP**: (e.g. `192.168.1.50`).
  - **Service Port**: `5000`.
  - **Protocol**: `HTTP` or `HTTPS`.
  - **Trust LAN SSL**: Checked for local competition networks.
- Click **Test Connection** to verify latency.
- Click **Connect to Central Server**.
- **Important**: In Client mode, the local coordinator is NEVER started and no local SQLite database is created. All operations synchronize directly with the Central PC.

---

## 5. Local Agent Worker Execution within Desktop Client

Once logged in as an authorized squad member (`alice_leader`, `bob_recon`, `charlie_exploit`, `diana_defense`):
1. Navigate to **Agent Monitoring** in the left sidebar.
2. The top card displays: **Local Agent Worker on this PC: `agent-XX` (Hill X)**.
3. Click **Start Local Worker**:
   - Electron spawns `resources\worker\koth-agent-worker.exe` with your authenticated session token.
   - The worker automatically collects local hardware telemetry (`psutil` CPU% and RAM%) and begins sending real heartbeats every 3-5 seconds.
   - The agent node in the central swarm grid transitions to `ONLINE / IDLE`.
4. Click **Stop Local Worker** to halt the worker subprocess at any time.

---

## 6. Post-Deployment Verification Checklist

Verify each of the following tests immediately after installation:

| Step | Verification Procedure | Expected Result | Pass/Fail |
|---|---|---|---|
| 1 | Launch `KOTH Command.exe` | Application window opens with light-themed dashboard | [ ] |
| 2 | Check `http://127.0.0.1:5000/healthz` via browser or curl | Returns JSON `{"service_status": "ok", ...}` | [ ] |
| 3 | Inspect `%APPDATA%\KOTH Command` | `koth_swarm.db` exists and is initialized | [ ] |
| 4 | Inspect `%APPDATA%\KOTH Command\logs\coordinator.log` | Log contains startup banner and hill status checks | [ ] |
| 5 | Team Registration | Navigate to Register Team, submit 4-member roster | Success message, tokens saved in session | [ ] |
| 6 | 4-Step Competition Wizard | Create a KOTH or Red vs Blue competition | Wizard advances through steps 1-4 and launches | [ ] |
| 7 | Application Exit | Close window, check Task Manager | `koth-coordinator.exe` terminates completely | [ ] |

---

## 6. Maintenance & Troubleshooting

### Coordinator Port Conflict (Port 5000 in use)
If port 5000 is occupied by another service:
1. Identify the occupying process:
   ```powershell
   Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess
   ```
2. If it is an orphaned `koth-coordinator.exe`, terminate it:
   ```powershell
   Stop-Process -Name "koth-coordinator" -Force
   ```

### Clearing / Resetting the Database
To reset the database to a blank competition slate:
1. Exit KOTH Command.
2. Delete `%APPDATA%\KOTH Command\koth_swarm.db`.
3. Restart KOTH Command; the schema will reinitialize automatically.

