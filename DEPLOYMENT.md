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
  - `KOTH Command.exe`: Main Electron launcher.
  - `resources\backend\koth-coordinator.exe`: Packaged coordinator engine.
  - `resources\app.asar`: Packaged React frontend assets.
- **Persistent Storage (User Data)**:
  `%APPDATA%\KOTH Command\`
  - `koth_swarm.db`: Authoritative SQLite database (persists across application updates).
  - `koth_swarm.db-wal` / `koth_swarm.db-shm`: SQLite Write-Ahead Log files.
- **Runtime Logs**:
  `%APPDATA%\KOTH Command\logs\`
  - `coordinator.log`: Output from the authoritative coordinator engine.

---

## 4. Starting the Application

### Automatic Standalone Mode (Single Operator Machine)
Launch `KOTH Command` from the desktop shortcut or Start Menu.
1. The Electron host checks whether port 5000 is already active.
2. If inactive, Electron automatically launches `resources\backend\koth-coordinator.exe` with:
   - `--port 5000`
   - `--host 0.0.0.0`
   - `--db-path "%APPDATA%\KOTH Command\koth_swarm.db"`
   - `--profile LOCAL_REHEARSAL`
3. Electron polls `http://127.0.0.1:5000/healthz` until healthy (under 2 seconds).
4. The Operations Center opens directly to the Competition Launcher or Participant Workspace.
5. On window close, Electron automatically terminates the coordinator process tree, preventing orphaned background tasks.

### Dedicated Server Mode (Team LAN Coordinator)
In a team competition where one machine acts as the dedicated coordinator and other team members connect from their own laptops:

1. Open PowerShell on the host machine as Administrator.
2. Run the standalone coordinator directly:
   ```powershell
   & "C:\Program Files\KOTH Command\resources\backend\koth-coordinator.exe" `
       --host 0.0.0.0 `
       --port 5000 `
       --profile LAN_REHEARSAL `
       --auth-token "YourSharedTeamToken123!" `
       --operator-token "YourOperatorAdminToken123!" `
       --db-path "C:\ProgramData\KOTH Command\koth_swarm.db"
   ```
3. Open Windows Firewall for LAN inbound access:
   ```powershell
   New-NetFirewallRule -DisplayName "KOTH Swarm Coordinator" `
       -Direction Inbound `
       -LocalPort 5000 `
       -Protocol TCP `
       -Action Allow
   ```
4. Client laptops can now run the KOTH Command desktop app pointing to `http://<SERVER_IP>:5000` or run their agent workers remotely.

---

## 5. Post-Deployment Verification Checklist

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

