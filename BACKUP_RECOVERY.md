# KOTH Command — Backup & Disaster Recovery Procedures

## 1. Storage Architecture Overview

All persistent data in KOTH Command is stored in an authoritative SQLite database outside the application installation directory:

- **Database File**: `%APPDATA%\KOTH Command\koth_swarm.db`
- **Write-Ahead Log (WAL)**: `%APPDATA%\KOTH Command\koth_swarm.db-wal`
- **Shared Memory File**: `%APPDATA%\KOTH Command\koth_swarm.db-shm`

### Persisted Schemas & Tables
- `teams`, `members`: Registered team rosters, hashed passwords, roles, seats.
- `competitions`, `competition_hills`: Competition state, modes (KOTH / Red vs Blue), hill targets, scoring parameters.
- `hill_state`: Authoritative hill control flags, defense statuses, capture timestamps.
- `agent_leases`: Active task locks, leases, and expiration timers.
- `notifications`: Competition events, attack alerts, and audit feed items.
- `coordination_messages`: Swarm cross-agent communication and task coordination.
- `agent_llm_configs`: Masked and encrypted per-agent model endpoints and providers.

---

## 2. Live Hot Backup Procedure

Because SQLite runs in Write-Ahead Logging (WAL) mode, simple file copy of `koth_swarm.db` without locking can produce an inconsistent snapshot if written during a competition round.

Use one of the following safe backup methods:

### Method A: SQLite CLI VACUUM INTO (Atomic Snapshot)
If `sqlite3.exe` or Python is available:
```powershell
python -c "import sqlite3, os; src = os.path.expandvars(r'%APPDATA%\KOTH Command\koth_swarm.db'); conn = sqlite3.connect(src); conn.execute('VACUUM INTO \"backup_snapshot.db\"'); conn.close(); print('Backup complete.')"
```

### Method B: PowerShell Snapshot Script
We provide a dedicated backup script `scripts/backup_database.ps1`:
```powershell
# Usage:
powershell -ExecutionPolicy Bypass -File scripts\backup_database.ps1 -BackupDir "C:\KOTH_Backups"
```

---

## 3. Automated Scheduled Backup Script

Create a scheduled PowerShell script `scripts/backup_database.ps1`:

```powershell
param(
    [string]$BackupDir = "$env:APPDATA\KOTH Command\backups",
    [int]$RetainDays = 7
)

$sourceDb = "$env:APPDATA\KOTH Command\koth_swarm.db"
if (-not (Test-Path $sourceDb)) {
    Write-Warning "Source database not found at $sourceDb"
    exit 1
}

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$targetBackup = Join-Path $BackupDir "koth_swarm_backup_$timestamp.db"

Write-Host "Creating atomic database backup to $targetBackup..."
$pythonScript = "import sqlite3; conn = sqlite3.connect(r'$sourceDb'); conn.execute('VACUUM INTO r''$targetBackup'''); conn.close()"
python -c $pythonScript

if (Test-Path $targetBackup) {
    Write-Host "Backup created successfully: $((Get-Item $targetBackup).Length / 1KB) KB"
} else {
    Write-Error "Backup creation failed!"
    exit 1
}

# Purge backups older than retention policy
Get-ChildItem -Path $BackupDir -Filter "koth_swarm_backup_*.db" | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetainDays) } | 
    Remove-Item -Force
```

---

## 4. Disaster Recovery & Restoration

### Scenario 1: State Restoration from Backup
If the active database becomes corrupted or a round was corrupted:

1. Close the **KOTH Command** desktop application.
2. Ensure no orphaned `koth-coordinator.exe` processes are running:
   ```powershell
   Get-Process -Name "koth-coordinator" -ErrorAction SilentlyContinue | Stop-Process -Force
   ```
3. Navigate to `%APPDATA%\KOTH Command\`.
4. Rename or archive the corrupted database:
   ```powershell
   Rename-Item "$env:APPDATA\KOTH Command\koth_swarm.db" "koth_swarm_corrupted.db"
   Remove-Item "$env:APPDATA\KOTH Command\koth_swarm.db-wal" -Force -ErrorAction SilentlyContinue
   Remove-Item "$env:APPDATA\KOTH Command\koth_swarm.db-shm" -Force -ErrorAction SilentlyContinue
   ```
5. Copy your selected backup into place:
   ```powershell
   Copy-Item "C:\KOTH_Backups\koth_swarm_backup_YYYYMMDD_HHMMSS.db" "$env:APPDATA\KOTH Command\koth_swarm.db"
   ```
6. Run SQLite Integrity Check:
   ```powershell
   python -c "import sqlite3, os; conn = sqlite3.connect(os.path.expandvars(r'%APPDATA%\KOTH Command\koth_swarm.db')); print(conn.execute('PRAGMA integrity_check;').fetchall()); print(conn.execute('PRAGMA foreign_key_check;').fetchall())"
   ```
   Expected output: `[('ok',)]` and `[]`.
7. Launch KOTH Command. The application will resume with the restored state.

---

## 5. Clean Slate Competition Reset

Before starting a brand-new tournament or rehearsal:
1. Close KOTH Command.
2. Delete the active database:
   ```powershell
   Remove-Item "$env:APPDATA\KOTH Command\koth_swarm.db*" -Force
   ```
3. Start KOTH Command. The system will create a fresh, clean database schema ready for team registration and competition launch.

