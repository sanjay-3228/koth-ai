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

