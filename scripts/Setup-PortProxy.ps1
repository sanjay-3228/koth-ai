<#
.SYNOPSIS
Configure Windows portproxy and firewall dynamically for WSL Coordinator hosting.
#>
param(
    [string]$CoordinatorLanIp = $env:COORDINATOR_LAN_IP,
    [string]$CoordinatorBindHost = $env:COORDINATOR_BIND_HOST,
    [int]$Port = 5000
)

if ($env:SWARM_PORT) { $Port = [int]$env:SWARM_PORT }

if (-not $CoordinatorLanIp) {
    $CoordinatorLanIp = Read-Host "Enter Windows/VPN reachable IP (listenaddress)"
}
if (-not $CoordinatorLanIp) {
    Write-Error "Error: Coordinator LAN/VPN IP is required."
    exit 1
}

if (-not $CoordinatorBindHost) {
    $CoordinatorBindHost = Read-Host "Enter WSL internal IP (connectaddress, from 'wsl hostname -I')"
}
if (-not $CoordinatorBindHost) {
    Write-Error "Error: Coordinator WSL bind IP is required."
    exit 1
}

Write-Host "Configuring portproxy: $CoordinatorLanIp`:$Port -> $CoordinatorBindHost`:$Port..." -ForegroundColor Cyan

netsh interface portproxy add v4tov4 `
    listenaddress=$CoordinatorLanIp `
    listenport=$Port `
    connectaddress=$CoordinatorBindHost `
    connectport=$Port

Write-Host "Verifying portproxy configuration:" -ForegroundColor Green
netsh interface portproxy show all

Write-Host "`nTo allow inbound traffic in Windows Firewall, run (as Administrator):" -ForegroundColor Yellow
Write-Host "New-NetFirewallRule -DisplayName 'KOTH-Swarm-Coordinator' -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow" -ForegroundColor White
