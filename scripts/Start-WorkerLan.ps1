<#
.SYNOPSIS
Start Swarm Worker in LAN_REHEARSAL or RADMIN_REHEARSAL on Windows PowerShell.
#>
param(
    [string]$AgentId = ($env:AGENT_ID ? $env:AGENT_ID : "agent-02"),
    [string]$TeamId = ($env:TEAM_ID ? $env:TEAM_ID : "null_warriors"),
    [string]$CoordinatorLanIp = $env:COORDINATOR_LAN_IP,
    [int]$Port = 5000,
    [string]$Profile = "LAN_REHEARSAL",
    [string]$AuthToken = $env:SWARM_AUTH_TOKEN,
    [string]$AgentToken = ($env:AGENT_TOKEN ? $env:AGENT_TOKEN : $env:SWARM_AGENT_TOKEN),
    [string]$CaCert = "certs/ca.crt"
)

if ($env:SWARM_PORT) { $Port = [int]$env:SWARM_PORT }
if ($env:SWARM_CA_CERT) { $CaCert = $env:SWARM_CA_CERT }

if (-not $CoordinatorLanIp) {
    $CoordinatorLanIp = Read-Host "Enter coordinator IP"
}

if (-not $CoordinatorLanIp) {
    Write-Error "Error: Coordinator LAN/VPN IP is required."
    exit 1
}

# Resolve token from roster defaults if not explicitly set
if (-not $AgentToken) {
    $rosterTokens = @{
        "agent-01" = "1000"
        "agent-02" = "1001"
        "agent-03" = "1002"
        "agent-04" = "1003"
    }
    if ($rosterTokens.ContainsKey($AgentId)) {
        $AgentToken = $rosterTokens[$AgentId]
    } else {
        $AgentToken = Read-Host "Enter token for $AgentId"
    }
}

if ($CoordinatorLanIp -like "26.*" -and $Profile -eq "LAN_REHEARSAL") {
    $Profile = "RADMIN_REHEARSAL"
}

$coordUrl = "https://${CoordinatorLanIp}:${Port}"

Write-Host "Registering with coordinator at $coordUrl" -ForegroundColor Green

python -m agent.koth_controller `
  --agent-id $AgentId `
  --team-id $TeamId `
  --role WORKER `
  --worker `
  --swarm `
  --profile $Profile `
  --coordinator-url $coordUrl `
  --auth-token $AuthToken `
  --agent-token $AgentToken `
  --ca-cert $CaCert `
  --use-tls

