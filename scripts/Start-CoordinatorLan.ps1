<#
.SYNOPSIS
Start Swarm Coordinator in LAN_REHEARSAL or RADMIN_REHEARSAL on Windows PowerShell.
#>
param(
    [string]$CoordinatorLanIp = $env:COORDINATOR_LAN_IP,
    [string]$CoordinatorBindHost = $env:COORDINATOR_BIND_HOST,
    [int]$Port = 5000,
    [string]$Profile = "LAN_REHEARSAL",
    [string]$AuthToken = $env:SWARM_AUTH_TOKEN,
    [string]$OperatorToken = $env:SWARM_OPERATOR_TOKEN,
    [string]$AgentTokens = ($env:SWARM_AGENT_TOKENS ? $env:SWARM_AGENT_TOKENS : "agent-01:1000,agent-02:1001,agent-03:1002,agent-04:1003"),
    [string]$AuthorizedAgents = "agent-01,agent-02,agent-03,agent-04",
    [string]$SslCert = "certs/server.crt",
    [string]$SslKey = "certs/server.key"
)

if ($env:SWARM_PORT) { $Port = [int]$env:SWARM_PORT }
if ($env:AUTHORIZED_AGENTS) { $AuthorizedAgents = $env:AUTHORIZED_AGENTS }
if ($env:SWARM_SSL_CERT) { $SslCert = $env:SWARM_SSL_CERT }
if ($env:SWARM_SSL_KEY) { $SslKey = $env:SWARM_SSL_KEY }

if (-not $CoordinatorLanIp) {
    $CoordinatorLanIp = Read-Host "Enter coordinator IP"
}

if (-not $CoordinatorLanIp) {
    Write-Error "Error: Coordinator LAN/VPN IP is required."
    exit 1
}

$bindHost = if ($CoordinatorBindHost) { $CoordinatorBindHost } else { $CoordinatorLanIp }

if (($CoordinatorLanIp -like "26.*" -or $bindHost -like "26.*") -and $Profile -eq "LAN_REHEARSAL") {
    $Profile = "RADMIN_REHEARSAL"
}

Write-Host "Starting Swarm Coordinator on $bindHost`:$Port (Reachable at: $CoordinatorLanIp, Profile: $Profile)..." -ForegroundColor Cyan

python -m agent.swarm.coordinator_server `
  --host $bindHost `
  --port $Port `
  --profile $Profile `
  --auth-token $AuthToken `
  --operator-token $OperatorToken `
  --authorized-agents $AuthorizedAgents `
  --agent-tokens $AgentTokens `
  --ssl-cert $SslCert `
  --ssl-key $SslKey `
  --use-tls

