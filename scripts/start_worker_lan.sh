#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${COORDINATOR_LAN_IP:-}" ]]; then
  read -r -p "Enter coordinator IP: " COORDINATOR_LAN_IP
fi

if [[ -z "$COORDINATOR_LAN_IP" ]]; then
  echo "Error: COORDINATOR_LAN_IP is required." >&2
  exit 1
fi

AGENT_ID="${AGENT_ID:-}"
if [[ -z "$AGENT_ID" ]]; then
  read -r -p "Enter agent ID [agent-02]: " AGENT_ID
  AGENT_ID="${AGENT_ID:-agent-02}"
fi

# Resolve token from roster defaults if not explicitly set
if [[ -z "${AGENT_TOKEN:-}" ]]; then
  case "$AGENT_ID" in
    agent-01) AGENT_TOKEN="1000" ;;
    agent-02) AGENT_TOKEN="1001" ;;
    agent-03) AGENT_TOKEN="1002" ;;
    agent-04) AGENT_TOKEN="1003" ;;
    *)
      read -r -s -p "Enter agent token for $AGENT_ID: " AGENT_TOKEN
      echo
      ;;
  esac
fi

SWARM_PORT="${SWARM_PORT:-5000}"
: "${SWARM_AUTH_TOKEN:?Set SWARM_AUTH_TOKEN}"

PROFILE="${PROFILE:-LAN_REHEARSAL}"
if [[ "$COORDINATOR_LAN_IP" =~ ^26\. ]] && [[ "$PROFILE" == "LAN_REHEARSAL" ]]; then
  PROFILE="RADMIN_REHEARSAL"
fi

echo "Registering with coordinator at https://${COORDINATOR_LAN_IP}:${SWARM_PORT}"

python3 -m agent.koth_controller \
  --agent-id "$AGENT_ID" \
  --team-id "${TEAM_ID:-null_warriors}" \
  --role WORKER \
  --worker \
  --swarm \
  --profile "$PROFILE" \
  --coordinator-url "https://${COORDINATOR_LAN_IP}:${SWARM_PORT}" \
  --auth-token "$SWARM_AUTH_TOKEN" \
  --agent-token "$AGENT_TOKEN" \
  --ca-cert "${SWARM_CA_CERT:-certs/ca.crt}" \
  --use-tls
