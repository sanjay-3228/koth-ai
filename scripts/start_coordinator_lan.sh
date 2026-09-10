#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${COORDINATOR_LAN_IP:-}" ]]; then
  read -r -p "Enter coordinator IP: " COORDINATOR_LAN_IP
fi

if [[ -z "$COORDINATOR_LAN_IP" ]]; then
  echo "Error: COORDINATOR_LAN_IP is required." >&2
  exit 1
fi

COORDINATOR_BIND_HOST="${COORDINATOR_BIND_HOST:-$COORDINATOR_LAN_IP}"
: "${SWARM_AUTH_TOKEN:?Set SWARM_AUTH_TOKEN}"
: "${SWARM_OPERATOR_TOKEN:?Set SWARM_OPERATOR_TOKEN}"
SWARM_AGENT_TOKENS="${SWARM_AGENT_TOKENS:-agent-01:1000,agent-02:1001,agent-03:1002,agent-04:1003}"

PROFILE="${PROFILE:-LAN_REHEARSAL}"

DETECTED_PROFILE=$(python3 - <<'PY' "$COORDINATOR_LAN_IP" "$COORDINATOR_BIND_HOST" "$PROFILE"
import ipaddress, sys
lan_ip = ipaddress.ip_address(sys.argv[1])
bind_ip = ipaddress.ip_address(sys.argv[2])
cur_profile = sys.argv[3]
radmin_net = ipaddress.ip_network("26.0.0.0/8")

for ip in (lan_ip, bind_ip):
    is_radmin = ip in radmin_net
    if (not ip.is_private and not is_radmin) or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise SystemExit(f"Refusing invalid coordinator IP: {ip}")

if (lan_ip in radmin_net or bind_ip in radmin_net) and cur_profile == "LAN_REHEARSAL":
    print("RADMIN_REHEARSAL")
else:
    print(cur_profile)
PY
)

python3 -m agent.swarm.coordinator_server \
  --host "$COORDINATOR_BIND_HOST" \
  --port "${SWARM_PORT:-5000}" \
  --profile "$DETECTED_PROFILE" \
  --auth-token "$SWARM_AUTH_TOKEN" \
  --operator-token "$SWARM_OPERATOR_TOKEN" \
  --authorized-agents "${AUTHORIZED_AGENTS:-agent-01,agent-02,agent-03,agent-04}" \
  --agent-tokens "$SWARM_AGENT_TOKENS" \
  --ssl-cert "${SWARM_SSL_CERT:-certs/server.crt}" \
  --ssl-key "${SWARM_SSL_KEY:-certs/server.key}" \
  --use-tls

