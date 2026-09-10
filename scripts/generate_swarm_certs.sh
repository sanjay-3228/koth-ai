#!/usr/bin/env bash
set -euo pipefail

IP="${1:-${COORDINATOR_LAN_IP:-}}"
OUT_DIR="${2:-certs}"

if [[ -z "$IP" ]]; then
  read -r -p "Enter coordinator LAN/VPN IP: " IP
fi

if [[ -z "$IP" ]]; then
  echo "Error: Coordinator IP is required." >&2
  exit 2
fi

# Validate all provided IPs (comma- or space-separated)
SAN_LIST=$(python3 - "$IP" <<'PY'
import ipaddress, sys
raw = sys.argv[1].replace(" ", ",")
ips = [item.strip() for item in raw.split(",") if item.strip()]
if not ips:
    raise SystemExit("No IP addresses provided.")

san_entries = []
for item in ips:
    ip = ipaddress.ip_address(item)
    is_radmin = ip in ipaddress.ip_network("26.0.0.0/8")
    if (not ip.is_private and not is_radmin) or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        raise SystemExit(f"Refusing non-private/non-Radmin coordinator IP: {ip}")
    san_entries.append(f"IP:{ip}")

print(",".join(san_entries))
PY
)

PRIMARY_IP=$(echo "$IP" | tr ',' ' ' | awk '{print $1}')

mkdir -p "$OUT_DIR"
umask 077

openssl genrsa -out "$OUT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" -sha256 -days 3650 \
  -out "$OUT_DIR/ca.crt" -subj "/CN=KOTH Swarm Local CA"

openssl genrsa -out "$OUT_DIR/server.key" 2048
openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
  -subj "/CN=$PRIMARY_IP"

cat > "$OUT_DIR/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN_LIST
EOF

openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/server.crt" -days 825 -sha256 -extfile "$OUT_DIR/server.ext"

rm -f "$OUT_DIR/server.csr" "$OUT_DIR/server.ext" "$OUT_DIR/ca.srl"
chmod 600 "$OUT_DIR"/*.key
chmod 644 "$OUT_DIR"/*.crt

echo "Created CA and coordinator certificate for $SAN_LIST in $OUT_DIR/"
echo "Distribute only ca.crt to workers. Keep ca.key and server.key private."
