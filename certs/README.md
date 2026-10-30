# TLS Certificates for KOTH Swarm

In compliance with cybersecurity best practices and finding `KOTH-SEC-001`, private keys are never committed to the repository.

## Generating Fresh TLS Certificates

Run the cross-platform TLS certificate generator script:

```bash
python scripts/generate_swarm_certs.py --ips 192.168.1.100
```

This will generate:
- `certs/ca.crt` (Distributed to all 4 worker agent nodes)
- `certs/ca.key` (Kept private on Coordinator node)
- `certs/server.crt` (Coordinator public certificate)
- `certs/server.key` (Coordinator private key)

