#!/usr/bin/env python3
"""Cross-platform TLS Certificate Generator for KOTH Swarm.
Generates CA and coordinator certificates with SAN containing required private IPs.
Works across Linux, WSL, and Windows without external bash dependencies.
"""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_certs(raw_ips: str, out_dir: str = "certs") -> None:
    ips_clean = [item.strip() for item in raw_ips.replace(" ", ",").split(",") if item.strip()]
    if not ips_clean:
        raise ValueError("At least one private LAN IP is required.")

    valid_ips = []
    for raw in ips_clean:
        ip = ipaddress.ip_address(raw)
        is_radmin = ip in ipaddress.ip_network("26.0.0.0/8")
        if (not ip.is_private and not is_radmin) or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise ValueError(f"Refusing non-private / non-Radmin / loopback / unspecified IP: {ip}")
        valid_ips.append(ip)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Generate Root CA Key & Certificate
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "KOTH Swarm Local CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KOTH Competition Swarm"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Generate Coordinator Server Key & Certificate
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    primary_ip = str(valid_ips[0])
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, primary_ip),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KOTH Swarm Coordinator"),
    ])

    san_names = [x509.IPAddress(ip) for ip in valid_ips]
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write files with restrictive permissions
    ca_key_path = out_path / "ca.key"
    ca_cert_path = out_path / "ca.crt"
    server_key_path = out_path / "server.key"
    server_cert_path = out_path / "server.crt"

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    server_key_path.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    try:
        os.chmod(ca_key_path, 0o600)
        os.chmod(server_key_path, 0o600)
        os.chmod(ca_cert_path, 0o644)
        os.chmod(server_cert_path, 0o644)
    except Exception:
        pass

    san_str = ", ".join(f"IP:{ip}" for ip in valid_ips)
    print(f"Successfully generated TLS certificates in '{out_dir}/':")
    print(f"  Root CA:      {ca_cert_path}")
    print(f"  Server Cert:  {server_cert_path} (SAN: {san_str})")
    print("  Server Key:   [kept private]")
    print(f"\nDistribute ONLY '{ca_cert_path}' to worker agents.")
    print("Keep 'ca.key' and 'server.key' private to Coordinator (Agent-1).")


def main():
    parser = argparse.ArgumentParser(description="KOTH Swarm Certificate Generator")
    parser.add_argument("ips", nargs="?", default=None, help="Comma-separated private LAN or Radmin VPN IP addresses for certificate SAN")
    parser.add_argument("--out-dir", default="certs", help="Output directory (default: certs)")
    args = parser.parse_args()

    ips_input = args.ips
    if not ips_input:
        ips_input = os.getenv("COORDINATOR_LAN_IP")
        if not ips_input:
            try:
                ips_input = input("Enter coordinator LAN/VPN IP(s) for certificate SAN (comma-separated): ").strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit("\nOperation cancelled.")

    if not ips_input:
        sys.exit("Error: No coordinator IP specified for certificate generation.")

    try:
        generate_certs(ips_input, args.out_dir)
    except Exception as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
