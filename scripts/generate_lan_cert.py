"""
Generate a self-signed Root CA and Server TLS Certificate with Subject Alternative Names (SAN)
for Central PC and Remote Agent PCs in a LAN deployment.
"""

import ipaddress
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("[!] 'cryptography' library is required to generate certificates.")
    print("    Install via: pip install cryptography")
    sys.exit(1)


def generate_lan_certificates(output_dir: str = "certs", extra_ips: list = None):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ca_key_path = out / "ca.key"
    ca_cert_path = out / "ca.crt"
    server_key_path = out / "server.key"
    server_cert_path = out / "server.crt"

    print(f"[*] Generating Root CA key and certificate...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KOTH Swarm Operations"),
        x509.NameAttribute(NameOID.COMMON_NAME, "KOTH Swarm Root CA"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA written to: {ca_cert_path}")

    # Discover hostnames and LAN IPs
    hostname = socket.gethostname()
    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(lan_ip)))
        print(f"[*] Added primary LAN IP to SAN: {lan_ip}")
    except Exception:
        pass

    if extra_ips:
        for ip_str in extra_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str.strip())
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    san_list.append(x509.IPAddress(ip_obj))
                    print(f"[*] Added extra IP to SAN: {ip_str}")
            except Exception:
                pass

    print(f"[*] Generating Server TLS key and certificate...")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KOTH Swarm Operations"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Server Certificate written to: {server_cert_path}")
    print(f"[+] Server Private Key written to: {server_key_path}")
    print("\n[✓] Certificate generation complete! Distribute 'ca.crt' to the 4 remote agent PCs.")


if __name__ == "__main__":
    extra = sys.argv[1].split(",") if len(sys.argv) > 1 else None
    generate_lan_certificates("certs", extra)

