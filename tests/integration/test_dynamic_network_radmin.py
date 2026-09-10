"""
Integration and Unit Tests for Dynamic Network IPs, Radmin VPN (26.0.0.0/8),
Dynamic TLS SAN generation, and Roster Verification.
"""
import ipaddress
import os
import shutil
import tempfile
import pytest
from cryptography import x509

from agent.config import Config, ConfigProfile, load_config
from agent.swarm.coordinator_server import validate_binding_host
from scripts.generate_swarm_certs import generate_certs


class TestDynamicNetworkBindingValidation:
    """Validate binding rules across LAN_REHEARSAL and RADMIN_REHEARSAL."""

    def test_lan_rehearsal_accepts_rfc1918(self):
        assert validate_binding_host("192.168.1.100", ConfigProfile.LAN_REHEARSAL) == "192.168.1.100"
        assert validate_binding_host("10.0.0.5", ConfigProfile.LAN_REHEARSAL) == "10.0.0.5"
        assert validate_binding_host("172.16.0.1", ConfigProfile.LAN_REHEARSAL) == "172.16.0.1"

    def test_lan_rehearsal_rejects_loopback_and_unspecified(self):
        with pytest.raises(ValueError, match="cannot be automatically exposed to 0.0.0.0"):
            validate_binding_host("0.0.0.0", ConfigProfile.LAN_REHEARSAL)

        with pytest.raises(ValueError, match="must NOT be 127.0.0.1"):
            validate_binding_host("127.0.0.1", ConfigProfile.LAN_REHEARSAL)

    def test_lan_rehearsal_rejects_public_ip(self):
        with pytest.raises(ValueError, match="must be a valid private LAN IP"):
            validate_binding_host("8.8.8.8", ConfigProfile.LAN_REHEARSAL)

    def test_radmin_rehearsal_accepts_26_subnet(self):
        # Radmin VPN assigns IPs in 26.0.0.0/8
        assert validate_binding_host("26.18.248.152", ConfigProfile.RADMIN_REHEARSAL) == "26.18.248.152"
        assert validate_binding_host("26.100.50.25", ConfigProfile.RADMIN_REHEARSAL) == "26.100.50.25"

    def test_radmin_rehearsal_accepts_rfc1918(self):
        assert validate_binding_host("192.168.1.50", ConfigProfile.RADMIN_REHEARSAL) == "192.168.1.50"
        assert validate_binding_host("10.200.1.1", ConfigProfile.RADMIN_REHEARSAL) == "10.200.1.1"

    def test_radmin_rehearsal_rejects_loopback_and_public(self):
        with pytest.raises(ValueError, match="cannot be automatically exposed to 0.0.0.0"):
            validate_binding_host("0.0.0.0", ConfigProfile.RADMIN_REHEARSAL)

        with pytest.raises(ValueError, match="must NOT be 127.0.0.1"):
            validate_binding_host("127.0.0.1", ConfigProfile.RADMIN_REHEARSAL)

        with pytest.raises(ValueError, match="must be a valid private LAN"):
            validate_binding_host("8.8.8.8", ConfigProfile.RADMIN_REHEARSAL)


class TestDynamicCertificateGeneration:
    """Validate that certificates are dynamically generated with SAN for entered IPs (LAN and Radmin)."""

    def test_generate_certs_with_radmin_and_lan_ips(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            test_ips = "26.18.248.152, 192.168.1.50, 172.20.10.5"
            generate_certs(test_ips, tmp_dir)

            cert_path = os.path.join(tmp_dir, "server.crt")
            assert os.path.exists(cert_path)

            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_ips = [str(ip.value) for ip in san_ext.value]

            assert "26.18.248.152" in san_ips
            assert "192.168.1.50" in san_ips
            assert "172.20.10.5" in san_ips
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_generate_certs_rejects_public_ip(self):
        tmp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValueError, match="Refusing non-private"):
                generate_certs("8.8.8.8", tmp_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestRosterAndTeamConfiguration:
    """Validate team null_warriors and roster defaults."""

    def test_team_id_is_null_warriors(self):
        cfg = Config()
        assert cfg.team_id == "null_warriors"

    def test_roster_tokens_structure(self):
        # SWARM_AGENT_TOKENS format
        raw = "agent-01:1000,agent-02:1001,agent-03:1002,agent-04:1003"
        tokens = dict(item.split(":") for item in raw.split(","))
        assert tokens["agent-01"] == "1000"
        assert tokens["agent-02"] == "1001"
        assert tokens["agent-03"] == "1002"
        assert tokens["agent-04"] == "1003"
