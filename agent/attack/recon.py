"""Read-only reconnaissance: port scanning and service fingerprinting.

This module never modifies or exploits anything. It answers "what is
running where" so the decision engine and your exploit plugins have
enough context to act.
"""
from dataclasses import dataclass, field
import os
import shutil
import socket
import subprocess
import time
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

from ..logger import get_logger

logger = get_logger(__name__)

try:
    import nmap
except ImportError:
    nmap = None


@dataclass
class HostFingerprint:
    host: str
    reachable: bool = True
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # port -> "name version"
    service_names: Dict[int, str] = field(default_factory=dict)  # port -> "name"
    service_versions: Dict[int, str] = field(default_factory=dict)  # port -> "version"
    started_at: float = 0.0
    completed_at: float = 0.0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "reachable": self.reachable,
            "open_ports": self.open_ports,
            "services": self.services,
            "service_names": self.service_names,
            "service_versions": self.service_versions,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 3),
        }


class ReconScanner:
    def __init__(self):
        self.scanner = None
        if nmap is not None:
            try:
                self.scanner = nmap.PortScanner()
            except Exception:
                self.scanner = None

    def check_reachability(self, host: str, timeout: float = 1.0) -> bool:
        """Check if target host responds to ping or common socket ports."""
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(max(1, timeout))), host],
                capture_output=True,
                timeout=timeout + 1.0,
                check=False,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Socket probe fallback
        for port in (80, 22, 443, 21):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0:
                        return True
            except Exception:
                continue
        return False

    def scan(self, host: str, ports: str = "1-1024") -> HostFingerprint:
        started_at = time.time()
        fp = HostFingerprint(host=host, started_at=started_at)
        fp.reachable = self.check_reachability(host)

        # 1. Try python-nmap if available
        if self.scanner is not None:
            try:
                self.scanner.scan(host, ports, arguments="-sV -Pn -T4")
                if host in self.scanner.all_hosts():
                    fp.reachable = True
                    for proto in self.scanner[host].all_protocols():
                        for port, info in self.scanner[host][proto].items():
                            if info.get("state") == "open":
                                fp.open_ports.append(port)
                                name = info.get("name", "unknown")
                                version = info.get("version", "").strip()
                                product = info.get("product", "").strip()
                                full_ver = f"{product} {version}".strip() or version or "unknown"
                                fp.service_names[port] = name
                                fp.service_versions[port] = full_ver
                                fp.services[port] = f"{name} {full_ver}".strip()
                    fp.completed_at = time.time()
                    fp.duration_seconds = fp.completed_at - started_at
                    return fp
            except Exception as exc:
                logger.debug("python-nmap failed (%s); trying fallback", exc)

        # 2. Try nmap binary via subprocess (non-shell, safe XML output parsing)
        nmap_bin = shutil.which("nmap") or ("/usr/bin/nmap" if os.path.exists("/usr/bin/nmap") else None)
        if nmap_bin:
            try:
                res = subprocess.run(
                    [nmap_bin, "-sV", "-Pn", "--open", "-oX", "-", "-p", ports, host],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    root = ET.fromstring(res.stdout)
                    for host_el in root.findall("host"):
                        status_el = host_el.find("status")
                        if status_el is not None and status_el.get("state") == "up":
                            fp.reachable = True
                        ports_el = host_el.find("ports")
                        if ports_el is not None:
                            for port_el in ports_el.findall("port"):
                                state_el = port_el.find("state")
                                if state_el is not None and state_el.get("state") == "open":
                                    port_id = int(port_el.get("portid", 0))
                                    fp.open_ports.append(port_id)
                                    service_el = port_el.find("service")
                                    if service_el is not None:
                                        s_name = service_el.get("name", "unknown")
                                        s_prod = service_el.get("product", "").strip()
                                        s_ver = service_el.get("version", "").strip()
                                        s_ext = service_el.get("extrainfo", "").strip()
                                        v_parts = [p for p in (s_prod, s_ver, s_ext) if p]
                                        full_ver = " ".join(v_parts) if v_parts else "unknown"
                                        fp.service_names[port_id] = s_name
                                        fp.service_versions[port_id] = full_ver
                                        fp.services[port_id] = f"{s_name} {full_ver}".strip()
                                    else:
                                        fp.service_names[port_id] = "unknown"
                                        fp.service_versions[port_id] = "unknown"
                                        fp.services[port_id] = "unknown"
                    fp.completed_at = time.time()
                    fp.duration_seconds = fp.completed_at - started_at
                    return fp
            except Exception as exc:
                logger.debug("nmap binary XML parsing failed (%s); using socket fallback", exc)

        # 3. Socket fallback if nmap is unavailable or throws
        sample_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888]
        for p in sample_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    if s.connect_ex((host, p)) == 0:
                        fp.reachable = True
                        fp.open_ports.append(p)
                        fp.service_names[p] = "open_port"
                        fp.service_versions[p] = "unknown"
                        fp.services[p] = "unknown"
            except Exception:
                continue

        fp.completed_at = time.time()
        fp.duration_seconds = fp.completed_at - started_at
        return fp
