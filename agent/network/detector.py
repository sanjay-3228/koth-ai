"""Cross-platform read-only network interface and routing detector for Linux (Kali) and Windows.

Guarantees:
  - Strictly read-only: never modifies routes, never alters interfaces, never connects/disconnects VPNs.
  - Normalizes interface state, addresses, CIDRs, and routing table entries.
  - Supports dependency injection for offline testing and simulation.
"""
import ipaddress
import json
import os
import platform
import re
import subprocess
from typing import List, Optional

from ..logger import get_logger
from .models import InterfaceType, NetworkInterface, Route

logger = get_logger(__name__)


def netmask_to_prefix_len(netmask_str: str) -> int:
    """Convert dotted netmask string to integer prefix length."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except ValueError:
        return 32


class NetworkDetector:
    """Read-only cross-platform network state detector."""

    def __init__(
        self,
        interfaces: Optional[List[NetworkInterface]] = None,
        routes: Optional[List[Route]] = None,
        default_gateway: Optional[str] = None,
    ):
        self._injected_interfaces = interfaces
        self._injected_routes = routes
        self._injected_gateway = default_gateway

    def get_default_gateway(self) -> Optional[str]:
        """Return the default IPv4 gateway address if available."""
        if self._injected_gateway is not None:
            return self._injected_gateway
        defaults = self.get_default_routes()
        for r in defaults:
            if r.gateway:
                return r.gateway
        return None

    def get_interfaces(self) -> List[NetworkInterface]:
        """Detect and return all normalized network interfaces."""
        if self._injected_interfaces is not None:
            return self._injected_interfaces

        system = platform.system().lower()
        if system == "linux":
            return self._detect_linux_interfaces()
        elif system == "windows":
            return self._detect_windows_interfaces()
        else:
            return self._detect_generic_interfaces()

    def get_routes(self) -> List[Route]:
        """Detect and return all normalized IPv4 routes."""
        if self._injected_routes is not None:
            return self._injected_routes

        system = platform.system().lower()
        if system == "linux":
            return self._detect_linux_routes()
        elif system == "windows":
            return self._detect_windows_routes()
        else:
            return []

    def get_default_routes(self) -> List[Route]:
        """Return default routes (destination 0.0.0.0 or default)."""
        return [
            r for r in self.get_routes()
            if r.destination in ("0.0.0.0", "default")
        ]

    # =========================================================================
    # LINUX / KALI DETECTION
    # =========================================================================

    def _detect_linux_interfaces(self) -> List[NetworkInterface]:
        """Parse Linux interfaces via 'ip -j addr' or fallback to 'ip addr'."""
        interfaces: List[NetworkInterface] = []

        # Try JSON output first (standard on modern Linux & Kali)
        try:
            res = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                for item in data:
                    name = item.get("ifname", "")
                    is_up = item.get("operstate", "").upper() in ("UP", "UNKNOWN")
                    flags = item.get("flags", [])
                    if "UP" in flags:
                        is_up = True

                    addresses = []
                    cidrs = []
                    for addr in item.get("addr_info", []):
                        if addr.get("family") == "inet":
                            ip_str = addr.get("local", "")
                            prefix = addr.get("prefixlen", 32)
                            if ip_str:
                                addresses.append(ip_str)
                                cidrs.append(f"{ip_str}/{prefix}")

                    iface_type = self._classify_interface_name(name)
                    interfaces.append(
                        NetworkInterface(
                            name=name,
                            addresses=addresses,
                            cidrs=cidrs,
                            is_up=is_up,
                            interface_type=iface_type,
                            mac=item.get("address", ""),
                        )
                    )
                return interfaces
        except Exception as exc:
            logger.debug("[network] 'ip -j addr' failed (%s); trying fallback", exc)

        # Text fallback: 'ip addr'
        try:
            res = subprocess.run(
                ["ip", "addr"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return self._parse_linux_ip_addr_text(res.stdout)
        except Exception as exc:
            logger.warning("[network] Failed to run 'ip addr' on Linux: %s", exc)

        return self._detect_generic_interfaces()

    def _parse_linux_ip_addr_text(self, text: str) -> List[NetworkInterface]:
        """Parse plain text output of 'ip addr'."""
        interfaces: List[NetworkInterface] = []
        current_name = ""
        current_up = False
        current_addrs: List[str] = []
        current_cidrs: List[str] = []
        current_mac = ""

        def commit():
            nonlocal current_name, current_up, current_addrs, current_cidrs, current_mac
            if current_name:
                interfaces.append(
                    NetworkInterface(
                        name=current_name,
                        addresses=current_addrs,
                        cidrs=current_cidrs,
                        is_up=current_up,
                        interface_type=self._classify_interface_name(current_name),
                        mac=current_mac,
                    )
                )
            current_name = ""
            current_up = False
            current_addrs = []
            current_cidrs = []
            current_mac = ""

        for line in text.splitlines():
            m_hdr = re.match(r"^\d+:\s+([a-zA-Z0-9.\-_@]+):.*?<([^>]+)>", line)
            if m_hdr:
                commit()
                current_name = m_hdr.group(1).split("@")[0]
                flags = m_hdr.group(2).split(",")
                current_up = "UP" in flags
                continue

            m_inet = re.search(r"inet\s+([0-9.]+)/(\d+)", line)
            if m_inet:
                ip_str = m_inet.group(1)
                prefix = m_inet.group(2)
                current_addrs.append(ip_str)
                current_cidrs.append(f"{ip_str}/{prefix}")

            m_mac = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
            if m_mac:
                current_mac = m_mac.group(1)

        commit()
        return interfaces

    def _detect_linux_routes(self) -> List[Route]:
        """Parse Linux routes via 'ip -j route' or fallback to 'ip route'."""
        routes: List[Route] = []

        # Try JSON output first
        try:
            res = subprocess.run(
                ["ip", "-j", "route"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                for item in data:
                    dst = item.get("dst", "default")
                    gw = item.get("gateway", "0.0.0.0")
                    dev = item.get("dev", "")
                    metric = int(item.get("metric", 0)) if item.get("metric") is not None else 0
                    routes.append(
                        Route(
                            destination=dst,
                            gateway=gw,
                            interface=dev,
                            metric=metric,
                        )
                    )
                return routes
        except Exception as exc:
            logger.debug("[network] 'ip -j route' failed (%s); trying fallback", exc)

        # Fallback to plain 'ip route'
        try:
            res = subprocess.run(
                ["ip", "route"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if not parts:
                        continue
                    dst = parts[0]
                    gw = "0.0.0.0"
                    dev = ""
                    metric = 0
                    if "via" in parts:
                        idx = parts.index("via")
                        if idx + 1 < len(parts):
                            gw = parts[idx + 1]
                    if "dev" in parts:
                        idx = parts.index("dev")
                        if idx + 1 < len(parts):
                            dev = parts[idx + 1]
                    if "metric" in parts:
                        idx = parts.index("metric")
                        if idx + 1 < len(parts):
                            try:
                                metric = int(parts[idx + 1])
                            except ValueError:
                                metric = 0
                    routes.append(
                        Route(
                            destination=dst,
                            gateway=gw,
                            interface=dev,
                            metric=metric,
                        )
                    )
                return routes
        except Exception as exc:
            logger.warning("[network] Failed to run 'ip route': %s", exc)

        return routes

    # =========================================================================
    # WINDOWS DETECTION
    # =========================================================================

    def _detect_windows_interfaces(self) -> List[NetworkInterface]:
        """Parse Windows interfaces via 'ipconfig /all'."""
        interfaces: List[NetworkInterface] = []
        try:
            res = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                interfaces = self._parse_windows_ipconfig(res.stdout)
        except Exception as exc:
            logger.warning("[network] Failed to run 'ipconfig /all': %s", exc)

        if not interfaces:
            interfaces = self._detect_generic_interfaces()

        return interfaces

    def _parse_windows_ipconfig(self, text: str) -> List[NetworkInterface]:
        interfaces: List[NetworkInterface] = []
        blocks = text.split("\n\n")
        current_name = ""
        current_addrs: List[str] = []
        current_cidrs: List[str] = []
        current_up = True
        current_type = InterfaceType.UNKNOWN
        current_mac = ""

        for line in text.splitlines():
            line_str = line.strip()
            # Adapter header line, e.g. "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
            m_head = re.match(r"^([a-zA-Z0-9\s\-]+adapter\s+[^:]+):", line)
            if m_head:
                if current_name and current_addrs:
                    interfaces.append(
                        NetworkInterface(
                            name=current_name,
                            addresses=current_addrs,
                            cidrs=current_cidrs,
                            is_up=current_up,
                            interface_type=current_type,
                            mac=current_mac,
                        )
                    )
                current_name = m_head.group(1).strip()
                current_addrs = []
                current_cidrs = []
                current_up = True
                current_type = self._classify_interface_name(current_name)
                current_mac = ""
                continue

            if "Media State" in line and "disconnected" in line.lower():
                current_up = False

            if "Physical Address" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    current_mac = parts[1].strip()

            m_ip = re.search(r"IPv4 Address[.\s]+:\s+([0-9.]+)", line)
            if m_ip:
                ip_str = m_ip.group(1).replace("(Preferred)", "").strip()
                current_addrs.append(ip_str)

            m_mask = re.search(r"Subnet Mask[.\s]+:\s+([0-9.]+)", line)
            if m_mask and current_addrs:
                mask_str = m_mask.group(1).strip()
                prefix = netmask_to_prefix_len(mask_str)
                latest_ip = current_addrs[-1]
                cidr = f"{latest_ip}/{prefix}"
                if cidr not in current_cidrs:
                    current_cidrs.append(cidr)

        if current_name and current_addrs:
            interfaces.append(
                NetworkInterface(
                    name=current_name,
                    addresses=current_addrs,
                    cidrs=current_cidrs,
                    is_up=current_up,
                    interface_type=current_type,
                    mac=current_mac,
                )
            )

        return interfaces

    def _detect_windows_routes(self) -> List[Route]:
        """Parse Windows routes via 'route print -4'."""
        routes: List[Route] = []
        try:
            res = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                in_active_routes = False
                for line in res.stdout.splitlines():
                    if "Active Routes:" in line:
                        in_active_routes = True
                        continue
                    if in_active_routes:
                        if "Persistent Routes:" in line or "=====" in line:
                            if "Persistent Routes:" in line:
                                break
                            continue
                        parts = line.strip().split()
                        # IPv4 Route Table: Network Destination, Netmask, Gateway, Interface, Metric
                        if len(parts) >= 5:
                            dst = parts[0]
                            netmask = parts[1]
                            gw = parts[2]
                            iface = parts[3]
                            try:
                                metric = int(parts[4])
                            except ValueError:
                                metric = 0
                            # Verify valid IPv4 string format
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dst):
                                routes.append(
                                    Route(
                                        destination=dst,
                                        gateway=gw,
                                        interface=iface,
                                        netmask=netmask,
                                        metric=metric,
                                    )
                                )
        except Exception as exc:
            logger.warning("[network] Failed to run 'route print -4': %s", exc)

        return routes

    # =========================================================================
    # GENERIC / FALLBACK DETECTION
    # =========================================================================

    def _detect_generic_interfaces(self) -> List[NetworkInterface]:
        """Fallback to socket hostname resolution."""
        import socket
        interfaces: List[NetworkInterface] = []
        try:
            hostname = socket.gethostname()
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            for ip in ip_list:
                if not ip.startswith("127."):
                    interfaces.append(
                        NetworkInterface(
                            name="default",
                            addresses=[ip],
                            cidrs=[f"{ip}/24"],
                            is_up=True,
                            interface_type=InterfaceType.UNKNOWN,
                        )
                    )
        except Exception:
            pass

        if not interfaces:
            interfaces.append(
                NetworkInterface(
                    name="lo",
                    addresses=["127.0.0.1"],
                    cidrs=["127.0.0.1/8"],
                    is_up=True,
                    interface_type=InterfaceType.LOOPBACK,
                )
            )
        return interfaces

    @staticmethod
    def _classify_interface_name(name: str) -> InterfaceType:
        """Classify interface type by standard naming conventions."""
        lower = name.lower()
        if lower.startswith("lo") or "loopback" in lower:
            return InterfaceType.LOOPBACK
        if any(lower.startswith(prefix) for prefix in ("tun", "tap", "wg", "ppp", "utun")):
            return InterfaceType.VPN
        if any(term in lower for term in ("openvpn", "wireguard", "tap-windows", "vpn")):
            return InterfaceType.VPN
        if any(lower.startswith(prefix) for prefix in ("wl", "wifi", "ath")) or any(t in lower for t in ("wi-fi", "wireless", "802.11")):
            return InterfaceType.WIFI
        if any(lower.startswith(prefix) for prefix in ("eth", "en")) or "ethernet" in lower:
            return InterfaceType.ETHERNET
        return InterfaceType.UNKNOWN
