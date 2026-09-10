"""VPN detection module identifying active tunnel/VPN interfaces.

Guarantees:
  - Strictly non-intrusive and read-only.
  - Detects active VPN interfaces (tun, tap, wg, wireguard, openvpn).
  - Explicit rule: A VPN interface alone NEVER authorizes competition actions.
"""
from typing import List, Tuple

from .models import InterfaceType, NetworkInterface, VpnStatus


class VpnDetector:
    """Detects presence and operational status of VPN connections."""

    @classmethod
    def is_vpn_interface(cls, iface: NetworkInterface) -> bool:
        """Check if an interface is classified as a VPN/tunnel device."""
        if iface.interface_type == InterfaceType.VPN:
            return True
        lower = iface.name.lower()
        vpn_prefixes = ("tun", "tap", "wg", "ppp", "utun", "wireguard")
        if any(lower.startswith(p) for p in vpn_prefixes):
            return True
        if any(term in lower for term in ("openvpn", "wireguard", "tap-windows", "vpn")):
            return True
        return False

    @classmethod
    def get_vpn_interfaces(cls, interfaces: List[NetworkInterface]) -> List[NetworkInterface]:
        """Return all detected VPN/tunnel interfaces."""
        return [i for i in interfaces if cls.is_vpn_interface(i)]

    @classmethod
    def get_active_vpn_interfaces(cls, interfaces: List[NetworkInterface]) -> List[NetworkInterface]:
        """Return all VPN interfaces that are currently UP and have an assigned IP."""
        return [
            i for i in interfaces
            if cls.is_vpn_interface(i) and i.is_up and len(i.addresses) > 0
        ]

    @classmethod
    def detect_vpn_status(cls, interfaces: List[NetworkInterface]) -> Tuple[VpnStatus, List[NetworkInterface]]:
        """Determine VPN status and return list of active VPN interfaces.

        Status:
          - CONNECTED: At least one VPN interface is UP with an assigned IP address.
          - NOT_CONNECTED: No active VPN interfaces found.
          - UNKNOWN: Network interfaces list was empty or unresolvable.
        """
        if not interfaces:
            return VpnStatus.UNKNOWN, []

        active = cls.get_active_vpn_interfaces(interfaces)
        if active:
            return VpnStatus.CONNECTED, active

        all_vpn = cls.get_vpn_interfaces(interfaces)
        if all_vpn:
            # Present but inactive / no IP
            return VpnStatus.NOT_CONNECTED, []

        return VpnStatus.NOT_CONNECTED, []
