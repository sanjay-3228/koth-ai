"""Data models and enums for network detection, routing, and PwnGrounds environment classification."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class InterfaceType(str, Enum):
    WIFI = "WIFI"
    ETHERNET = "ETHERNET"
    VPN = "VPN"
    LOOPBACK = "LOOPBACK"
    UNKNOWN = "UNKNOWN"


class VpnStatus(str, Enum):
    CONNECTED = "CONNECTED"
    NOT_CONNECTED = "NOT_CONNECTED"
    UNKNOWN = "UNKNOWN"


class EnvironmentMode(str, Enum):
    WIFI_ONLY = "WIFI_ONLY"
    WIFI_PLUS_VPN = "WIFI_PLUS_VPN"
    VPN_ONLY = "VPN_ONLY"
    UNKNOWN = "UNKNOWN"


@dataclass
class NetworkInterface:
    name: str
    addresses: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    is_up: bool = True
    interface_type: InterfaceType = InterfaceType.UNKNOWN
    mac: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "addresses": self.addresses,
            "cidrs": self.cidrs,
            "is_up": self.is_up,
            "interface_type": self.interface_type.value,
            "mac": self.mac,
        }


@dataclass
class Route:
    destination: str
    gateway: str
    interface: str
    netmask: str = ""
    metric: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "destination": self.destination,
            "gateway": self.gateway,
            "interface": self.interface,
            "netmask": self.netmask,
            "metric": self.metric,
        }


@dataclass
class EnvironmentState:
    mode: EnvironmentMode
    competition_route_present: bool
    competition_cidr: Optional[str]
    vpn_present: bool
    interfaces: List[NetworkInterface] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    confidence: float = 1.0
    details: str = ""
    vpn_route_present: bool = False
    active_vpn_interfaces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "competition_route_present": self.competition_route_present,
            "competition_cidr": self.competition_cidr,
            "vpn_present": self.vpn_present,
            "vpn_route_present": self.vpn_route_present,
            "active_vpn_interfaces": self.active_vpn_interfaces,
            "interfaces": [i.to_dict() for i in self.interfaces],
            "routes": [r.to_dict() for r in self.routes],
            "confidence": self.confidence,
            "details": self.details,
        }
