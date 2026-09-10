"""Monitors own services for downtime and tampering.

Integrity checking is done via checksum diffing against a known-good
baseline you record at the start of the competition — this is generic and
does not depend on knowing any specific vulnerability.
"""
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class IntegrityBaseline:
    checksums: Dict[str, str] = field(default_factory=dict)

    def record(self, paths: List[str]) -> None:
        for path in paths:
            if os.path.isfile(path):
                self.checksums[path] = self._hash_file(path)

    def check(self, paths: List[str]) -> List[str]:
        """Returns list of paths whose checksum no longer matches baseline."""
        changed = []
        for path in paths:
            if not os.path.isfile(path):
                changed.append(f"{path} (missing)")
                continue
            current = self._hash_file(path)
            baseline = self.checksums.get(path)
            if baseline and current != baseline:
                changed.append(path)
        return changed

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


class ServiceMonitor:
    """Simple TCP-reachability check for own services."""

    def __init__(self, watch_paths: List[str] = None):
        self.baseline = IntegrityBaseline()
        self.watch_paths = watch_paths or []
        if self.watch_paths:
            self.baseline.record(self.watch_paths)

    def check_port(self, host: str, port: int, timeout: float = 3.0) -> bool:
        import socket

        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def check_integrity(self) -> List[str]:
        if not self.watch_paths:
            return []
        return self.baseline.check(self.watch_paths)

    def snapshot(self, host: str, port: int) -> dict:
        return {
            "host": host,
            "port": port,
            "up": self.check_port(host, port),
            "tampered_files": self.check_integrity(),
            "checked_at": time.time(),
        }

    def full_snapshot(self, own_services: List[str] = None) -> dict:
        """Collect reachability across all configured own services and integrity status."""
        from ..config import config

        services_to_check = own_services if own_services is not None else config.own_services
        service_statuses = []
        down_services = []

        for item in services_to_check:
            parts = item.split(":")
            if len(parts) >= 2:
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    continue
                up = self.check_port(host, port)
                entry = {"host": host, "port": port, "up": up}
                service_statuses.append(entry)
                if not up:
                    down_services.append(entry)

        return {
            "services": service_statuses,
            "down_services": down_services,
            "tampered_files": self.check_integrity(),
            "checked_at": time.time(),
        }
