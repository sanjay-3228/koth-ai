"""Restarts/rolls back own services when they go down or fail integrity checks.

Relies on systemd — adjust `_run` targets if your services are managed
differently (docker, supervisord, etc).
"""
import subprocess
from dataclasses import dataclass

from ..config import config
from ..logger import get_logger

logger = get_logger(__name__)


@dataclass
class PatchResult:
    service: str
    action: str
    success: bool
    output: str = ""


class ServicePatcher:
    def __init__(self, dry_run: bool = None):
        self.dry_run = config.dry_run if dry_run is None else dry_run

    def restart(self, service_name: str) -> PatchResult:
        return self._run(service_name, ["systemctl", "restart", service_name])

    def rollback(self, service_name: str, backup_path: str, live_path: str) -> PatchResult:
        cmd = ["cp", "-f", backup_path, live_path]
        result = self._run(service_name, cmd, label="rollback")
        if result.success and not self.dry_run:
            self.restart(service_name)
        return result

    def _run(self, service: str, cmd: list, label: str = "restart") -> PatchResult:
        if self.dry_run:
            logger.info(f"[dry-run] would run: {' '.join(cmd)}")
            return PatchResult(service=service, action=label, success=True, output="dry-run")

        result = subprocess.run(cmd, capture_output=True, text=True)
        return PatchResult(
            service=service,
            action=label,
            success=result.returncode == 0,
            output=result.stdout + result.stderr,
        )
