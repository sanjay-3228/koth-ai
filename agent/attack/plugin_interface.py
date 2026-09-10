"""The contract every exploit plugin must implement.

This file defines the interface only — it contains no exploit logic.
Your team writes actual plugins in /plugins based on the specific
vulnerable services provided by your competition, and drops them in.

Example plugin skeleton (put this in plugins/my_service_exploit.py):

    from agent.attack.plugin_interface import ExploitPlugin, ExploitResult

    class MyServiceExploit(ExploitPlugin):
        name = "my-service-cve-XXXX"
        matches_service = "my-service"  # matches recon fingerprint substring

        def run(self, target_host, target_port, context):
            # your team's logic here
            ...
            return ExploitResult(success=True, flag=None, notes="...")
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ExploitResult:
    success: bool
    flag: Optional[str] = None
    notes: str = ""


class ExploitPlugin(ABC):
    name: str = "unnamed-plugin"
    matches_service: str = ""  # substring to match against recon fingerprint

    @abstractmethod
    def run(self, target_host: str, target_port: int, context: dict) -> ExploitResult:
        """Execute the plugin against a target. Implement in /plugins."""
        raise NotImplementedError
