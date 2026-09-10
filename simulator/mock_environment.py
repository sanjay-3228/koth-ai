"""Mock environment for local, safe KOTH simulation and integration testing.

Provides in-memory simulations of:
- Scoreboard / Telemetry endpoint
- Systemd services & port reachability
- File system integrity
- provider/model API simulation (fast & reasoning tiers)
- Firewall subsystem (nftables transactional rollback)
"""
from dataclasses import dataclass, field
import json
import os
import time
from typing import Any, Dict, List, Optional

from agent.defense.patcher import PatchResult
from agent.defense.firewall import FirewallManager, FirewallRule
from agent.gemini_client import Decision
from agent.telemetry import Telemetry, ServiceStatus


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")


class MockScoreboardServer:
    """Simulates the competition scoreboard API and telemetry states."""

    def __init__(self, fixtures_path: Optional[str] = None):
        path = fixtures_path or os.path.join(FIXTURES_DIR, "scoreboard_states.json")
        with open(path, "r", encoding="utf-8") as f:
            self.fixtures = json.load(f)
        self.current_state = "healthy"
        self._custom_telemetry: Optional[Telemetry] = None

    def set_state(self, state_name: str) -> None:
        if state_name not in self.fixtures:
            raise KeyError(f"Unknown fixture state: {state_name}")
        self.current_state = state_name
        self._custom_telemetry = None

    def set_custom_telemetry(self, telemetry: Telemetry) -> None:
        self._custom_telemetry = telemetry

    def fetch(self) -> Telemetry:
        if self._custom_telemetry:
            return self._custom_telemetry

        data = self.fixtures[self.current_state]
        services = []
        for s in data.get("our_services", []):
            services.append(
                ServiceStatus(
                    host=s["host"],
                    port=s["port"],
                    up=s["up"],
                    last_checked=time.time(),
                    note=s.get("note", ""),
                )
            )

        return Telemetry(
            timestamp=time.time(),
            our_score=data.get("our_score", 0.0),
            rank=data.get("rank"),
            our_services=services,
            competitor_scores=data.get("competitor_scores", {}),
            raw=data.get("raw", {}),
        )


class MockServiceHost:
    """Simulates local systemd services, recovery actions, and port reachability."""

    def __init__(self):
        # Service registry: unit_name -> service details
        self.services: Dict[str, Dict[str, Any]] = {
            "web-service": {
                "host": "10.0.1.5",
                "port": 80,
                "up": True,
                "restarted_count": 0,
                "restart_should_fail": False,
                "verification_should_fail": False,
            },
            "nginx-ssl": {
                "host": "10.0.1.5",
                "port": 443,
                "up": True,
                "restarted_count": 0,
                "restart_should_fail": False,
                "verification_should_fail": False,
            },
            "sshd": {
                "host": "10.0.1.5",
                "port": 22,
                "up": True,
                "restarted_count": 0,
                "restart_should_fail": False,
                "verification_should_fail": False,
            },
        }

    def fail_service(self, host: str, port: int) -> None:
        for s in self.services.values():
            if s["host"] == host and s["port"] == port:
                s["up"] = False

    def recover_service(self, host: str, port: int) -> None:
        for s in self.services.values():
            if s["host"] == host and s["port"] == port:
                s["up"] = True

    def restart(self, service_name: str) -> PatchResult:
        if service_name not in self.services:
            return PatchResult(
                success=False,
                service=service_name,
                action="restart",
                output=f"Unit {service_name}.service not found.",
            )

        svc = self.services[service_name]
        svc["restarted_count"] += 1

        if svc["restart_should_fail"]:
            return PatchResult(
                success=False,
                service=service_name,
                action="restart",
                output=f"Job for {service_name}.service failed.",
            )

        # Service restarts and becomes UP
        svc["up"] = True
        return PatchResult(
            success=True,
            service=service_name,
            action="restart",
            output=f"Successfully restarted {service_name}.service.",
        )

    def check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        for s in self.services.values():
            if s["host"] == host and s["port"] == port:
                if s["verification_should_fail"]:
                    return False
                return s["up"]
        return False


class MockFileSystem:
    """Simulates file integrity monitoring."""

    def __init__(self, fixtures_path: Optional[str] = None):
        path = fixtures_path or os.path.join(FIXTURES_DIR, "integrity_manifest.json")
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.clean_hashes = manifest["clean_hashes"]
        self.tampered_hashes = manifest["tampered_hashes"]
        self.current_hashes = dict(self.clean_hashes)

    def tamper(self, file_path: str) -> None:
        if file_path in self.tampered_hashes:
            self.current_hashes[file_path] = self.tampered_hashes[file_path]
        else:
            self.current_hashes[file_path] = "tampered_arbitrary_hash_val"

    def restore(self, file_path: str) -> None:
        if file_path in self.clean_hashes:
            self.current_hashes[file_path] = self.clean_hashes[file_path]

    def get_tampered_files(self) -> List[str]:
        tampered = []
        for path, clean_hash in self.clean_hashes.items():
            if self.current_hashes.get(path) != clean_hash:
                tampered.append(path)
        return tampered


class MockMonitor:
    """Mock ServiceMonitor combining MockServiceHost and MockFileSystem."""

    def __init__(self, service_host: MockServiceHost, file_system: MockFileSystem):
        self.host = service_host
        self.fs = file_system

    def check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        return self.host.check_port(host, port, timeout)

    def check_integrity(self, file_path: str, expected_hash: str) -> bool:
        return self.fs.current_hashes.get(file_path) == expected_hash

    def full_snapshot(self, own_services: List[str]) -> Dict[str, Any]:
        services_status = []
        down_services = []
        for svc_str in own_services:
            parts = svc_str.split(":")
            h, p = parts[0], int(parts[1])
            is_up = self.check_port(h, p)
            services_status.append({"host": h, "port": p, "up": is_up})
            if not is_up:
                down_services.append({"host": h, "port": p})

        return {
            "services": services_status,
            "down_services": down_services,
            "tampered_files": self.fs.get_tampered_files(),
            "timestamp": time.time(),
        }


class MockGeminiEngine:
    """Simulates Gemini 3.8 Flash and Gemini 3.1 Pro Preview with programmable responses."""

    def __init__(self, fixtures_path: Optional[str] = None):
        path = fixtures_path or os.path.join(FIXTURES_DIR, "mock_gemini_responses.json")
        with open(path, "r", encoding="utf-8") as f:
            self.fixtures = json.load(f)

        self.flash_available: bool = True
        self.pro_available: bool = True
        self.force_low_confidence: bool = False
        self.force_timeout: bool = False
        self.custom_response: Optional[Decision] = None

        self.call_history: List[Dict[str, Any]] = []

    def decide(
        self,
        telemetry_summary: str,
        recent_actions: List[str],
        model: Optional[str] = None,
    ) -> Decision:
        selected_model = model or "nvidia/nemotron-3.5-lightning-30b-a3b"
        start_t = time.time()

        self.call_history.append({
            "model": selected_model,
            "timestamp": start_t,
            "summary": telemetry_summary,
        })

        if self.custom_response:
            resp = self.custom_response
            resp.model_used = selected_model
            resp.latency_ms = (time.time() - start_t) * 1000
            return resp

        is_reasoning = any(k in selected_model.lower() for k in ("pro", "super", "120b", "reasoning"))
        if is_reasoning:
            if not self.pro_available:
                return Decision(
                    action_type="hold",
                    target="",
                    priority="low",
                    reasoning="Failed to parse decision: Reasoning model service unavailable",
                    confidence=0.0,
                    latency_ms=10.0,
                    model_used=selected_model,
                )
            fix = self.fixtures["pro_deep_reasoning"]
            return Decision(
                action_type=fix["action_type"],
                target=fix["target"],
                priority=fix["priority"],
                reasoning=fix["reasoning"],
                confidence=fix["confidence"],
                latency_ms=(time.time() - start_t) * 1000,
                model_used=selected_model,
            )

        # Fast / Flash model
        if not self.flash_available or self.force_timeout:
            return Decision(
                action_type="hold",
                target="",
                priority="low",
                reasoning="Failed to parse decision: Fast (Flash) service timeout / unavailable",
                confidence=0.0,
                latency_ms=25.0,
                model_used=selected_model,
            )

        if self.force_low_confidence:
            fix = self.fixtures["flash_low_confidence"]
            return Decision(
                action_type=fix["action_type"],
                target=fix["target"],
                priority=fix["priority"],
                reasoning=fix["reasoning"],
                confidence=fix["confidence"],
                latency_ms=(time.time() - start_t) * 1000,
                model_used=selected_model,
            )

        fix = self.fixtures["flash_normal_tactical"]
        return Decision(
            action_type=fix["action_type"],
            target=fix["target"],
            priority=fix["priority"],
            reasoning=fix["reasoning"],
            confidence=fix["confidence"],
            latency_ms=(time.time() - start_t) * 1000,
            model_used=selected_model,
        )


MockNvidiaEngine = MockGeminiEngine


class MockFirewallManager(FirewallManager):
    """Simulates nftables firewall operations with programmable failure & rollback verification."""

    def __init__(self, dry_run: bool = True, should_fail_apply: bool = False):
        super().__init__(dry_run=dry_run)
        self.ruleset_history: List[str] = []
        self.should_fail: bool = should_fail_apply
        self.rollback_occurred: bool = False

    def backup_ruleset(self) -> str:
        return "# mock backup ruleset v1"

    def restore_ruleset(self, ruleset_data: str) -> bool:
        self.rollback_occurred = True
        return True

    def apply(self, rule: FirewallRule) -> str:
        self.validate_rule(rule)
        backup = self.backup_ruleset()
        self.ruleset_history.append(backup)

        if self.should_fail:
            self.restore_ruleset(backup)
            raise RuntimeError("Mock simulated kernel nftables error: Simulated nft apply failure (rolled back)")

        nft_rule = rule.to_nft()
        self.applied.append(rule)
        return nft_rule


class MockReconFast:
    """Fast in-memory mock recon scanner avoiding real network sockets."""

    def scan(self, host: str, ports: str = "1-1024"):
        from agent.attack.recon import HostFingerprint
        return HostFingerprint(
            host=host,
            open_ports=[80, 443],
            services={80: "apache 2.4", 443: "nginx 1.18"},
        )

