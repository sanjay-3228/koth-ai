"""Central config loaded from environment variables / .env file."""
from enum import Enum
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from dotenv import load_dotenv

import requests

load_dotenv()


class ConfigProfile(str, Enum):
    DEV = "DEV"
    LOCAL_REHEARSAL = "LOCAL_REHEARSAL"
    PWNGROUNDS_SIM = "PWNGROUNDS_SIM"
    LAN_REHEARSAL = "LAN_REHEARSAL"
    RADMIN_REHEARSAL = "RADMIN_REHEARSAL"



@dataclass
class ServiceConfig:
    host: str
    port: int
    systemd_unit: str = ""

    @classmethod
    def from_string(cls, raw: str) -> "ServiceConfig":
        parts = raw.strip().split(":")
        if len(parts) >= 3:
            return cls(host=parts[0], port=int(parts[1]), systemd_unit=parts[2])
        elif len(parts) == 2:
            return cls(host=parts[0], port=int(parts[1]), systemd_unit="")
        return cls(host=parts[0], port=0, systemd_unit="")


@dataclass
class Config:
    nvidia_api_key: Optional[str] = None
    nvidia_base_url: Optional[str] = None
    nvidia_fast_model: Optional[str] = None
    nvidia_reasoning_model: Optional[str] = None
    nvidia_confidence_threshold: Optional[float] = None

    # Groq Provider (Reasoning / Escalation)
    groq_api_key: Optional[str] = None
    groq_base_url: Optional[str] = None
    groq_reasoning_model: Optional[str] = None

    # OpenRouter Provider (Specialist / Final Escalation)
    openrouter_api_key: Optional[str] = None
    openrouter_base_url: Optional[str] = None
    openrouter_specialist_model: Optional[str] = None

    # Model Routing Thresholds & Timeouts
    fast_confidence_threshold: float = 0.75
    reasoning_confidence_threshold: float = 0.85
    llm_timeout_seconds: float = 30.0
    llm_max_retries: int = 1

    # Backward compatibility fields
    gemini_api_key: Optional[str] = None
    gemini_fast_model: Optional[str] = None
    gemini_reasoning_model: Optional[str] = None
    gemini_confidence_threshold: Optional[float] = None

    @property
    def gemini_model(self) -> str:
        """Alias for primary/fast model for backwards compatibility."""
        return self.nvidia_fast_model or "nvidia/nemotron-3.5-lightning-30b-a3b"

    scoreboard_url: str = os.getenv("SCOREBOARD_URL", "")
    scoreboard_poll_seconds: int = int(os.getenv("SCOREBOARD_POLL_SECONDS", "30"))

    # Your own hosts/services to defend, e.g. "<HOST_IP>:80:web-service,<HOST_IP>:22:sshd"
    own_services: List[str] = field(
        default_factory=lambda: [
            s for s in os.getenv("OWN_SERVICES", "").split(",") if s
        ]
    )

    # Competitor hosts you are authorized to target under competition rules
    target_hosts: List[str] = field(
        default_factory=lambda: [
            s for s in os.getenv("TARGET_HOSTS", "").split(",") if s
        ]
    )

    # Explicit allowlist of authorized exploit plugins (empty by default)
    allowed_plugins: List[str] = field(
        default_factory=lambda: [
            s for s in os.getenv("ALLOWED_PLUGINS", "").split(",") if s
        ]
    )

    # Operational mode: DRY_RUN (default, non-destructive) or LIVE (strictly guarded)
    koth_mode: str = os.getenv("KOTH_MODE", "DRY_RUN").upper()
    observation_only: bool = os.getenv("OBSERVATION_ONLY", "true").lower() in ("true", "1")
    dry_run: bool = True
    kill_switch: bool = os.getenv("KILL_SWITCH", "false").lower() in ("true", "1")
    max_actions_per_minute: int = int(os.getenv("MAX_ACTIONS_PER_MINUTE", "12"))
    action_timeout_seconds: float = float(os.getenv("ACTION_TIMEOUT_SECONDS", "10.0"))
    stale_telemetry_threshold: float = float(os.getenv("STALE_TELEMETRY_THRESHOLD", "60.0"))
    tick_interval_seconds: int = int(float(os.getenv("TICK_INTERVAL_SECONDS", "20")))
    db_path: str = os.getenv("DB_PATH", "koth_agent.db")
    dashboard_host: str = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    dashboard_port: int = int(os.getenv("DASHBOARD_PORT", "5000"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # PwnGrounds Network & Environment configuration
    pwn_mode: str = os.getenv("PWN_MODE", "auto").lower()
    pwn_competition_cidrs_raw: str = os.getenv("PWN_COMPETITION_CIDRS", "")
    pwn_own_hosts_raw: str = os.getenv("PWN_OWN_HOSTS", "")
    pwn_own_services_raw: str = os.getenv("PWN_OWN_SERVICES", "")
    pwn_target_hosts_raw: str = os.getenv("PWN_TARGET_HOSTS", "")
    pwn_scoreboard_url: str = os.getenv("PWN_SCOREBOARD_URL", "")

    # Swarm Configuration for 4-Agent Team
    team_id: str = os.getenv("TEAM_ID", "null_warriors")
    agent_id: str = os.getenv("AGENT_ID", "agent-01")
    agent_role: str = os.getenv("AGENT_ROLE", "WORKER").upper()
    swarm_enabled: bool = os.getenv("SWARM_ENABLED", "true").lower() in ("true", "1")
    coordinator_url: str = os.getenv("COORDINATOR_URL", "")
    swarm_bind_host: str = os.getenv("SWARM_BIND_HOST", "")
    swarm_port: int = int(os.getenv("SWARM_PORT", "5000"))
    swarm_auth_token: str = os.getenv("SWARM_AUTH_TOKEN", "")
    operator_token: Optional[str] = os.getenv("SWARM_OPERATOR_TOKEN")
    agent_token: Optional[str] = os.getenv("SWARM_AGENT_TOKEN")
    agent_tokens: Dict[str, str] = field(default_factory=dict)
    ssl_cert: Optional[str] = os.getenv("SWARM_SSL_CERT")
    ssl_key: Optional[str] = os.getenv("SWARM_SSL_KEY")
    use_tls: bool = os.getenv("SWARM_USE_TLS", "false").lower() in ("true", "1")
    ca_cert: Optional[str] = os.getenv("SWARM_CA_CERT")
    authorized_agents: List[str] = field(
        default_factory=lambda: [
            s.strip()
            for s in os.getenv("AUTHORIZED_AGENTS", "agent-01,agent-02,agent-03,agent-04").split(",")
            if s.strip()
        ]
    )
    phase_poll_interval_seconds: float = float(os.getenv("PHASE_POLL_INTERVAL_SECONDS", "3.0"))

    heartbeat_interval_seconds: float = float(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "3.0"))
    lease_ttl_seconds: float = float(os.getenv("LEASE_TTL_SECONDS", "15.0"))
    pwn_profile: str = os.getenv("PWN_PROFILE", "PWNGROUNDS_LAN").upper()
    protected_hosts: List[str] = field(
        default_factory=lambda: [s for s in os.getenv("PROTECTED_HOSTS", "").split(",") if s]
    )
    allowed_ports: List[int] = field(
        default_factory=lambda: [
            int(p)
            for p in os.getenv("ALLOWED_PORTS", "21,22,80,443,8080").split(",")
            if p.strip().isdigit()
        ]
    )
    allowed_actions: List[str] = field(
        default_factory=lambda: [
            s.strip()
            for s in os.getenv(
                "ALLOWED_ACTIONS",
                "nmap_scan,audit_local_services,patch_vulnerability,monitor_connections,exploit_service,restart_service,rate_limit_port,recon_scan,exploit_plugin,hold",
            ).split(",")
            if s.strip()
        ]
    )

    # Lab Environment Profile: DEV (default), LOCAL_REHEARSAL, PWNGROUNDS_SIM, LAN_REHEARSAL
    lab_profile: str = os.getenv("LAB_PROFILE", "DEV").upper()

    def __post_init__(self):
        # Resolve API key
        if self.nvidia_api_key is None and self.gemini_api_key is not None:
            self.nvidia_api_key = self.gemini_api_key
        elif self.nvidia_api_key is None:
            self.nvidia_api_key = os.getenv("NVIDIA_API_KEY", os.getenv("GEMINI_API_KEY", ""))
        if self.gemini_api_key is None:
            self.gemini_api_key = self.nvidia_api_key

        # Resolve Base URL
        if not self.nvidia_base_url:
            self.nvidia_base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/")

        # Resolve Fast Model (NVIDIA)
        if self.nvidia_fast_model is None and self.gemini_fast_model is not None:
            self.nvidia_fast_model = self.gemini_fast_model
        elif self.nvidia_fast_model is None:
            self.nvidia_fast_model = os.getenv("NVIDIA_FAST_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
        if self.gemini_fast_model is None:
            self.gemini_fast_model = self.nvidia_fast_model

        # Resolve Reasoning Model (Groq / legacy NVIDIA)
        if self.groq_api_key is None:
            self.groq_api_key = os.getenv("GROQ_API_KEY", "")
        if not self.groq_base_url:
            self.groq_base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
        if self.groq_reasoning_model is None:
            self.groq_reasoning_model = os.getenv("GROQ_REASONING_MODEL", "openai/gpt-oss-120b")

        # Resolve Specialist Model (OpenRouter)
        if self.openrouter_api_key is None:
            self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY", "")
        if not self.openrouter_base_url:
            self.openrouter_base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        if self.openrouter_specialist_model is None:
            self.openrouter_specialist_model = os.getenv("OPENROUTER_SPECIALIST_MODEL", "z-ai/glm-5.3-flash")

        # Resolve Routing Thresholds & Timeouts
        raw_fast_thresh = os.getenv("FAST_CONFIDENCE_THRESHOLD", os.getenv("NVIDIA_CONFIDENCE_THRESHOLD", "0.75"))
        try:
            self.fast_confidence_threshold = float(raw_fast_thresh)
        except (ValueError, TypeError):
            self.fast_confidence_threshold = 0.75

        raw_reason_thresh = os.getenv("REASONING_CONFIDENCE_THRESHOLD", "0.85")
        try:
            self.reasoning_confidence_threshold = float(raw_reason_thresh)
        except (ValueError, TypeError):
            self.reasoning_confidence_threshold = 0.85

        try:
            self.llm_timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", str(self.llm_timeout_seconds)))
        except (ValueError, TypeError):
            self.llm_timeout_seconds = 30.0

        try:
            self.llm_max_retries = int(os.getenv("LLM_MAX_RETRIES", str(self.llm_max_retries)))
        except (ValueError, TypeError):
            self.llm_max_retries = 1

        # Legacy reasoning model mapping
        if self.nvidia_reasoning_model is None:
            self.nvidia_reasoning_model = os.getenv("NVIDIA_REASONING_MODEL", self.groq_reasoning_model)
        if self.gemini_reasoning_model is None:
            self.gemini_reasoning_model = self.nvidia_reasoning_model
        if self.nvidia_confidence_threshold is None:
            self.nvidia_confidence_threshold = self.fast_confidence_threshold
        if self.gemini_confidence_threshold is None:
            self.gemini_confidence_threshold = self.fast_confidence_threshold

        # Sync legacy and PwnGrounds variables bidirectionally
        if self.pwn_scoreboard_url and not self.scoreboard_url:
            self.scoreboard_url = self.pwn_scoreboard_url
        elif self.scoreboard_url and not self.pwn_scoreboard_url:
            self.pwn_scoreboard_url = self.scoreboard_url

        if self.pwn_own_services_raw and not self.own_services:
            self.own_services = [s.strip() for s in self.pwn_own_services_raw.split(",") if s.strip()]

        if self.pwn_target_hosts_raw and not self.target_hosts:
            self.target_hosts = [t.strip() for t in self.pwn_target_hosts_raw.split(",") if t.strip()]

        if self.lab_profile == "LOCAL_REHEARSAL":
            self.pwn_profile = "LOCAL_REHEARSAL"
            self.pwn_competition_cidrs_raw = "10.254.254.0/24"
            self.target_hosts = ["10.254.254.11", "10.254.254.12", "10.254.254.13", "10.254.254.14"]
            self.own_services = [
                "10.254.254.101:22:sshd",
                "10.254.254.102:22:sshd",
                "10.254.254.103:22:sshd",
                "10.254.254.104:22:sshd",
            ]
            self.protected_hosts = ["10.254.254.101", "10.254.254.102", "10.254.254.103", "10.254.254.104"]
            self.dry_run = True
            self.observation_only = True
            self.koth_mode = "DRY_RUN"
            if not self.swarm_bind_host:
                self.swarm_bind_host = "127.0.0.1"
            if not self.coordinator_url or self.coordinator_url == "http://127.0.0.1:5000":
                self.coordinator_url = f"http://127.0.0.1:{self.swarm_port}"
            self.use_tls = False

        elif self.lab_profile in ("LAN_REHEARSAL", "RADMIN_REHEARSAL"):
            self.pwn_profile = self.lab_profile
            if not self.pwn_competition_cidrs_raw:
                self.pwn_competition_cidrs_raw = "10.254.254.0/24"
            if not self.target_hosts:
                self.target_hosts = ["10.254.254.11", "10.254.254.12", "10.254.254.13", "10.254.254.14"]
            if not self.own_services:
                self.own_services = [
                    "10.254.254.101:22:sshd",
                    "10.254.254.102:22:sshd",
                    "10.254.254.103:22:sshd",
                    "10.254.254.104:22:sshd",
                ]
            if not self.protected_hosts:
                self.protected_hosts = ["10.254.254.101", "10.254.254.102", "10.254.254.103", "10.254.254.104"]
            self.dry_run = True
            self.observation_only = True
            self.koth_mode = "DRY_RUN"
            if self.swarm_bind_host and (not self.coordinator_url or self.coordinator_url == "http://127.0.0.1:5000"):
                self.coordinator_url = f"http://{self.swarm_bind_host}:{self.swarm_port}"

        if self.koth_mode != "LIVE" or self.observation_only:
            self.dry_run = True

        # Parse SWARM_AGENT_TOKENS if agent_tokens dict is empty
        if not self.agent_tokens:
            raw_tokens = os.getenv("SWARM_AGENT_TOKENS", "")
            if raw_tokens:
                tokens = {}
                for item in raw_tokens.split(","):
                    item = item.strip()
                    if ":" in item:
                        k, v = item.split(":", 1)
                        tokens[k.strip()] = v.strip()
                    elif "=" in item:
                        k, v = item.split("=", 1)
                        tokens[k.strip()] = v.strip()
                self.agent_tokens = tokens

        # Also support individual SWARM_AGENT_TOKEN_<AGENT_ID> env vars
        for aid in self.authorized_agents:
            env_var = f"SWARM_AGENT_TOKEN_{aid.upper().replace('-', '_')}"
            val = os.getenv(env_var)
            if val and aid not in self.agent_tokens:
                self.agent_tokens[aid] = val

        # If this instance is a worker and agent_token is not explicitly set, look up in agent_tokens
        if not self.agent_token and self.agent_id in self.agent_tokens:
            self.agent_token = self.agent_tokens[self.agent_id]


    @property
    def parsed_services(self) -> Dict[str, ServiceConfig]:
        """Map of 'host:port' -> ServiceConfig."""
        mapping = {}
        for raw in self.own_services:
            try:
                cfg = ServiceConfig.from_string(raw)
                mapping[f"{cfg.host}:{cfg.port}"] = cfg
            except (ValueError, IndexError):
                continue
        return mapping

    @property
    def own_hosts(self) -> List[str]:
        """Distinct host IPs/names of own infrastructure."""
        hosts = set()
        for svc in self.parsed_services.values():
            hosts.add(svc.host)
        return list(hosts)

    def get_service_unit(self, host: str, port: int) -> Optional[str]:
        """Resolve preconfigured systemd unit name for host:port."""
        key = f"{host}:{port}"
        svc = self.parsed_services.get(key)
        return svc.systemd_unit if svc and svc.systemd_unit else None

    def is_own_service(self, host: str, port: int) -> bool:
        """Check if host:port is configured as an own service."""
        return f"{host}:{port}" in self.parsed_services

    def is_protected_host(self, host: str) -> bool:
        """Check if host is in protected or own hosts."""
        return host in self.protected_hosts or host in self.own_hosts

    def is_target_host(self, host: str) -> bool:
        """Check if host is an explicitly authorized competition target."""
        return host in self.target_hosts

    def is_allowed_plugin(self, plugin_name: str) -> bool:
        """Check if plugin is in the explicit allowlist."""
        return plugin_name in self.allowed_plugins

    def is_action_allowed(self, action_name: str) -> bool:
        """Check if action is explicitly permitted by deterministic allowlist."""
        if not action_name or action_name == "hold":
            return True
        return action_name in self.allowed_actions

    def validate_models(self) -> List[str]:
        """Fetch available models from NVIDIA NIM API and verify configured models exist."""
        url = f"{self.nvidia_base_url}/models"
        headers = {"Authorization": f"Bearer {self.nvidia_api_key}"}
        try:
            resp = requests.get(url, headers=headers, params={"key": self.gemini_api_key, "pageSize": 100}, timeout=15)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"NVIDIA API returned status {resp.status_code} during model validation. "
                    "Verify your NVIDIA_API_KEY is valid and has access to NVIDIA NIM."
                )
            data = resp.json()
            available = []
            if "data" in data:
                available = [m.get("id", "") for m in data.get("data", [])]
            elif "models" in data:
                available = [m.get("name", "").replace("models/", "") for m in data.get("models", [])]
        except requests.RequestException as exc:
            raise RuntimeError(f"Network error validating models: {exc}")

        missing = []
        if self.nvidia_fast_model not in available and self.gemini_fast_model not in available:
            missing.append(f"FAST_MODEL '{self.nvidia_fast_model or self.gemini_fast_model}'")
        if self.nvidia_reasoning_model not in available and self.gemini_reasoning_model not in available:
            missing.append(f"REASONING_MODEL '{self.nvidia_reasoning_model or self.gemini_reasoning_model}'")

        if missing:
            raise RuntimeError(
                f"Model validation failed: {', '.join(missing)} not available through this API key. "
                f"Available models: {', '.join(available[:10])}..."
            )
        return available

    def validate(self, skip_model_check: bool = False) -> None:
        # Binding host safety validation
        if self.swarm_bind_host == "0.0.0.0":
            raise RuntimeError("Coordinator cannot be bound to 0.0.0.0. Specify an explicit private IP address or 127.0.0.1.")

        if self.lab_profile in ("LAN_REHEARSAL", "RADMIN_REHEARSAL"):
            if not self.swarm_bind_host:
                raise RuntimeError(f"In {self.lab_profile} profile, SWARM_BIND_HOST must be explicitly configured with a private LAN or VPN IP.")
            if self.swarm_bind_host == "127.0.0.1":
                raise RuntimeError(f"In {self.lab_profile} profile, SWARM_BIND_HOST must NOT be 127.0.0.1. An explicit private LAN or VPN IP is required.")
            import ipaddress
            try:
                ip = ipaddress.ip_address(self.swarm_bind_host)
                if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
                    raise RuntimeError(f"SWARM_BIND_HOST '{self.swarm_bind_host}' is not a permitted host address.")
                is_radmin = ip in ipaddress.ip_network("26.0.0.0/8")
                if self.lab_profile == "RADMIN_REHEARSAL":
                    if not (ip.is_private or is_radmin):
                        raise RuntimeError(f"SWARM_BIND_HOST '{self.swarm_bind_host}' must be a valid private LAN (RFC 1918) or Radmin VPN (26.0.0.0/8) IP address.")
                else:
                    if not ip.is_private:
                        raise RuntimeError(f"SWARM_BIND_HOST '{self.swarm_bind_host}' must be a valid private LAN IP address (RFC 1918).")
            except ValueError:
                raise RuntimeError(f"SWARM_BIND_HOST '{self.swarm_bind_host}' is not a valid IP address.")

        missing = []
        if self.lab_profile not in ("LOCAL_REHEARSAL", "LAN_REHEARSAL", "RADMIN_REHEARSAL") and not self.nvidia_api_key and not self.gemini_api_key:
            missing.append("NVIDIA_API_KEY (GEMINI_API_KEY)")
        if self.lab_profile not in ("LOCAL_REHEARSAL", "LAN_REHEARSAL", "RADMIN_REHEARSAL") and not self.scoreboard_url:
            missing.append("SCOREBOARD_URL")
        if missing:
            raise RuntimeError(f"Missing required config: {', '.join(missing)}")

        # Validate models against the actual NVIDIA NIM API unless skipped
        skip_env = os.getenv("SKIP_MODEL_VALIDATION", "false").lower() in ("true", "1")
        if self.lab_profile not in ("LOCAL_REHEARSAL", "LAN_REHEARSAL", "RADMIN_REHEARSAL") and not skip_model_check and not skip_env:
            self.validate_models()



config = Config()


def load_config(
    profile: Optional[Union[ConfigProfile, str]] = None,
    **overrides,
) -> Config:
    """Load a Config instance configured for a specific profile with optional overrides."""
    if profile is not None:
        prof_val = profile.value if isinstance(profile, ConfigProfile) else str(profile)
        overrides["lab_profile"] = prof_val
        overrides["pwn_profile"] = prof_val
    return Config(**overrides)
