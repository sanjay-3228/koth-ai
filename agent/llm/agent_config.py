"""Independent LLM Configuration Manager per Agent with secure credential storage,
masking, endpoint validation, and isolated access control.
"""
import re
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..config import config as global_config
from ..logger import get_logger

logger = get_logger(__name__)

VALID_PROVIDERS = ("none", "openai", "anthropic", "gemini", "custom", "local_simulated")

DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "custom": "http://localhost:11434/v1",
    "local_simulated": "local://simulated",
    "none": "",
}

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-sonnet-20241022",
    "gemini": "gemini-1.5-flash",
    "custom": "llama3",
    "local_simulated": "simulated-advisory",
    "none": "",
}

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"AIzaSy[A-Za-z0-9_-]{10,}", re.IGNORECASE),
    re.compile(r"nvapi-[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"gsk_[A-Za-z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"flag\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"flag_[A-Za-z0-9_.-]+", re.IGNORECASE),
]


def mask_api_key(key: Optional[str]) -> str:
    """Mask sensitive API key for UI and log safety."""
    if not key or not key.strip():
        return ""
    stripped = key.strip()
    if len(stripped) <= 8:
        return "***"
    return f"{stripped[:3]}...{stripped[-4:]}"


def redact_secrets(text: str, extra_secrets: Optional[List[str]] = None) -> str:
    """Scrub sensitive credentials, API keys, private keys, and competition flags from text."""
    if not text:
        return ""
    result = str(text)
    if extra_secrets:
        for s in extra_secrets:
            if s and len(s) >= 4 and s in result:
                result = result.replace(s, "[REDACTED]")
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def validate_endpoint(endpoint: str, provider: str) -> Tuple[bool, str]:
    """Validate endpoint URL structure and protocol."""
    if provider in ("none", "local_simulated") and not endpoint:
        return True, ""
    if provider == "local_simulated" and endpoint.startswith("local://"):
        return True, ""
    if not endpoint or not endpoint.strip():
        return False, "Endpoint URL cannot be empty."

    cleaned = endpoint.strip()
    if any(ch in cleaned for ch in (" ", "\t", "\n", "\r", ";", '"', "'", "`")):
        return False, "Endpoint contains invalid characters or injection attempts."

    try:
        parsed = urllib.parse.urlparse(cleaned)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported protocol '{parsed.scheme}': must be http or https."
        if not parsed.netloc:
            return False, "Endpoint URL must include a valid host / port."
        return True, ""
    except Exception as exc:
        return False, f"Invalid URL format: {exc}"


@dataclass
class AgentLLMConfig:
    agent_id: str
    provider: str = "none"
    endpoint: str = ""
    model_id: str = ""
    api_key: str = ""
    enabled: bool = False
    connection_status: str = "UNCONFIGURED"
    last_tested_at: float = 0.0
    last_error: str = ""
    updated_at: float = 0.0

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model_id": self.model_id,
            "api_key": mask_api_key(self.api_key) if mask_secrets else self.api_key,
            "api_key_masked": mask_api_key(self.api_key),
            "has_api_key": bool(self.api_key and self.api_key.strip()),
            "enabled": bool(self.enabled),
            "connection_status": self.connection_status,
            "last_tested_at": self.last_tested_at,
            "last_error": redact_secrets(self.last_error, [self.api_key]),
            "updated_at": self.updated_at,
        }


class AgentLLMConfigManager:
    """Manages persistent SQLite storage and operations for per-agent LLM configurations."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or global_config.db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_llm_configs (
                    agent_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL DEFAULT 'none',
                    endpoint TEXT DEFAULT '',
                    model_id TEXT DEFAULT '',
                    api_key TEXT DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 0,
                    connection_status TEXT NOT NULL DEFAULT 'UNCONFIGURED',
                    last_tested_at REAL DEFAULT 0.0,
                    last_error TEXT DEFAULT '',
                    updated_at REAL DEFAULT 0.0
                )
                """
            )
            # Ensure default rows exist for all four agents
            now = time.time()
            for aid in ("agent-01", "agent-02", "agent-03", "agent-04"):
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO agent_llm_configs 
                    (agent_id, provider, endpoint, model_id, api_key, enabled, connection_status, updated_at)
                    VALUES (?, 'none', '', '', '', 0, 'UNCONFIGURED', ?)
                    """,
                    (aid, now),
                )
            conn.commit()

    def get_config(self, agent_id: str, mask_secrets: bool = True) -> Dict[str, Any]:
        """Retrieve isolated LLM configuration for the specified agent."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agent_llm_configs WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                # Return unconfigured baseline
                cfg = AgentLLMConfig(agent_id=agent_id)
                return cfg.to_dict(mask_secrets=mask_secrets)

            cfg = AgentLLMConfig(
                agent_id=row["agent_id"],
                provider=row["provider"] or "none",
                endpoint=row["endpoint"] or "",
                model_id=row["model_id"] or "",
                api_key=row["api_key"] or "",
                enabled=bool(row["enabled"]),
                connection_status=row["connection_status"] or "UNCONFIGURED",
                last_tested_at=row["last_tested_at"] or 0.0,
                last_error=row["last_error"] or "",
                updated_at=row["updated_at"] or 0.0,
            )
            return cfg.to_dict(mask_secrets=mask_secrets)

    def set_config(
        self,
        agent_id: str,
        provider: str,
        endpoint: str,
        model_id: str,
        api_key: Optional[str] = None,
        enabled: bool = False,
    ) -> Dict[str, Any]:
        """Save isolated LLM configuration for the specified agent."""
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"Invalid provider '{provider}'. Must be one of: {', '.join(VALID_PROVIDERS)}")

        endpoint_val = endpoint.strip() if endpoint else DEFAULT_ENDPOINTS.get(provider, "")
        valid, err_msg = validate_endpoint(endpoint_val, provider)
        if not valid:
            raise ValueError(f"Invalid endpoint: {err_msg}")

        model_val = model_id.strip() if model_id else DEFAULT_MODELS.get(provider, "")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT api_key, connection_status FROM agent_llm_configs WHERE agent_id = ?", (agent_id,))
            existing = cursor.fetchone()
            current_key = existing["api_key"] if existing else ""
            status = existing["connection_status"] if existing else "UNCONFIGURED"

            # Determine key to save: if user passed None, empty, or a masked string like 'sk-...', keep existing
            new_key = current_key
            if api_key is not None and api_key != "":
                if not ("..." in api_key or api_key == "***"):
                    new_key = api_key.strip()

            if not enabled:
                status = "DISABLED"
            elif provider == "none":
                status = "UNCONFIGURED"

            now = time.time()
            cursor.execute(
                """
                INSERT OR REPLACE INTO agent_llm_configs 
                (agent_id, provider, endpoint, model_id, api_key, enabled, connection_status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    provider,
                    endpoint_val,
                    model_val,
                    new_key,
                    1 if enabled else 0,
                    status,
                    now,
                ),
            )
            conn.commit()

        logger.info(
            f"[LLM CONFIG] Saved isolated LLM settings for {agent_id}: provider={provider}, "
            f"model={model_val}, enabled={enabled}, endpoint={endpoint_val}"
        )
        return self.get_config(agent_id, mask_secrets=True)

    def update_connection_status(
        self,
        agent_id: str,
        status: str,
        error_message: str = "",
        tested_at: Optional[float] = None,
    ) -> None:
        """Update live connection status and last error message with secret redaction."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT api_key FROM agent_llm_configs WHERE agent_id = ?", (agent_id,))
            existing = cursor.fetchone()
            key = existing["api_key"] if existing else ""
            scrubbed_error = redact_secrets(error_message, [key])

            now = tested_at or time.time()
            cursor.execute(
                """
                UPDATE agent_llm_configs
                SET connection_status = ?, last_error = ?, last_tested_at = ?
                WHERE agent_id = ?
                """,
                (status, scrubbed_error, now, agent_id),
            )
            conn.commit()

    def get_raw_config(self, agent_id: str) -> Optional[AgentLLMConfig]:
        """Internal method retrieving unmasked configuration strictly for execution adapters."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agent_llm_configs WHERE agent_id = ?", (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return AgentLLMConfig(
                agent_id=row["agent_id"],
                provider=row["provider"] or "none",
                endpoint=row["endpoint"] or "",
                model_id=row["model_id"] or "",
                api_key=row["api_key"] or "",
                enabled=bool(row["enabled"]),
                connection_status=row["connection_status"] or "UNCONFIGURED",
                last_tested_at=row["last_tested_at"] or 0.0,
                last_error=row["last_error"] or "",
                updated_at=row["updated_at"] or 0.0,
            )
