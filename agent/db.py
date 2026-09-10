"""SQLite persistence layer for telemetry history and action logs."""
import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from .config import config
from .logger import get_logger

logger = get_logger(__name__)


class DatabaseManager:
    """Manages SQLite database storage for telemetry and actions."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or config.db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create necessary tables and indices if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    our_score REAL,
                    rank INTEGER,
                    our_services TEXT,
                    competitor_scores TEXT,
                    raw TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp
                ON telemetry_history(timestamp DESC)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS action_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    reasoning TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    model_used TEXT DEFAULT '',
                    confidence REAL DEFAULT 1.0,
                    latency_ms REAL DEFAULT 0.0
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS model_call_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    model TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    latency_ms REAL DEFAULT 0.0,
                    success INTEGER DEFAULT 1,
                    fallback INTEGER DEFAULT 0,
                    escalation INTEGER DEFAULT 0
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_model_call_timestamp
                ON model_call_log(timestamp DESC)
                """
            )
            # Automatic migrations for existing DBs
            for col, col_def in [
                ("model_used", "TEXT DEFAULT ''"),
                ("confidence", "REAL DEFAULT 1.0"),
                ("latency_ms", "REAL DEFAULT 0.0"),
                ("verification_result", "TEXT DEFAULT ''"),
                ("empirical_success", "INTEGER DEFAULT 1"),
                ("execution_status", "TEXT DEFAULT 'completed'"),
                ("authorized", "INTEGER DEFAULT 1"),
                ("would_execute", "INTEGER DEFAULT 1"),
                ("provider", "TEXT DEFAULT ''"),
                ("fallback_level", "INTEGER DEFAULT 0"),
                ("parse_status", "TEXT DEFAULT ''"),
                ("request_id", "TEXT DEFAULT ''"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE action_log ADD COLUMN {col} {col_def}")
                except sqlite3.OperationalError:
                    pass  # column already present

            for col, col_def in [
                ("api_latency_ms", "REAL DEFAULT 0.0"),
                ("http_status", "INTEGER DEFAULT 200"),
                ("timeout", "INTEGER DEFAULT 0"),
                ("rate_limit", "INTEGER DEFAULT 0"),
                ("malformed_response", "INTEGER DEFAULT 0"),
                ("empirical_outcome", "INTEGER DEFAULT NULL"),
                ("provider", "TEXT DEFAULT ''"),
                ("fallback_level", "INTEGER DEFAULT 0"),
                ("parse_status", "TEXT DEFAULT ''"),
                ("request_id", "TEXT DEFAULT ''"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE model_call_log ADD COLUMN {col} {col_def}")
                except sqlite3.OperationalError:
                    pass  # column already present

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_action_timestamp
                ON action_log(timestamp DESC)
                """
            )
            conn.commit()

    def record_telemetry(self, telemetry: Any) -> int:
        """Persist a Telemetry instance to SQLite."""
        services_data = []
        if hasattr(telemetry, "our_services"):
            for svc in telemetry.our_services:
                services_data.append(
                    {
                        "host": getattr(svc, "host", ""),
                        "port": getattr(svc, "port", 0),
                        "up": getattr(svc, "up", False),
                        "last_checked": getattr(svc, "last_checked", time.time()),
                        "note": getattr(svc, "note", ""),
                    }
                )

        competitor_scores = getattr(telemetry, "competitor_scores", {})
        if not isinstance(competitor_scores, dict):
            competitor_scores = {}
        raw = getattr(telemetry, "raw", {})
        if not isinstance(raw, dict):
            raw = {}
        ts = getattr(telemetry, "timestamp", time.time())
        our_score = getattr(telemetry, "our_score", None)
        rank = getattr(telemetry, "rank", None)

        try:
            comp_json = json.dumps(competitor_scores)
        except (TypeError, ValueError):
            comp_json = "{}"

        try:
            raw_json = json.dumps(raw)
        except (TypeError, ValueError):
            raw_json = "{}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO telemetry_history
                    (timestamp, our_score, rank, our_services, competitor_scores, raw)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    our_score,
                    rank,
                    json.dumps(services_data),
                    comp_json,
                    raw_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_latest_telemetry(self) -> Optional[Dict[str, Any]]:
        """Fetch the most recent telemetry entry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, our_score, rank, our_services, competitor_scores, raw
                FROM telemetry_history
                ORDER BY timestamp DESC
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_telemetry_dict(row)

    def get_telemetry_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent telemetry history up to limit."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, our_score, rank, our_services, competitor_scores, raw
                FROM telemetry_history
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [self._row_to_telemetry_dict(r) for r in cursor.fetchall()]

    def record_model_call(
        self,
        model: str,
        reason: str,
        confidence: float = 1.0,
        latency_ms: float = 0.0,
        success: bool = True,
        fallback: bool = False,
        escalation: bool = False,
        timestamp: Optional[float] = None,
        api_latency_ms: float = 0.0,
        http_status: Optional[int] = 200,
        timeout: bool = False,
        rate_limit: bool = False,
        malformed_response: bool = False,
        empirical_outcome: Optional[bool] = None,
        provider: str = "",
        fallback_level: int = 0,
        parse_status: str = "",
        request_id: str = "",
    ) -> int:
        """Record model invocation telemetry including provider-specific fields."""
        ts = timestamp if timestamp is not None else time.time()
        succ_val = 1 if success else 0
        fall_val = 1 if fallback else 0
        esc_val = 1 if escalation else 0
        timeo_val = 1 if timeout else 0
        rl_val = 1 if rate_limit else 0
        malf_val = 1 if malformed_response else 0
        emp_val = None if empirical_outcome is None else (1 if empirical_outcome else 0)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO model_call_log
                    (timestamp, model, reason, confidence, latency_ms, success, fallback, escalation,
                     api_latency_ms, http_status, timeout, rate_limit, malformed_response, empirical_outcome,
                     provider, fallback_level, parse_status, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    model,
                    reason,
                    confidence,
                    latency_ms,
                    succ_val,
                    fall_val,
                    esc_val,
                    api_latency_ms,
                    http_status,
                    timeo_val,
                    rl_val,
                    malf_val,
                    emp_val,
                    provider,
                    fallback_level,
                    parse_status,
                    request_id,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_recent_model_calls(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch the most recent model calls up to limit (newest first)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, model, reason, confidence, latency_ms, success, fallback, escalation,
                       api_latency_ms, http_status, timeout, rate_limit, malformed_response, empirical_outcome,
                       provider, fallback_level, parse_status, request_id
                FROM model_call_log
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]

    def record_action(
        self,
        action_type: str,
        target: str,
        priority: str,
        reasoning: str,
        details: str = "",
        timestamp: Optional[float] = None,
        model_used: str = "",
        confidence: float = 1.0,
        latency_ms: float = 0.0,
        verification_result: Optional[Dict[str, Any]] = None,
        empirical_success: Optional[bool] = None,
        execution_status: str = "completed",
        authorized: bool = True,
        would_execute: bool = True,
        provider: str = "",
        fallback_level: int = 0,
        parse_status: str = "",
        request_id: str = "",
    ) -> int:
        """Persist an action/decision to SQLite including authorization and would_execute flags."""
        ts = timestamp if timestamp is not None else time.time()
        verif_str = json.dumps(verification_result) if verification_result is not None else ""
        emp_succ = 1 if empirical_success is None or empirical_success else 0
        auth_val = 1 if authorized else 0
        exec_val = 1 if would_execute else 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO action_log
                    (timestamp, action_type, target, priority, reasoning, details, model_used, confidence, latency_ms,
                     verification_result, empirical_success, execution_status, authorized, would_execute,
                     provider, fallback_level, parse_status, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ts, action_type, target, priority, reasoning, details, model_used, confidence, latency_ms,
                 verif_str, emp_succ, execution_status, auth_val, exec_val,
                 provider, fallback_level, parse_status, request_id),
            )
            conn.commit()
            return cursor.lastrowid

    def get_recent_actions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch the most recent actions up to limit (newest first)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, action_type, target, priority, reasoning, details,
                       model_used, confidence, latency_ms, verification_result, empirical_success,
                       execution_status, authorized, would_execute
                FROM action_log
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                verif = {}
                if "verification_result" in r.keys() and r["verification_result"]:
                    try:
                        verif = json.loads(r["verification_result"])
                    except (json.JSONDecodeError, TypeError):
                        verif = {}
                results.append({
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "action_type": r["action_type"],
                    "target": r["target"],
                    "priority": r["priority"],
                    "reasoning": r["reasoning"],
                    "details": r["details"],
                    "model_used": r["model_used"] if "model_used" in r.keys() else "",
                    "confidence": r["confidence"] if "confidence" in r.keys() else 1.0,
                    "latency_ms": r["latency_ms"] if "latency_ms" in r.keys() else 0.0,
                    "verification_result": verif,
                    "empirical_success": bool(r["empirical_success"]) if "empirical_success" in r.keys() and r["empirical_success"] is not None else True,
                    "execution_status": r["execution_status"] if "execution_status" in r.keys() and r["execution_status"] else "completed",
                    "authorized": bool(r["authorized"]) if "authorized" in r.keys() and r["authorized"] is not None else True,
                    "would_execute": bool(r["would_execute"]) if "would_execute" in r.keys() and r["would_execute"] is not None else True,
                })
            return results

    def get_empirical_success_stats(self, limit: int = 50) -> Dict[str, Any]:
        """Calculate verified action success rate over recent actions."""
        actions = self.get_recent_actions(limit=limit)
        if not actions:
            return {"total": 0, "successful": 0, "rate": 1.0}
        successful = sum(1 for a in actions if a.get("empirical_success", True))
        return {
            "total": len(actions),
            "successful": successful,
            "rate": round(successful / len(actions), 3),
        }

    def get_recent_action_strings(self, limit: int = 10) -> List[str]:
        """Fetch formatted strings '{action_type}:{target}:{reasoning}' oldest first for prompt context."""
        recent = self.get_recent_actions(limit=limit)
        # Reverse to chronological order (oldest -> newest) for model context
        return [
            f"{a['action_type']}:{a['target']}:{a['reasoning']}"
            for a in reversed(recent)
        ]

    @staticmethod
    def _row_to_telemetry_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "our_score": row["our_score"],
            "rank": row["rank"],
            "our_services": json.loads(row["our_services"] or "[]"),
            "competitor_scores": json.loads(row["competitor_scores"] or "{}"),
            "raw": json.loads(row["raw"] or "{}"),
        }


db = DatabaseManager()
