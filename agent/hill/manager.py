"""
Hill Management, Portals, and Flag Verification Engine.

Enforces:
  1. Fixed mapping:
     - Hill 1 -> agent-01 (Leader)
     - Hill 2 -> agent-02 (Teammate 1)
     - Hill 3 -> agent-03 (Teammate 2)
     - Hill 4 -> agent-04 (Teammate 3)
  2. Strict backend authorization: Teammates cannot modify other teammates' hills.
  3. Flag secrecy: Flags are hashed (SHA-256) and never leaked in logs or API responses.
  4. Ownership states: UNVERIFIED, SUBMITTED, OWNED, LOST, UNKNOWN.
  5. Hill health is strictly decoupled from ownership status.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from agent.logger import get_logger
from agent.swarm.team_manager import AGENT_HILL_MAPPING, HILL_AGENT_MAPPING, TeamManager

logger = get_logger(__name__)


class OwnershipStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SUBMITTED = "SUBMITTED"
    OWNED = "OWNED"
    LOST = "LOST"
    UNKNOWN = "UNKNOWN"


class HillHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


@dataclass
class HillState:
    hill_id: int
    team_id: str
    name: str
    target_host: str
    target_port: int
    service_name: str
    assigned_agent_id: str
    flag_configured: bool
    flag_hash: str
    verifier_type: str
    verifier_endpoint: str
    ownership_status: OwnershipStatus
    health_status: HillHealth
    last_verified_at: float
    updated_at: float

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return dict with zero plaintext flag leaks."""
        return {
            "hill_id": self.hill_id,
            "team_id": self.team_id,
            "name": self.name,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "service_name": self.service_name,
            "assigned_agent_id": self.assigned_agent_id,
            "flag_configured": self.flag_configured,
            "flag_hash": self.flag_hash[:12] + "..." if self.flag_hash else "",
            "verifier_type": self.verifier_type,
            "verifier_endpoint": self.verifier_endpoint,
            "ownership_status": self.ownership_status.value,
            "health_status": self.health_status.value,
            "last_verified_at": self.last_verified_at,
            "updated_at": self.updated_at,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.to_safe_dict()


class HillManager:
    """Manages the 4 competition hills, configurations, and state transitions."""

    def __init__(self, db_path: Optional[str] = None, team_manager: Optional[TeamManager] = None):
        from agent.config import config
        self.db_path = db_path or config.db_path
        self.team_mgr = team_manager or TeamManager(db_path=self.db_path)
        self.default_team_id = "null_warriors"
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Ensure hill_configs and hill_verification_log tables exist."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS hill_configs (
                    hill_id INTEGER PRIMARY KEY,
                    team_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    target_host TEXT DEFAULT '',
                    target_port INTEGER DEFAULT 0,
                    service_name TEXT DEFAULT '',
                    assigned_agent_id TEXT NOT NULL,
                    flag_hash TEXT DEFAULT '',
                    flag_token_enc TEXT DEFAULT '',
                    verifier_type TEXT DEFAULT 'SIMULATED',
                    verifier_endpoint TEXT DEFAULT '',
                    ownership_status TEXT DEFAULT 'UNVERIFIED',
                    health_status TEXT DEFAULT 'UNKNOWN',
                    last_verified_at REAL DEFAULT 0.0,
                    updated_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS hill_verification_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hill_id INTEGER NOT NULL,
                    team_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    previous_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    verifier_type TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    evidence TEXT DEFAULT ''
                )
                """
            )
            conn.commit()

    def get_hill(self, hill_id: int, session: Optional[Dict[str, Any]] = None) -> Any:
        """Fetch hill status enforcing backend RBAC if session is provided."""
        if session is not None:
            allowed, reason = self.team_mgr.check_hill_access(session, hill_id, write_access=False)
            if not allowed:
                raise PermissionError(reason)
            team_id = session.get("team_id", self.default_team_id)
        else:
            team_id = self.default_team_id

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM hill_configs WHERE hill_id = ?",
                (hill_id,),
            )
            row = cur.fetchone()
            if not row:
                now = time.time()
                cur.execute(
                    """
                    INSERT OR REPLACE INTO hill_configs 
                    (hill_id, team_id, name, assigned_agent_id, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (hill_id, team_id, f"Hill {hill_id}", HILL_AGENT_MAPPING.get(hill_id, "agent-01"), now),
                )
                conn.commit()
                cur.execute("SELECT * FROM hill_configs WHERE hill_id = ?", (hill_id,))
                row = cur.fetchone()

            state = HillState(
                hill_id=row["hill_id"],
                team_id=row["team_id"],
                name=row["name"],
                target_host=row["target_host"],
                target_port=row["target_port"],
                service_name=row["service_name"],
                assigned_agent_id=row["assigned_agent_id"],
                flag_configured=bool(row["flag_hash"]),
                flag_hash=row["flag_hash"],
                verifier_type=row["verifier_type"],
                verifier_endpoint=row["verifier_endpoint"],
                ownership_status=OwnershipStatus(row["ownership_status"]),
                health_status=HillHealth(row["health_status"]),
                last_verified_at=row["last_verified_at"],
                updated_at=row["updated_at"],
            )
            if session is not None:
                return state.to_safe_dict()
            return state

    def get_hill_state(self, hill_id: int) -> Optional[HillState]:
        res = self.get_hill(hill_id, session=None)
        return res if isinstance(res, HillState) else None

    def get_hill_view(
        self,
        hill_id: int,
        member_assigned_hill: Optional[int] = None,
        member_role: str = "TEAMMATE",
        session: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if session is None:
            session = {
                "team_id": self.default_team_id,
                "username": f"agent-0{member_assigned_hill}" if member_assigned_hill else "operator",
                "agent_id": f"agent-0{member_assigned_hill}" if member_assigned_hill else "operator",
                "role": member_role,
                "assigned_hill": member_assigned_hill if member_assigned_hill is not None else hill_id,
            }
        return self.get_hill(hill_id, session=session)

    def get_all_hills_leader_view(self, member_role: str = "LEADER") -> List[Dict[str, Any]]:
        session = {
            "team_id": self.default_team_id,
            "username": "leader",
            "agent_id": "agent-01",
            "role": "LEADER",
            "assigned_hill": 1,
        }
        return self.get_all_hills_view(session)

    def configure_hill(
        self,
        hill_id: int,
        service_name: Optional[str] = None,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        defense_endpoint: Optional[str] = None,
        configured_by: str = "operator",
        member_role: str = "TEAMMATE",
        member_assigned_hill: Optional[int] = None,
        session: Optional[Dict[str, Any]] = None,
    ) -> HillState:
        if session is None:
            session = {
                "team_id": self.default_team_id,
                "username": configured_by,
                "agent_id": configured_by,
                "role": member_role,
                "assigned_hill": member_assigned_hill if member_assigned_hill is not None else hill_id,
            }
        current = self.get_hill(hill_id, session=None)
        self.update_hill_config(
            hill_id=hill_id,
            session=session,
            target_host=target_host if target_host is not None else current.target_host,
            target_port=target_port if target_port is not None else current.target_port,
            service_name=service_name if service_name is not None else current.service_name,
            verifier_endpoint=defense_endpoint if defense_endpoint is not None else current.verifier_endpoint,
        )
        return self.get_hill_state(hill_id)

    def update_ownership_status(
        self,
        hill_id: int,
        status: OwnershipStatus,
        details: Optional[Dict[str, Any]] = None,
        team_id: Optional[str] = None,
    ) -> None:
        self.record_verification(
            hill_id=hill_id,
            team_id=team_id or self.default_team_id,
            new_status=status,
            evidence=str(details or ""),
        )

    def update_health(
        self,
        hill_id: int,
        health: HillHealth,
        latency_ms: float = 0.0,
        team_id: Optional[str] = None,
    ) -> None:
        tid = team_id or self.default_team_id
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE hill_configs SET health_status = ?, updated_at = ? WHERE hill_id = ? AND team_id = ?",
                (health.value, now, hill_id, tid),
            )
            conn.commit()

    def update_hill_config(
        self,
        hill_id: int,
        session: Dict[str, Any],
        target_host: str,
        target_port: int,
        service_name: str = "",
        verifier_type: str = "SIMULATED",
        verifier_endpoint: str = "",
    ) -> Dict[str, Any]:
        """Update hill target and verifier configuration with strict write RBAC."""
        allowed, reason = self.team_mgr.check_hill_access(session, hill_id, write_access=True)
        if not allowed:
            raise PermissionError(reason)

        team_id = session["team_id"]
        now = time.time()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE hill_configs SET
                    target_host = ?,
                    target_port = ?,
                    service_name = ?,
                    verifier_type = ?,
                    verifier_endpoint = ?,
                    updated_at = ?
                WHERE hill_id = ?
                """,
                (
                    target_host.strip(),
                    int(target_port),
                    service_name.strip(),
                    verifier_type.strip(),
                    verifier_endpoint.strip(),
                    now,
                    hill_id,
                ),
            )
            conn.commit()

        logger.info(f"[HILL] Hill {hill_id} configuration updated by {session['username']} ({session['agent_id']}).")
        return self.get_hill(hill_id, session)

    def set_hill_flag(
        self,
        hill_id: int,
        session: Optional[Dict[str, Any]] = None,
        flag_token: Optional[str] = None,
        flag_plaintext: Optional[str] = None,
        configured_by: str = "operator",
        member_role: str = "TEAMMATE",
        member_assigned_hill: Optional[int] = None,
    ) -> Any:
        """
        Configure flag token for a hill.
        Stores SHA-256 hash strictly; never logs the raw flag string.
        """
        flag = flag_token or flag_plaintext
        if isinstance(session, str):
            flag = session
            session = None

        if session is None:
            session = {
                "team_id": self.default_team_id,
                "username": configured_by,
                "agent_id": configured_by,
                "role": member_role,
                "assigned_hill": member_assigned_hill if member_assigned_hill is not None else hill_id,
            }

        allowed, reason = self.team_mgr.check_hill_access(session, hill_id, write_access=True)
        if not allowed:
            raise PermissionError(reason)

        clean_flag = (flag or "").strip()
        if not clean_flag:
            raise ValueError("Flag token cannot be empty.")

        flag_hash = hashlib.sha256(clean_flag.encode("utf-8")).hexdigest()
        now = time.time()
        team_id = session.get("team_id", self.default_team_id)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE hill_configs SET
                    flag_hash = ?,
                    ownership_status = 'SUBMITTED',
                    updated_at = ?
                WHERE hill_id = ?
                """,
                (flag_hash, now, hill_id),
            )
            conn.commit()

        logger.info(
            f"[FLAG] Flag configured for Hill {hill_id} by {session.get('username')} (hash: {flag_hash[:8]}...)."
        )
        if flag_plaintext is not None:
            return flag_hash
        return self.get_hill(hill_id, session)

    def get_all_hills_view(self, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Return the 4-hill overview:
          - Leader sees full telemetry of all 4 hills.
          - Teammate sees detailed view of assigned hill, and restricted placeholder for others.
        """
        team_id = session["team_id"]
        role = session.get("role", "")
        agent_id = session.get("agent_id", "")
        assigned_hill = session.get("assigned_hill", 0)

        is_leader = (role == "LEADER" or agent_id == "agent-01")

        results = []
        for hid in (1, 2, 3, 4):
            if is_leader or hid == assigned_hill:
                results.append(self.get_hill(hid, session))
            else:
                results.append({
                    "hill_id": hid,
                    "team_id": team_id,
                    "name": f"Hill {hid}",
                    "assigned_agent_id": HILL_AGENT_MAPPING.get(hid, ""),
                    "restricted": True,
                    "ownership_status": "RESTRICTED",
                    "health_status": "UNKNOWN",
                    "message": f"Restricted: Assigned to {HILL_AGENT_MAPPING.get(hid)}.",
                })
        return results

    def record_verification(
        self,
        hill_id: int,
        team_id: str,
        new_status: OwnershipStatus,
        health_status: Optional[HillHealth] = None,
        evidence: str = "",
        agent_id: str = "verifier",
    ) -> None:
        """Record an authoritative verifier state change."""
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT ownership_status FROM hill_configs WHERE hill_id = ?", (hill_id,))
            prev_row = cur.fetchone()
            prev_status = prev_row["ownership_status"] if prev_row else "UNVERIFIED"

            update_sql = """
                UPDATE hill_configs SET
                    ownership_status = ?,
                    last_verified_at = ?,
                    updated_at = ?
            """
            params: List[Any] = [new_status.value, now, now]

            if health_status is not None:
                update_sql += ", health_status = ?"
                params.append(health_status.value)

            update_sql += " WHERE hill_id = ?"
            params.append(hill_id)

            cur.execute(update_sql, params)
            cur.execute(
                """
                INSERT INTO hill_verification_log
                (hill_id, team_id, agent_id, timestamp, previous_status, new_status, verifier_type, verified, evidence)
                VALUES (?, ?, ?, ?, ?, ?, 'VERIFIER', ?, ?)
                """,
                (hill_id, team_id, agent_id, now, prev_status, new_status.value, 1 if new_status == OwnershipStatus.OWNED else 0, evidence),
            )
            conn.commit()

        logger.info(
            f"[VERIFY] Hill {hill_id} status updated: {prev_status} -> {new_status.value} (evidence: {evidence})."
        )
