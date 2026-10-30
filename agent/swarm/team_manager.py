"""
Team and Member Registration, Authentication, and RBAC Management.

Enforces:
  1. Team leader creates team (team_id, team_name, leader credentials).
  2. Teammates join using team_id and individual username + password.
  3. Passwords stored strictly as PBKDF2-HMAC-SHA256 hashes with random 16-byte salts.
  4. 4-Agent fixed mapping:
       Agent-01 -> Team Leader (Hill 1, All Agent Telemetry, Competition Config)
       Agent-02 -> Teammate 1 (Hill 2 only)
       Agent-03 -> Teammate 2 (Hill 3 only)
       Agent-04 -> Teammate 3 (Hill 4 only)
  5. Cryptographic session tokens with expiration and explicit revocation.
  6. Strict team and hill isolation: unauthorized cross-hill or cross-team access blocked.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from agent.logger import get_logger

logger = get_logger(__name__)

# Standard 4-agent assignment layout
AGENT_HILL_MAPPING = {
    "agent-01": 1,
    "agent-02": 2,
    "agent-03": 3,
    "agent-04": 4,
}

HILL_AGENT_MAPPING = {
    1: "agent-01",
    2: "agent-02",
    3: "agent-03",
    4: "agent-04",
}


def validate_password_strength(password: str, min_length: int = 8) -> Tuple[bool, str]:
    """Validate password against security standards."""
    if not password:
        return False, "Password cannot be empty."
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long."
    has_letter = any(c.isalpha() for c in password)
    has_digit_or_special = any(not c.isalpha() for c in password)
    if not (has_letter and has_digit_or_special):
        return False, "Password must contain letters and numbers or symbols."
    return True, ""


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256 with a unique random salt."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return hashed.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against stored PBKDF2 hash using constant-time comparison."""
    if not password or not password_hash or not salt:
        return False
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, password_hash)


class TeamManager:
    """Persistent manager for team rosters, member credentials, and sessions."""

    def __init__(self, db_path: Optional[str] = None):
        from agent.config import config
        self.db_path = db_path or config.db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize team, member, session, and hill tables with safe migration."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS teams (
                    team_id TEXT PRIMARY KEY,
                    team_name TEXT NOT NULL,
                    leader_username TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    competition_id TEXT DEFAULT '',
                    registration_status TEXT DEFAULT 'COMPLETE',
                    leader_member_id INTEGER,
                    created_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS team_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    full_name TEXT DEFAULT '',
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    assigned_hill INTEGER NOT NULL,
                    account_status TEXT DEFAULT 'ACTIVE',
                    last_login REAL DEFAULT 0.0,
                    created_at REAL NOT NULL,
                    UNIQUE(team_id, username),
                    UNIQUE(team_id, agent_id),
                    FOREIGN KEY(team_id) REFERENCES teams(team_id)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_token TEXT PRIMARY KEY,
                    team_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    assigned_hill INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER DEFAULT 0
                )
                """
            )
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
                CREATE TABLE IF NOT EXISTS login_rate_limits (
                    username TEXT PRIMARY KEY,
                    failed_attempts INTEGER DEFAULT 0,
                    last_failed_at REAL DEFAULT 0.0,
                    locked_until REAL DEFAULT 0.0
                )
                """
            )

            # Safe migration for existing schemas
            team_cols = {row["name"] for row in cur.execute("PRAGMA table_info(teams)")}
            if "description" not in team_cols:
                cur.execute("ALTER TABLE teams ADD COLUMN description TEXT DEFAULT ''")
            if "competition_id" not in team_cols:
                cur.execute("ALTER TABLE teams ADD COLUMN competition_id TEXT DEFAULT ''")
            if "registration_status" not in team_cols:
                cur.execute("ALTER TABLE teams ADD COLUMN registration_status TEXT DEFAULT 'COMPLETE'")
            if "leader_member_id" not in team_cols:
                cur.execute("ALTER TABLE teams ADD COLUMN leader_member_id INTEGER")

            member_cols = {row["name"] for row in cur.execute("PRAGMA table_info(team_members)")}
            if "full_name" not in member_cols:
                cur.execute("ALTER TABLE team_members ADD COLUMN full_name TEXT DEFAULT ''")
            if "account_status" not in member_cols:
                cur.execute("ALTER TABLE team_members ADD COLUMN account_status TEXT DEFAULT 'ACTIVE'")
            if "last_login" not in member_cols:
                cur.execute("ALTER TABLE team_members ADD COLUMN last_login REAL DEFAULT 0.0")

            # Explicitly mark legacy leader-only teams as INCOMPLETE without generating fake accounts
            cur.execute(
                """
                UPDATE teams SET registration_status = 'INCOMPLETE'
                WHERE team_id IN (
                    SELECT t.team_id FROM teams t
                    LEFT JOIN team_members m ON t.team_id = m.team_id
                    GROUP BY t.team_id
                    HAVING COUNT(m.id) < 4
                )
                """
            )
            conn.commit()

    # --------------------------------------------------------------------------
    # Rate Limiting Helpers
    # --------------------------------------------------------------------------

    def _check_rate_limit(self, cur: sqlite3.Cursor, username: str) -> None:
        """Check if username is temporarily locked out due to failed attempts."""
        cur.execute(
            "SELECT failed_attempts, locked_until FROM login_rate_limits WHERE username = ?",
            (username.strip().lower(),),
        )
        row = cur.fetchone()
        if row and row["locked_until"] > time.time():
            remaining = int(row["locked_until"] - time.time())
            raise ValueError(f"Account locked due to too many failed attempts. Try again in {remaining} seconds.")

    def _record_failed_attempt(self, cur: sqlite3.Cursor, username: str) -> None:
        """Record failed login attempt and apply lock out after 5 consecutive failures."""
        now = time.time()
        clean = username.strip().lower()
        cur.execute("SELECT failed_attempts FROM login_rate_limits WHERE username = ?", (clean,))
        row = cur.fetchone()
        if row:
            attempts = row["failed_attempts"] + 1
            locked = (now + 60.0) if attempts >= 5 else 0.0
            cur.execute(
                "UPDATE login_rate_limits SET failed_attempts = ?, last_failed_at = ?, locked_until = ? WHERE username = ?",
                (attempts, now, locked, clean),
            )
        else:
            cur.execute(
                "INSERT INTO login_rate_limits (username, failed_attempts, last_failed_at, locked_until) VALUES (?, 1, ?, 0.0)",
                (clean, now),
            )

    def _reset_rate_limit(self, cur: sqlite3.Cursor, username: str) -> None:
        """Reset failed login count on successful authentication."""
        cur.execute(
            "UPDATE login_rate_limits SET failed_attempts = 0, locked_until = 0.0 WHERE username = ?",
            (username.strip().lower(),),
        )

    # --------------------------------------------------------------------------
    # 4-Member Complete Team Registration
    # --------------------------------------------------------------------------

    def register_four_member_team(self, team_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Atomically register a complete 4-member team in a single database transaction.
        Collects:
          - Team Information (team_name, optional description, optional competition_id)
          - Section B: Team Leader (Agent 01, Hill 1)
          - Section C: Teammate 1 (Agent 02, Hill 2)
          - Section D: Teammate 2 (Agent 03, Hill 3)
          - Section E: Teammate 3 (Agent 04, Hill 4)
        Enforces:
          - All 4 members are mandatory.
          - Password confirmation and password strength.
          - Username uniqueness across the submission and existing DB.
          - Transactional rollback on any validation or constraint error.
        """
        if not isinstance(team_data, dict):
            raise ValueError("Invalid registration payload: expected dictionary.")

        team_name = str(team_data.get("team_name") or team_data.get("name") or "").strip()
        description = str(team_data.get("description") or "").strip()
        competition_id = str(team_data.get("competition_id") or "").strip()

        if not team_name:
            raise ValueError("Team name is mandatory.")
        if len(team_name) < 3 or len(team_name) > 50:
            raise ValueError("Team name must be between 3 and 50 characters.")

        raw_team_id = team_data.get("team_id")
        if raw_team_id:
            team_id = str(raw_team_id).strip().lower()
        else:
            team_id = re.sub(r"[^a-z0-9_-]", "_", team_name.lower())

        if not team_id or len(team_id) < 3:
            raise ValueError("Team identifier could not be determined.")

        # Extract all 4 member slots
        leader = team_data.get("leader") or team_data.get("team_leader")
        tm1 = team_data.get("teammate_1") or team_data.get("teammate1")
        tm2 = team_data.get("teammate_2") or team_data.get("teammate2")
        tm3 = team_data.get("teammate_3") or team_data.get("teammate3")

        # Support array inputs
        if not leader and "members" in team_data and isinstance(team_data["members"], list) and len(team_data["members"]) == 4:
            leader, tm1, tm2, tm3 = team_data["members"]
        elif not tm1 and "teammates" in team_data and isinstance(team_data["teammates"], list) and len(team_data["teammates"]) == 3:
            tm1, tm2, tm3 = team_data["teammates"]

        if not leader or not tm1 or not tm2 or not tm3:
            raise ValueError("All four team members (Team Leader and 3 Teammates) are mandatory.")

        slots = [
            ("Team Leader", "LEADER", "agent-01", 1, leader),
            ("Teammate 1", "MEMBER", "agent-02", 2, tm1),
            ("Teammate 2", "MEMBER", "agent-03", 3, tm2),
            ("Teammate 3", "MEMBER", "agent-04", 4, tm3),
        ]

        cleaned_members = []
        usernames_seen = set()

        for label, role, agent_id, hill_id, spec in slots:
            if not isinstance(spec, dict):
                raise ValueError(f"Missing required details for {label}.")

            full_name = str(spec.get("full_name") or spec.get("name") or "").strip()
            username = str(spec.get("username") or "").strip()
            password = str(spec.get("password") or "")
            confirm = str(spec.get("confirm_password") or spec.get("confirmPassword") or "")

            if not full_name or len(full_name) < 2:
                raise ValueError(f"Full name is required for {label} (minimum 2 characters).")
            if not username or len(username) < 3 or len(username) > 30:
                raise ValueError(f"Username for {label} must be between 3 and 30 characters.")
            if not re.match(r"^[A-Za-z0-9_-]+$", username):
                raise ValueError(f"Username for {label} may only contain letters, numbers, underscores, and hyphens.")

            u_norm = username.lower()
            if u_norm in usernames_seen:
                raise ValueError(f"Duplicate username '{username}' within team registration.")
            usernames_seen.add(u_norm)

            if not password:
                raise ValueError(f"Password is required for {label}.")
            if password != confirm:
                raise ValueError(f"Password confirmation does not match for {label}.")

            ok, err = validate_password_strength(password, min_length=6)
            if not ok:
                raise ValueError(f"Password for {label} does not meet strength requirements: {err}")

            pwd_hash, salt = hash_password(password)

            cleaned_members.append({
                "label": label,
                "role": role,
                "agent_id": agent_id,
                "assigned_hill": hill_id,
                "full_name": full_name,
                "username": username,
                "password_hash": pwd_hash,
                "salt": salt,
            })

        now = time.time()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                # 1. Uniqueness check for team
                cur.execute("SELECT team_id FROM teams WHERE team_id = ?", (team_id,))
                if cur.fetchone():
                    raise ValueError(f"Team ID '{team_id}' already exists.")

                cur.execute("SELECT team_name FROM teams WHERE LOWER(team_name) = LOWER(?)", (team_name,))
                if cur.fetchone():
                    raise ValueError(f"Team name '{team_name}' already exists.")

                # 2. Uniqueness check for usernames across existing members
                placeholders = ",".join("?" for _ in usernames_seen)
                cur.execute(
                    f"SELECT username FROM team_members WHERE LOWER(username) IN ({placeholders})",
                    list(usernames_seen),
                )
                existing = cur.fetchone()
                if existing:
                    raise ValueError(f"Username '{existing['username']}' is already registered.")

                # 3. Insert team record
                leader_username = cleaned_members[0]["username"]
                cur.execute(
                    """
                    INSERT INTO teams
                    (team_id, team_name, leader_username, description, competition_id, registration_status, created_at)
                    VALUES (?, ?, ?, ?, ?, 'COMPLETE', ?)
                    """,
                    (team_id, team_name, leader_username, description, competition_id, now),
                )

                # 4. Insert all 4 member records
                leader_member_id = None
                members_summary = []
                for m in cleaned_members:
                    cur.execute(
                        """
                        INSERT INTO team_members
                        (team_id, username, full_name, password_hash, salt, role, agent_id, assigned_hill, account_status, last_login, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0.0, ?)
                        """,
                        (team_id, m["username"], m["full_name"], m["password_hash"], m["salt"], m["role"], m["agent_id"], m["assigned_hill"], now),
                    )
                    mid = cur.lastrowid
                    if m["agent_id"] == "agent-01":
                        leader_member_id = mid

                    members_summary.append({
                        "id": mid,
                        "full_name": m["full_name"],
                        "username": m["username"],
                        "role": m["role"],
                        "agent_id": m["agent_id"],
                        "assigned_hill": m["assigned_hill"],
                        "hill_id": m["assigned_hill"],
                        "account_status": "ACTIVE",
                        "created_at": now,
                    })

                cur.execute(
                    "UPDATE teams SET leader_member_id = ? WHERE team_id = ?",
                    (leader_member_id, team_id),
                )

                # 5. Initialize 4 hill configurations
                for hill_id in (1, 2, 3, 4):
                    cur.execute(
                        """
                        INSERT OR REPLACE INTO hill_configs
                        (hill_id, team_id, name, target_host, target_port, service_name, assigned_agent_id,
                         flag_hash, verifier_type, verifier_endpoint, ownership_status, health_status, updated_at)
                        VALUES (?, ?, ?, '', 0, '', ?, '', 'SIMULATED', '', 'UNVERIFIED', 'UNKNOWN', ?)
                        """,
                        (hill_id, team_id, f"Hill {hill_id}", HILL_AGENT_MAPPING[hill_id], now),
                    )

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        # Generate active session for the leader
        session = self.create_session(
            team_id=team_id,
            username=leader_username,
            agent_id="agent-01",
            role="LEADER",
            assigned_hill=1,
        )

        logger.info(f"[TEAM] Complete 4-member team '{team_id}' registered successfully.")
        return {
            "success": True,
            "team_id": team_id,
            "team_name": team_name,
            "description": description,
            "competition_id": competition_id,
            "registration_status": "COMPLETE",
            "leader": members_summary[0],
            "members": members_summary,
            "session_token": session["session_token"],
            "agent_id": "agent-01",
            "role": "LEADER",
            "assigned_hill": 1,
            "hill_id": 1,
        }

    # --------------------------------------------------------------------------
    # Incomplete Registration Completion Workflow
    # --------------------------------------------------------------------------

    def complete_team_registration(
        self,
        team_id: str,
        leader_session_token: str,
        teammates: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Complete registration for an incomplete team by onboarding the remaining teammates."""
        session = self.validate_session(leader_session_token)
        if not session:
            raise PermissionError("Authentication required: invalid or expired session.")
        if session.get("team_id") != team_id.strip().lower() or session.get("role") != "LEADER":
            raise PermissionError("Access denied: only the Team Leader can complete team registration.")

        clean_team = team_id.strip().lower()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT registration_status FROM teams WHERE team_id = ?", (clean_team,))
            t_row = cur.fetchone()
            if not t_row:
                raise ValueError(f"Team '{clean_team}' does not exist.")
            if t_row["registration_status"] == "COMPLETE":
                raise ValueError(f"Team '{clean_team}' is already completely registered.")

            cur.execute("SELECT agent_id FROM team_members WHERE team_id = ? ORDER BY agent_id ASC", (clean_team,))
            existing_agents = {r["agent_id"] for r in cur.fetchall()}
            needed_agents = [aid for aid in ("agent-02", "agent-03", "agent-04") if aid not in existing_agents]

            if len(teammates) != len(needed_agents):
                raise ValueError(f"Expected {len(needed_agents)} teammates to complete registration, received {len(teammates)}.")

            now = time.time()
            cur.execute("BEGIN IMMEDIATE")
            try:
                for idx, aid in enumerate(needed_agents):
                    tm = teammates[idx]
                    full_name = str(tm.get("full_name") or tm.get("name") or "").strip()
                    username = str(tm.get("username") or "").strip()
                    password = str(tm.get("password") or "")
                    confirm = str(tm.get("confirm_password") or tm.get("confirmPassword") or "")

                    if not full_name or len(full_name) < 2:
                        raise ValueError(f"Full name is required for teammate {idx+1}.")
                    if not username or len(username) < 3 or len(username) > 30:
                        raise ValueError(f"Username for teammate {idx+1} must be between 3 and 30 characters.")
                    if password != confirm:
                        raise ValueError(f"Password confirmation does not match for teammate {idx+1}.")

                    ok, err = validate_password_strength(password, min_length=6)
                    if not ok:
                        raise ValueError(f"Password for teammate {idx+1} is too weak: {err}")

                    cur.execute("SELECT username FROM team_members WHERE LOWER(username) = LOWER(?)", (username,))
                    if cur.fetchone():
                        raise ValueError(f"Username '{username}' is already registered.")

                    pwd_hash, salt = hash_password(password)
                    hill_id = AGENT_HILL_MAPPING[aid]
                    cur.execute(
                        """
                        INSERT INTO team_members
                        (team_id, username, full_name, password_hash, salt, role, agent_id, assigned_hill, account_status, last_login, created_at)
                        VALUES (?, ?, ?, ?, ?, 'MEMBER', ?, ?, 'ACTIVE', 0.0, ?)
                        """,
                        (clean_team, username, full_name, pwd_hash, salt, aid, hill_id, now),
                    )

                cur.execute("SELECT COUNT(*) as cnt FROM team_members WHERE team_id = ?", (clean_team,))
                if cur.fetchone()["cnt"] == 4:
                    cur.execute("UPDATE teams SET registration_status = 'COMPLETE' WHERE team_id = ?", (clean_team,))

                conn.commit()
            except Exception:
                conn.rollback()
                raise

        return {
            "success": True,
            "team_id": clean_team,
            "registration_status": "COMPLETE",
            "members": self.get_team_members(clean_team),
        }

    # --------------------------------------------------------------------------
    # Team Management View (Leader Only)
    # --------------------------------------------------------------------------

    def get_team_management_view(self, team_id: str, caller_agent_id: str) -> Dict[str, Any]:
        """Leader-only team management view showing leader and 3 teammates details."""
        if caller_agent_id != "agent-01":
            raise PermissionError("Access denied: Team management view is restricted to the Team Leader (Agent 01).")

        clean_team = team_id.strip().lower()
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM teams WHERE team_id = ?", (clean_team,))
            t_row = cur.fetchone()
            if not t_row:
                raise ValueError(f"Team '{clean_team}' does not exist.")

            team_dict = dict(t_row)

            cur.execute(
                """
                SELECT id, team_id, username, full_name, role, agent_id, assigned_hill, account_status, last_login, created_at
                FROM team_members WHERE team_id = ? ORDER BY assigned_hill ASC
                """,
                (clean_team,),
            )
            members = [dict(r) for r in cur.fetchall()]
            for m in members:
                m["hill_id"] = m["assigned_hill"]

            leader = next((m for m in members if m["agent_id"] == "agent-01"), None)
            teammates = [m for m in members if m["agent_id"] != "agent-01"]

            return {
                "team_id": clean_team,
                "team_name": team_dict.get("team_name"),
                "description": team_dict.get("description", ""),
                "competition_id": team_dict.get("competition_id", ""),
                "registration_status": team_dict.get("registration_status", "COMPLETE"),
                "created_at": team_dict.get("created_at"),
                "leader": leader,
                "teammates": teammates,
                "members": members,
            }

    # --------------------------------------------------------------------------
    # Legacy / Test Compatibility Methods
    # --------------------------------------------------------------------------

    def create_team(
        self,
        team_id: str,
        team_name: str,
        leader_username: str,
        leader_password: str,
        full_name: str = "",
        description: str = "",
        competition_id: str = "",
        teammates: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create team; if teammates provided, performs complete 4-member registration."""
        if teammates and len(teammates) == 3:
            return self.register_four_member_team({
                "team_id": team_id,
                "team_name": team_name,
                "description": description,
                "competition_id": competition_id,
                "leader": {
                    "full_name": full_name or leader_username,
                    "username": leader_username,
                    "password": leader_password,
                    "confirm_password": leader_password,
                },
                "teammate_1": teammates[0],
                "teammate_2": teammates[1],
                "teammate_3": teammates[2],
            })

        clean_team_id = team_id.strip().lower()
        clean_team_name = team_name.strip()
        clean_username = leader_username.strip()

        if not clean_team_id or not clean_team_name or not clean_username:
            raise ValueError("team_id, team_name, and leader_username cannot be empty.")
        if len(leader_password) < 6:
            raise ValueError("Password must be at least 6 characters.")

        pwd_hash, salt = hash_password(leader_password)
        now = time.time()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT team_id FROM teams WHERE team_id = ?", (clean_team_id,))
            if cur.fetchone():
                raise ValueError(f"Team '{clean_team_id}' already exists.")

            # Create team record marked as INCOMPLETE pending teammates onboarding
            cur.execute(
                """
                INSERT INTO teams 
                (team_id, team_name, leader_username, description, competition_id, registration_status, created_at) 
                VALUES (?, ?, ?, ?, ?, 'INCOMPLETE', ?)
                """,
                (clean_team_id, clean_team_name, clean_username, description, competition_id, now),
            )

            # Register Leader as agent-01, Hill 1
            cur.execute(
                """
                INSERT INTO team_members 
                (team_id, username, full_name, password_hash, salt, role, agent_id, assigned_hill, account_status, last_login, created_at)
                VALUES (?, ?, ?, ?, ?, 'LEADER', 'agent-01', 1, 'ACTIVE', 0.0, ?)
                """,
                (clean_team_id, clean_username, full_name or clean_username, pwd_hash, salt, now),
            )
            leader_mid = cur.lastrowid
            cur.execute("UPDATE teams SET leader_member_id = ? WHERE team_id = ?", (leader_mid, clean_team_id))

            for hill_id in (1, 2, 3, 4):
                cur.execute(
                    """
                    INSERT OR REPLACE INTO hill_configs
                    (hill_id, team_id, name, target_host, target_port, service_name, assigned_agent_id,
                     flag_hash, verifier_type, verifier_endpoint, ownership_status, health_status, updated_at)
                    VALUES (?, ?, ?, '', 0, '', ?, '', 'SIMULATED', '', 'UNVERIFIED', 'UNKNOWN', ?)
                    """,
                    (hill_id, clean_team_id, f"Hill {hill_id}", HILL_AGENT_MAPPING[hill_id], now),
                )

            conn.commit()

        session = self.create_session(
            team_id=clean_team_id,
            username=clean_username,
            agent_id="agent-01",
            role="LEADER",
            assigned_hill=1,
        )

        logger.info(f"[TEAM] Team '{clean_team_id}' created by leader '{clean_username}' (agent-01).")
        return {
            "success": True,
            "team_id": clean_team_id,
            "team_name": clean_team_name,
            "username": clean_username,
            "leader_username": clean_username,
            "agent_id": "agent-01",
            "role": "LEADER",
            "assigned_hill": 1,
            "hill_id": 1,
            "session_token": session["session_token"],
        }

    def join_team(
        self,
        team_id: str,
        username: str,
        password: str,
    ) -> Dict[str, Any]:
        """Join an existing team as the next available teammate (agent-02..agent-04)."""
        clean_team_id = team_id.strip().lower()
        clean_username = username.strip()

        if not clean_team_id or not clean_username:
            raise ValueError("team_id and username cannot be empty.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters.")

        with self._get_connection() as conn:
            cur = conn.cursor()
            # Verify team exists
            cur.execute("SELECT team_name FROM teams WHERE team_id = ?", (clean_team_id,))
            team_row = cur.fetchone()
            if not team_row:
                raise ValueError(f"Team '{clean_team_id}' does not exist.")

            # Check if username already exists in this team
            cur.execute(
                "SELECT username FROM team_members WHERE team_id = ? AND username = ?",
                (clean_team_id, clean_username),
            )
            if cur.fetchone():
                raise ValueError(f"Username '{clean_username}' is already registered in team '{clean_team_id}'.")

            # Check existing members count & assign next agent
            cur.execute(
                "SELECT agent_id FROM team_members WHERE team_id = ? ORDER BY agent_id ASC",
                (clean_team_id,),
            )
            existing_agents = {r["agent_id"] for r in cur.fetchall()}

            available_agents = [aid for aid in ("agent-02", "agent-03", "agent-04") if aid not in existing_agents]
            if not available_agents:
                raise ValueError(f"Team '{clean_team_id}' is full (maximum 4 agents registered).")

            assigned_agent = available_agents[0]
            assigned_hill = AGENT_HILL_MAPPING[assigned_agent]
            now = time.time()
            pwd_hash, salt = hash_password(password)

            cur.execute(
                """
                INSERT INTO team_members
                (team_id, username, password_hash, salt, role, agent_id, assigned_hill, created_at)
                VALUES (?, ?, ?, ?, 'TEAMMATE', ?, ?, ?)
                """,
                (clean_team_id, clean_username, pwd_hash, salt, assigned_agent, assigned_hill, now),
            )
            conn.commit()

        session = self.create_session(
            team_id=clean_team_id,
            username=clean_username,
            agent_id=assigned_agent,
            role="TEAMMATE",
            assigned_hill=assigned_hill,
        )

        logger.info(
            f"[TEAM] Member '{clean_username}' joined team '{clean_team_id}' -> assigned {assigned_agent} (Hill {assigned_hill})."
        )
        return {
            "success": True,
            "team_id": clean_team_id,
            "username": clean_username,
            "agent_id": assigned_agent,
            "role": "TEAMMATE",
            "assigned_hill": assigned_hill,
            "hill_id": assigned_hill,
            "session_token": session["session_token"],
        }

    # --------------------------------------------------------------------------
    # Authentication & Session Management
    # --------------------------------------------------------------------------

    def login(
        self,
        username: str,
        password: str,
        team_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Authenticate user with rate limiting and return a cryptographically secure session token."""
        clean_user = username.strip()
        clean_team = team_id.strip().lower() if team_id else None

        with self._get_connection() as conn:
            cur = conn.cursor()
            # 1. Enforce rate limiting lockout before credential checks
            self._check_rate_limit(cur, clean_user)

            if clean_team:
                cur.execute(
                    """
                    SELECT id, team_id, username, full_name, password_hash, salt, role, agent_id, assigned_hill, account_status
                    FROM team_members WHERE team_id = ? AND LOWER(username) = LOWER(?)
                    """,
                    (clean_team, clean_user),
                )
            else:
                cur.execute(
                    """
                    SELECT id, team_id, username, full_name, password_hash, salt, role, agent_id, assigned_hill, account_status
                    FROM team_members WHERE LOWER(username) = LOWER(?)
                    """,
                    (clean_user,),
                )

            rows = cur.fetchall()
            if not rows:
                self._record_failed_attempt(cur, clean_user)
                conn.commit()
                return None

            matched = None
            for row in rows:
                if verify_password(password, row["password_hash"], row["salt"]):
                    matched = row
                    break

            if not matched:
                self._record_failed_attempt(cur, clean_user)
                conn.commit()
                return None

            # Reset rate limit and record successful login
            self._reset_rate_limit(cur, clean_user)
            now = time.time()
            cur.execute("UPDATE team_members SET last_login = ? WHERE id = ?", (now, matched["id"]))

            # Retrieve team details
            cur.execute("SELECT team_name, registration_status FROM teams WHERE team_id = ?", (matched["team_id"],))
            t_row = cur.fetchone()
            team_name = t_row["team_name"] if t_row else matched["team_id"]
            reg_status = t_row["registration_status"] if t_row else "COMPLETE"
            conn.commit()

        session = self.create_session(
            team_id=matched["team_id"],
            username=matched["username"],
            agent_id=matched["agent_id"],
            role=matched["role"],
            assigned_hill=matched["assigned_hill"],
        )

        logger.info(f"[AUTH] User '{matched['username']}' logged in successfully ({matched['agent_id']}).")
        return {
            "success": True,
            "team_id": matched["team_id"],
            "team_name": team_name,
            "registration_status": reg_status,
            "username": matched["username"],
            "full_name": dict(matched).get("full_name", ""),
            "agent_id": matched["agent_id"],
            "role": matched["role"],
            "assigned_hill": matched["assigned_hill"],
            "hill_id": matched["assigned_hill"],
            "session_token": session["session_token"],
            "expires_at": session["expires_at"],
        }

    def create_session(
        self,
        team_id: str,
        username: str,
        agent_id: str,
        role: str,
        assigned_hill: int,
        ttl_seconds: float = 86400.0,
    ) -> Dict[str, Any]:
        """Issue a new session token stored in SQLite."""
        token = secrets.token_hex(32)
        now = time.time()
        expires_at = now + ttl_seconds

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO auth_sessions
                (session_token, team_id, username, agent_id, role, assigned_hill, created_at, last_seen, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (token, team_id, username, agent_id, role, assigned_hill, now, now, expires_at),
            )
            conn.commit()

        return {
            "session_token": token,
            "team_id": team_id,
            "username": username,
            "agent_id": agent_id,
            "role": role,
            "assigned_hill": assigned_hill,
            "created_at": now,
            "expires_at": expires_at,
        }

    def validate_session(self, session_token: Optional[str]) -> Optional[Dict[str, Any]]:
        """Validate session token, check expiry and revocation, and touch last_seen."""
        if not session_token:
            return None

        clean_token = session_token.strip()
        now = time.time()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT session_token, team_id, username, agent_id, role, assigned_hill, created_at, expires_at, revoked
                FROM auth_sessions WHERE session_token = ?
                """,
                (clean_token,),
            )
            row = cur.fetchone()
            if not row:
                return None

            if row["revoked"] or row["expires_at"] <= now:
                return None

            # Touch last seen
            cur.execute("UPDATE auth_sessions SET last_seen = ? WHERE session_token = ?", (now, clean_token))
            conn.commit()

            return {
                "session_token": row["session_token"],
                "team_id": row["team_id"],
                "username": row["username"],
                "agent_id": row["agent_id"],
                "role": row["role"],
                "assigned_hill": row["assigned_hill"],
                "hill_id": row["assigned_hill"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
            }

    verify_session = validate_session

    def revoke_session(self, session_token: str) -> bool:
        """Revoke an active session token."""
        if not session_token:
            return False
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE auth_sessions SET revoked = 1 WHERE session_token = ?", (session_token.strip(),))
            conn.commit()
            return cur.rowcount > 0

    # --------------------------------------------------------------------------
    # Roster & Permissions
    # --------------------------------------------------------------------------

    def get_team_members(self, team_id: str) -> List[Dict[str, Any]]:
        """List team members without exposing password hashes or salts."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT team_id, username, role, agent_id, assigned_hill, created_at
                FROM team_members WHERE team_id = ? ORDER BY assigned_hill ASC
                """,
                (team_id.strip().lower(),),
            )
            rows = cur.fetchall()
            members = []
            for r in rows:
                d = dict(r)
                d["hill_id"] = d.get("assigned_hill")
                members.append(d)
            return members

    list_team_members = get_team_members

    def check_hill_access(
        self,
        session: Dict[str, Any],
        hill_id: int,
        write_access: bool = False,
    ) -> Tuple[bool, str]:
        """
        Enforce backend RBAC for hill portals:
          - Leader (agent-01) has full access to Hill 1 and read-only monitoring of Hills 2, 3, 4.
          - Teammates (agent-02..04) have exclusive access ONLY to their own assigned hill.
          - Access to another teammate's hill returns (False, reason).
        """
        role = session.get("role", "")
        agent_id = session.get("agent_id", "")
        assigned_hill = session.get("assigned_hill", 0)

        # Leader privileges
        if role == "LEADER" or agent_id == "agent-01":
            if write_access and hill_id != 1:
                return False, f"Team Leader (agent-01) can only configure Hill 1; Hill {hill_id} is assigned to {HILL_AGENT_MAPPING.get(hill_id)}."
            return True, "Authorized (Leader)"

        # Teammate privileges
        if hill_id != assigned_hill:
            return False, f"Access denied: {agent_id} is assigned strictly to Hill {assigned_hill}, not Hill {hill_id}."

        return True, f"Authorized ({agent_id} on Hill {assigned_hill})"
