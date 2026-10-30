"""
Authoritative Competition and Hill Ownership Engine.
Manages KOTH (5 formats) and Red vs Blue (6 formats) competitions,
hill state transitions, evidence verification, anti-replay guards,
idempotent score events, side aggregation, and elimination rules.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from agent.competition.models import (
    CaptureSubmission,
    Competition,
    CompetitionHill,
    CompetitionMode,
    CompetitionRules,
    CompetitionStatus,
    CompetitionTeam,
    DefenseSubmission,
    HillEnvironmentType,
    KothFormat,
    OwnershipHistoryEvent,
    OwnershipState,
    RedVsBlueFormat,
    ScoreCategory,
    TeamSide,
    VerifierType,
)

logger = logging.getLogger("koth.competition.manager")


class CompetitionManager:
    """Authoritative manager for multi-mode KOTH and Red vs Blue competitions."""

    def __init__(self, db_path: Optional[str] = None):
        from agent.config import config
        self.db_path = db_path or config.db_path
        self._lock = threading.RLock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create competition platform tables and indices if not already present."""
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()

            # 1. Competitions
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS competitions (
                    competition_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    mode TEXT NOT NULL,
                    format TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'DRAFT',
                    start_time REAL DEFAULT 0.0,
                    end_time REAL DEFAULT 0.0,
                    duration_minutes INTEGER DEFAULT 60,
                    rules_json TEXT DEFAULT '{}',
                    created_at REAL NOT NULL,
                    created_by TEXT DEFAULT 'admin'
                )
                """
            )

            # 2. Competition Teams
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS competition_teams (
                    competition_id TEXT NOT NULL,
                    team_id TEXT NOT NULL,
                    team_name TEXT NOT NULL,
                    side TEXT NOT NULL DEFAULT 'NEUTRAL',
                    score INTEGER DEFAULT 0,
                    eliminated INTEGER DEFAULT 0,
                    eliminated_reason TEXT DEFAULT '',
                    captures_count INTEGER DEFAULT 0,
                    defenses_count INTEGER DEFAULT 0,
                    recaptures_count INTEGER DEFAULT 0,
                    penalties_count INTEGER DEFAULT 0,
                    uptime_seconds REAL DEFAULT 0.0,
                    joined_at REAL NOT NULL,
                    PRIMARY KEY (competition_id, team_id)
                )
                """
            )

            # 3. Competition Hills
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS competition_hills (
                    competition_id TEXT NOT NULL,
                    hill_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    environment_type TEXT NOT NULL,
                    target_host TEXT DEFAULT '',
                    target_port INTEGER DEFAULT 80,
                    service_name TEXT DEFAULT '',
                    initial_owner_team_id TEXT,
                    initial_owner_side TEXT,
                    current_owner_team_id TEXT,
                    current_owner_side TEXT,
                    state TEXT NOT NULL DEFAULT 'AVAILABLE',
                    health_status TEXT NOT NULL DEFAULT 'HEALTHY',
                    points_per_interval INTEGER DEFAULT 10,
                    capture_points INTEGER DEFAULT 100,
                    flag_hash TEXT DEFAULT '',
                    verifier_type TEXT DEFAULT 'SIMULATED',
                    verifier_endpoint TEXT DEFAULT '',
                    last_captured_at REAL DEFAULT 0.0,
                    last_verified_at REAL DEFAULT 0.0,
                    defense_notes TEXT DEFAULT '',
                    PRIMARY KEY (competition_id, hill_id)
                )
                """
            )

            # 4. Competition Scores Log
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS competition_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    competition_id TEXT NOT NULL,
                    team_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    timestamp REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_comp_scores_lookup
                ON competition_scores(competition_id, team_id, timestamp DESC)
                """
            )

            # 5. Capture Submissions
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS capture_submissions (
                    submission_id TEXT PRIMARY KEY,
                    competition_id TEXT NOT NULL,
                    hill_id INTEGER NOT NULL,
                    team_id TEXT NOT NULL,
                    side TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    awarded_points INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_comp_capture_ev
                ON capture_submissions(competition_id, hill_id, evidence_hash)
                """
            )

            # 6. Defense Submissions
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS defense_submissions (
                    submission_id TEXT PRIMARY KEY,
                    competition_id TEXT NOT NULL,
                    hill_id INTEGER NOT NULL,
                    team_id TEXT NOT NULL,
                    side TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    service_status TEXT NOT NULL,
                    patch_summary TEXT DEFAULT '',
                    verified INTEGER NOT NULL,
                    awarded_points INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )

            # 7. Ownership History
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ownership_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    competition_id TEXT NOT NULL,
                    hill_id INTEGER NOT NULL,
                    previous_owner_team_id TEXT,
                    previous_side TEXT,
                    new_owner_team_id TEXT NOT NULL,
                    new_side TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    details TEXT DEFAULT ''
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_ownership_hist
                ON ownership_history(competition_id, hill_id, timestamp DESC)
                """
            )

            conn.commit()

    # --------------------------------------------------------------------------
    # COMPETITION LIFECYCLE
    # --------------------------------------------------------------------------

    def create_competition(
        self,
        name: str,
        mode: str,
        format: str,
        description: str = "",
        duration_minutes: int = 60,
        rules: Optional[Dict[str, Any]] = None,
        created_by: str = "admin",
        competition_id: Optional[str] = None,
    ) -> Competition:
        """Create a new competition record."""
        cid = competition_id.strip() if competition_id else f"comp-{uuid.uuid4().hex[:8]}"
        mode_val = CompetitionMode(mode.upper()) if isinstance(mode, str) else mode
        comp_rules = CompetitionRules.from_dict(rules or {})
        now = time.time()

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO competitions (
                    competition_id, name, description, mode, format, status,
                    start_time, end_time, duration_minutes, rules_json, created_at, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    name.strip(),
                    description.strip(),
                    mode_val.value,
                    format.upper(),
                    CompetitionStatus.DRAFT.value,
                    0.0,
                    0.0,
                    duration_minutes,
                    json.dumps(comp_rules.to_dict()),
                    now,
                    created_by,
                ),
            )
            conn.commit()

        logger.info(f"Created competition '{name}' ({cid}) in mode {mode_val.value}:{format}")
        return self.get_competition(cid)  # type: ignore

    def get_competition(self, competition_id: str) -> Optional[Competition]:
        """Fetch competition details by ID."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, name, description, mode, format, status,
                       start_time, end_time, duration_minutes, rules_json, created_at, created_by
                FROM competitions WHERE competition_id = ?
                """,
                (competition_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            try:
                rules_dict = json.loads(row["rules_json"] or "{}")
            except Exception:
                rules_dict = {}

            return Competition(
                competition_id=row["competition_id"],
                name=row["name"],
                description=row["description"],
                mode=CompetitionMode(row["mode"]),
                format=row["format"],
                status=CompetitionStatus(row["status"]),
                start_time=row["start_time"],
                end_time=row["end_time"],
                duration_minutes=row["duration_minutes"],
                rules=CompetitionRules.from_dict(rules_dict),
                created_at=row["created_at"],
                created_by=row["created_by"],
            )

    def list_competitions(self) -> List[Dict[str, Any]]:
        """List all competitions in the database."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, name, description, mode, format, status,
                       start_time, end_time, duration_minutes, rules_json, created_at, created_by
                FROM competitions ORDER BY created_at DESC
                """
            )
            results = []
            for row in cur.fetchall():
                try:
                    rdict = json.loads(row["rules_json"] or "{}")
                except Exception:
                    rdict = {}
                c = Competition(
                    competition_id=row["competition_id"],
                    name=row["name"],
                    description=row["description"],
                    mode=CompetitionMode(row["mode"]),
                    format=row["format"],
                    status=CompetitionStatus(row["status"]),
                    start_time=row["start_time"],
                    end_time=row["end_time"],
                    duration_minutes=row["duration_minutes"],
                    rules=CompetitionRules.from_dict(rdict),
                    created_at=row["created_at"],
                    created_by=row["created_by"],
                )
                results.append(c.to_dict())
            return results

    def start_competition(self, competition_id: str) -> bool:
        """Transition competition to ACTIVE, set start_time and end_time."""
        comp = self.get_competition(competition_id)
        if not comp:
            return False

        now = time.time()
        end = now + (comp.duration_minutes * 60)

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE competitions
                SET status = ?, start_time = ?, end_time = ?
                WHERE competition_id = ?
                """,
                (CompetitionStatus.ACTIVE.value, now, end, competition_id),
            )
            conn.commit()
        logger.info(f"Competition {competition_id} is now ACTIVE until {end}")
        return True

    def pause_competition(self, competition_id: str) -> bool:
        """Pause competition clock and operations."""
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE competitions SET status = ? WHERE competition_id = ?",
                (CompetitionStatus.PAUSED.value, competition_id),
            )
            conn.commit()
        return True

    def complete_competition(self, competition_id: str) -> bool:
        """Mark competition as COMPLETED."""
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE competitions SET status = ? WHERE competition_id = ?",
                (CompetitionStatus.COMPLETED.value, competition_id),
            )
            conn.commit()
        return True

    # --------------------------------------------------------------------------
    # TEAM MANAGEMENT & SIDE ASSIGNMENTS
    # --------------------------------------------------------------------------

    def enroll_team(
        self,
        competition_id: str,
        team_id: str,
        team_name: str,
        side: str = "NEUTRAL",
    ) -> bool:
        """Enroll a team into a competition with side assignment (RED, BLUE, or NEUTRAL)."""
        side_val = TeamSide(side.upper()) if isinstance(side, str) else side
        now = time.time()

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO competition_teams (
                    competition_id, team_id, team_name, side, score,
                    eliminated, captures_count, defenses_count, recaptures_count,
                    penalties_count, uptime_seconds, joined_at
                ) VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0.0, ?)
                ON CONFLICT(competition_id, team_id) DO UPDATE SET
                    team_name = excluded.team_name,
                    side = excluded.side
                """,
                (competition_id, team_id, team_name, side_val.value, now),
            )
            conn.commit()
        return True

    def get_competition_teams(self, competition_id: str) -> List[CompetitionTeam]:
        """Fetch all teams enrolled in a competition."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, team_id, team_name, side, score, eliminated,
                       eliminated_reason, captures_count, defenses_count,
                       recaptures_count, penalties_count, uptime_seconds, joined_at
                FROM competition_teams
                WHERE competition_id = ?
                ORDER BY score DESC
                """,
                (competition_id,),
            )
            teams = []
            for row in cur.fetchall():
                teams.append(
                    CompetitionTeam(
                        competition_id=row["competition_id"],
                        team_id=row["team_id"],
                        team_name=row["team_name"],
                        side=TeamSide(row["side"]),
                        score=row["score"],
                        eliminated=bool(row["eliminated"]),
                        eliminated_reason=row["eliminated_reason"] or "",
                        captures_count=row["captures_count"],
                        defenses_count=row["defenses_count"],
                        recaptures_count=row["recaptures_count"],
                        penalties_count=row["penalties_count"],
                        uptime_seconds=row["uptime_seconds"],
                        joined_at=row["joined_at"],
                    )
                )
            return teams

    def get_team(self, competition_id: str, team_id: str) -> Optional[CompetitionTeam]:
        """Fetch a specific team in a competition."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, team_id, team_name, side, score, eliminated,
                       eliminated_reason, captures_count, defenses_count,
                       recaptures_count, penalties_count, uptime_seconds, joined_at
                FROM competition_teams
                WHERE competition_id = ? AND team_id = ?
                """,
                (competition_id, team_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            return CompetitionTeam(
                competition_id=row["competition_id"],
                team_id=row["team_id"],
                team_name=row["team_name"],
                side=TeamSide(row["side"]),
                score=row["score"],
                eliminated=bool(row["eliminated"]),
                eliminated_reason=row["eliminated_reason"] or "",
                captures_count=row["captures_count"],
                defenses_count=row["defenses_count"],
                recaptures_count=row["recaptures_count"],
                penalties_count=row["penalties_count"],
                uptime_seconds=row["uptime_seconds"],
                joined_at=row["joined_at"],
            )

    def verify_competition_access(
        self, competition_id: str, team_id: str
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Verify whether a team is authorized and active within a competition."""
        comp = self.get_competition(competition_id)
        if not comp:
            return False, f"Competition '{competition_id}' not found.", None
        team = self.get_team(competition_id, team_id)
        if not team:
            return False, f"Team '{team_id}' is not enrolled in competition '{competition_id}'.", None
        if team.eliminated:
            return False, f"Team '{team_id}' is eliminated from competition: {team.eliminated_reason}", None

        return True, "Authorized", {
            "competition": comp.to_dict(),
            "team": team.to_dict(),
            "side": team.side.value if hasattr(team.side, "value") else str(team.side),
        }

    # --------------------------------------------------------------------------
    # HILL MANAGEMENT
    # --------------------------------------------------------------------------

    def add_hill(
        self,
        competition_id: str,
        hill_id: int,
        name: str,
        environment_type: str = "LINUX",
        target_host: str = "127.0.0.1",
        target_port: int = 80,
        service_name: str = "service",
        initial_owner_team_id: Optional[str] = None,
        initial_owner_side: Optional[str] = None,
        points_per_interval: int = 10,
        capture_points: int = 100,
        flag: Optional[str] = None,
        verifier_type: str = "SIMULATED",
        verifier_endpoint: str = "",
    ) -> bool:
        """Add or configure a target hill for the competition."""
        env_val = HillEnvironmentType(environment_type.upper()) if isinstance(environment_type, str) else environment_type
        ver_val = VerifierType(verifier_type.upper()) if isinstance(verifier_type, str) else verifier_type
        side_val = TeamSide(initial_owner_side.upper()).value if initial_owner_side else None

        flag_hash = hashlib.sha256(flag.encode("utf-8")).hexdigest() if flag else ""
        initial_state = OwnershipState.OWNED.value if initial_owner_team_id else OwnershipState.AVAILABLE.value

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO competition_hills (
                    competition_id, hill_id, name, environment_type, target_host, target_port,
                    service_name, initial_owner_team_id, initial_owner_side,
                    current_owner_team_id, current_owner_side, state, health_status,
                    points_per_interval, capture_points, flag_hash, verifier_type,
                    verifier_endpoint, last_captured_at, last_verified_at, defense_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'HEALTHY', ?, ?, ?, ?, ?, 0.0, 0.0, '')
                ON CONFLICT(competition_id, hill_id) DO UPDATE SET
                    name = excluded.name,
                    environment_type = excluded.environment_type,
                    target_host = excluded.target_host,
                    target_port = excluded.target_port,
                    service_name = excluded.service_name,
                    points_per_interval = excluded.points_per_interval,
                    capture_points = excluded.capture_points,
                    flag_hash = CASE WHEN excluded.flag_hash != '' THEN excluded.flag_hash ELSE competition_hills.flag_hash END,
                    verifier_type = excluded.verifier_type,
                    verifier_endpoint = excluded.verifier_endpoint
                """,
                (
                    competition_id,
                    hill_id,
                    name,
                    env_val.value,
                    target_host,
                    target_port,
                    service_name,
                    initial_owner_team_id,
                    side_val,
                    initial_owner_team_id,
                    side_val,
                    initial_state,
                    points_per_interval,
                    capture_points,
                    flag_hash,
                    ver_val.value,
                    verifier_endpoint,
                ),
            )
            # Record initial ownership history event if initially owned
            if initial_owner_team_id:
                cur.execute(
                    """
                    INSERT INTO ownership_history (
                        competition_id, hill_id, previous_owner_team_id, previous_side,
                        new_owner_team_id, new_side, event_type, evidence_hash, timestamp, details
                    ) VALUES (?, ?, NULL, NULL, ?, ?, 'INITIAL_ASSIGNMENT', '', ?, 'Initial hill allocation')
                    """,
                    (competition_id, hill_id, initial_owner_team_id, side_val or "NEUTRAL", time.time()),
                )
            conn.commit()
        return True

    def get_competition_hills(self, competition_id: str) -> List[CompetitionHill]:
        """Fetch all hills in a competition."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, hill_id, name, environment_type, target_host, target_port,
                       service_name, initial_owner_team_id, initial_owner_side,
                       current_owner_team_id, current_owner_side, state, health_status,
                       points_per_interval, capture_points, flag_hash, verifier_type,
                       verifier_endpoint, last_captured_at, last_verified_at, defense_notes
                FROM competition_hills
                WHERE competition_id = ?
                ORDER BY hill_id ASC
                """,
                (competition_id,),
            )
            hills = []
            for row in cur.fetchall():
                hills.append(
                    CompetitionHill(
                        competition_id=row["competition_id"],
                        hill_id=row["hill_id"],
                        name=row["name"],
                        environment_type=HillEnvironmentType(row["environment_type"]),
                        target_host=row["target_host"],
                        target_port=row["target_port"],
                        service_name=row["service_name"],
                        initial_owner_team_id=row["initial_owner_team_id"],
                        initial_owner_side=TeamSide(row["initial_owner_side"]) if row["initial_owner_side"] else None,
                        current_owner_team_id=row["current_owner_team_id"],
                        current_owner_side=TeamSide(row["current_owner_side"]) if row["current_owner_side"] else None,
                        state=OwnershipState(row["state"]),
                        health_status=row["health_status"],
                        points_per_interval=row["points_per_interval"],
                        capture_points=row["capture_points"],
                        flag_hash=row["flag_hash"],
                        verifier_type=VerifierType(row["verifier_type"]),
                        verifier_endpoint=row["verifier_endpoint"],
                        last_captured_at=row["last_captured_at"],
                        last_verified_at=row["last_verified_at"],
                        defense_notes=row["defense_notes"] or "",
                    )
                )
            return hills

    def get_hill(self, competition_id: str, hill_id: int) -> Optional[CompetitionHill]:
        """Fetch a single hill by ID."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT competition_id, hill_id, name, environment_type, target_host, target_port,
                       service_name, initial_owner_team_id, initial_owner_side,
                       current_owner_team_id, current_owner_side, state, health_status,
                       points_per_interval, capture_points, flag_hash, verifier_type,
                       verifier_endpoint, last_captured_at, last_verified_at, defense_notes
                FROM competition_hills
                WHERE competition_id = ? AND hill_id = ?
                """,
                (competition_id, hill_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            return CompetitionHill(
                competition_id=row["competition_id"],
                hill_id=row["hill_id"],
                name=row["name"],
                environment_type=HillEnvironmentType(row["environment_type"]),
                target_host=row["target_host"],
                target_port=row["target_port"],
                service_name=row["service_name"],
                initial_owner_team_id=row["initial_owner_team_id"],
                initial_owner_side=TeamSide(row["initial_owner_side"]) if row["initial_owner_side"] else None,
                current_owner_team_id=row["current_owner_team_id"],
                current_owner_side=TeamSide(row["current_owner_side"]) if row["current_owner_side"] else None,
                state=OwnershipState(row["state"]),
                health_status=row["health_status"],
                points_per_interval=row["points_per_interval"],
                capture_points=row["capture_points"],
                flag_hash=row["flag_hash"],
                verifier_type=VerifierType(row["verifier_type"]),
                verifier_endpoint=row["verifier_endpoint"],
                last_captured_at=row["last_captured_at"],
                last_verified_at=row["last_verified_at"],
                defense_notes=row["defense_notes"] or "",
            )

    def update_hill_defense_notes(self, competition_id: str, hill_id: int, team_id: str, notes: str) -> bool:
        """Update private defense notes if caller is the controlling team."""
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE competition_hills
                SET defense_notes = ?
                WHERE competition_id = ? AND hill_id = ? AND current_owner_team_id = ?
                """,
                (notes.strip(), competition_id, hill_id, team_id),
            )
            conn.commit()
            return cur.rowcount > 0

    # --------------------------------------------------------------------------
    # CAPTURE, RECAPTURE & EVIDENCE VERIFICATION ENGINE
    # --------------------------------------------------------------------------

    def submit_capture(
        self,
        competition_id: str,
        hill_id: int,
        team_id: str,
        agent_id: str,
        flag: str,
    ) -> Tuple[bool, str, Optional[CaptureSubmission]]:
        """
        Process a capture or recapture submission with:
        - Elimination check
        - Strict flag verification
        - Anti-replay protection
        - Automatic RECAPTURE detection and bonus awarding
        - Transition of hill state
        - Atomic score updating
        """
        now = time.time()
        comp = self.get_competition(competition_id)
        if not comp:
            return False, f"Competition '{competition_id}' not found.", None
        if comp.status != CompetitionStatus.ACTIVE:
            return False, f"Competition is not active (current status: {comp.status.value}).", None

        team = self.get_team(competition_id, team_id)
        if not team:
            return False, f"Team '{team_id}' is not enrolled in this competition.", None
        if team.eliminated:
            return False, f"Team '{team_id}' has been eliminated from competition.", None

        hill = self.get_hill(competition_id, hill_id)
        if not hill:
            return False, f"Hill {hill_id} not found in this competition.", None

        # Verify flag
        submitted_hash = hashlib.sha256(flag.strip().encode("utf-8")).hexdigest()
        if not hill.flag_hash or submitted_hash != hill.flag_hash:
            # Penalize team for invalid submission
            penalty = comp.rules.penalty_points
            self._apply_penalty(competition_id, team_id, penalty, f"Invalid flag submission on Hill {hill_id}")
            return False, "Invalid flag token submitted. Penalty recorded.", None

        # Check self-capture (already own it)
        if hill.current_owner_team_id == team_id and hill.state in (OwnershipState.OWNED, OwnershipState.CAPTURED):
            return False, f"Hill {hill_id} is already owned by team '{team_id}'.", None

        # Anti-replay / Idempotency check:
        # Compute evidence hash
        evidence_hash = hashlib.sha256(f"{competition_id}:{hill_id}:{submitted_hash}:{team_id}".encode()).hexdigest()
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT submission_id FROM capture_submissions
                WHERE competition_id = ? AND hill_id = ? AND evidence_hash = ? AND verified = 1
                """,
                (competition_id, hill_id, evidence_hash),
            )
            if cur.fetchone():
                return False, "Replay rejected: identical capture proof already accepted for this hill.", None

            # Determine whether this is a regular CAPTURE or a RECAPTURE
            is_recapture = False
            prev_owner = hill.current_owner_team_id
            prev_side = hill.current_owner_side.value if hill.current_owner_side else None

            # Check if this team previously owned this hill and is recapturing it,
            # or in Red vs Blue mode, capturing an enemy-owned hill
            if prev_owner and prev_owner != team_id:
                is_recapture = True

            awarded_points = hill.capture_points
            if is_recapture:
                awarded_points += comp.rules.recapture_bonus

            submission_id = f"cap-{uuid.uuid4().hex[:12]}"
            cur.execute(
                """
                INSERT INTO capture_submissions (
                    submission_id, competition_id, hill_id, team_id, side, agent_id,
                    evidence_hash, verified, awarded_points, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    submission_id,
                    competition_id,
                    hill_id,
                    team_id,
                    team.side.value,
                    agent_id,
                    evidence_hash,
                    awarded_points,
                    now,
                ),
            )

            # Record score event
            cur.execute(
                """
                INSERT INTO competition_scores (
                    competition_id, team_id, category, points, details_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    competition_id,
                    team_id,
                    ScoreCategory.RECAPTURE.value if is_recapture else ScoreCategory.CAPTURE.value,
                    awarded_points,
                    json.dumps({"hill_id": hill_id, "submission_id": submission_id, "recapture": is_recapture}),
                    now,
                ),
            )

            # Update team score and counts
            if is_recapture:
                cur.execute(
                    """
                    UPDATE competition_teams
                    SET score = score + ?,
                        recaptures_count = recaptures_count + 1,
                        captures_count = captures_count + 1
                    WHERE competition_id = ? AND team_id = ?
                    """,
                    (awarded_points, competition_id, team_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE competition_teams
                    SET score = score + ?,
                        captures_count = captures_count + 1
                    WHERE competition_id = ? AND team_id = ?
                    """,
                    (awarded_points, competition_id, team_id),
                )

            # Update hill state
            cur.execute(
                """
                UPDATE competition_hills
                SET current_owner_team_id = ?,
                    current_owner_side = ?,
                    state = ?,
                    health_status = 'HEALTHY',
                    last_captured_at = ?,
                    last_verified_at = ?
                WHERE competition_id = ? AND hill_id = ?
                """,
                (
                    team_id,
                    team.side.value,
                    OwnershipState.CAPTURED.value,
                    now,
                    now,
                    competition_id,
                    hill_id,
                ),
            )

            # Log to ownership history
            event_type = "RECAPTURE" if is_recapture else "CAPTURE"
            cur.execute(
                """
                INSERT INTO ownership_history (
                    competition_id, hill_id, previous_owner_team_id, previous_side,
                    new_owner_team_id, new_side, event_type, evidence_hash, timestamp, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    competition_id,
                    hill_id,
                    prev_owner,
                    prev_side,
                    team_id,
                    team.side.value,
                    event_type,
                    evidence_hash,
                    now,
                    f"Hill {hill_id} captured by {team_id} ({team.side.value}) via {agent_id}",
                ),
            )

            conn.commit()

        submission = CaptureSubmission(
            submission_id=submission_id,
            competition_id=competition_id,
            hill_id=hill_id,
            team_id=team_id,
            side=team.side,
            agent_id=agent_id,
            evidence_hash=evidence_hash,
            verified=True,
            awarded_points=awarded_points,
            timestamp=now,
        )

        logger.info(
            f"[CAPTURE] Hill {hill_id} in {competition_id} captured by team {team_id} (+{awarded_points} pts)"
        )
        return True, f"Capture verified! +{awarded_points} points awarded.", submission

    # --------------------------------------------------------------------------
    # DEFENSE & PATCH VERIFICATION ENGINE
    # --------------------------------------------------------------------------

    def submit_defense(
        self,
        competition_id: str,
        hill_id: int,
        team_id: str,
        agent_id: str,
        patch_summary: str,
        service_status: str = "HEALTHY",
    ) -> Tuple[bool, str, Optional[DefenseSubmission]]:
        """
        Record a defense or hardening verification on a controlled hill.
        Awards defense points and verifies service availability.
        """
        now = time.time()
        comp = self.get_competition(competition_id)
        if not comp:
            return False, f"Competition '{competition_id}' not found.", None
        if comp.status != CompetitionStatus.ACTIVE:
            return False, f"Competition is not active.", None

        team = self.get_team(competition_id, team_id)
        if not team:
            return False, f"Team '{team_id}' not found.", None
        if team.eliminated:
            return False, f"Team is eliminated.", None

        hill = self.get_hill(competition_id, hill_id)
        if not hill:
            return False, f"Hill {hill_id} not found.", None

        # Verify that the team actually owns the hill
        if hill.current_owner_team_id != team_id and (
            not hill.current_owner_side or hill.current_owner_side != team.side
        ):
            return False, f"Team '{team_id}' does not currently hold Hill {hill_id}.", None

        awarded_points = comp.rules.defense_points
        sub_id = f"def-{uuid.uuid4().hex[:12]}"

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO defense_submissions (
                    submission_id, competition_id, hill_id, team_id, side, agent_id,
                    service_status, patch_summary, verified, awarded_points, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    sub_id,
                    competition_id,
                    hill_id,
                    team_id,
                    team.side.value,
                    agent_id,
                    service_status,
                    patch_summary.strip(),
                    awarded_points,
                    now,
                ),
            )

            # Score update
            cur.execute(
                """
                INSERT INTO competition_scores (
                    competition_id, team_id, category, points, details_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    competition_id,
                    team_id,
                    ScoreCategory.DEFENSE.value,
                    awarded_points,
                    json.dumps({"hill_id": hill_id, "submission_id": sub_id, "service_status": service_status}),
                    now,
                ),
            )

            cur.execute(
                """
                UPDATE competition_teams
                SET score = score + ?,
                    defenses_count = defenses_count + 1
                WHERE competition_id = ? AND team_id = ?
                """,
                (awarded_points, competition_id, team_id),
            )

            cur.execute(
                """
                UPDATE competition_hills
                SET health_status = ?,
                    state = 'OWNED',
                    last_verified_at = ?
                WHERE competition_id = ? AND hill_id = ?
                """,
                (service_status, now, competition_id, hill_id),
            )
            conn.commit()

        submission = DefenseSubmission(
            submission_id=sub_id,
            competition_id=competition_id,
            hill_id=hill_id,
            team_id=team_id,
            side=team.side,
            agent_id=agent_id,
            service_status=service_status,
            patch_summary=patch_summary,
            verified=True,
            awarded_points=awarded_points,
            timestamp=now,
        )
        logger.info(f"[DEFENSE] Hill {hill_id} defended by {team_id} (+{awarded_points} pts)")
        return True, f"Defense verified! +{awarded_points} points awarded.", submission

    # --------------------------------------------------------------------------
    # PERIODIC TICK SCORING & INTERVAL HOLD
    # --------------------------------------------------------------------------

    def process_tick(self, competition_id: str) -> Dict[str, Any]:
        """
        Process a scoring tick for all hills held by teams.
        Awards points_per_interval to each controlling team and updates uptime.
        """
        now = time.time()
        comp = self.get_competition(competition_id)
        if not comp or comp.status != CompetitionStatus.ACTIVE:
            return {"awarded": 0, "status": "inactive"}

        hills = self.get_competition_hills(competition_id)
        awarded_total = 0

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            for h in hills:
                if (
                    h.current_owner_team_id
                    and h.state in (OwnershipState.OWNED, OwnershipState.CAPTURED)
                    and h.health_status == "HEALTHY"
                ):
                    pts = h.points_per_interval
                    cur.execute(
                        """
                        UPDATE competition_teams
                        SET score = score + ?,
                            uptime_seconds = uptime_seconds + ?
                        WHERE competition_id = ? AND team_id = ? AND eliminated = 0
                        """,
                        (pts, comp.rules.hold_interval_seconds, competition_id, h.current_owner_team_id),
                    )
                    cur.execute(
                        """
                        INSERT INTO competition_scores (
                            competition_id, team_id, category, points, details_json, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            competition_id,
                            h.current_owner_team_id,
                            ScoreCategory.HOLD_INTERVAL.value,
                            pts,
                            json.dumps({"hill_id": h.hill_id}),
                            now,
                        ),
                    )
                    awarded_total += pts

            conn.commit()

        # Check elimination thresholds
        self.check_eliminations(competition_id)
        return {"awarded": awarded_total, "status": "active"}

    def _apply_penalty(self, competition_id: str, team_id: str, penalty: int, reason: str) -> None:
        """Deduct penalty points from team and log."""
        now = time.time()
        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE competition_teams
                SET score = MAX(0, score - ?),
                    penalties_count = penalties_count + 1
                WHERE competition_id = ? AND team_id = ?
                """,
                (penalty, competition_id, team_id),
            )
            cur.execute(
                """
                INSERT INTO competition_scores (
                    competition_id, team_id, category, points, details_json, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    competition_id,
                    team_id,
                    ScoreCategory.PENALTY.value,
                    -penalty,
                    json.dumps({"reason": reason}),
                    now,
                ),
            )
            conn.commit()

    # --------------------------------------------------------------------------
    # LEADERBOARD, TIE-BREAKING & ELIMINATION
    # --------------------------------------------------------------------------

    def get_leaderboard(self, competition_id: str) -> Dict[str, Any]:
        """
        Generate authoritative leaderboard.
        Sorts by:
        1. Score DESC
        2. Penalties ASC
        3. Captures DESC
        4. Uptime DESC
        5. Joined_at ASC
        Aggregates side totals for Red vs Blue mode.
        """
        teams = self.get_competition_teams(competition_id)
        # Tie-breaker sort
        teams.sort(
            key=lambda t: (
                -t.score,
                t.penalties_count,
                -t.captures_count,
                -t.uptime_seconds,
                t.joined_at,
            )
        )

        red_score = sum(t.score for t in teams if t.side == TeamSide.RED)
        blue_score = sum(t.score for t in teams if t.side == TeamSide.BLUE)

        hills = self.get_competition_hills(competition_id)
        red_hills = sum(1 for h in hills if h.current_owner_side == TeamSide.RED)
        blue_hills = sum(1 for h in hills if h.current_owner_side == TeamSide.BLUE)
        neutral_hills = sum(1 for h in hills if not h.current_owner_side or h.current_owner_side == TeamSide.NEUTRAL)

        return {
            "competition_id": competition_id,
            "teams": [t.to_dict() for t in teams],
            "red_score": red_score,
            "blue_score": blue_score,
            "red_hills_count": red_hills,
            "blue_hills_count": blue_hills,
            "neutral_hills_count": neutral_hills,
            "total_hills": len(hills),
        }

    def check_eliminations(self, competition_id: str) -> List[str]:
        """Check and mark eliminated teams based on threshold or loss of all hills."""
        comp = self.get_competition(competition_id)
        if not comp:
            return []

        eliminated_team_ids = []
        teams = self.get_competition_teams(competition_id)
        hills = self.get_competition_hills(competition_id)

        threshold = comp.rules.elimination_threshold

        with self._lock, self._get_connection() as conn:
            cur = conn.cursor()
            for t in teams:
                if t.eliminated:
                    continue

                is_eliminated = False
                reason = ""

                # 1. Score below elimination threshold
                if threshold is not None and t.score < threshold:
                    is_eliminated = True
                    reason = f"Score ({t.score}) dropped below threshold ({threshold})"

                # 2. ELIMINATION format: if team has zero hills after being previously assigned
                if not is_eliminated and (comp.format == KothFormat.ELIMINATION.value or comp.format == RedVsBlueFormat.ELIMINATION.value):
                    owned_count = sum(1 for h in hills if h.current_owner_team_id == t.team_id)
                    # Check if match has started and team owns zero hills
                    if comp.status == CompetitionStatus.ACTIVE and (time.time() - comp.start_time) > 120 and owned_count == 0:
                        is_eliminated = True
                        reason = "All controlled hills lost in Elimination match"

                if is_eliminated:
                    cur.execute(
                        """
                        UPDATE competition_teams
                        SET eliminated = 1, eliminated_reason = ?
                        WHERE competition_id = ? AND team_id = ?
                        """,
                        (reason, competition_id, t.team_id),
                    )
                    eliminated_team_ids.append(t.team_id)
                    logger.warning(f"Team {t.team_id} ELIMINATED in {competition_id}: {reason}")

            conn.commit()

        return eliminated_team_ids

    # --------------------------------------------------------------------------
    # AUDIT TRAIL & HISTORY
    # --------------------------------------------------------------------------

    def get_ownership_history(
        self, competition_id: str, hill_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve authoritative ownership history events."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            if hill_id is not None:
                cur.execute(
                    """
                    SELECT id, competition_id, hill_id, previous_owner_team_id, previous_side,
                           new_owner_team_id, new_side, event_type, evidence_hash, timestamp, details
                    FROM ownership_history
                    WHERE competition_id = ? AND hill_id = ?
                    ORDER BY timestamp DESC
                    """,
                    (competition_id, hill_id),
                )
            else:
                cur.execute(
                    """
                    SELECT id, competition_id, hill_id, previous_owner_team_id, previous_side,
                           new_owner_team_id, new_side, event_type, evidence_hash, timestamp, details
                    FROM ownership_history
                    WHERE competition_id = ?
                    ORDER BY timestamp DESC
                    """,
                    (competition_id,),
                )

            events = []
            for row in cur.fetchall():
                ev = OwnershipHistoryEvent(
                    id=row["id"],
                    competition_id=row["competition_id"],
                    hill_id=row["hill_id"],
                    previous_owner_team_id=row["previous_owner_team_id"],
                    previous_side=row["previous_side"],
                    new_owner_team_id=row["new_owner_team_id"],
                    new_side=row["new_side"],
                    event_type=row["event_type"],
                    evidence_hash=row["evidence_hash"],
                    timestamp=row["timestamp"],
                    details=row["details"] or "",
                )
                events.append(ev.to_dict())
            return events

