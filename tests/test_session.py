"""Unit tests for KOTH AI Session State and Scientific Workflow Management.

Requirements verified:
1. session creation
2. persistence/reload
3. evidence references
4. hypothesis lifecycle
5. failed approach recording
6. invalid state rejection
7. atomic persistence
8. scientific workflow consistency
"""

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from core.evidence import EvidenceCollector, IntegrityError, SecurityError
from core.schemas import (
    Conclusion,
    ConclusionStatus,
    FailedApproach,
    Finding,
    FindingSeverity,
    Hypothesis,
    HypothesisStatus,
    InvalidStateTransitionError,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
)
from core.session import (
    ApproachAlreadyFailedError,
    Session,
    SessionError,
    SessionManager,
    SessionSecurityError,
    SessionValidationError,
)


class TestSessionState(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.evidence_dir = self.base_path / "evidence"
        self.sessions_dir = self.base_path / "sessions"
        self.evidence_collector = EvidenceCollector(evidence_dir=self.evidence_dir)
        self.session_manager = SessionManager(
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

    def tearDown(self):
        # Restore permissions if needed before cleanup
        for p in self.base_path.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_session_creation(self):
        """Verify session creation, metadata initialization, and initial state."""
        session = Session(
            session_id="session-001",
            active_target="target-01",
            configuration_snapshot={"mode": "authorized-lab-only", "port": 8080},
            sessions_dir=self.sessions_dir,
            evidence_collector=self.evidence_collector,
        )

        self.assertEqual(session.session_id, "session-001")
        self.assertEqual(session.active_target, "target-01")
        self.assertEqual(session.configuration_snapshot["mode"], "authorized-lab-only")
        self.assertEqual(session.configuration_snapshot["port"], 8080)
        self.assertIsNotNone(session.start_time)
        self.assertIsNone(session.end_time)
        self.assertEqual(session.observations, [])
        self.assertEqual(session.hypotheses, [])
        self.assertEqual(session.safe_tests, [])
        self.assertEqual(session.test_results, [])
        self.assertEqual(session.conclusions, [])
        self.assertEqual(session.findings, [])
        self.assertEqual(session.failed_approaches, [])

        # Verify invalid session ID rejections
        with self.assertRaises(SessionValidationError):
            Session("", "target-01", sessions_dir=self.sessions_dir)
        with self.assertRaises(SessionSecurityError):
            Session("../evil-session", "target-01", sessions_dir=self.sessions_dir)
        with self.assertRaises(SessionSecurityError):
            Session("bad/name", "target-01", sessions_dir=self.sessions_dir)
        with self.assertRaises(SessionSecurityError):
            Session("null\x00byte", "target-01", sessions_dir=self.sessions_dir)

        # Verify invalid target rejection
        with self.assertRaises(ValidationError):
            Session("session-valid", "", sessions_dir=self.sessions_dir)
        with self.assertRaises(ValidationError):
            Session("session-valid", "target/with/slashes", sessions_dir=self.sessions_dir)

    def test_2_persistence_and_reload(self):
        """Verify saving to disk, atomic JSON formatting, and accurate reloading."""
        session = self.session_manager.create_session(
            session_id="session-persist-01",
            active_target="target-01",
            configuration_snapshot={"env": "test"},
        )

        # Store dummy evidence
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"path": "/index"})

        # Populate workflow entities
        obs = session.add_observation("obs-1", ev.evidence_id, "Found homepage")
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Homepage exposes debug info")
        test = session.add_safe_test("test-1", "hyp-1", "http_probe", "Safe GET", "200 OK", {"path": "/debug"})
        ev_test = self.evidence_collector.store_evidence("http_probe", "target-01", {"debug": True})
        res = session.record_test_result("res-1", "test-1", ev_test.evidence_id, TestStatus.SUCCESS, "Debug flag present")
        concl = session.add_conclusion("concl-1", "hyp-1", ["res-1"], ConclusionStatus.VALIDATED, "Confirmed debug flag")
        finding = session.add_finding(
            "find-1",
            "Debug Endpoint Exposed",
            FindingSeverity.LOW,
            "concl-1",
            {"conclusion": "concl-1", "hypothesis": "hyp-1", "test": "test-1", "result": "res-1", "observation": "obs-1"},
            "Exposed /debug endpoint",
            "Information leakage",
        )
        session.close()

        # Save session
        saved_path = session.save()
        self.assertTrue(saved_path.exists())
        self.assertEqual(saved_path.name, "session-persist-01.json")

        # Verify session manager listing
        sessions_list = self.session_manager.list_sessions()
        self.assertIn("session-persist-01", sessions_list)
        self.assertTrue(self.session_manager.session_exists("session-persist-01"))

        # Reload session
        reloaded = self.session_manager.load_session("session-persist-01")
        self.assertEqual(reloaded.session_id, "session-persist-01")
        self.assertEqual(reloaded.active_target, "target-01")
        self.assertEqual(reloaded.configuration_snapshot, {"env": "test"})
        self.assertIsNotNone(reloaded.end_time)
        self.assertEqual(len(reloaded.observations), 1)
        self.assertEqual(reloaded.observations[0].observation_id, "obs-1")
        self.assertEqual(reloaded.observations[0].evidence_ref, ev.evidence_id)
        self.assertEqual(len(reloaded.hypotheses), 1)
        self.assertEqual(reloaded.hypotheses[0].hypothesis_id, "hyp-1")
        self.assertEqual(reloaded.hypotheses[0].status, HypothesisStatus.VALIDATED.value)
        self.assertEqual(len(reloaded.safe_tests), 1)
        self.assertEqual(reloaded.safe_tests[0].test_id, "test-1")
        self.assertEqual(len(reloaded.test_results), 1)
        self.assertEqual(reloaded.test_results[0].result_id, "res-1")
        self.assertEqual(len(reloaded.conclusions), 1)
        self.assertEqual(reloaded.conclusions[0].conclusion_id, "concl-1")
        self.assertEqual(len(reloaded.findings), 1)
        self.assertEqual(reloaded.findings[0].finding_id, "find-1")

        # Reload non-existent session
        with self.assertRaises(FileNotFoundError):
            self.session_manager.load_session("non-existent-session")

        # Corrupted session file
        corrupt_file = self.sessions_dir / "session-corrupt.json"
        with open(corrupt_file, "w") as f:
            f.write("{invalid json")
        with self.assertRaises(SessionValidationError):
            self.session_manager.load_session("session-corrupt")

    def test_3_evidence_references(self):
        """Verify session only references evidence by ID/hash and never modifies or duplicates raw evidence."""
        raw_payload = {"sensitive_data": "secret-12345", "nested": [1, 2, 3]}
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", raw_payload)

        session = self.session_manager.create_session("session-ev-ref", "target-01")
        obs = session.add_observation("obs-ev", ev.evidence_id, "Observation referencing evidence")

        self.assertEqual(obs.evidence_ref, ev.evidence_id)
        self.assertEqual(len(obs.evidence_ref), 64)

        # Ensure session serialization only holds the hash, not the full payload
        session_dict = session.to_dict()
        obs_serialized = session_dict["observations"][0]
        self.assertEqual(obs_serialized["evidence_ref"], ev.evidence_id)
        self.assertNotIn("sensitive_data", json.dumps(obs_serialized))

        # Invalid evidence_ref format (must be 64-char lowercase hex)
        with self.assertRaises(SessionValidationError):
            session.add_observation("obs-bad-ref", "not-a-sha256-hash", "Invalid hash ref")

        with self.assertRaises(SessionValidationError):
            session.add_observation("obs-bad-ref2", "a" * 63, "Wrong length hash ref")

        # Non-existent evidence hash when EvidenceCollector is attached
        fake_hash = "0" * 64
        with self.assertRaises(FileNotFoundError):
            session.add_observation("obs-fake-ref", fake_hash, "Reference to non-existent evidence")

        # Ensure evidence artifact in evidence/raw cannot be overwritten by session save
        ev_file = self.evidence_dir / "raw" / f"{ev.evidence_id}.json"
        self.assertTrue(ev_file.exists())
        file_mode_before = ev_file.stat().st_mode

        session.save()
        # Evidence file mode should remain 0444 read-only
        self.assertEqual(ev_file.stat().st_mode & 0o777, 0o444)
        self.assertEqual(file_mode_before, ev_file.stat().st_mode)

    def test_4_hypothesis_lifecycle(self):
        """Verify explicit hypothesis state transitions and timestamps."""
        session = self.session_manager.create_session("session-hypo-life", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"status": "ok"})
        session.add_observation("obs-1", ev.evidence_id, "Recon observation")

        # 1. Created as PROPOSED
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Service has exposed config")
        self.assertEqual(hyp.status, HypothesisStatus.PROPOSED.value)
        initial_time = hyp.created_at

        # Verify can_transition_to checks
        self.assertTrue(hyp.can_transition_to(HypothesisStatus.TESTING))
        self.assertTrue(hyp.can_transition_to(HypothesisStatus.ABANDONED))
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.VALIDATED))
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.REFUTED))

        # 2. Transition PROPOSED -> TESTING
        session.transition_hypothesis("hyp-1", HypothesisStatus.TESTING)
        self.assertEqual(hyp.status, HypothesisStatus.TESTING.value)
        self.assertTrue(hyp.can_transition_to(HypothesisStatus.VALIDATED))
        self.assertTrue(hyp.can_transition_to(HypothesisStatus.REFUTED))
        self.assertTrue(hyp.can_transition_to(HypothesisStatus.ABANDONED))
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.PROPOSED))

        # 3. Transition TESTING -> VALIDATED
        session.transition_hypothesis("hyp-1", HypothesisStatus.VALIDATED)
        self.assertEqual(hyp.status, HypothesisStatus.VALIDATED.value)
        # Terminal state: cannot transition anywhere
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.TESTING))
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.REFUTED))
        self.assertFalse(hyp.can_transition_to(HypothesisStatus.ABANDONED))

        # Test another hypothesis for REFUTED transition
        hyp2 = session.add_hypothesis("hyp-2", ["obs-1"], "Service has SQL injection")
        session.transition_hypothesis("hyp-2", HypothesisStatus.TESTING)
        session.transition_hypothesis("hyp-2", HypothesisStatus.REFUTED)
        self.assertEqual(hyp2.status, HypothesisStatus.REFUTED.value)

        # Test another hypothesis for ABANDONED transition directly from PROPOSED
        hyp3 = session.add_hypothesis("hyp-3", ["obs-1"], "Service has XSS")
        session.transition_hypothesis("hyp-3", HypothesisStatus.ABANDONED)
        self.assertEqual(hyp3.status, HypothesisStatus.ABANDONED.value)

    def test_5_failed_approach_recording(self):
        """Verify failed approaches capture negative knowledge and prevent repetitive failures."""
        session = self.session_manager.create_session("session-failed-approach", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"info": "service"})
        session.add_observation("obs-1", ev.evidence_id, "Found port 8080")
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Endpoint /admin-login exists")

        # Add safe test
        test = session.add_safe_test(
            "test-1",
            "hyp-1",
            "http_probe",
            "Probe /admin-login",
            "200 OK with login form",
            {"path": "/admin-login", "method": "GET"},
        )

        # Test fails with 404
        ev_fail = self.evidence_collector.store_evidence("http_probe", "target-01", {"status": 404, "body": "Not Found"})
        session.record_test_result(
            "res-1",
            "test-1",
            ev_fail.evidence_id,
            TestStatus.FAILURE,
            "Endpoint /admin-login returned 404 Not Found",
            failure_reason="Endpoint does not exist",
            negative_knowledge="Path /admin-login does not exist on target-01. Do not repeat.",
        )

        # Verify failed_approaches contains the record
        self.assertEqual(len(session.failed_approaches), 1)
        fa = session.failed_approaches[0]
        self.assertEqual(fa.test_id, "test-1")
        self.assertEqual(fa.hypothesis_id, "hyp-1")
        self.assertEqual(fa.tool, "http_probe")
        self.assertEqual(fa.parameters, {"path": "/admin-login", "method": "GET"})
        self.assertEqual(fa.reason, "Endpoint does not exist")
        self.assertEqual(fa.negative_knowledge, "Path /admin-login does not exist on target-01. Do not repeat.")
        self.assertEqual(fa.evidence_ref, ev_fail.evidence_id)

        # Verify negative knowledge query
        self.assertTrue(session.is_approach_failed("http_probe", {"path": "/admin-login", "method": "GET"}))
        # Parameter ordering invariance test
        self.assertTrue(session.is_approach_failed("http_probe", {"method": "GET", "path": "/admin-login"}))
        # Different parameters should return False
        self.assertFalse(session.is_approach_failed("http_probe", {"path": "/user-login", "method": "GET"}))

        # Attempting to schedule the exact same failed test must raise ApproachAlreadyFailedError!
        with self.assertRaises(ApproachAlreadyFailedError):
            session.add_safe_test(
                "test-repeat",
                "hyp-1",
                "http_probe",
                "Retry probe",
                "200 OK",
                {"path": "/admin-login", "method": "GET"},
            )

        # Explicit override works if requested
        test_override = session.add_safe_test(
            "test-override",
            "hyp-1",
            "http_probe",
            "Explicit re-test with new hypothesis reasoning",
            "200 OK",
            {"path": "/admin-login", "method": "GET"},
            allow_failed_repeat=True,
        )
        self.assertIsNotNone(test_override)

        # Test standalone record_failed_approach
        fa_manual = session.record_failed_approach(
            approach_id="fa-manual-1",
            hypothesis_id="hyp-1",
            test_id="test-1",
            target="target-01",
            tool="dir_scan",
            parameters={"wordlist": "common.txt"},
            reason="Wordlist scan blocked by rate limiting",
            negative_knowledge="Rate limiter blocks brute-force scanning. Use selective probing instead.",
        )
        self.assertIn(fa_manual, session.failed_approaches)
        self.assertTrue(session.is_approach_failed("dir_scan", {"wordlist": "common.txt"}))

    def test_6_invalid_state_rejection(self):
        """Verify strict rejection of illegal states, transitions, and mismatched references."""
        session = self.session_manager.create_session("session-invalid-states", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"data": 1})
        session.add_observation("obs-1", ev.evidence_id, "Base observation")
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Claim 1")

        # 1. Illegal hypothesis transitions
        # Direct PROPOSED -> VALIDATED (cannot skip testing)
        with self.assertRaises(InvalidStateTransitionError):
            session.transition_hypothesis("hyp-1", HypothesisStatus.VALIDATED)

        # Direct PROPOSED -> REFUTED
        with self.assertRaises(InvalidStateTransitionError):
            session.transition_hypothesis("hyp-1", HypothesisStatus.REFUTED)

        # Transition to testing, then validated
        session.transition_hypothesis("hyp-1", HypothesisStatus.TESTING)
        session.transition_hypothesis("hyp-1", HypothesisStatus.VALIDATED)

        # Cannot reopen terminal state
        with self.assertRaises(InvalidStateTransitionError):
            session.transition_hypothesis("hyp-1", HypothesisStatus.TESTING)
        with self.assertRaises(InvalidStateTransitionError):
            session.transition_hypothesis("hyp-1", HypothesisStatus.REFUTED)

        # 2. Cannot add SafeTest to a terminal hypothesis
        with self.assertRaises(SessionValidationError):
            session.add_safe_test("test-term", "hyp-1", "http_probe", "Justification", "Outcome")

        # 3. Hypothesis referencing non-existent observation
        with self.assertRaises(SessionValidationError):
            session.add_hypothesis("hyp-bad-obs", ["non-existent-obs"], "Claim")

        # 4. SafeTest referencing non-existent hypothesis
        with self.assertRaises(SessionValidationError):
            session.add_safe_test("test-bad-hyp", "non-existent-hyp", "tool", "Just", "Exp")

        # 5. TestResult referencing non-existent SafeTest
        with self.assertRaises(SessionValidationError):
            session.record_test_result("res-bad-test", "non-existent-test", ev.evidence_id, TestStatus.SUCCESS, "Summary")

        # Setup active hypothesis and test
        hyp2 = session.add_hypothesis("hyp-2", ["obs-1"], "Claim 2")
        test2 = session.add_safe_test("test-2", "hyp-2", "http_probe", "Justification 2", "Expected 2")
        ev2 = self.evidence_collector.store_evidence("http_probe", "target-01", {"result": "ok"})
        res2 = session.record_test_result("res-2", "test-2", ev2.evidence_id, TestStatus.SUCCESS, "Success summary")

        # 6. Conclusion referencing test result from a DIFFERENT hypothesis
        hyp3 = session.add_hypothesis("hyp-3", ["obs-1"], "Claim 3")
        # hyp3 is in PROPOSED, so add a test to put it into TESTING
        test3 = session.add_safe_test("test-3", "hyp-3", "http_probe", "Just 3", "Exp 3")
        with self.assertRaises(SessionValidationError):
            # res-2 belongs to hyp-2, not hyp-3!
            session.add_conclusion("concl-bad-ref", "hyp-3", ["res-2"], ConclusionStatus.VALIDATED, "Rationale")

        # 7. Finding referencing non-existent conclusion
        with self.assertRaises(SessionValidationError):
            session.add_finding("find-bad-concl", "Title", FindingSeverity.INFO, "fake-concl", {}, "Desc", "Impact")

        # 8. Finding referencing REFUTED conclusion (findings require VALIDATED conclusions)
        concl_refuted = session.add_conclusion(
            "concl-refuted", "hyp-2", ["res-2"], ConclusionStatus.REFUTED, "Refuted by test"
        )
        with self.assertRaises(SessionValidationError):
            session.add_finding(
                "find-refuted",
                "Refuted Finding",
                FindingSeverity.MEDIUM,
                "concl-refuted",
                {"conclusion": "concl-refuted"},
                "Desc",
                "Impact",
            )

        # 9. Path traversal prevention in session save/load
        with self.assertRaises(SessionSecurityError):
            Session.load("../../etc/passwd", sessions_dir=self.sessions_dir)

    def test_7_atomic_persistence(self):
        """Verify atomic file write semantics, POSIX replace, and file mode integrity."""
        session = self.session_manager.create_session("session-atomic-01", "target-01")
        ev = self.evidence_collector.store_evidence("http_probe", "target-01", {"key": "val"})
        session.add_observation("obs-1", ev.evidence_id, "Atomic persistence observation")

        session_file = session.save()
        self.assertTrue(session_file.exists())

        # Check permissions (0600)
        mode = session_file.stat().st_mode
        self.assertEqual(mode & 0o777, 0o600)

        # Verify no temporary files (.tmp) remain lingering in the directory
        temp_files = list(self.sessions_dir.glob(".*.tmp"))
        self.assertEqual(len(temp_files), 0)

        # Subsequent atomic update
        hyp = session.add_hypothesis("hyp-1", ["obs-1"], "Hypothesis updated")
        session_file_updated = session.save()
        self.assertEqual(session_file, session_file_updated)

        # File content reflects update and remains valid JSON
        with open(session_file_updated, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["hypotheses"]), 1)
        self.assertEqual(data["hypotheses"][0]["hypothesis_id"], "hyp-1")

    def test_8_scientific_workflow_consistency(self):
        """Verify complete Observation -> Hypothesis -> SafeTest -> Result -> Conclusion -> Finding pipeline."""
        session = self.session_manager.create_session("session-pipeline", "target-01")

        # Step 1: Reconnaissance Evidence & Observation
        ev_recon = self.evidence_collector.store_evidence(
            source_tool="http_probe",
            target="target-01",
            payload={"status": 200, "headers": {"X-Debug": "1"}},
        )
        obs = session.add_observation(
            observation_id="obs-debug-header",
            evidence_ref=ev_recon.evidence_id,
            description="Response headers contain X-Debug: 1",
            attributes={"header": "X-Debug", "value": "1"},
        )
        self.assertEqual(obs.evidence_ref, ev_recon.evidence_id)

        # Step 2: Formulate Hypothesis
        hyp = session.add_hypothesis(
            hypothesis_id="hyp-debug-mode",
            based_on_observations=[obs.observation_id],
            claim="Debug mode is enabled allowing verbose error traces",
        )
        self.assertEqual(hyp.status, HypothesisStatus.PROPOSED.value)

        # Step 3: Safe Test Planning (transitions hypothesis to TESTING)
        test = session.add_safe_test(
            test_id="test-trigger-debug",
            hypothesis_id=hyp.hypothesis_id,
            tool="http_probe",
            safety_justification="Query non-existent path to trigger debug error page on allowlisted target-01",
            expected_outcome="HTTP 404 or 500 containing stack trace or environment details",
            parameters={"path": "/nonexistent-path-for-testing", "method": "GET"},
        )
        self.assertEqual(session.get_hypothesis(hyp.hypothesis_id).status, HypothesisStatus.TESTING.value)

        # Step 4: Test Execution & Result Recording with new immutable evidence
        ev_test = self.evidence_collector.store_evidence(
            source_tool="http_probe",
            target="target-01",
            payload={"status": 500, "body": "DEBUG TRACE: Werkzeug Debugger active"},
        )
        res = session.record_test_result(
            result_id="res-debug-trace",
            test_id=test.test_id,
            evidence_ref=ev_test.evidence_id,
            status=TestStatus.SUCCESS,
            summary="Server responded with 500 containing active debugger banner",
        )
        self.assertEqual(res.evidence_ref, ev_test.evidence_id)

        # Step 5: Deduce Conclusion (transitions hypothesis to VALIDATED)
        concl = session.add_conclusion(
            conclusion_id="concl-debug-validated",
            hypothesis_id=hyp.hypothesis_id,
            result_refs=[res.result_id],
            status=ConclusionStatus.VALIDATED,
            rationale="Triggered error trace confirmed Werkzeug Debugger is active",
        )
        self.assertEqual(session.get_hypothesis(hyp.hypothesis_id).status, HypothesisStatus.VALIDATED.value)

        # Step 6: Create Verified Security Finding linking entire evidence chain
        finding = session.add_finding(
            finding_id="find-active-debugger",
            title="Interactive Debugger Enabled in Production Target",
            severity=FindingSeverity.HIGH,
            conclusion_ref=concl.conclusion_id,
            evidence_chain={
                "observation": obs.observation_id,
                "hypothesis": hyp.hypothesis_id,
                "test": test.test_id,
                "result": res.result_id,
                "conclusion": concl.conclusion_id,
            },
            description="The web service runs in debug mode with interactive debugger enabled.",
            impact="Attackers can inspect sensitive application internals and stack traces.",
            remediation="Disable debug mode in environment settings.",
        )
        self.assertEqual(finding.conclusion_ref, concl.conclusion_id)

        # Step 7: Close session
        session.close()
        self.assertIsNotNone(session.end_time)

        # Step 8: Save and reload to verify end-to-end chain persists perfectly
        session_file = session.save()
        reloaded = Session.load("session-pipeline", sessions_dir=self.sessions_dir, evidence_collector=self.evidence_collector)

        self.assertEqual(len(reloaded.observations), 1)
        self.assertEqual(len(reloaded.hypotheses), 1)
        self.assertEqual(len(reloaded.safe_tests), 1)
        self.assertEqual(len(reloaded.test_results), 1)
        self.assertEqual(len(reloaded.conclusions), 1)
        self.assertEqual(len(reloaded.findings), 1)
        self.assertEqual(reloaded.findings[0].title, "Interactive Debugger Enabled in Production Target")


if __name__ == "__main__":
    unittest.main()
