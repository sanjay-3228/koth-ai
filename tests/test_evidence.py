"""Unit tests for the evidence collection and scientific reasoning layer.

Verifies:
1. Evidence can be stored.
2. Evidence hash is deterministic.
3. Duplicate identical evidence does not corrupt storage.
4. Evidence cannot be overwritten.
5. Tampered evidence fails integrity verification.
6. Manifest entries are generated correctly.
7. Invalid evidence metadata is rejected.
8. Scientific workflow schemas (Observation -> Hypothesis -> SafeTest -> TestResult -> Conclusion -> Finding).
"""

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from core.evidence import (
    EvidenceCollector,
    EvidenceError,
    IntegrityError,
    SecurityError,
    canonicalize_json,
    compute_hash,
)
from core.schemas import (
    Conclusion,
    ConclusionStatus,
    EvidenceRecord,
    Finding,
    FindingSeverity,
    Hypothesis,
    HypothesisStatus,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
)


class TestEvidenceLayer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_dir = Path(self.temp_dir.name) / "evidence"
        self.collector = EvidenceCollector(evidence_dir=self.evidence_dir)

    def tearDown(self):
        # Restore permissions if needed before cleanup
        for p in self.evidence_dir.glob("**/*"):
            if p.is_file():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        self.temp_dir.cleanup()

    def test_1_evidence_can_be_stored(self):
        """Verify evidence is stored correctly with 0444 permissions and valid record."""
        payload = {"status": 200, "headers": {"Server": "BaseHTTP/0.6"}, "body": "KOTH Target 01"}
        record = self.collector.store_evidence(
            source_tool="http_probe",
            target="koth-target-01",
            payload=payload,
        )

        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(len(record.evidence_id), 64)
        self.assertEqual(record.sha256, record.evidence_id)
        self.assertEqual(record.source_tool, "http_probe")
        self.assertEqual(record.target, "koth-target-01")

        raw_file = self.collector.raw_dir / f"{record.evidence_id}.json"
        self.assertTrue(raw_file.exists())

        # Check read-only permission (0444)
        file_mode = raw_file.stat().st_mode
        self.assertEqual(file_mode & 0o777, 0o444)

        # Retrieve and verify
        retrieved = self.collector.get_evidence(record.evidence_id)
        self.assertEqual(retrieved.evidence_id, record.evidence_id)
        self.assertEqual(retrieved.payload, payload)

    def test_2_evidence_hash_is_deterministic(self):
        """Verify canonicalization ensures identical hashes regardless of dictionary key ordering."""
        d1 = {
            "b_key": 2,
            "a_key": 1,
            "nested": {"z": 9, "y": 8, "x": [3, 2, 1]},
        }
        d2 = {
            "nested": {"x": [3, 2, 1], "y": 8, "z": 9},
            "a_key": 1,
            "b_key": 2,
        }

        h1 = compute_hash(d1)
        h2 = compute_hash(d2)
        self.assertEqual(h1, h2)
        self.assertEqual(canonicalize_json(d1), canonicalize_json(d2))

    def test_3_duplicate_identical_evidence_does_not_corrupt_storage(self):
        """Verify duplicate identical evidence is handled deterministically without conflicting records."""
        payload = {"path": "/robots.txt", "content": "Disallow: /admin"}
        rec1 = self.collector.store_evidence("http_probe", "target-01", payload)
        rec2 = self.collector.store_evidence("http_probe", "target-01", payload)

        self.assertEqual(rec1.evidence_id, rec2.evidence_id)
        self.assertTrue(self.collector.verify_evidence(rec1.evidence_id))

        # Check that manifest does not contain redundant entries
        manifest_entries = self.collector.list_evidence()
        matching = [e for e in manifest_entries if e["evidence_id"] == rec1.evidence_id]
        self.assertEqual(len(matching), 1)

    def test_4_evidence_cannot_be_overwritten(self):
        """Verify stored evidence cannot be overwritten directly due to 0444 permissions."""
        payload = {"data": "initial-secret"}
        record = self.collector.store_evidence("http_probe", "target-01", payload)
        raw_file = self.collector.raw_dir / f"{record.evidence_id}.json"

        # Attempting standard open in write mode should raise PermissionError
        with self.assertRaises(PermissionError):
            with open(raw_file, "w") as f:
                f.write("malicious overwrite attempt")

        # Verify file contents are unchanged
        retrieved = self.collector.get_evidence(record.evidence_id)
        self.assertEqual(retrieved.payload, payload)

    def test_5_tampered_evidence_fails_integrity_verification(self):
        """Verify that modified file contents or tampered payloads fail verification."""
        payload = {"endpoint": "/admin", "allowed": False}
        record = self.collector.store_evidence("http_probe", "target-01", payload)
        raw_file = self.collector.raw_dir / f"{record.evidence_id}.json"

        # Initial check passes
        self.assertTrue(self.collector.verify_evidence(record.evidence_id))

        # Tamper with file: temporarily make writable, change payload, make read-only
        os.chmod(raw_file, 0o600)
        with open(raw_file, "r") as f:
            data = json.load(f)
        data["payload"]["allowed"] = True  # Tamper
        with open(raw_file, "w") as f:
            json.dump(data, f)
        os.chmod(raw_file, 0o444)

        # Integrity verification must fail
        self.assertFalse(self.collector.verify_evidence(record.evidence_id))
        with self.assertRaises(IntegrityError):
            self.collector.verify_evidence(record.evidence_id, raise_on_error=True)
        with self.assertRaises(IntegrityError):
            self.collector.get_evidence(record.evidence_id)

    def test_6_manifest_entries_are_generated_correctly(self):
        """Verify manifest entries match schema and file attributes."""
        payload = {"status": "ok"}
        record = self.collector.store_evidence("http_probe", "koth-target-01", payload)

        entries = self.collector.list_evidence()
        self.assertEqual(len(entries), 1)
        entry = entries[0]

        self.assertEqual(entry["evidence_id"], record.evidence_id)
        self.assertEqual(entry["sha256"], record.sha256)
        self.assertEqual(entry["source_tool"], "http_probe")
        self.assertEqual(entry["target"], "koth-target-01")
        self.assertEqual(entry["file_path"], record.file_path)
        raw_file = self.collector.raw_dir / f"{record.evidence_id}.json"
        self.assertEqual(entry["size_bytes"], raw_file.stat().st_size)

    def test_7_invalid_evidence_metadata_is_rejected(self):
        """Verify rejection of empty or dangerous metadata."""
        # Empty tool
        with self.assertRaises(ValidationError):
            self.collector.store_evidence("", "target-01", {"data": 1})
        # Empty target
        with self.assertRaises(ValidationError):
            self.collector.store_evidence("http_probe", "", {"data": 1})
        # None payload
        with self.assertRaises(ValidationError):
            self.collector.store_evidence("http_probe", "target-01", None)
        # Path traversal in tool
        with self.assertRaises(ValidationError):
            self.collector.store_evidence("../evil_tool", "target-01", {"data": 1})
        # Invalid evidence_id in getter
        with self.assertRaises(ValidationError):
            self.collector.get_evidence("short_id")

    def test_8_scientific_workflow_schemas(self):
        """Verify full Observation -> Hypothesis -> SafeTest -> TestResult -> Conclusion -> Finding pipeline."""
        # 1. Evidence
        ev = self.collector.store_evidence("http_probe", "target-01", {"body": "Disallow: /admin"})

        # 2. Observation
        obs = Observation(
            observation_id="obs-001",
            evidence_ref=ev.evidence_id,
            timestamp="2026-09-02T14:00:00Z",
            target="target-01",
            description="robots.txt disallows /admin",
            attributes={"disallowed_path": "/admin"},
        )
        self.assertEqual(obs.evidence_ref, ev.evidence_id)

        # 3. Hypothesis
        hyp = Hypothesis(
            hypothesis_id="hyp-001",
            based_on_observations=[obs.observation_id],
            claim="Endpoint /admin is active and serves administrative content",
            status=HypothesisStatus.TESTING.value,
        )
        self.assertIn("obs-001", hyp.based_on_observations)

        # 4. SafeTest
        test = SafeTest(
            test_id="test-001",
            hypothesis_id=hyp.hypothesis_id,
            tool="http_probe",
            safety_justification="Target is explicitly allowlisted target-01 and probe is read-only HTTP GET",
            expected_outcome="HTTP 200 with admin training endpoint string",
            parameters={"path": "/admin"},
        )
        self.assertEqual(test.hypothesis_id, hyp.hypothesis_id)

        # 5. TestResult with new evidence
        ev_test = self.collector.store_evidence("http_probe", "target-01", {"status": 200, "body": "Training admin endpoint"})
        result = TestResult(
            result_id="res-001",
            test_id=test.test_id,
            evidence_ref=ev_test.evidence_id,
            status=TestStatus.SUCCESS.value,
            summary="Endpoint /admin returned HTTP 200 with training admin text",
        )
        self.assertEqual(result.evidence_ref, ev_test.evidence_id)

        # 6. Conclusion
        conclusion = Conclusion(
            conclusion_id="concl-001",
            hypothesis_id=hyp.hypothesis_id,
            result_refs=[result.result_id],
            status=ConclusionStatus.VALIDATED.value,
            rationale="Test confirmed that /admin exists and is accessible",
        )
        self.assertEqual(conclusion.status, ConclusionStatus.VALIDATED.value)

        # 7. Finding
        finding = Finding(
            finding_id="find-001",
            title="Unauthenticated Training Admin Endpoint Exposed",
            target="target-01",
            severity=FindingSeverity.INFO.value,
            conclusion_ref=conclusion.conclusion_id,
            evidence_chain={
                "observation": obs.observation_id,
                "hypothesis": hyp.hypothesis_id,
                "test": test.test_id,
                "result": result.result_id,
                "conclusion": conclusion.conclusion_id,
            },
            description="The web service exposes /admin directly as indicated in robots.txt.",
            impact="Training administrative features are reachable.",
            remediation="Enforce authentication or remove training endpoint if in production.",
        )
        self.assertEqual(finding.conclusion_ref, conclusion.conclusion_id)
        self.assertEqual(finding.severity, FindingSeverity.INFO.value)

        # Verify serialization
        f_dict = finding.to_dict()
        f_obj = Finding.from_dict(f_dict)
        self.assertEqual(f_obj.finding_id, finding.finding_id)


if __name__ == "__main__":
    unittest.main()
