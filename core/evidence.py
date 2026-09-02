"""Immutable, content-addressed evidence collection and verification engine.

Requirements:
- Python standard library only.
- Content-addressed storage using SHA-256.
- Deterministic JSON canonicalization before hashing.
- Write-once storage under evidence/raw/<sha256>.json.
- Read-only permissions (0444) on stored artifacts.
- Append-only manifest under evidence/manifest.jsonl.
- Integrity verification and tamper detection.
- Deterministic duplicate handling without conflicting records.
- Path safety and symlink avoidance.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Optional, Union

from .schemas import EvidenceRecord, ValidationError


class EvidenceError(Exception):
    """Base exception for evidence operations."""
    pass


class IntegrityError(EvidenceError):
    """Raised when evidence integrity verification fails."""
    pass


class SecurityError(EvidenceError):
    """Raised when path traversal, symlink, or security policy violations occur."""
    pass


def canonicalize_json(data: Any) -> bytes:
    """Canonicalize Python data structures or JSON strings to deterministic UTF-8 bytes.
    
    Dictionaries have keys sorted recursively, separators are normalized to (',', ':'),
    and ensure_ascii is set to False for consistent Unicode handling.
    """
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except Exception:
            return data.encode("utf-8")
            
    if isinstance(data, (dict, list)):
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def compute_hash(data: Any) -> str:
    """Compute SHA-256 hex digest of canonicalized data."""
    return hashlib.sha256(canonicalize_json(data)).hexdigest()


class EvidenceCollector:
    """Manages immutable, content-addressed evidence storage and verification."""

    def __init__(self, evidence_dir: Optional[Union[str, Path]] = None):
        if evidence_dir is None:
            evidence_dir = Path.home() / "koth-ai" / "evidence"
        self.evidence_dir = Path(evidence_dir).resolve()
        self.raw_dir = self.evidence_dir / "raw"
        self.manifest_path = self.evidence_dir / "manifest.jsonl"
        
        # Ensure directories exist
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def _validate_safe_path(self, target_path: Path, expected_parent: Path) -> Path:
        """Verify target path is safely constrained within expected directory and not a symlink."""
        target_resolved = target_path.resolve()
        parent_resolved = expected_parent.resolve()

        if not target_resolved.is_relative_to(parent_resolved):
            raise SecurityError(f"Path traversal detected: {target_path} is outside {expected_parent}")

        if target_path.is_symlink():
            raise SecurityError(f"Symlinks are prohibited: {target_path}")

        # Ensure no parent component in the hierarchy is an untrusted symlink
        curr = target_path.parent
        while curr != curr.parent:
            if curr.is_symlink():
                raise SecurityError(f"Symlink in path hierarchy prohibited: {curr}")
            if curr == parent_resolved:
                break
            curr = curr.parent

        return target_path

    def _get_manifest_index(self) -> Dict[str, Dict[str, Any]]:
        """Read and index the manifest by evidence_id."""
        if not self.manifest_path.exists():
            return {}

        self._validate_safe_path(self.manifest_path, self.evidence_dir)
        index = {}
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ev_id = entry.get("evidence_id")
                    if ev_id:
                        index[ev_id] = entry
                except json.JSONDecodeError as exc:
                    raise IntegrityError(f"Manifest corrupted at line {line_no}: {exc}")
        return index

    def store_evidence(
        self,
        source_tool: str,
        target: str,
        payload: Any,
        timestamp: Optional[str] = None,
    ) -> EvidenceRecord:
        """Store evidence immutably using content addressing.
        
        If duplicate identical evidence exists, verify its integrity and return
        the existing record deterministically without creating conflicting files.
        """
        if not isinstance(source_tool, str) or not source_tool.strip():
            raise ValidationError("Field 'source_tool' must be a non-empty string")
        if not isinstance(target, str) or not target.strip():
            raise ValidationError("Field 'target' must be a non-empty string")
        if payload is None:
            raise ValidationError("Field 'payload' cannot be None")

        # Canonicalize payload and compute content address
        payload_bytes = canonicalize_json(payload)
        sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
        
        file_rel_path = f"raw/{sha256_hash}.json"
        raw_file = self.raw_dir / f"{sha256_hash}.json"
        self._validate_safe_path(raw_file, self.raw_dir)

        # Handle duplicate identical evidence deterministically
        if raw_file.exists():
            # Verify the integrity of the existing file
            existing_record = self.get_evidence(sha256_hash)
            # Ensure the manifest has this entry
            manifest_index = self._get_manifest_index()
            if sha256_hash not in manifest_index:
                self._append_manifest(existing_record, raw_file.stat().st_size)
            return existing_record

        # Build new record
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        record = EvidenceRecord(
            evidence_id=sha256_hash,
            timestamp=ts,
            source_tool=source_tool,
            target=target,
            payload=payload,
            sha256=sha256_hash,
            file_path=file_rel_path,
        )

        content_to_write = json.dumps(record.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")

        # Atomic, write-once file creation
        fd = None
        try:
            # O_CREAT | O_EXCL ensures file must not exist (atomic write-once)
            # O_NOFOLLOW prevents following symlinks
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(raw_file), flags, 0o600)
            os.write(fd, content_to_write)
            os.fsync(fd)
        except FileExistsError:
            # Race condition or existing file - re-verify and return
            return self.get_evidence(sha256_hash)
        except Exception:
            if raw_file.exists():
                try:
                    os.unlink(raw_file)
                except OSError:
                    pass
            raise
        finally:
            if fd is not None:
                os.close(fd)

        # Set permissions to read-only (0444)
        os.chmod(raw_file, 0o444)

        # Append to manifest
        self._append_manifest(record, len(content_to_write))

        return record

    def _append_manifest(self, record: EvidenceRecord, size_bytes: int) -> None:
        """Append an entry to the evidence manifest."""
        self._validate_safe_path(self.manifest_path, self.evidence_dir)
        manifest_entry = {
            "evidence_id": record.evidence_id,
            "sha256": record.sha256,
            "timestamp": record.timestamp,
            "source_tool": record.source_tool,
            "target": record.target,
            "file_path": record.file_path,
            "size_bytes": size_bytes,
        }
        line = json.dumps(manifest_entry, separators=(",", ":"), ensure_ascii=False) + "\n"
        with open(self.manifest_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        """Retrieve an evidence record and verify its integrity."""
        if not re.fullmatch(r"^[0-9a-f]{64}$", evidence_id):
            raise ValidationError("Invalid evidence_id format: must be 64-character lowercase hex")

        raw_file = self.raw_dir / f"{evidence_id}.json"
        self._validate_safe_path(raw_file, self.raw_dir)

        if not raw_file.exists():
            raise FileNotFoundError(f"Evidence artifact not found: {evidence_id}")

        with open(raw_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise IntegrityError(f"Malformed evidence file {evidence_id}: {exc}")

        record = EvidenceRecord.from_dict(data)
        
        # Verify internal integrity
        self._verify_record_integrity(record, raw_file, raise_on_error=True)
        return record

    def _verify_record_integrity(
        self,
        record: EvidenceRecord,
        file_path: Path,
        raise_on_error: bool = False,
    ) -> bool:
        """Verify that the evidence file and payload match content address and schema."""
        try:
            # Check read-only file mode (no write bits allowed)
            file_stat = file_path.stat()
            if (file_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)) != 0:
                msg = f"Evidence file {file_path.name} is not read-only (mode: {oct(file_stat.st_mode)})"
                if raise_on_error:
                    raise IntegrityError(msg)
                return False

            # Verify content address against payload hash
            payload_canonical = canonicalize_json(record.payload)
            computed_hash = hashlib.sha256(payload_canonical).hexdigest()

            if computed_hash != record.sha256:
                msg = f"Hash mismatch: computed {computed_hash} != recorded {record.sha256}"
                if raise_on_error:
                    raise IntegrityError(msg)
                return False

            if record.sha256 != record.evidence_id:
                msg = f"ID mismatch: sha256 {record.sha256} != evidence_id {record.evidence_id}"
                if raise_on_error:
                    raise IntegrityError(msg)
                return False

            if file_path.name != f"{record.evidence_id}.json":
                msg = f"Filename mismatch: {file_path.name} != {record.evidence_id}.json"
                if raise_on_error:
                    raise IntegrityError(msg)
                return False

            return True

        except Exception as exc:
            if raise_on_error:
                if isinstance(exc, IntegrityError):
                    raise
                raise IntegrityError(f"Integrity check failed: {exc}") from exc
            return False

    def verify_evidence(self, evidence_id: str, raise_on_error: bool = False) -> bool:
        """Public integrity verification method for a specific evidence ID."""
        try:
            if not re.fullmatch(r"^[0-9a-f]{64}$", evidence_id):
                msg = "Invalid evidence_id: must be 64-character lowercase hex"
                if raise_on_error:
                    raise ValidationError(msg)
                return False

            raw_file = self.raw_dir / f"{evidence_id}.json"
            self._validate_safe_path(raw_file, self.raw_dir)

            if not raw_file.exists():
                msg = f"Evidence file does not exist: {evidence_id}"
                if raise_on_error:
                    raise FileNotFoundError(msg)
                return False

            with open(raw_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            record = EvidenceRecord.from_dict(data)

            # Check file and payload integrity
            if not self._verify_record_integrity(record, raw_file, raise_on_error=raise_on_error):
                return False

            # Check manifest integrity if manifest exists
            manifest_index = self._get_manifest_index()
            if evidence_id in manifest_index:
                entry = manifest_index[evidence_id]
                if entry.get("sha256") != record.sha256 or entry.get("source_tool") != record.source_tool or entry.get("target") != record.target:
                    msg = f"Manifest entry mismatch for {evidence_id}"
                    if raise_on_error:
                        raise IntegrityError(msg)
                    return False

            return True

        except Exception as exc:
            if raise_on_error:
                raise
            return False

    def verify_all_evidence(self) -> Dict[str, bool]:
        """Verify integrity of all evidence records in storage."""
        results = {}
        for file_path in self.raw_dir.glob("*.json"):
            ev_id = file_path.stem
            results[ev_id] = self.verify_evidence(ev_id)
        return results

    def list_evidence(self) -> List[Dict[str, Any]]:
        """Return all entries recorded in the manifest."""
        if not self.manifest_path.exists():
            return []
        self._validate_safe_path(self.manifest_path, self.evidence_dir)
        entries = []
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries
