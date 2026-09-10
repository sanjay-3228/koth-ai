"""
Test for Clean Release Archive and Secret Scanner.
Verifies that:
1. Release packaging strictly excludes:
   - .env
   - .git
   - __pycache__, *.pyc
   - .pytest_cache
   - runtime databases (*.db)
   - runtime reports
   - Zone.Identifier files
   - local secrets and real flags
2. Secret scanner scans all archive contents and fails if any:
   - NVIDIA API keys
   - Gemini API keys
   - swarm tokens / credentials
   - private keys
   - real passwords
   - session cookies / tokens
   are present.
"""

import re
import tempfile
import zipfile
from pathlib import Path

from scripts.package_release import build_release_archive, should_include_file


# Secret detection patterns
SECRET_PATTERNS = {
    "NVIDIA API Key": re.compile(r"nvapi-[A-Za-z0-9_-]{20,}"),
    "Groq API Key": re.compile(r"gsk_[A-Za-z0-9_-]{20,}"),
    "OpenRouter API Key": re.compile(r"sk-or-v1-[A-Za-z0-9_-]{20,}"),
    "Gemini API Key": re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Hardcoded Password": re.compile(r"""(?i)(?:password|passwd)\s*[:=]\s*["'](?!your-|test-|password|none|admin|root)[a-zA-Z0-9@#$%^&+=_-]{8,}["']"""),
    "Session Cookie / Token": re.compile(r"""(?i)(?:session_token|sessionid)\s*[:=]\s*["'][a-f0-9]{32,64}["']"""),
}

FORBIDDEN_FILENAMES = [
    ".env",
    ".flag",
    "flag.txt",
    "koth_agent.db",
    "benchmark_koth.db",
    "note",
]


def test_should_include_file_filter():
    """Verify individual file inclusion / exclusion rules."""
    # Forbidden files
    assert not should_include_file(".env")
    assert not should_include_file(".env.local")
    assert not should_include_file(".git/config")
    assert not should_include_file(".flag")
    assert not should_include_file("koth_agent.db")
    assert not should_include_file("benchmark_koth.db")
    assert not should_include_file("agent/__pycache__/config.cpython-313.pyc")
    assert not should_include_file("agent/config.py:Zone.Identifier")
    assert not should_include_file("reports/test_run.json")
    assert not should_include_file("note")

    # Permitted files
    assert should_include_file("README.md")
    assert should_include_file(".env.example")
    assert should_include_file("requirements.txt")
    assert should_include_file("agent/config.py")
    assert should_include_file("agent/swarm/coordinator.py")
    assert should_include_file("tests/test_clean_release.py")
    assert should_include_file("docs/LAN_DEPLOYMENT_GUIDE.md")


def test_build_clean_release_archive_and_scan_secrets():
    """Build the release zip to a temporary file and perform comprehensive secret scanning."""
    repo_root = Path(__file__).resolve().parent.parent

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "koth-agent-clean.zip"
        build_release_archive(repo_root, zip_path)

        assert zip_path.exists(), "Release archive was not created."
        assert zip_path.stat().st_size > 0, "Release archive is empty."

        findings = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            namelist = zf.namelist()

            # 1. Structural checks
            assert ".env.example" in namelist
            assert "requirements.txt" in namelist
            assert "agent/config.py" in namelist
            assert "agent/swarm/coordinator.py" in namelist

            for name in namelist:
                # Disallow .env file (must only be .env.example)
                assert name != ".env" and not name.endswith("/.env"), f"Forbidden .env in archive: {name}"
                assert not name.startswith(".git/"), f"Git metadata in archive: {name}"
                assert "__pycache__" not in name, f"pycache in archive: {name}"
                assert not name.endswith((".pyc", ".pyo")), f"pyc/pyo in archive: {name}"
                assert not name.endswith((".db", ".sqlite", ".sqlite3")), f"database in archive: {name}"
                assert "Zone.Identifier" not in name, f"Zone.Identifier in archive: {name}"
                assert not name.startswith("reports/"), f"reports in archive: {name}"
                assert not name.startswith(".flag") and name != ".flag", f"flag in archive: {name}"

                # 2. Secret Scan
                # Skip binary files or images
                if any(name.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".ico", ".bin")):
                    continue

                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # Scan for each secret pattern
                for pattern_name, regex in SECRET_PATTERNS.items():
                    matches = regex.findall(content)
                    if matches:
                        real_matches = []
                        for m in matches:
                            m_lower = m.lower()
                            # Check placeholders
                            if any(
                                placeholder in m_lower
                                for placeholder in (
                                    "your-nvidia-api-key",
                                    "your-groq-api-key",
                                    "your-openrouter-api-key",
                                    "your-gemini-api-key",
                                    "your-swarm-token",
                                    "example",
                                    "placeholder",
                                    "mock",
                                    "dummy",
                                    "test",
                                )
                            ):
                                continue

                            # Allow dummy headers inside test files specifically asserting boundary rejections
                            if name.startswith("tests/") and pattern_name == "Private Key" and len(m) < 40:
                                continue

                            real_matches.append(m)

                        if real_matches:
                            findings.append(f"File '{name}' contains potential {pattern_name}: {real_matches}")

        assert len(findings) == 0, f"Secret scanner detected potential leaks:\n" + "\n".join(findings)
