"""
Clean Release Packaging and Secret Scanning Utility.
Produces clean distribution bundles stripped of local secrets, environments,
caches, runtime databases, and debug reports.
"""

import os
import re
import sys
import zipfile
from pathlib import Path
from typing import List, Union

FORBIDDEN_FILENAMES = {
    ".env",
    ".flag",
    "flag.txt",
    "koth_agent.db",
    "benchmark_koth.db",
    "note",
}

EXCLUDED_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
    "reports",
    "certs",
}

FORBIDDEN_EXTENSIONS = (
    ".pyc",
    ".pyo",
    ".pyd",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".key",
)

SECRET_PATTERNS = {
    "NVIDIA API Key": re.compile(r"nvapi-[A-Za-z0-9_-]{20,}"),
    "Groq API Key": re.compile(r"gsk_[A-Za-z0-9_-]{20,}"),
    "OpenRouter API Key": re.compile(r"sk-or-v1-[A-Za-z0-9_-]{20,}"),
    "Gemini API Key": re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Hardcoded Password": re.compile(
        r"""(?i)(?:password|passwd)\s*[:=]\s*["'](?!your-|test-|password|none|admin|root)[a-zA-Z0-9@#$%^&+=_-]{8,}["']"""
    ),
    "Session Cookie / Token": re.compile(
        r"""(?i)(?:session_token|sessionid)\s*[:=]\s*["'][a-f0-9]{32,64}["']"""
    ),
}

PLACEHOLDER_WHITELIST = (
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


def should_include_file(file_path: Union[str, Path]) -> bool:
    """Determine whether a given file path should be included in the release archive."""
    p = Path(file_path)
    posix_path = p.as_posix()

    if not posix_path or posix_path == ".":
        return False

    # Check for Zone.Identifier
    if "Zone.Identifier" in posix_path:
        return False

    parts = p.parts
    filename = p.name

    # Check directory components
    for part in parts[:-1]:
        if part in EXCLUDED_DIR_NAMES or part.startswith(".git"):
            return False

    # If the root directory or single component is in EXCLUDED_DIR_NAMES
    if len(parts) > 1 and parts[0] in EXCLUDED_DIR_NAMES:
        return False

    # Check reports directory
    if posix_path.startswith("reports/") or (parts and parts[0] == "reports"):
        return False

    # Check exact forbidden filenames
    if filename in FORBIDDEN_FILENAMES:
        return False

    # Check .env files (.env.example is allowed, all other .env* are forbidden)
    if filename == ".env.example":
        pass
    elif filename == ".env" or filename.startswith(".env.") or filename.startswith(".env"):
        return False

    # Check flag files
    if filename == ".flag" or filename.startswith(".flag") or filename == "flag.txt":
        return False

    # Check forbidden extensions
    lower_name = filename.lower()
    if lower_name.endswith(FORBIDDEN_EXTENSIONS):
        return False

    # Check temp / swap files
    if lower_name.endswith("~") or lower_name.startswith(".#") or lower_name.endswith(".swp"):
        return False

    return True


def should_include_dir(dir_path: Union[str, Path]) -> bool:
    """Determine whether directory should be traversed during archive packaging."""
    p = Path(dir_path)
    posix_path = p.as_posix()
    if not posix_path or posix_path == ".":
        return True

    parts = p.parts
    for part in parts:
        if part in EXCLUDED_DIR_NAMES or part.startswith(".git"):
            return False
    return True


def build_release_archive(repo_root: Path, zip_path: Path) -> Path:
    """Build a clean zip archive from repo_root at zip_path."""
    repo_root = Path(repo_root).resolve()
    zip_path = Path(zip_path).resolve()
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(repo_root):
            rel_root = Path(root).relative_to(repo_root)
            # Filter directories in-place to avoid descending into excluded trees
            dirs[:] = [
                d for d in dirs
                if should_include_dir(rel_root / d if rel_root != Path(".") else Path(d))
            ]

            for f in sorted(files):
                full_path = Path(root) / f
                rel_file = full_path.relative_to(repo_root)
                rel_posix = rel_file.as_posix()
                if should_include_file(rel_posix):
                    zf.write(full_path, arcname=rel_posix)

    return zip_path


def scan_archive_for_secrets(zip_path: Path) -> List[str]:
    """Scan all text files in zip_path for potential secret leaks."""
    findings = []
    zip_path = Path(zip_path).resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        for name in namelist:
            if any(name.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".ico", ".bin")):
                continue

            try:
                content = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue

            for pattern_name, regex in SECRET_PATTERNS.items():
                matches = regex.findall(content)
                if matches:
                    real_matches = []
                    for m in matches:
                        m_lower = m.lower()
                        if any(placeholder in m_lower for placeholder in PLACEHOLDER_WHITELIST):
                            continue

                        if name.startswith("tests/") and pattern_name == "Private Key" and len(m) < 40:
                            continue

                        real_matches.append(m)

                    if real_matches:
                        findings.append(f"File '{name}' contains potential {pattern_name}: {real_matches}")

    return findings


def main():
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dist_dir / "koth-agent-release.zip"

    print(f"Building clean release archive: {zip_path}")
    build_release_archive(repo_root, zip_path)
    print(f"Archive built successfully ({zip_path.stat().st_size:,} bytes).")

    print("Running automated secret scan on package...")
    findings = scan_archive_for_secrets(zip_path)
    if findings:
        print("ERROR: Secret scanner detected potential leaks:")
        for finding in findings:
            print(f"  - {finding}")
        sys.exit(1)

    print("Secret scan passed! Release archive is clean.")


if __name__ == "__main__":
    main()
