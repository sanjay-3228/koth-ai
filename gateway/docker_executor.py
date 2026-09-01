#!/usr/bin/env python3

import subprocess
import uuid
from pathlib import Path


BASE = Path.home() / "koth-ai"
WORKSPACE = BASE / "runtime" / "workspace"
EVIDENCE = BASE / "runtime" / "evidence"

IMAGE = "koth-runner:latest"


def run(command, timeout=30):
    if not command:
        raise ValueError("Empty command")

    container = f"koth-job-{uuid.uuid4().hex[:12]}"

    docker_cmd = [
        "sudo", "docker", "run",
        "--rm",
        "--name", container,

        # Isolation
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--network=none",

        # Resource limits
        "--memory=2g",
        "--cpus=2",
        "--pids-limit=512",

        # Temporary filesystems
        "--tmpfs",
        "/tmp:rw,size=512m,nosuid,nodev,noexec",

        "--tmpfs",
        "/run:rw,size=64m,nosuid,nodev,noexec",

        # ONLY workspace is writable
        "-v",
        f"{WORKSPACE}:/workspace:rw",

        IMAGE,

        *command
    ]

    result = subprocess.run(
        docker_cmd,
        cwd=str(WORKSPACE),
        capture_output=True,
        text=True,
        timeout=timeout + 5,
    )

    return {
        "container": container,
        "command": command,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


if __name__ == "__main__":
    import json
    import sys

    command = sys.argv[1:]

    if not command:
        print("Usage: docker_executor.py COMMAND [ARGS...]")
        raise SystemExit(1)

    print(json.dumps(run(command), indent=2))
