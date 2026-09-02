#!/usr/bin/env python3

import subprocess
import uuid
from pathlib import Path


BASE = Path.home() / "koth-ai"
WORKSPACE = BASE / "runtime" / "workspace"
EVIDENCE = BASE / "runtime" / "evidence"

from enum import Enum

IMAGE = "koth-runner:latest"


class RunnerNetwork(str, Enum):
    """Typed authoritative runner network modes."""
    NONE = "none"
    KOTH_LAB = "koth-lab"


ALLOWED_NETWORKS = {RunnerNetwork.NONE.value, RunnerNetwork.KOTH_LAB.value}


def build_docker_cmd(command, container=None, network="none"):
    """Construct the isolated Docker execution command line.

    Preserves:
    - --read-only
    - --cap-drop=ALL
    - --security-opt=no-new-privileges:true
    - Resource limits (memory, cpus, pids-limit)
    - Temporary filesystem limits
    - Strict network allowlisting (defaults to 'none')
    """
    if not command:
        raise ValueError("Empty command")

    if any(arg in ("--privileged", "privileged") for arg in command):
        raise ValueError("Privileged mode is strictly prohibited")

    if isinstance(network, RunnerNetwork):
        network = network.value

    if network not in ALLOWED_NETWORKS:
        raise ValueError(
            f"Unauthorized network '{network}'. Permitted networks: {sorted(list(ALLOWED_NETWORKS))}"
        )

    cid = container or f"koth-job-{uuid.uuid4().hex[:12]}"

    net_flag = "--network=none" if network == "none" else f"--network={network}"

    return [
        "sudo", "-n", "docker", "run",
        "--rm",
        "--name", cid,

        # Isolation
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        net_flag,

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

        "-v",
        f"{EVIDENCE}:/evidence:ro",

        IMAGE,

        *command
    ]


def run(command, timeout=30, network="none"):
    """Execute a command in an isolated ephemeral Docker runner."""
    docker_cmd = build_docker_cmd(command, network=network)

    try:
        name_idx = docker_cmd.index("--name")
        cid = docker_cmd[name_idx + 1]
    except (ValueError, IndexError):
        cid = "unknown"

    try:
        result = subprocess.run(
            docker_cmd,
            cwd=str(WORKSPACE),
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return {
            "container": cid,
            "command": command,
            "network": network,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except Exception as exc:
        return {
            "container": cid,
            "command": command,
            "network": network,
            "return_code": -1,
            "stdout": "",
            "stderr": str(exc),
        }


if __name__ == "__main__":
    import json
    import sys

    command = sys.argv[1:]

    if not command:
        print("Usage: docker_executor.py COMMAND [ARGS...]")
        raise SystemExit(1)

    print(json.dumps(run(command), indent=2))
