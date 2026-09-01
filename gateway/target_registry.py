#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

import yaml

CONFIG = Path.home() / "koth-ai" / "config" / "targets.yaml"
ALLOWED_NETWORK = "koth-lab"


def docker_inspect(container: str) -> dict:
    result = subprocess.run(
        ["sudo", "docker", "inspect", container],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    data = json.loads(result.stdout)

    if not data:
        raise RuntimeError(f"Container not found: {container}")

    return data[0]


def resolve_target(target: dict) -> dict:
    if not target.get("enabled", False):
        raise RuntimeError(f"Target disabled: {target.get('id')}")

    container = target["container"]

    data = docker_inspect(container)

    if data.get("Config", {}).get("NetworkMode") == "host":
        raise RuntimeError(f"Host networking forbidden: {container}")

    networks = data.get("NetworkSettings", {}).get("Networks", {})

    if ALLOWED_NETWORK not in networks:
        raise RuntimeError(
            f"{container} is not attached to {ALLOWED_NETWORK}"
        )

    network = networks[ALLOWED_NETWORK]
    ip = network.get("IPAddress")

    if not ip:
        raise RuntimeError(f"No IP assigned to {container}")

    return {
        "id": target["id"],
        "container": container,
        "protocol": target["protocol"],
        "port": int(target["port"]),
        "enabled": True,
        "network": ALLOWED_NETWORK,
        "ip": ip,
    }


def load_targets():
    if not CONFIG.exists():
        raise RuntimeError(f"Missing target configuration: {CONFIG}")

    with CONFIG.open() as f:
        config = yaml.safe_load(f) or {}

    if config.get("network") != ALLOWED_NETWORK:
        raise RuntimeError(
            f"Configuration must use network '{ALLOWED_NETWORK}'"
        )

    targets = config.get("targets", [])

    return [resolve_target(target) for target in targets]


if __name__ == "__main__":
    try:
        print(json.dumps(load_targets(), indent=2))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": str(exc),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
