#!/usr/bin/env python3

import json
import shlex
import time
from pathlib import Path

from docker_executor import run


BASE = Path.home() / "koth-ai"
LOG_DIR = BASE / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "gateway.jsonl"


# Very small initial policy.
# Expand this only after each command is tested.
ALLOWED_PROGRAMS = {
    "whoami",
    "pwd",
    "ls",
    "cat",
    "printf",
    "echo",
}


def audit(event):
    record = {
        "timestamp": time.time(),
        **event,
    }

    with LOG_FILE.open("a") as f:
        f.write(json.dumps(record) + "\n")


def validate(command):
    if not isinstance(command, list):
        return False, "Command must be a JSON array"

    if not command:
        return False, "Empty command"

    if not all(isinstance(x, str) for x in command):
        return False, "Command arguments must be strings"

    program = command[0]

    if program not in ALLOWED_PROGRAMS:
        return False, f"Program '{program}' is not allowed"

    # Prevent shell interpretation through common shell programs.
    blocked = {
        "sh",
        "bash",
        "zsh",
        "fish",
        "dash",
        "ash",
        "sudo",
        "su",
    }

    if program in blocked:
        return False, f"Shell/privilege program '{program}' is blocked"

    return True, "allowed"


def execute(command):
    allowed, reason = validate(command)

    audit({
        "event": "request",
        "command": command,
        "allowed": allowed,
        "reason": reason,
    })

    if not allowed:
        return {
            "allowed": False,
            "reason": reason,
            "command": command,
        }

    try:
        result = run(command)

        response = {
            "allowed": True,
            **result,
        }

        audit({
            "event": "result",
            **response,
        })

        return response

    except Exception as exc:
        audit({
            "event": "execution_error",
            "command": command,
            "error": str(exc),
        })

        return {
            "allowed": True,
            "execution_error": str(exc),
            "command": command,
        }


def main():
    print("KOTH Gateway")
    print("Execution: Docker")
    print("Network: DISABLED")
    print("Filesystem: READ-ONLY except /workspace")
    print("Policy: DEFAULT DENY")
    print()

    while True:
        try:
            line = input("koth> ").strip()

            if not line:
                continue

            if line in {"exit", "quit"}:
                break

            command = json.loads(line)

            result = execute(command)

            print(json.dumps(result, indent=2))

        except json.JSONDecodeError as exc:
            print(json.dumps({
                "allowed": False,
                "error": f"Invalid JSON: {exc}",
            }, indent=2))

        except KeyboardInterrupt:
            print()
            break

        except Exception as exc:
            print(json.dumps({
                "allowed": False,
                "error": str(exc),
            }, indent=2))


if __name__ == "__main__":
    main()
