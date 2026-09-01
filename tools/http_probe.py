#!/usr/bin/env python3

import json
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print(json.dumps({
            "error": "usage: http_probe.py <target-ip>"
        }))
        return 2

    target_ip = sys.argv[1]

    # This tool is intentionally limited to an IP supplied by the
    # target registry. It does not accept arbitrary shell commands.
    url = f"http://{target_ip}:8080/"

    result = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "5",
            "--include",
            url,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    print(json.dumps({
        "tool": "http_probe",
        "target": target_ip,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, indent=2))

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
