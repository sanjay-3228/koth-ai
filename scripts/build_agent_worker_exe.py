"""
Build standalone Windows executable for KOTH Swarm Remote Agent Worker.
Produces: agent-worker-dist/koth-agent-worker.exe
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = repo_root / "agent-worker-dist"
    build_dir = repo_root / "build-agent-worker"
    entry_point = repo_root / "agent_worker_main.py"
    icon_path = repo_root / "desktop" / "build" / "icon.ico"

    dist_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Building standalone KOTH Agent Worker executable...")
    print(f"[*] Entry point: {entry_point}")
    print(f"[*] Output directory: {dist_dir}")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name=koth-agent-worker",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        f"--paths={repo_root}",
        # Exclude bulky ML frameworks not needed by agent worker
        "--exclude-module=torch",
        "--exclude-module=torchvision",
        "--exclude-module=scipy",
        "--exclude-module=pandas",
        "--exclude-module=matplotlib",
        "--exclude-module=IPython",
        "--exclude-module=notebook",
        "--exclude-module=tkinter",
        "--hidden-import=requests",
        "--hidden-import=urllib3",
        "--hidden-import=agent.worker_main",
    ]

    if icon_path.exists():
        cmd.append(f"--icon={icon_path}")

    cmd.append(str(entry_point))

    print(f"[*] Executing PyInstaller command:\n{' '.join(cmd)}\n")
    res = subprocess.run(cmd, cwd=str(repo_root))
    if res.returncode != 0:
        print("[!] PyInstaller build failed!")
        sys.exit(res.returncode)

    exe_path = dist_dir / "koth-agent-worker.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[+] Successfully built KOTH Agent Worker executable: {exe_path} ({size_mb:.2f} MB)")
    else:
        print("\n[!] Error: Expected binary not found at " + str(exe_path))
        sys.exit(1)

if __name__ == "__main__":
    main()

