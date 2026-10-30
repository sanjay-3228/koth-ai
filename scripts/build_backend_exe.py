"""
Build script to package the KOTH Swarm Coordinator Python backend into a standalone Windows executable.
Outputs to: backend-dist/koth-coordinator.exe
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
ENTRY_POINT = ROOT_DIR / "backend_main.py"
OUTPUT_DIR = ROOT_DIR / "backend-dist"
TEMPLATES_DIR = ROOT_DIR / "agent" / "templates"

def build():
    print(f"[*] Packaging KOTH Backend from {ENTRY_POINT}...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--name",
        "koth-coordinator",
        "--onefile",
        "--distpath",
        str(OUTPUT_DIR),
        "--workpath",
        str(ROOT_DIR / "build" / "pyinstaller"),
        "--specpath",
        str(ROOT_DIR / "build"),
        f"--add-data={TEMPLATES_DIR};agent/templates",
        "--hidden-import=sqlite3",
        "--hidden-import=flask",
        "--hidden-import=werkzeug",
        "--hidden-import=cryptography",
        "--hidden-import=agent.swarm.coordinator",
        "--hidden-import=agent.swarm.coordinator_server",
        "--hidden-import=agent.swarm.models",
        "--hidden-import=agent.swarm.events",
        "--hidden-import=agent.swarm.heartbeat",
        "--hidden-import=agent.swarm.leases",
        "--hidden-import=agent.swarm.phase_manager",
        "--hidden-import=agent.swarm.shared_state",
        "--hidden-import=agent.swarm.task_manager",
        "--hidden-import=agent.swarm.team_manager",
        "--hidden-import=agent.competition.manager",
        "--hidden-import=agent.competition.models",
        "--hidden-import=agent.hill.manager",
        "--hidden-import=agent.hill.verifier",
        "--hidden-import=agent.llm.agent_config",
        "--hidden-import=agent.llm.client_factory",
        "--hidden-import=agent.db",
        "--hidden-import=agent.config",
        # Exclude unnecessary global site-packages
        "--exclude-module=torch",
        "--exclude-module=torchaudio",
        "--exclude-module=torchvision",
        "--exclude-module=scipy",
        "--exclude-module=pandas",
        "--exclude-module=matplotlib",
        "--exclude-module=IPython",
        "--exclude-module=jupyter",
        "--exclude-module=sympy",
        "--exclude-module=transformers",
        "--exclude-module=mediapipe",
        "--exclude-module=ctranslate2",
        "--exclude-module=faster_whisper",
        "--exclude-module=pyannote",
        "--exclude-module=tkinter",
        str(ENTRY_POINT),
    ]

    print("[*] Running command:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=str(ROOT_DIR))
    if res.returncode != 0:
        print(f"[!] PyInstaller failed with code {res.returncode}")
        sys.exit(res.returncode)

    exe_path = OUTPUT_DIR / "koth-coordinator.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"[+] Successfully built standalone backend: {exe_path} ({size_mb:.2f} MB)")
    else:
        print("[!] Target executable not found after build.")
        sys.exit(1)

if __name__ == "__main__":
    build()
