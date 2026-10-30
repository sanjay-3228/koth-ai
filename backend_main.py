"""
KOTH Command - Standalone Packaged Coordinator Server
Entry point for PyInstaller compilation into a single Windows binary (koth-coordinator.exe).
"""

import os
import sys

# Ensure base directory is present on sys.path
if getattr(sys, "frozen", False):
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from agent.swarm.coordinator_server import main

if __name__ == "__main__":
    main()

