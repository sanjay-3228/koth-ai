================================================================================
KOTH SWARM — DISTRIBUTED AGENT WORKER (STANDALONE WINDOWS CLIENT)
================================================================================

This package runs on each of the 4 dedicated Agent PCs:
  PC 1: Agent 01 — Team Leader / Swarm Coordinator (Hill 1)
  PC 2: Agent 02 — Reconnaissance Specialist (Hill 2)
  PC 3: Agent 03 — Exploitation Specialist (Hill 3)
  PC 4: Agent 04 — Defense & Hardening Specialist (Hill 4)

QUICK START INSTRUCTIONS:
-------------------------
1. Double click 'enroll_agent.bat' to launch the interactive setup wizard.
2. Enter the Central Server URL (e.g. http://192.168.1.50:5000).
3. Select this PC's Agent seat (1, 2, 3, or 4).
4. Enter your teammate username & password.
5. Setup will test connectivity, enroll the agent, and save your configuration.
6. The agent will immediately enter the active swarm loop!

AUTOMATED / HEADLESS RUN:
-------------------------
koth-agent-worker.exe --coordinator-url "http://192.168.1.50:5000" --agent-id agent-02 --token "<YOUR_TOKEN>"
