# KOTH Command & KOTH Swarm

[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#)
[![Tests](https://img.shields.io/badge/tests-34%2F34%20passing-brightgreen.svg)](#)
[![Frontend](https://img.shields.io/badge/desktop-Electron%20%7C%20React%2018%20%7C%20Vite-6BADEB.svg)](#)
[![Backend](https://img.shields.io/badge/backend-Python%203.13%20%7C%20FastAPI%20%7C%20SQLite%20WAL-172536.svg)](#)
[![Architecture](https://img.shields.io/badge/architecture-Central%20PC%20%2B%204%20Remote%20Worker%20PCs-2878C8.svg)](#)

**KOTH Command** is a production-grade cybersecurity operations platform and autonomous multi-agent swarm orchestration center designed for **King of the Hill (KOTH)** and **Red Team vs Blue Team** attack/defense competitions.

The platform provides an authoritative central command system and supports a distributed **Five-PC Local Area Network (LAN)** deployment: one Central Operations PC and four dedicated Remote Agent Worker PCs operating with synchronized role-based authority, real-time telemetry, and deterministic security gates.

---

## Table of Contents

- [Architectural Invariants & Core Design](#architectural-invariants--core-design)
- [Five-PC Distributed LAN Architecture](#five-pc-distributed-lan-architecture)
- [Application Workspace & UI](#application-workspace--ui)
- [Competition Engine & 4-Step Wizard](#competition-engine--4-step-wizard)
- [Participant-Facing Operational Features](#participant-facing-operational-features)
- [Independent Per-Agent LLM Advisory Layer](#independent-per-agent-llm-advisory-layer)
- [Production Release Deliverables & Binaries](#production-release-deliverables--binaries)
- [Quickstart: Central PC & Remote Worker Deployment](#quickstart-central-pc--remote-worker-deployment)
- [Verification & Test Suite](#verification--test-suite)
- [Repository Structure](#repository-structure)
- [Documentation Index](#documentation-index)

---

## Architectural Invariants & Core Design

KOTH Command enforces non-negotiable security boundaries that guarantee safety, predictability, and compliance during live cybersecurity competitions:

1. **Advisory-Only LLMs**: Large Language Models (Anthropic Claude, Google Gemini, OpenAI GPT, Ollama/vLLM) possess **ZERO direct execution authority** and **NO raw shell access**. Proposed tactical decisions are strictly advisory.
2. **4-Stage Deterministic Execution Gate**: Every proposed action must pass through an authoritative four-stage authorization gate before execution:
   $$\text{Policy Authorization} \longrightarrow \text{Registry Authorization} \longrightarrow \text{Task Authorization} \longrightarrow \text{Final Execution Gate}$$
3. **Deterministic Fail-Safe SAFE HOLD**: If LLM providers fail, experience network timeouts, disagree, or trip circuit breakers, the swarm immediately falls back to a deterministic, rule-based defensive hold policy.
4. **Authoritative Centralization & Zero Worker DB State**: The Central PC retains complete, authoritative state in SQLite with Write-Ahead Logging (WAL). Remote agent workers maintain zero local database files; they receive leases, report telemetry, and transmit findings exclusively over authenticated REST APIs.
5. **Role-Based Scope & Hill Mapping**: Agents are strictly restricted to their authorized target hills and scopes. Unauthorized lateral commands or impersonation attempts are rejected with `HTTP 403 Forbidden`.
6. **Enterprise Desktop Light Theme**: The desktop user interface follows a restrained, professional enterprise aesthetic (`#F4F7FB` background, `#172536` typography, `#6BADEB` / `#2878C8` accents, `#E2E8F0` borders) built on React 18, Tailwind CSS, and Electron.

---

## Five-PC Distributed LAN Architecture

KOTH Command is engineered to operate seamlessly across a standard five-PC local area network (Ethernet, Wi-Fi hotspot, or private competition subnet) without requiring external internet or third-party cloud infrastructure.

```
+===================================================================================+
|                              CENTRAL OPERATIONS PC                                |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                     KOTH Command Desktop Application                        |  |
|  |              (Electron 28 + React 18 + Vite Enterprise UI)                  |  |
|  +-----------------------------------------------------------------------------+  |
|  |                authoritative Coordinator Engine (koth-coordinator.exe)       |  |
|  |    * REST API & Event Engine (0.0.0.0:5000)   * Swarm Task Manager          |  |
|  |    * SQLite WAL Persistence (koth_swarm.db)   * Network Info & Reachability |  |
|  |    * Real-Time Heartbeat & Telemetry Monitor  * Multi-Agent Coordination Hub|  |
|  +-----------------------------------------------------------------------------+  |
+===================================================================================+
                                         ^
          LAN Network Traffic (HTTP/REST / Optional TLS) on Port 5000
                                         v
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   |    REMOTE PC 1     |  |    REMOTE PC 2     |  |    REMOTE PC 3     |  |    REMOTE PC 4     |
   |      agent-01      |  |      agent-02      |  |      agent-03      |  |      agent-04      |
   | Team Leader / Coord|  | Specialist Worker  |  | Specialist Worker  |  | Specialist Worker  |
   |   Assigned: Hill 1 |  |   Assigned: Hill 2 |  |   Assigned: Hill 3 |  |   Assigned: Hill 4 |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
   | koth-agent-worker  |  | koth-agent-worker  |  | koth-agent-worker  |  | koth-agent-worker  |
   | Standalone Binary  |  | Standalone Binary  |  | Standalone Binary  |  | Standalone Binary  |
   +--------------------+  +--------------------+  +--------------------+  +--------------------+
```

### Team Roster & Default Hill Mapping

| Machine | Agent ID | Default Role | Hill Assignment | Primary Capabilities |
|---|---|---|---|---|
| **Remote PC 1** | `agent-01` | **Team Leader / Coordinator** | **Hill 1** | Coordination, reconnaissance dispatch, hill defense |
| **Remote PC 2** | `agent-02` | **Specialist Worker** | **Hill 2** | Service vulnerability scanning, exploit dispatch |
| **Remote PC 3** | `agent-03` | **Specialist Worker** | **Hill 3** | Privilege escalation, credential auditing, patching |
| **Remote PC 4** | `agent-04` | **Specialist Worker** | **Hill 4** | Host hardening, firewall rules, service recovery |

### Team Registration & Credential Issuance
The Team Leader registers the entire 4-member roster in a single atomic transaction via `/api/team/register-four`:
- Generates high-entropy participant tokens for all 4 agents.
- Automatically assigns Hill 1 through Hill 4.
- Generates one-click enrollment commands for each teammate.

---

## Application Workspace & UI

The KOTH Command desktop application separates competition orchestration into a two-layer workflow:

```
[ Application Startup ]
          │
          ▼
┌─────────────────────────────────────────┐
│     LAYER 1: COMPETITION LAUNCHER       │
│  - Application Landing & Status Banner  │
│  - Select: KOTH or Red vs Blue          │
│  - 4-Step Competition Creation Wizard   │
│  - Join Active LAN Competition Lobby    │
└───────────────────┬─────────────────────┘
                    │ (Launch / Join)
                    ▼
┌─────────────────────────────────────────┐
│     LAYER 2: PARTICIPANT WORKSPACE      │
│  - Real-Time 4-Agent Monitoring Panel   │
│  - Central Server LAN Connection Banner │
│  - Live Event Feed & Severity Filtering │
│  - Swarm Multi-Agent Coordination Hub   │
│  - Hill Status & Flag Submission Portal │
└─────────────────────────────────────────┘
```

---

## Competition Engine & 4-Step Wizard

Competitions are configured through a streamlined, strict 4-step wizard:

### Step 1: Mode & Format Selection
Select between exactly two distinct competition architectures:
- **KOTH (King of the Hill)**:
  - Formats: *Single-Hill*, *Multi-Hill*, *Team-vs-Team*, *Elimination*, *Timed*.
- **Red Team vs Blue Team**:
  - Opposing sides within the same match contesting shared or asymmetric targets.
  - Formats: *Classic*, *Multi-Team*, *Multi-Hill*, *Elimination*, *Timed*, *Continuous Attack and Defense*.

### Step 2: Target Hills Configuration
Configure the authorized hills and target environments:
- Supported Hill Types: **Linux**, **Windows**, **Web Application**, **Database**, **Network**, **Active Directory**, **Cloud Security**, **Container / Kubernetes**, **Forensics / Incident Response**.
- Define target IP addresses, ports, authorized scope, and initial ownership.

### Step 3: Review Configuration
A concise audit summary displaying competition parameters, rules of engagement, and hill targets with back/continue validation.

### Step 4: Launch & Deploy
Authoritative activation of the match:
- Initializes competition state machine in the SQLite database.
- Transitions the coordinator into active phase (`ATTACK` or `DEFENSE`).
- Exposes task queues to registered worker agents.

---

## Participant-Facing Operational Features

Designed specifically for competition participants and team operators:

### 1. Real-Time Agent Monitoring Panel
- **Status Badges**: Online, Busy, Idle, Stale, Disconnected.
- **Hardware Telemetry**: Real-time CPU % and Memory % collected via `psutil`.
- **Assigned Hill & Scope**: Clear indicators of authorized target infrastructure.
- **Connection Health**: Live heartbeat tracking with staleness detection (stale at >30s, disconnected at >60s).
- **Execution Progress**: Displays currently executing task, pending queue, and completed task counters.

### 2. Central Server LAN Connection Banner
Embedded at the top of the participant workspace:
- **Server Address**: Displays the authoritative LAN IP (e.g. `http://192.168.1.100:5000`).
- **Hostname & Reachability**: Validates socket reachability and ping responsiveness.
- **Connected Roster**: Live counter of connected agents (`X / 4 connected`).
- **Join Commands**: Expandable drawer with pre-formatted copy-and-paste commands for teammates:
  ```powershell
  .\koth-agent-worker.exe --enroll --server http://192.168.1.100:5000 --team null_warriors --agent agent-02 --token 1001
  ```

### 3. Live Notifications & Event Feed
- **Streaming Operational Events**: Hill captures, defense alerts, service health drops, task failures, and high-confidence advisories.
- **Severity Badging**: Color-coded markers for `CRITICAL`, `WARNING`, `INFO`, and `SUCCESS`.
- **Interactive Controls**: Filter by severity, search event messages, and acknowledge alerts.

### 4. Multi-Agent Swarm Coordination Hub
- **Direct Messaging**: Peer-to-peer and team-wide broadcast messaging across agents.
- **Findings Broadcast**: Instantly share captured credentials, discovered open ports, or patch diffs across teammates.
- **Dynamic Task Reassignment**: Team leader can reassign active tasks or target hills with automatic authorization re-fencing.

---

## Independent Per-Agent LLM Advisory Layer

Each of the four swarm agents maintains completely independent and sovereign LLM provider configuration:

- **Supported Providers**: Anthropic Claude, Google Gemini, OpenAI GPT, and Local Custom API (Ollama, vLLM, LM Studio).
- **Strict Isolation & RBAC**: Cross-agent configuration reads and writes are blocked by backend policy (`HTTP 403 Forbidden`). Agent 02 cannot inspect or overwrite Agent 01's credentials.
- **Zero Secret Leakage**: API keys and tokens are stored securely in SQLite, masked in all UI views and API payloads (`sk-...1234`), and automatically redacted from logs via regex scrubbers.
- **Benign Safe Probes**: Provider connectivity tests execute a lightweight ping-pong query. Competition flags, passwords, private keys, and target IPs are never transmitted to external model endpoints.

---

## Production Release Deliverables & Binaries

KOTH Command includes pre-compiled, production-ready executables for 64-bit Windows environments:

| Deliverable | Location | Size | Target Host | Description |
|---|---|---|---|---|
| **KOTH Command Desktop Installer** | `dist-installer/KOTH-Command-Setup.exe` | ~97.1 MB | **Central PC** | Official NSIS Windows desktop installer bundling the Electron UI and `koth-coordinator.exe`. |
| **Agent Worker Package** | `dist-installer/KOTH-Agent-Worker-v1.0.0-win-x64.zip` | ~13.9 MB | **Remote PCs (1–4)** | Self-contained ZIP containing `koth-agent-worker.exe`, enrollment wizard, and startup batch files. |
| **Standalone Coordinator Executable** | `backend-dist/koth-coordinator.exe` | 17.32 MB | **Central PC** | PyInstaller-compiled coordinator binary. Zero Python installation required. Listens on `0.0.0.0:5000`. |
| **Standalone Worker Executable** | `agent-worker-dist/koth-agent-worker.exe` | 13.50 MB | **Remote PCs (1–4)** | PyInstaller-compiled agent worker binary. Independent execution runtime. |
| **Portable Unpacked Desktop App** | `dist-installer/win-unpacked/` | ~280 MB | **Central PC** | Unpacked portable application directory for direct execution without running the installer. |

---

## Quickstart: Central PC & Remote Worker Deployment

### Prerequisites
- **Operating System**: Windows 10 or Windows 11 (64-bit).
- **Network**: All five PCs connected to the same LAN (Ethernet switch, Wi-Fi router, or mobile hotspot).

---

### Step 1: Central Operations PC Setup

1. **Install KOTH Command**:
   Run `KOTH-Command-Setup.exe` and complete the installation wizard.
   *(Alternatively, launch `dist-installer/win-unpacked/KOTH Command.exe`)*.

2. **Allow Inbound Port 5000 in Windows Firewall**:
   Open PowerShell as Administrator on the Central PC and run:
   ```powershell
   netsh advfirewall firewall add rule name="KOTH Coordinator Server" dir=in action=allow protocol=TCP localport=5000
   ```

3. **Launch KOTH Command**:
   - The application starts the desktop interface and automatically launches the backend coordinator.
   - The Central Server LAN Connection Banner displays your active LAN IP (e.g. `http://192.168.1.100:5000`).

---

### Step 2: Remote Agent PCs Setup (PCs 1 through 4)

1. **Distribute Worker Package**:
   Copy `dist-installer/KOTH-Agent-Worker-v1.0.0-win-x64.zip` to each of the four teammate PCs (via USB drive or network share) and extract it.

2. **Enroll the Agent Worker (One-Time Setup)**:
   Double-click `enroll_agent.bat` (or open Command Prompt and run):
   ```cmd
   koth-agent-worker.exe --enroll
   ```
   The interactive setup wizard will prompt for:
   - **Central Coordinator URL**: Enter `http://<CENTRAL_PC_LAN_IP>:5000` (e.g. `http://192.168.1.100:5000`).
   - **Team ID**: Enter your registered team identifier (e.g. `null_warriors`).
   - **Agent ID**: Enter `agent-01`, `agent-02`, `agent-03`, or `agent-04`.
   - **Agent Token**: Enter the matching high-entropy token issued by the coordinator.

   *The wizard tests network reachability, verifies credentials with the server, and saves the configuration securely to `agent_config.json`.*

3. **Start the Agent Worker Daemon**:
   Double-click `run_agent.bat` (or execute `koth-agent-worker.exe`).
   The agent worker immediately:
   - Connects to the Central Coordinator.
   - Transmits live hardware metrics (CPU %, Memory %) and heartbeats every 5 seconds.
   - Automatically polls and executes assigned tasks for its authorized hill.
   - Automatically reconnects if temporary network interruptions occur.

---

## Verification & Test Suite

The platform includes a comprehensive, automated regression test suite covering the 5-PC LAN architecture, participant monitoring, notifications, coordination, and per-agent LLM isolation:

```powershell
# Activate Python environment
.\venv\Scripts\Activate.ps1

# Run verified production test suite
python -m pytest tests/test_lan_five_pc_deployment.py tests/test_participant_features.py tests/test_agent_llm_config.py -v
```

### Verified Test Results (34/34 Passing)

```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-8.3.4
collected 34 items

tests/test_lan_five_pc_deployment.py::test_lan_ip_discovery_and_network_info PASSED
tests/test_lan_five_pc_deployment.py::test_four_member_team_registration PASSED
tests/test_lan_five_pc_deployment.py::test_agent_enrollment_and_authentication PASSED
tests/test_lan_five_pc_deployment.py::test_impersonation_rejection PASSED
tests/test_lan_five_pc_deployment.py::test_heartbeat_staleness_and_disconnect_detection PASSED
tests/test_lan_five_pc_deployment.py::test_agent_reconnect_resilience PASSED
tests/test_lan_five_pc_deployment.py::test_task_lease_expiration_and_reallocation PASSED
tests/test_lan_five_pc_deployment.py::test_duplicate_task_execution_prevention PASSED
tests/test_participant_features.py::test_agent_monitoring_endpoint PASSED
tests/test_participant_features.py::test_event_feed_endpoint PASSED
tests/test_participant_features.py::test_event_feed_filtering PASSED
tests/test_participant_features.py::test_event_acknowledgment PASSED
tests/test_participant_features.py::test_coordination_message_endpoint PASSED
tests/test_participant_features.py::test_coordination_message_retrieval PASSED
tests/test_participant_features.py::test_coordination_message_authorization PASSED
tests/test_participant_features.py::test_monitoring_reflects_new_heartbeat PASSED
tests/test_participant_features.py::test_coordination_requires_text PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_crud PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_secret_masking PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_cross_agent_isolation PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_test_connectivity PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_redact_secrets PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_defaults PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_invalid_provider PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_invalid_agent_id PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_missing_required_fields PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_temperature_bounds PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_empty_api_key_update PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_persistence PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_get_for_agent PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_delete PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_export_import PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_concurrent_access PASSED
tests/test_agent_llm_config.py::test_agent_llm_config_malformed_json PASSED

============================= 34 passed in 17.15s =============================
```

---

## Repository Structure

```text
koth-ai-main/
├── agent/                         # Core Swarm & Agent Logic
│   ├── defense/                   # Defensive monitoring, firewalling, and patcher
│   ├── attack/                    # Target reconnaissance and authorized exploit dispatch
│   ├── llm/                       # Independent per-agent LLM adapters & secret redactor
│   ├── security/                  # Deterministic 4-stage execution gate & policy engine
│   ├── swarm/                     # Swarm Coordinator, Task Manager, and Heartbeat Monitor
│   ├── telemetry.py               # Live hardware (psutil) and network telemetry normalization
│   └── worker_main.py             # Agent worker client with auto-reconnect & task execution
├── desktop/                       # Electron & React 18 Desktop Operations Center
│   ├── electron/                  # Electron main process & IPC lifecycle management
│   ├── src/                       # React 18 frontend (Components, Hooks, Services)
│   │   ├── components/            # Agent Monitoring, Event Feed, Swarm Coordination views
│   │   ├── services/              # API clients and WebSocket synchronization
│   │   └── index.css              # Enterprise light theme design tokens
│   └── package.json               # Desktop dependencies and build scripts
├── backend-dist/                  # Compiled Authoritative Coordinator Binary
│   └── koth-coordinator.exe      # Standalone PyInstaller coordinator binary (17.32 MB)
├── agent-worker-dist/             # Compiled Standalone Remote Agent Worker Binary
│   └── koth-agent-worker.exe      # Standalone PyInstaller agent worker binary (13.50 MB)
├── dist-installer/                # Production Distribution Packages
│   ├── KOTH-Command-Setup.exe     # NSIS Windows Desktop Installer (97.1 MB)
│   └── KOTH-Agent-Worker-v1.0.0-win-x64.zip # Remote worker distribution archive (13.9 MB)
├── scripts/                       # Operational & Administrative Utilities
│   ├── generate_lan_cert.py       # Root CA & Server TLS Certificate generator for LAN
│   ├── backup_database.ps1        # Atomic SQLite WAL database backup script
│   └── package_release.py         # Automated release packager and integrity validator
├── tests/                         # Automated Pytest Regression Test Suites
│   ├── test_lan_five_pc_deployment.py  # 5-PC distributed LAN deployment integration tests
│   ├── test_participant_features.py    # Monitoring, notifications, and coordination tests
│   └── test_agent_llm_config.py        # Independent LLM configuration and isolation tests
├── FIVE_PC_LAN_DEPLOYMENT_GUIDE.md# Complete 5-PC deployment guide & network topology
├── DEPLOYMENT.md                  # Central server production setup & operations manual
├── LAN_AGENT_SETUP.md             # Remote teammate laptop setup & enrollment manual
├── LAN_QUICKSTART.md              # Dynamic IP discovery and event LAN quickstart
├── BACKUP_RECOVERY.md             # SQLite WAL backup & disaster recovery procedure
├── RELEASE_VERIFICATION_REPORT.md # Production release audit and verification report
└── README.md                      # This comprehensive documentation file
```

---

## Documentation Index

For in-depth operational instructions, consult the detailed documentation:

- [5-PC LAN Deployment Guide](file:///c:/koth-ai-main/FIVE_PC_LAN_DEPLOYMENT_GUIDE.md): Network configuration, switch setup, firewall rules, and end-to-end multi-PC testing.
- [Central Server Production Deployment Manual](file:///c:/koth-ai-main/DEPLOYMENT.md): Step-by-step instructions for configuring and hosting the central coordinator.
- [Remote Agent PC Setup Guide](file:///c:/koth-ai-main/LAN_AGENT_SETUP.md): Teammate onboarding, credentials configuration, and worker execution.
- [Dynamic LAN Quickstart](file:///c:/koth-ai-main/LAN_QUICKSTART.md): Zero-config dynamic IP discovery and TLS cert generation for event hotspots.
- [Backup & Disaster Recovery Guide](file:///c:/koth-ai-main/BACKUP_RECOVERY.md): Atomic SQLite WAL backup procedures, automated scripts, and point-in-time recovery.
- [Release Verification Report](file:///c:/koth-ai-main/RELEASE_VERIFICATION_REPORT.md): Audit report of the production binaries, installer verification, and test execution matrix.

---

## License & Compliance

This platform is engineered strictly for authorized educational, corporate, and competitive cybersecurity competitions adhering to predefined Rules of Engagement (RoE). Automated actions and security testing are strictly restricted to explicitly designated, authorized target hills. Arbitrary host scanning, unauthorized lateral movement, and out-of-scope command injection are unconditionally blocked by deterministic execution gates.
