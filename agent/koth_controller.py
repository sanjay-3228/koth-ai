"""CLI entrypoint for koth-agent with 4-agent swarm support for PwnGrounds.

Examples:
  python -m agent.koth_controller --once
  python -m agent.koth_controller --agent-id agent-01 --swarm
  python -m agent.koth_controller --agent-id agent-02 --coordinator-url https://<COORDINATOR_LAN_IP>:5000 --swarm
  python -m agent.koth_controller --rehearsal
"""
import argparse
import logging
import signal
import sys
import threading
import time
from typing import Optional

if __package__ is None or __package__ == "":
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agent.config import ConfigProfile, config, load_config
    from agent.logger import setup_logging
    from agent.main import KothAgent
    from agent.swarm.client import SwarmClient
    from agent.swarm.models import Phase
else:
    from .config import ConfigProfile, config, load_config
    from .logger import setup_logging
    from .main import KothAgent
    from .swarm.client import SwarmClient
    from .swarm.models import Phase

logger = logging.getLogger("koth.controller")


def run_worker_loop(
    swarm_client: SwarmClient,
    max_cycles: Optional[int] = None,
    poll_interval: float = 0.5,
) -> int:
    """Continuous worker execution loop for multi-process swarm rehearsals."""
    stop_event = threading.Event()

    def _sig_handler(sig, frame):
        logger.info(f"[{swarm_client.agent_id}] Received stop signal, shutting down worker loop.")
        stop_event.set()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print(f"Registering with coordinator at {swarm_client.coordinator_url}")
    logger.info(f"Registering with coordinator at {swarm_client.coordinator_url}")
    registered = swarm_client.register(role="WORKER")
    if not registered:
        logger.warning(f"[{swarm_client.agent_id}] Initial registration failed; will retry in worker loop.")

    swarm_client.start_heartbeat_loop()
    cycles = 0

    try:
        while not stop_event.is_set():
            if not swarm_client.session_token:
                logger.debug(f"[{swarm_client.agent_id}] No active session; attempting registration...")
                swarm_client.register(role="WORKER")

            if swarm_client.kill_switch_active:
                logger.warning(f"[{swarm_client.agent_id}] Kill switch active! Halting active operations.")
                time.sleep(poll_interval)
                continue

            phase_state = swarm_client.sync_phase()
            current_phase = phase_state.phase

            if current_phase in (Phase.HOLD, Phase.UNKNOWN):
                logger.debug(
                    f"[{swarm_client.agent_id}] Standing by in safe hold (epoch={phase_state.phase_epoch})."
                )
            elif current_phase in (Phase.ATTACK, Phase.DEFENSE):
                task, lease = swarm_client.request_task()
                if task:
                    logger.info(
                        f"[{swarm_client.agent_id}] Leased task {task.task_id} for target {task.target_host} (lease {lease.lease_id})"
                    )
                    # Simulated execution for rehearsal
                    time.sleep(0.1)

                    result = {
                        "status": "success",
                        "target": task.target_host,
                        "action_type": task.task_type.value,
                        "epoch": phase_state.phase_epoch,
                        "simulated": True,
                    }
                    completed = swarm_client.complete_task(result=result)
                    if completed:
                        logger.info(f"[{swarm_client.agent_id}] Completed task {task.task_id}")
                        if current_phase == Phase.ATTACK:
                            swarm_client.update_shared_state({
                                "scan": {
                                    "host": task.target_host,
                                    "ports": [22, 80],
                                    "os": "linux",
                                },
                                "compromise": {
                                    "host": task.target_host,
                                    "agent_id": swarm_client.agent_id,
                                },
                                "flag": {
                                    "flag_hash": f"flag_{swarm_client.agent_id}_{task.target_host}_{phase_state.phase_epoch}",
                                    "agent_id": swarm_client.agent_id,
                                    "round_id": phase_state.round_id,
                                },
                            })
                        elif current_phase == Phase.DEFENSE:
                            swarm_client.update_shared_state({
                                "patch": {
                                    "service_or_host": task.target_host,
                                    "agent_id": swarm_client.agent_id,
                                    "details": "hardened firewall & verified flag",
                                }
                            })
                else:
                    logger.debug(
                        f"[{swarm_client.agent_id}] No task available for phase {current_phase.value}"
                    )

            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                logger.info(f"[{swarm_client.agent_id}] Completed requested max cycles ({max_cycles}).")
                break

            time.sleep(poll_interval)
    finally:
        swarm_client.stop()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="koth-agent controller")
    parser.add_argument("--target", help="Target host override", default=None)
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument("--skip-model-validation", action="store_true")
    parser.add_argument(
        "--agent-id",
        help="Swarm agent ID (e.g. agent-01, agent-02, agent-03, agent-04)",
        default=None,
    )
    parser.add_argument("--team-id", help="Swarm team ID (e.g. null_warriors)", default=None)
    parser.add_argument("--username", help="Swarm username (e.g. sanjay/prachi/aman/akshitha) for username login", default=None)
    parser.add_argument("--coordinator-url", help="HTTP URL to swarm coordinator", default=None)
    parser.add_argument("--swarm", action="store_true", help="Enable 4-agent swarm mode")
    parser.add_argument(
        "--role", choices=["PRIMARY", "WORKER"], help="Agent role in swarm", default=None
    )
    parser.add_argument(
        "--rehearsal", action="store_true", help="Run 4-agent swarm rehearsal simulation"
    )
    parser.add_argument(
        "--profile",
        choices=["DEV", "LOCAL_REHEARSAL", "PWNGROUNDS_SIM", "LAN_REHEARSAL", "RADMIN_REHEARSAL"],
        help="Configuration profile",
        default=None,
    )
    parser.add_argument(
        "--auth-token",
        help="Shared swarm authentication token (default: SWARM_AUTH_TOKEN)",
        default=None,
    )
    parser.add_argument(
        "--agent-token",
        help="Unique per-agent secret token (default: SWARM_AGENT_TOKEN)",
        default=None,
    )
    parser.add_argument(
        "--ca-cert",
        help="Path to CA certificate for TLS coordinator verification",
        default=None,
    )
    parser.add_argument(
        "--use-tls",
        action="store_true",
        help="Enable HTTPS TLS transport for swarm communication",
    )
    parser.add_argument(
        "--worker",
        action="store_true",
        help="Run continuous swarm worker loop",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Maximum cycles before clean exit (useful for rehearsal tests)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="Worker poll interval in seconds",
    )
    args = parser.parse_args()

    setup_logging()

    if args.profile:
        try:
            p = ConfigProfile(args.profile.strip())
        except ValueError:
            p = ConfigProfile.LOCAL_REHEARSAL
        prof_cfg = load_config(profile=p)
        for k, v in prof_cfg.__dict__.items():
            if not k.startswith("_"):
                setattr(config, k, v)

    if args.rehearsal:
        from .swarm.rehearsal import run_swarm_rehearsal

        success = run_swarm_rehearsal()
        return 0 if success else 1

    if args.agent_id:
        config.agent_id = args.agent_id.strip()
    if args.team_id:
        config.team_id = args.team_id.strip()
    if args.coordinator_url:
        config.coordinator_url = args.coordinator_url.strip()
    if args.auth_token:
        config.swarm_auth_token = args.auth_token.strip()
    if args.agent_token:
        config.agent_token = args.agent_token.strip()
    if args.ca_cert:
        config.ca_cert = args.ca_cert.strip()
    if args.use_tls:
        config.use_tls = True
    if args.role:
        config.agent_role = args.role.strip()
    if args.swarm or args.worker:
        config.swarm_enabled = True

    if args.target:
        target = args.target.strip()
        import ipaddress

        try:
            ipaddress.ip_address(target)
        except ValueError:
            parser.error("--target must be a valid IP address")
        if target not in config.target_hosts:
            config.target_hosts.append(target)

    if not config.coordinator_url:
        coord_lan_ip = os.getenv("COORDINATOR_LAN_IP")
        if coord_lan_ip:
            scheme = "https" if (config.use_tls or args.use_tls) else "http"
            config.coordinator_url = f"{scheme}://{coord_lan_ip}:{config.swarm_port}"

    swarm_client = None
    if config.swarm_enabled:
        print(f"Team: {config.team_id}")
        print(f"Agent: {config.agent_id}")
        print(f"Coordinator: {config.coordinator_url}")
        print(f"TLS: {'enabled' if (config.use_tls or args.use_tls) else 'disabled'}")
        print("Phase: HOLD")

        swarm_client = SwarmClient(
            agent_id=config.agent_id,
            team_id=config.team_id,
            coordinator_url=config.coordinator_url,
            auth_token=config.swarm_auth_token,
            agent_credential=config.agent_token,
            ca_cert=config.ca_cert,
            use_tls=config.use_tls,
            username=args.username,
        )

    if args.worker:
        if args.username and swarm_client:
            if not swarm_client.login_with_username():
                logger.error("Username login failed; worker will not start")
                return 1
        return run_worker_loop(
            swarm_client=swarm_client,
            max_cycles=args.max_cycles,
            poll_interval=args.poll_interval,
        )

    if swarm_client:
        if args.username:
            if not swarm_client.login_with_username():
                logger.error("Username login failed; agent will not start")
                return 1
            if not swarm_client.register():
                logger.error("Coordinator registration failed; agent will not start")
                return 1
        swarm_client.sync_phase()
        swarm_client.start_heartbeat_loop()

    agent = KothAgent(
        config=config,
        skip_validation=args.skip_model_validation,
        swarm_client=swarm_client,
    )

    if args.once:
        agent.tick()
        if swarm_client:
            swarm_client.stop()
        return 0

    try:
        agent.run_forever()
    finally:
        if swarm_client:
            swarm_client.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
