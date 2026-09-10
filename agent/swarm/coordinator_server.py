"""
Standalone HTTP Swarm Coordinator Server for Local LAN Rehearsals and Multi-Agent Orchestration.

Exposes REST endpoints for:
- Agent registration with team & roster validation
- Heartbeat tracking with liveness detection
- Authoritative phase polling & advancement
- Exclusive task leases, renews, completions, failures
- Shared intelligence snapshot & updates (zero credential leakage)
- Kill switch triggers
- Public minimal health probe (/healthz)
"""

import argparse
import ipaddress
import logging
import signal
import sys
import threading
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template_string

from agent.config import ConfigProfile, load_config
from agent.swarm.coordinator import SwarmCoordinator, create_coordinator_blueprint

logger = logging.getLogger("koth.swarm.coordinator_server")



ADMIN_CONSOLE_HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KOTH Swarm Command Center</title>
<style>
body{font-family:system-ui;background:#0b1020;color:#eef2ff;max-width:1100px;margin:28px auto;padding:20px}
.card{background:#111827;border:1px solid #26334d;border-radius:14px;padding:18px;margin:14px 0}
button{padding:12px 18px;margin:5px;border:0;border-radius:8px;font-weight:700;cursor:pointer}.attack{background:#dc2626;color:white}.defense{background:#2563eb;color:white}.hold{background:#64748b;color:white}.danger{background:#991b1b;color:white}
input{padding:12px;width:100%;max-width:420px;background:#0f172a;color:white;border:1px solid #334155;border-radius:8px;box-sizing:border-box}
#phase{font-size:30px;font-weight:800;margin:10px 0}.muted{color:#94a3b8}.hidden{display:none}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.agent{border:1px solid #334155;border-radius:12px;padding:14px;background:#0f172a}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;background:#64748b}.online .dot{background:#22c55e}.offline .dot{background:#ef4444}.status{font-weight:800}.small{font-size:13px}.bar{height:8px;background:#1e293b;border-radius:5px;overflow:hidden}.bar>div{height:100%;width:0%;background:#22c55e;transition:width .3s}.row{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
</style></head><body>
<h1>KOTH Swarm Command Center</h1>
<div id="login" class="card"><h2>Login</h2><p class="muted">Enter your assigned username. In LOCAL_REHEARSAL username login is enabled for this test.</p><input id="username" autocomplete="username" placeholder="Username (admin / sanjay / prachi / aman / akshitha)"><br><button onclick="login()">LOGIN</button><div id="loginmsg" class="muted"></div></div>
<div id="app" class="hidden">
<div class="card"><div class="row"><div><div class="muted">Logged in as</div><strong id="who">--</strong></div><div><div class="muted">Team</div><strong id="team">--</strong></div></div><div id="phase">PHASE: --</div><div id="phaseStatus" class="muted">Loading…</div></div>
<div id="operatorControls" class="card hidden"><h2>Manual phase control</h2><p class="muted">Only the administrator can change the authoritative team phase.</p><button class="attack" onclick="setPhase('ATTACK')">ATTACK</button><button class="defense" onclick="setPhase('DEFENSE')">DEFENSE</button><button class="hold" onclick="setPhase('HOLD')">HOLD</button><h3>Emergency</h3><button class="danger" onclick="killSwitch()">KILL SWITCH</button></div>
<div class="card"><div class="row"><h2>Agent status</h2><div id="summary" class="muted">0/4 connected</div></div><div id="agents" class="grid"></div></div>
<div class="card"><h2>Task activity</h2><div id="tasks" class="grid"></div></div>
</div>
<script>
let session=sessionStorage.getItem('koth_session')||'';
const esc=s=>String(s??'--').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
function headers(){return {'Content-Type':'application/json','X-Session-Token':session,'Authorization':'Bearer '+session};}
async function login(){const u=document.getElementById('username').value.trim();if(!u){return;}const r=await fetch('/api/swarm/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});const d=await r.json();if(!r.ok||!d.logged_in){document.getElementById('loginmsg').textContent=d.message||'Login rejected';return;}session=d.session_token;sessionStorage.setItem('koth_session',session);document.getElementById('login').classList.add('hidden');document.getElementById('app').classList.remove('hidden');document.getElementById('who').textContent=d.username+' · '+d.role;document.getElementById('operatorControls').classList.toggle('hidden',d.role!=='OPERATOR');refresh();}
async function refresh(){if(!session)return;try{const r=await fetch('/api/swarm/status',{headers:headers()});if(r.status===401){session='';sessionStorage.removeItem('koth_session');location.reload();return;}const d=await r.json();const p=d.phase||{};document.getElementById('phase').textContent='PHASE: '+(p.phase||'HOLD');document.getElementById('team').textContent=d.team_id||'--';document.getElementById('phaseStatus').textContent='Epoch '+(p.phase_epoch||0)+' · Round '+(p.round_id||0)+' · '+(p.source||'coordinator');const entries=Object.entries(d.agents||{});const online=entries.filter(([,a])=>a.alive).length;document.getElementById('summary').textContent=online+'/'+entries.length+' connected';document.getElementById('agents').innerHTML=entries.map(([id,a])=>{const pct=a.alive?100:0;return `<div class="agent ${a.alive?'online':'offline'}"><h3><span class="dot"></span>${esc(a.username)} <span class="muted">(${esc(id)})</span></h3><div class="status">${esc(a.status)} · ${esc(a.phase)}</div><div class="small muted">Task: ${esc(a.current_task_type||'IDLE')}</div><div class="small">Target: ${esc(a.current_target||'--')}</div><div class="small">Task status: ${esc(a.task_status||'--')}</div><div class="small muted">Heartbeat: ${a.last_heartbeat?new Date(a.last_heartbeat*1000).toLocaleTimeString():'never'}</div><div class="bar"><div style="width:${pct}%"></div></div></div>`}).join('');const tc=d.task_counts||{};document.getElementById('tasks').innerHTML=`<div class="agent"><strong>Total</strong><div>${tc.total||0}</div></div><div class="agent"><strong>Pending</strong><div>${tc.pending||0}</div></div><div class="agent"><strong>Leased</strong><div>${tc.leased||0}</div></div><div class="agent"><strong>Completed</strong><div>${tc.completed||0}</div></div><div class="agent"><strong>Failed</strong><div>${tc.failed||0}</div></div>`;}catch(e){document.getElementById('phaseStatus').textContent='Coordinator unavailable';}}
async function setPhase(phase){const r=await fetch('/api/swarm/phase/advance',{method:'POST',headers:headers(),body:JSON.stringify({phase})});const d=await r.json();if(!r.ok)alert(d.message||'Phase change rejected');else refresh();}
async function killSwitch(){if(!confirm('ENGAGE KILL SWITCH for all agents?'))return;const r=await fetch('/api/swarm/kill-switch',{method:'POST',headers:headers(),body:JSON.stringify({reason:'Admin console emergency stop'})});const d=await r.json();alert(d.status||d.message||'Request complete');refresh();}
async function restore(){if(!session)return;try{const r=await fetch('/api/swarm/session',{headers:headers()});if(!r.ok){session='';sessionStorage.removeItem('koth_session');return;}const d=await r.json();document.getElementById('login').classList.add('hidden');document.getElementById('app').classList.remove('hidden');document.getElementById('who').textContent=d.username+' · '+d.role;document.getElementById('operatorControls').classList.toggle('hidden',d.role!=='OPERATOR');refresh();}catch(e){}}
restore();setInterval(refresh,2000);
</script></body></html>
"""

def create_coordinator_app(coordinator: SwarmCoordinator) -> Flask:
    """Factory creating Flask app hosting the Swarm Coordinator REST API."""
    app = Flask("koth_swarm_coordinator")
    bp = create_coordinator_blueprint(coordinator)
    app.register_blueprint(bp)

    @app.route("/admin")
    def admin_console():
        return render_template_string(ADMIN_CONSOLE_HTML)

    @app.route("/")
    @app.route("/healthz")
    def healthz():
        """
        Public health probe revealing strictly operational state without sensitive credentials.
        Exposes exactly: service status, team ID, phase, round, phase epoch, registered agent count.
        """
        phase_state = coordinator.get_phase()
        alive_count = len([
            aid
            for aid, a in coordinator.get_swarm_status().get("agents", {}).items()
            if a.get("alive")
        ])
        return jsonify({
            "service_status": "ok",
            "team_id": coordinator.team_id,
            "phase": phase_state.phase.value,
            "round": phase_state.round_id,
            "phase_epoch": phase_state.phase_epoch,
            "registered_agent_count": alive_count,
        })

    return app


def validate_binding_host(host: str, profile: ConfigProfile) -> str:
    """Validate binding host rules for local vs private LAN rehearsal."""
    if not host:
        if profile in (ConfigProfile.LAN_REHEARSAL, ConfigProfile.RADMIN_REHEARSAL):
            raise ValueError(
                f"In {profile.value} profile, coordinator host must be explicitly configured "
                "with a private LAN IP (cannot be empty)."
            )
        return "127.0.0.1"

    if host == "0.0.0.0":
        raise ValueError(
            "Coordinator server cannot be automatically exposed to 0.0.0.0. "
            "Specify an explicit private LAN IP address or 127.0.0.1."
        )

    if profile in (ConfigProfile.LAN_REHEARSAL, ConfigProfile.RADMIN_REHEARSAL):
        if host == "127.0.0.1":
            raise ValueError(
                f"In {profile.value} profile, coordinator host must NOT be 127.0.0.1. "
                "An explicit private LAN IP address is required."
            )
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
                raise ValueError(
                    f"Coordinator host '{host}' is not a permitted host address."
                )
            is_radmin = ip in ipaddress.ip_network("26.0.0.0/8")
            if profile == ConfigProfile.RADMIN_REHEARSAL:
                if not (ip.is_private or is_radmin):
                    raise ValueError(
                        f"Coordinator host '{host}' must be a valid private LAN (RFC 1918) or Radmin VPN (26.0.0.0/8) address."
                    )
            else:
                if not ip.is_private:
                    raise ValueError(
                        f"Coordinator host '{host}' must be a valid private LAN IP address (RFC 1918)."
                    )
        except ValueError as ve:
            raise ValueError(f"Coordinator host '{host}' is invalid: {ve}")

    return host


def run_coordinator_server(
    host: Optional[str] = None,
    port: Optional[int] = None,
    profile: str = "LOCAL_REHEARSAL",
    auth_token: Optional[str] = None,
    operator_token: Optional[str] = None,
    agent_tokens: Optional[Dict[str, str]] = None,
    authorized_agents: Optional[List[str]] = None,
    lease_ttl: float = 15.0,
    heartbeat_timeout: float = 10.0,
    maintenance_interval: float = 1.0,
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
    use_tls: bool = False,
    coordinator: Optional[SwarmCoordinator] = None,
    agent_usernames: Optional[Dict[str, str]] = None,
    admin_username: str = "admin",
    enable_username_login: bool = False,
) -> None:
    """Run coordinator server and block until interrupted."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [COORDINATOR] %(message)s",
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    try:
        cfg_profile = ConfigProfile(profile)
    except ValueError:
        cfg_profile = ConfigProfile.LOCAL_REHEARSAL

    cfg = load_config(profile=cfg_profile)

    target_hosts = getattr(
        cfg,
        "target_hosts",
        ["10.254.254.11", "10.254.254.12", "10.254.254.13", "10.254.254.14"],
    )
    own_hosts = getattr(
        cfg,
        "own_hosts",
        ["10.254.254.101", "10.254.254.102", "10.254.254.103", "10.254.254.104"],
    )

    candidate_host = host or cfg.swarm_bind_host
    resolved_host = validate_binding_host(candidate_host, cfg_profile)
    resolved_port = port or cfg.swarm_port or 5000

    resolved_token = auth_token if auth_token is not None else cfg.swarm_auth_token
    resolved_operator_token = operator_token if operator_token is not None else cfg.operator_token
    resolved_agent_tokens = agent_tokens if agent_tokens is not None else cfg.agent_tokens
    resolved_agents = authorized_agents if authorized_agents is not None else cfg.authorized_agents

    if enable_username_login and (cfg_profile != ConfigProfile.LOCAL_REHEARSAL or resolved_host != "127.0.0.1"):
        raise ValueError("Username-only login is restricted to LOCAL_REHEARSAL on 127.0.0.1; use provisioned agent credentials for LAN deployment.")

    if agent_usernames is None:
        agent_usernames = {
            "agent-01": "sanjay",
            "agent-02": "prachi",
            "agent-03": "aman",
            "agent-04": "akshitha",
        }

    if coordinator is None:
        coordinator = SwarmCoordinator(
            team_id=cfg.team_id or "null_warriors",
            lease_ttl=lease_ttl,
            heartbeat_timeout=heartbeat_timeout,
            target_hosts=target_hosts,
            own_hosts=own_hosts,
            auth_token=resolved_token,
            operator_token=resolved_operator_token,
            agent_tokens=resolved_agent_tokens,
            authorized_agents=resolved_agents,
            agent_usernames=agent_usernames,
            admin_username=admin_username,
            enable_username_login=enable_username_login,
        )

    coordinator.start_background_maintenance(interval_seconds=maintenance_interval)
    logger.info(
        f"Swarm Coordinator initialized: team={coordinator.team_id} profile={cfg_profile.value} "
        f"auth_enabled={bool(coordinator.auth_token)} operator_auth={bool(coordinator.operator_token)} "
        f"targets={len(target_hosts)} own_hosts={len(own_hosts)}"
    )

    app = create_coordinator_app(coordinator)

    def _shutdown_signal(sig, frame):
        logger.info("Shutdown signal received. Stopping coordinator...")
        coordinator.stop_background_maintenance()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown_signal)
    signal.signal(signal.SIGTERM, _shutdown_signal)

    # SSL Context configuration
    cert_path = ssl_cert or (cfg.ssl_cert if cfg_profile == ConfigProfile.LAN_REHEARSAL else None)
    key_path = ssl_key or (cfg.ssl_key if cfg_profile == ConfigProfile.LAN_REHEARSAL else None)
    ssl_context = None
    tls_requested = use_tls or (cfg_profile == ConfigProfile.LAN_REHEARSAL and cfg.use_tls) or (ssl_cert and ssl_key)
    if tls_requested:
        if cert_path and key_path:
            ssl_context = (cert_path, key_path)
        else:
            ssl_context = "adhoc"

    scheme = "https" if ssl_context else "http"
    logger.info(f"Starting Swarm Coordinator REST API on {scheme}://{resolved_host}:{resolved_port}")
    try:
        app.run(
            host=resolved_host,
            port=resolved_port,
            debug=False,
            use_reloader=False,
            threaded=True,
            ssl_context=ssl_context,
        )
    finally:
        coordinator.stop_background_maintenance()


def main():
    parser = argparse.ArgumentParser(description="KOTH Swarm Authoritative Coordinator Server")
    parser.add_argument("--host", default=None, help="Bind host (default: 127.0.0.1 for LOCAL_REHEARSAL; required private IP for LAN_REHEARSAL)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 5000 / SWARM_PORT)")
    parser.add_argument(
        "--profile",
        default="LOCAL_REHEARSAL",
        choices=["LOCAL_REHEARSAL", "LAN_REHEARSAL", "RADMIN_REHEARSAL", "PWNGROUNDS_SIM", "DEV"],
        help="Configuration profile",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Shared team secret token for worker-coordinator authentication (default: SWARM_AUTH_TOKEN)",
    )
    parser.add_argument(
        "--operator-token",
        default=None,
        help="Privileged operator token for phase control, kill switch, and administration (default: SWARM_OPERATOR_TOKEN)",
    )
    parser.add_argument(
        "--authorized-agents",
        default=None,
        help="Comma-separated authorized agent roster (default: agent-01,agent-02,agent-03,agent-04)",
    )
    parser.add_argument(
        "--agent-usernames",
        default=None,
        help="Username mapping, e.g. 'agent-01:sanjay,agent-02:prachi,agent-03:aman,agent-04:akshitha'",
    )
    parser.add_argument(
        "--admin-username",
        default="admin",
        help="Administrator username for LOCAL_REHEARSAL username login (default: admin)",
    )
    parser.add_argument(
        "--enable-username-login",
        action="store_true",
        help="Enable username-only login (intended for local rehearsal; keep disabled for live LAN)",
    )
    parser.add_argument(
        "--lease-ttl",
        type=float,
        default=15.0,
        help="Task lease TTL in seconds (default: 15.0)",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=10.0,
        help="Agent heartbeat timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--maintenance-interval",
        type=float,
        default=1.0,
        help="Background reaper interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--agent-tokens",
        default=None,
        help="Comma-separated per-agent tokens (e.g. 'agent-01:tok1,agent-02:tok2' or JSON)",
    )
    parser.add_argument(
        "--ssl-cert",
        default=None,
        help="Path to SSL certificate for HTTPS transport",
    )
    parser.add_argument(
        "--ssl-key",
        default=None,
        help="Path to SSL private key for HTTPS transport",
    )
    parser.add_argument(
        "--use-tls",
        action="store_true",
        help="Enable HTTPS secure transport",
    )
    args = parser.parse_args()

    agents_list = (
        [s.strip() for s in args.authorized_agents.split(",") if s.strip()]
        if args.authorized_agents
        else None
    )

    parsed_usernames = None
    if args.agent_usernames:
        parsed_usernames = {}
        for item in args.agent_usernames.split(","):
            item = item.strip()
            if ":" in item:
                aid, username = item.split(":", 1)
                if aid.strip() and username.strip():
                    parsed_usernames[aid.strip()] = username.strip()

    parsed_agent_tokens = None
    if args.agent_tokens:
        import json
        try:
            parsed_agent_tokens = json.loads(args.agent_tokens)
        except Exception:
            parsed_agent_tokens = {}
            for item in args.agent_tokens.split(","):
                item = item.strip()
                if ":" in item:
                    k, v = item.split(":", 1)
                    parsed_agent_tokens[k.strip()] = v.strip()
                elif "=" in item:
                    k, v = item.split("=", 1)
                    parsed_agent_tokens[k.strip()] = v.strip()

    run_coordinator_server(
        host=args.host,
        port=args.port,
        profile=args.profile,
        auth_token=args.auth_token,
        operator_token=args.operator_token,
        agent_tokens=parsed_agent_tokens,
        authorized_agents=agents_list,
        lease_ttl=args.lease_ttl,
        heartbeat_timeout=args.heartbeat_timeout,
        maintenance_interval=args.maintenance_interval,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        use_tls=args.use_tls,
        agent_usernames=parsed_usernames,
        admin_username=args.admin_username,
        enable_username_login=args.enable_username_login,
    )


if __name__ == "__main__":
    main()
