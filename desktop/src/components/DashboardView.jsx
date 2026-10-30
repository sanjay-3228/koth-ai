import React from 'react';
import {
  Shield,
  Activity,
  Cpu,
  CheckCircle,
  AlertTriangle,
  Clock,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';

export default function DashboardView({
  user,
  teamName,
  teamId,
  swarmStatus,
  hills,
  auditLogs,
  onNavigate,
  onAdvancePhase,
}) {
  const isLeader = user?.role === 'LEADER';
  const killSwitchActive = swarmStatus?.kill_switch || false;
  const currentPhase = swarmStatus?.phase?.phase || 'HOLD';
  const epoch = swarmStatus?.phase?.phase_epoch || 0;
  const activeCount = swarmStatus?.phase?.active_count || 0;
  const agents = swarmStatus?.agents || {};

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Swarm Operations Overview</h1>
          <p className="view-subtitle">
            Autonomous multi-agent orchestration for team <strong>{user?.team_name || teamName}</strong> (ID: <code>{teamId}</code>)
          </p>
        </div>

        {isLeader && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className={currentPhase === 'ATTACK' ? 'btn-primary' : ''}
              onClick={() => onAdvancePhase('ATTACK')}
            >
              Set Attack
            </button>
            <button
              type="button"
              className={currentPhase === 'DEFENSE' ? 'btn-primary' : ''}
              onClick={() => onAdvancePhase('DEFENSE')}
            >
              Set Defense
            </button>
            <button
              type="button"
              className={currentPhase === 'HOLD' ? 'btn-primary' : ''}
              onClick={() => onAdvancePhase('HOLD')}
            >
              Safe Hold
            </button>
          </div>
        )}
      </div>

      {/* Emergency Stop Active Alert */}
      {killSwitchActive && (
        <div className="alert-banner alert-danger">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldAlert size={20} />
            <div>
              <strong>Emergency Kill Switch Engaged</strong>
              <div style={{ fontSize: 12 }}>All active leases have been revoked. Swarm workers are halted.</div>
            </div>
          </div>
          <button
            type="button"
            className="btn-sm btn-outline-danger"
            onClick={() => onNavigate('security')}
          >
            Review Security ➔
          </button>
        </div>
      )}

      {/* Metrics Top Row */}
      <div className="grid-4" style={{ marginBottom: 20 }}>
        <div className="card" style={{ marginBottom: 0, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Current Swarm Phase
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className={`dot ${currentPhase === 'ATTACK' ? 'dot-red' : currentPhase === 'DEFENSE' ? 'dot-blue' : 'dot-yellow'}`} style={{ width: 10, height: 10 }} />
            {currentPhase}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            Epoch: <strong>{epoch}</strong> · Active Tasks: <strong>{activeCount}</strong>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Distributed Nodes
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)' }}>
            {Object.values(agents).filter((a) => a?.alive).length} / 4 Online
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            Local Network (LAN) Isolated
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Controlled Hills
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)' }}>
            {hills.filter((h) => h?.ownership_status === 'OWNED').length} / 4 Hills
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            {hills.filter((h) => h?.health_status === 'HEALTHY').length} Verified Healthy
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0, padding: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Emergency Stop Status
          </div>
          <div style={{ fontSize: 22, fontWeight: 700, marginTop: 4, color: killSwitchActive ? '#DC5555' : '#16A36A', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className={`dot ${killSwitchActive ? 'dot-red' : 'dot-green'}`} style={{ width: 10, height: 10 }} />
            {killSwitchActive ? 'HALTED' : 'OPERATIONAL'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            {killSwitchActive ? 'Leases Revoked' : 'All 4 Gates Armed'}
          </div>
        </div>
      </div>

      {/* 4 Agent Connection Status */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Activity size={16} />
              <span>Four Distributed Agent Nodes</span>
            </div>
            <div className="card-subtitle">
              Live heartbeat monitoring and worker assignment across the local network
            </div>
          </div>
          <button
            type="button"
            className="btn-sm"
            onClick={() => onNavigate('agents')}
          >
            Telemetry Details ➔
          </button>
        </div>

        <div className="grid-4">
          {['agent-01', 'agent-02', 'agent-03', 'agent-04'].map((aid, idx) => {
            const ag = agents[aid];
            const isAlive = ag?.alive || false;
            const hillId = idx + 1;
            const isAssignedToUser = user?.agent_id === aid;

            return (
              <div
                key={aid}
                style={{
                  background: isAssignedToUser ? '#F8FAFD' : 'var(--bg-card)',
                  border: isAssignedToUser ? '1px solid #BFDBFE' : '1px solid var(--border-color)',
                  borderRadius: 6,
                  padding: 14,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)' }}>
                    {aid} {isAssignedToUser && <span style={{ color: '#2878C8', fontSize: 11 }}>(You)</span>}
                  </div>
                  <span className={`badge ${isAlive ? 'badge-green' : 'badge-red'}`}>
                    <span className={`dot ${isAlive ? 'dot-green' : 'dot-red'}`} />
                    {isAlive ? 'ONLINE' : 'OFFLINE'}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Role: <strong>{idx === 0 ? 'Team Leader' : `Teammate ${idx}`}</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Assigned: <strong>Hill {hillId}</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6 }}>
                  Task: <code>{ag?.current_task_type || 'IDLE'}</code>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Clock size={11} />
                  <span>
                    Heartbeat: {ag?.last_heartbeat ? new Date(ag.last_heartbeat * 1000).toLocaleTimeString() : 'Never'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4 Hill Status Cards */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Shield size={16} />
              <span>Hill Portals & Target Status</span>
            </div>
            <div className="card-subtitle">
              Ownership status, health verification, and network targets
            </div>
          </div>
          <button
            type="button"
            className="btn-sm"
            onClick={() => onNavigate('hills')}
          >
            Configure Hills ➔
          </button>
        </div>

        <div className="grid-4">
          {[1, 2, 3, 4].map((hid) => {
            const h = hills.find((item) => item.hill_id === hid) || {};
            const ownStatus = h.ownership_status || 'UNVERIFIED';
            const health = h.health_status || 'UNKNOWN';

            const ownBadge = {
              OWNED: 'badge-green',
              LOST: 'badge-red',
              SUBMITTED: 'badge-yellow',
              UNVERIFIED: 'badge-neutral',
            }[ownStatus] || 'badge-neutral';

            const healthBadge = {
              HEALTHY: 'badge-green',
              DEGRADED: 'badge-yellow',
              DOWN: 'badge-red',
              UNKNOWN: 'badge-neutral',
            }[health] || 'badge-neutral';

            const isUserHill = user?.assigned_hill === hid || user?.hill_id === hid;

            return (
              <div
                key={hid}
                style={{
                  background: isUserHill ? '#F8FAFD' : 'var(--bg-card)',
                  border: isUserHill ? '1px solid #BFDBFE' : '1px solid var(--border-color)',
                  borderRadius: 6,
                  padding: 14,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)' }}>
                    Hill {hid} {isUserHill && <span style={{ color: '#2878C8', fontSize: 11 }}>(Your Hill)</span>}
                  </div>
                  <span className={`badge ${ownBadge}`}>{ownStatus}</span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Service: <strong>{h.service_name || 'Not configured'}</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                  Target: <code>{h.target_host ? `${h.target_host}:${h.target_port || 80}` : 'None'}</code>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span>Health:</span>
                  <span className={`badge ${healthBadge}`}>{health}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Audit Events */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Cpu size={16} />
              <span>Recent Immutable Audit Events</span>
            </div>
            <div className="card-subtitle">
              Cryptographically hashed events with zero secret or password leaks
            </div>
          </div>
          <button
            type="button"
            className="btn-sm"
            onClick={() => onNavigate('audit')}
          >
            Full Trail ➔
          </button>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.slice(0, 5).map((ev) => (
                <tr key={ev.event_id}>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {new Date(ev.timestamp * 1000).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="badge badge-neutral" style={{ fontSize: 11 }}>
                      {ev.event_type}
                    </span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{ev.actor}</td>
                  <td><code>{ev.target}</code></td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                    {JSON.stringify(ev.details || {})}
                  </td>
                </tr>
              ))}
              {auditLogs.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 18 }}>
                    No audit events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

