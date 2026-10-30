import React from 'react';
import { AlertTriangle, RefreshCw, LogOut, ShieldAlert, ArrowLeft, Bell } from 'lucide-react';

export default function Header({
  activeView,
  user,
  teamName,
  competitionId,
  swarmStatus,
  isOffline,
  lastSync,
  onRefresh,
  onTriggerEmergencyStop,
  onResetEmergencyStop,
  onLogout,
  onExitToLauncher,
  onNavigate,
}) {
  const isLeader = user?.role === 'LEADER';
  const killSwitchActive = swarmStatus?.kill_switch || false;
  const currentPhase = swarmStatus?.phase?.phase || 'HOLD';
  const epoch = swarmStatus?.phase?.phase_epoch || 0;

  const viewTitles = {
    overview: 'Operations Dashboard',
    team_mgmt: 'Team Management & Member Onboarding',
    hills: 'Hill Portals & Target Configuration',
    agents: 'Distributed Agent Nodes Telemetry',
    coordination: 'Multi-Agent Swarm Coordination',
    notifications: 'Live Competition Event Feed',
    coordinator: 'Swarm Coordinator & Phase Control',
    tasks: 'Task Leases & Execution Pipeline',
    competition: 'Competition Environment & Rules',
    llm: 'Agent LLM Advisory Configuration',
    audit: 'Immutable Audit Trail',
    security: 'Security Gates & Emergency Control',
  };

  const phaseBadgeClass = {
    ATTACK: 'badge-red',
    DEFENSE: 'badge-blue',
    HOLD: 'badge-yellow',
  }[currentPhase] || 'badge-neutral';

  return (
    <header className="top-header">
      {/* Left: View Title & Breadcrumb */}
      <div className="header-left">
        <div className="header-breadcrumb">
          <span>{viewTitles[activeView] || 'KOTH Command'}</span>
        </div>

        {/* Team & Competition Badges */}
        <span className="badge badge-blue">
          Team: {user?.team_name || teamName}
        </span>

        {competitionId && (
          <span className="badge badge-neutral">
            Comp: {competitionId}
          </span>
        )}

        <span className={`badge ${phaseBadgeClass}`}>
          <span className={`dot ${currentPhase === 'ATTACK' ? 'dot-red' : currentPhase === 'DEFENSE' ? 'dot-blue' : 'dot-yellow'}`} />
          {currentPhase} · Epoch {epoch}
        </span>

        {isOffline && (
          <span className="badge badge-red">
            <span className="dot dot-red" /> Coordinator Offline
          </span>
        )}
      </div>

      {/* Right: Actions */}
      <div className="header-right">
        {/* Restrained Emergency Stop */}
        {killSwitchActive ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="badge badge-red" style={{ padding: '6px 10px', fontSize: 12 }}>
              <ShieldAlert size={14} /> KILL SWITCH ENGAGED
            </span>
            {isLeader && (
              <button
                type="button"
                className="btn-success btn-sm"
                onClick={onResetEmergencyStop}
                title="Reset emergency stop and resume normal swarm loop"
              >
                Reset Stop
              </button>
            )}
          </div>
        ) : (
          <button
            type="button"
            className="btn-outline-danger btn-sm"
            onClick={onTriggerEmergencyStop}
            title="Immediately revoke all leases and halt swarm workers"
          >
            <AlertTriangle size={13} />
            <span>Emergency Stop</span>
          </button>
        )}

        {/* Sync Indicator */}
        <button
          type="button"
          onClick={onRefresh}
          className="btn-sm"
          title={lastSync ? `Last synced at ${lastSync.toLocaleTimeString()}` : 'Syncing'}
          style={{ padding: '5px 8px' }}
        >
          <RefreshCw size={13} />
        </button>

        {/* Exit to Launcher Button */}
        {onExitToLauncher && (
          <button
            type="button"
            onClick={onExitToLauncher}
            className="btn-sm"
            title="Return to Competition Launcher"
            style={{ display: 'flex', alignItems: 'center', gap: 4 }}
          >
            <ArrowLeft size={13} />
            <span>Launcher</span>
          </button>
        )}

        {/* Logout Button */}
        <button
          type="button"
          onClick={onLogout}
          className="btn-sm"
          title="Sign out of current session"
        >
          <LogOut size={13} />
          <span>Logout</span>
        </button>
      </div>
    </header>
  );
}

