import React from 'react';
import { Cpu, Play, Shield, RefreshCw, AlertCircle } from 'lucide-react';

export default function CoordinatorView({
  swarmStatus,
  user,
  onAdvancePhase,
}) {
  const isLeader = user?.role === 'LEADER';
  const currentPhase = swarmStatus?.phase?.phase || 'HOLD';
  const epoch = swarmStatus?.phase?.phase_epoch || 0;
  const activeCount = swarmStatus?.phase?.active_count || 0;
  const instanceId = swarmStatus?.coordinator_instance_id || 'coord-lan-main';

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Coordinator & Swarm Phase Control</h1>
          <p className="view-subtitle">
            Centralized phase state machine, task lease dispatching, and synchronization
          </p>
        </div>
      </div>

      {/* Phase Orchestration Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Cpu size={16} />
            <span>Swarm Phase Orchestration</span>
          </div>
          <span className="badge badge-neutral">
            Coordinator: {instanceId}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            Current State:
          </div>
          <span className={`badge ${currentPhase === 'ATTACK' ? 'badge-red' : currentPhase === 'DEFENSE' ? 'badge-blue' : 'badge-yellow'}`} style={{ fontSize: 13, padding: '5px 12px' }}>
            <span className={`dot ${currentPhase === 'ATTACK' ? 'dot-red' : currentPhase === 'DEFENSE' ? 'dot-blue' : 'dot-yellow'}`} />
            {currentPhase}
          </span>
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            Epoch Number: <strong>{epoch}</strong>
          </span>
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            Active Tasks: <strong>{activeCount}</strong>
          </span>
        </div>

        {isLeader ? (
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>
              Advance Coordinator State (Authorized as Team Leader)
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button
                type="button"
                className={`btn-danger ${currentPhase === 'ATTACK' ? '' : ''}`}
                onClick={() => onAdvancePhase('ATTACK')}
                style={{ padding: '9px 18px' }}
              >
                Trigger Attack Phase
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => onAdvancePhase('DEFENSE')}
                style={{ padding: '9px 18px' }}
              >
                Trigger Defense Phase
              </button>
              <button
                type="button"
                onClick={() => onAdvancePhase('HOLD')}
                style={{ padding: '9px 18px' }}
              >
                Engage Safe Hold
              </button>
            </div>
          </div>
        ) : (
          <div className="alert-banner alert-warning" style={{ marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertCircle size={16} />
              <span>
                Phase orchestration is restricted to the Team Leader (Agent 01). Worker nodes follow phase directives automatically.
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Coordinator Architecture Overview */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} />
              <span>Phase Definitions & Semantics</span>
            </div>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            <div style={{ marginBottom: 10 }}>
              <strong style={{ color: '#DC5555' }}>ATTACK:</strong> Swarm actively scans, exploits, and submits flags on adversary hills within authorized CIDR ranges.
            </div>
            <div style={{ marginBottom: 10 }}>
              <strong style={{ color: '#2878C8' }}>DEFENSE:</strong> Agents lock down hill ports, apply firewall rules, verify service health, and prevent compromise.
            </div>
            <div>
              <strong style={{ color: '#D99A27' }}>HOLD:</strong> Safe standby mode. Telemetry continues but all active network operations are paused.
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} />
              <span>Coordinator Parameters</span>
            </div>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <div>Instance ID: <code>{instanceId}</code></div>
            <div>Lease Heartbeat TTL: <strong>60 Seconds</strong></div>
            <div>Phase Epoch Increments: <strong>Atomic on transition</strong></div>
            <div>Network Boundary: <strong>Strict Local Network (LAN) Only</strong></div>
          </div>
        </div>
      </div>
    </div>
  );
}

