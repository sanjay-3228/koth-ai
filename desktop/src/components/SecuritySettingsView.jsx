import React from 'react';
import { Lock, ShieldAlert, AlertTriangle, CheckCircle, ShieldCheck } from 'lucide-react';

export default function SecuritySettingsView({
  user,
  swarmStatus,
  onTriggerEmergencyStop,
  onResetEmergencyStop,
}) {
  const isLeader = user?.role === 'LEADER';
  const killSwitchActive = swarmStatus?.kill_switch || false;

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Security Settings & Emergency Stop</h1>
          <p className="view-subtitle">
            Swarm kill switch, access control verification, and defensive policy safeguards
          </p>
        </div>
      </div>

      {/* Emergency Stop Panel */}
      <div className="card" style={{ borderLeft: killSwitchActive ? '4px solid #DC5555' : '4px solid #16A36A' }}>
        <div className="card-header">
          <div className="card-title">
            <ShieldAlert size={18} color={killSwitchActive ? '#DC5555' : '#16A36A'} />
            <span>Swarm Kill Switch & Lease Revocation</span>
          </div>
          <span className={`badge ${killSwitchActive ? 'badge-red' : 'badge-green'}`} style={{ fontSize: 12 }}>
            Status: {killSwitchActive ? 'ENGAGED (HALTED)' : 'ARMED & OPERATIONAL'}
          </span>
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
          The emergency stop revokes all outstanding worker task leases immediately, stops background maintenance routines, and prevents new tasks from executing across all 4 hill portals.
        </p>

        {killSwitchActive ? (
          <div style={{ background: '#FDF2F2', border: '1px solid #F5B6B6', padding: 16, borderRadius: 6, marginBottom: 14 }}>
            <div style={{ fontWeight: 700, fontSize: 14, color: '#991B1B', marginBottom: 4 }}>
              🚨 Emergency Stop is Currently Active
            </div>
            <div style={{ fontSize: 13, color: '#7F1D1D', marginBottom: 14 }}>
              All agent task loops are paused. Normal operations will not resume until an authenticated Team Leader resets the kill switch.
            </div>
            {isLeader ? (
              <button
                type="button"
                className="btn-success"
                onClick={onResetEmergencyStop}
              >
                Reset Emergency Stop & Resume Operations
              </button>
            ) : (
              <div style={{ fontSize: 12, color: '#991B1B' }}>
                🔒 Reset authority restricted to Team Leader (Agent 01).
              </div>
            )}
          </div>
        ) : (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-subtle)', padding: 14, borderRadius: 6, border: '1px solid var(--border-color)' }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>
                Operator Manual Kill Switch
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Requires confirmation dialog with mandatory operational reason.
              </div>
            </div>
            <button
              type="button"
              className="btn-danger"
              onClick={onTriggerEmergencyStop}
            >
              <AlertTriangle size={14} />
              <span>Engage Emergency Stop</span>
            </button>
          </div>
        )}
      </div>

      {/* Security Posture Overview */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ShieldCheck size={16} />
              <span>Active Security Safeguards</span>
            </div>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <div>✓ <strong>Physical LAN Only:</strong> Internet egress is prohibited.</div>
            <div>✓ <strong>PBKDF2 Password Hashing:</strong> 100,000 iterations with 16-byte random salts.</div>
            <div>✓ <strong>Rate Limiting Protection:</strong> 60s lockout after 5 failed attempts.</div>
            <div>✓ <strong>Strict Hill Isolation:</strong> Teammates cannot modify other hills.</div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Lock size={16} />
              <span>Advisory LLM Architecture</span>
            </div>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            <div>✓ <strong>Zero Autonomous Action:</strong> LLM outputs are strictly advisory.</div>
            <div>✓ <strong>Four Security Gates:</strong> All actions pass Registry, Auth, Policy, and Execution gates.</div>
            <div>✓ <strong>Isolated Per-Agent Keys:</strong> One agent cannot read another's credentials.</div>
            <div>✓ <strong>Zero Token Leakage:</strong> Secrets and flags are redacted from prompts and logs.</div>
          </div>
        </div>
      </div>
    </div>
  );
}

