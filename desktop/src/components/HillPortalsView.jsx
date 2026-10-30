import React, { useState } from 'react';
import { Shield, Lock, CheckCircle, Play, Save, KeyRound } from 'lucide-react';

export default function HillPortalsView({
  user,
  hills,
  onSaveConfig,
  onSetFlag,
  onVerify,
  hillConfig,
  setHillConfig,
  flagInput,
  setFlagInput,
  actionMsg,
}) {
  const isLeader = user?.role === 'LEADER';
  const assignedHill = user?.assigned_hill || user?.hill_id || 1;

  // Active sub-tab defaults to assigned hill for teammates, or Hill 1 for leader
  const [selectedHill, setSelectedHill] = useState(assignedHill);

  const hill = hills.find((h) => h.hill_id === selectedHill) || {};
  const isAccessible = isLeader || assignedHill === selectedHill;

  const ownStatus = hill?.ownership_status || 'UNVERIFIED';
  const healthStatus = hill?.health_status || 'UNKNOWN';

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
  }[healthStatus] || 'badge-neutral';

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Hill Portals & Target Configuration</h1>
          <p className="view-subtitle">
            Isolated hill portal endpoints, defense scripts, and competition flags
          </p>
        </div>
      </div>

      {actionMsg && (
        <div className="alert-banner alert-info" style={{ marginBottom: 16 }}>
          <span>ℹ️ {actionMsg}</span>
        </div>
      )}

      {/* Hill Sub-Tabs */}
      <div className="sub-tabs">
        {[1, 2, 3, 4].map((hid) => {
          const isUserHill = assignedHill === hid;
          const hObj = hills.find((h) => h.hill_id === hid);
          const isOwned = hObj?.ownership_status === 'OWNED';

          return (
            <button
              key={hid}
              type="button"
              className={`sub-tab-btn ${selectedHill === hid ? 'active' : ''}`}
              onClick={() => setSelectedHill(hid)}
            >
              Hill {hid} {isUserHill ? '(Your Hill)' : `(Agent 0${hid})`}
              {isOwned && ' 👑'}
            </button>
          );
        })}
      </div>

      {/* Main Hill Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={18} />
            <span>
              Hill {selectedHill} Portal {assignedHill === selectedHill && '(Assigned to You)'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className={`badge ${ownBadge}`}>Ownership: {ownStatus}</span>
            <span className={`badge ${healthBadge}`}>Health: {healthStatus}</span>
          </div>
        </div>

        {!isAccessible ? (
          <div className="alert-banner alert-danger" style={{ marginTop: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Lock size={18} />
              <div>
                <strong>Hill Isolation Enforced by RBAC</strong>
                <div style={{ fontSize: 12, marginTop: 2 }}>
                  You are assigned to <strong>Hill {assignedHill}</strong>. Access control prohibits configuring or viewing secret telemetry for Hill {selectedHill}.
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="grid-2" style={{ marginTop: 10 }}>
            {/* Left: Target & Defense Configuration */}
            <div>
              <h4 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>
                Target & Defense Parameters
              </h4>

              <label htmlFor="service-name">Service Name</label>
              <input
                id="service-name"
                type="text"
                placeholder="e.g. koth-http-service"
                defaultValue={hill?.service_name || ''}
                onChange={(e) => setHillConfig((c) => ({ ...c, service_name: e.target.value }))}
              />

              <div style={{ display: 'flex', gap: 10 }}>
                <div style={{ flex: 2 }}>
                  <label htmlFor="target-host">Target Host (LAN IP)</label>
                  <input
                    id="target-host"
                    type="text"
                    placeholder="10.254.254.11"
                    defaultValue={hill?.target_host || ''}
                    onChange={(e) => setHillConfig((c) => ({ ...c, target_host: e.target.value }))}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label htmlFor="target-port">Target Port</label>
                  <input
                    id="target-port"
                    type="number"
                    placeholder="80"
                    defaultValue={hill?.target_port || 80}
                    onChange={(e) => setHillConfig((c) => ({ ...c, target_port: parseInt(e.target.value) || 80 }))}
                  />
                </div>
              </div>

              <label htmlFor="defense-endpoint">Defense Verification Endpoint</label>
              <input
                id="defense-endpoint"
                type="text"
                placeholder="/api/defense/verify"
                defaultValue={hill?.defense_endpoint || ''}
                onChange={(e) => setHillConfig((c) => ({ ...c, defense_endpoint: e.target.value }))}
              />

              <button
                type="button"
                className="btn-primary"
                onClick={() => onSaveConfig(selectedHill)}
                style={{ marginTop: 4 }}
              >
                <Save size={14} />
                <span>Save Hill {selectedHill} Configuration</span>
              </button>
            </div>

            {/* Right: Secret Flag & Live Verification */}
            <div>
              <h4 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>
                Competition Flag & Verifier
              </h4>

              <label htmlFor="flag-input">Register Plaintext Flag</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  id="flag-input"
                  type="password"
                  placeholder="Enter flag string (e.g. FLAG{...})"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  style={{ marginBottom: 0 }}
                />
                <button
                  type="button"
                  onClick={() => onSetFlag(selectedHill)}
                  disabled={!flagInput}
                >
                  <KeyRound size={14} />
                  <span>Hash & Store</span>
                </button>
              </div>

              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, marginBottom: 14 }}>
                Flags are immediately hashed via SHA-256. Plaintext is never written to disk or returned over the API.
              </p>

              <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, border: '1px solid var(--border-color)', marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Stored SHA-256 Flag Hash
                </div>
                <div style={{ fontSize: 12, fontFamily: 'monospace', wordBreak: 'break-all', marginTop: 4, color: 'var(--text-primary)' }}>
                  {hill?.flag_hash ? hill.flag_hash : 'No flag registered yet'}
                </div>
              </div>

              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>Simulated Verifier Probe</div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      Evaluates ownership and target health latency
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn-success"
                    onClick={() => onVerify(selectedHill)}
                  >
                    <Play size={13} />
                    <span>Run Verification</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

