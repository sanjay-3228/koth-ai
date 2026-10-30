import React from 'react';
import { Users, AlertTriangle, ShieldCheck, RefreshCw, UserPlus } from 'lucide-react';

export default function TeamManagementView({
  isLeader,
  user,
  teamId,
  teamMgmtData,
  onRefresh,
  onCompleteRegistration,
  mgmtError,
  incompleteTeammates,
  setIncompleteTeammates,
}) {
  const status = teamMgmtData?.registration_status || 'COMPLETE';
  const members = teamMgmtData?.members || [];

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Team Management & Roster</h1>
          <p className="view-subtitle">
            Centralized member credentials and fixed 4-agent assignment layout
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span className={`badge ${status === 'COMPLETE' ? 'badge-green' : 'badge-yellow'}`}>
            Registration: {status}
          </span>
          <button type="button" onClick={onRefresh} className="btn-sm">
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Teammate Access Note if non-leader */}
      {!isLeader && (
        <div className="alert-banner alert-warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={18} />
            <div>
              <strong>Limited Access View</strong>
              <div style={{ fontSize: 12 }}>
                As a team member ({user?.agent_id}), roster modifications and onboarding are restricted to the Team Leader (Agent 01).
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Team Profile Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Users size={16} />
            <span>Team Profile: {teamMgmtData?.team_name || teamId}</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Created: {teamMgmtData?.created_at ? new Date(teamMgmtData.created_at * 1000).toLocaleDateString() : 'Active'}
          </div>
        </div>

        <div className="grid-3" style={{ marginBottom: 14 }}>
          <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Team Identifier
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2, color: 'var(--text-primary)' }}>
              <code>{teamMgmtData?.team_id || teamId}</code>
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Competition ID
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2, color: 'var(--text-primary)' }}>
              {teamMgmtData?.competition_id || 'DEFCON-KOTH-2026'}
            </div>
          </div>

          <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Roster Capacity
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, marginTop: 2, color: 'var(--text-primary)' }}>
              {members.length} / 4 Members Assigned
            </div>
          </div>
        </div>

        {teamMgmtData?.description && (
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 0 }}>
            {teamMgmtData.description}
          </p>
        )}
      </div>

      {/* Incomplete Registration Onboarding Form for Leader */}
      {status === 'INCOMPLETE' && isLeader && (
        <div className="card" style={{ borderColor: 'var(--color-warning-border)' }}>
          <div className="card-header">
            <div className="card-title" style={{ color: 'var(--color-warning)' }}>
              <UserPlus size={16} />
              <span>Incomplete Team Registration — Onboard Missing Teammates</span>
            </div>
          </div>

          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
            This team was initialized without full member credentials. Register the remaining 3 teammates below to enable multi-agent defense across all 4 hill portals.
          </p>

          <form onSubmit={onCompleteRegistration}>
            {incompleteTeammates.map((tm, idx) => (
              <div
                key={idx}
                style={{
                  background: 'var(--bg-subtle)',
                  padding: 14,
                  borderRadius: 6,
                  marginBottom: 12,
                  border: '1px solid var(--border-color)',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8, color: 'var(--text-primary)' }}>
                  Teammate {idx + 1} (Agent 0{idx + 2} · Assigned to Hill {idx + 2})
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Full Name *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. Bob Defender"
                      value={tm.full_name}
                      onChange={(e) => {
                        const val = e.target.value;
                        setIncompleteTeammates((list) => list.map((item, i) => i === idx ? { ...item, full_name: val } : item));
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Unique Username *</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. bob"
                      value={tm.username}
                      onChange={(e) => {
                        const val = e.target.value;
                        setIncompleteTeammates((list) => list.map((item, i) => i === idx ? { ...item, username: val } : item));
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Password * (min 6 chars)</label>
                    <input
                      type="password"
                      required
                      placeholder="••••••••"
                      value={tm.password}
                      onChange={(e) => {
                        const val = e.target.value;
                        setIncompleteTeammates((list) => list.map((item, i) => i === idx ? { ...item, password: val } : item));
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Confirm Password *</label>
                    <input
                      type="password"
                      required
                      placeholder="••••••••"
                      value={tm.confirm_password}
                      onChange={(e) => {
                        const val = e.target.value;
                        setIncompleteTeammates((list) => list.map((item, i) => i === idx ? { ...item, confirm_password: val } : item));
                      }}
                    />
                  </div>
                </div>
              </div>
            ))}

            {mgmtError && (
              <div style={{ color: 'var(--color-error)', fontSize: 13, marginBottom: 12 }}>
                ⚠️ {mgmtError}
              </div>
            )}

            <button type="submit" className="btn-primary">
              Complete Team Registration & Onboard Teammates
            </button>
          </form>
        </div>
      )}

      {/* Four-Member Team Roster Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={16} />
            <span>Four-Member Team Roster & Agent Assignments</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            PBKDF2-HMAC-SHA256 (100k rounds)
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Role</th>
                <th>Agent Node</th>
                <th>Assigned Hill</th>
                <th>Full Name</th>
                <th>Username</th>
                <th>Account Status</th>
                <th>Last Login</th>
              </tr>
            </thead>
            <tbody>
              {members.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 18 }}>
                    Loading team roster...
                  </td>
                </tr>
              ) : (
                members.map((m) => (
                  <tr key={m.agent_id}>
                    <td>
                      <span className={`badge ${m.role === 'LEADER' ? 'badge-blue' : 'badge-neutral'}`}>
                        {m.role}
                      </span>
                    </td>
                    <td>
                      <strong>{m.agent_id}</strong>
                    </td>
                    <td>Hill {m.assigned_hill || m.hill_id}</td>
                    <td>{m.full_name || '--'}</td>
                    <td>
                      <code>{m.username}</code>
                    </td>
                    <td>
                      <span className="badge badge-green">
                        <span className="dot dot-green" /> {m.account_status || 'ACTIVE'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {m.last_login && m.last_login > 0
                        ? new Date(m.last_login * 1000).toLocaleString()
                        : 'Never'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 14, fontSize: 12, color: 'var(--text-muted)' }}>
          🔒 Passwords, password hashes, and salts are strictly masked and never transmitted in API responses.
        </div>
      </div>
    </div>
  );
}

