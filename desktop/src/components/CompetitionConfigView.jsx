import React from 'react';
import { Trophy, Globe, Shield, Plus, Swords, Play, CheckCircle2, Clock } from 'lucide-react';

export default function CompetitionConfigView({
  teamName,
  teamId,
  competitionId,
  hills,
  competitions = [],
  activeCompetition,
  onSelectCompetition,
  onOpenWizard,
}) {
  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Competition Configuration & Arena Engine</h1>
          <p className="view-subtitle">
            Configure KOTH and Red vs Blue competitions, formats, rules, and heterogeneous hills
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {onOpenWizard && (
            <button className="btn btn-primary" onClick={onOpenWizard}>
              <Plus size={16} /> New Competition (8-Step Wizard)
            </button>
          )}
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid-3" style={{ marginBottom: 20 }}>
        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Active Competition
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)' }}>
            {activeCompetition?.name || competitionId || 'DEFCON-KOTH-2026'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            Mode: <strong>{activeCompetition?.mode || 'RED_VS_BLUE'}</strong> | Format: <strong>{activeCompetition?.format || 'CLASSIC'}</strong>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Registered Team
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)' }}>
            {teamName}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            Slug: <code>{teamId}</code>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Operating Network
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: 'var(--text-primary)' }}>
            Physical LAN
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            Zero internet egress allowed
          </div>
        </div>
      </div>

      {/* Existing Competitions Selector */}
      {competitions.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <div className="card-title">
              <Swords size={16} />
              <span>Available Competitions on Swarm Network</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Competition ID</th>
                  <th>Name</th>
                  <th>Mode</th>
                  <th>Format</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {competitions.map((comp) => {
                  const isCurrent = activeCompetition?.competition_id === comp.competition_id;
                  return (
                    <tr key={comp.competition_id}>
                      <td><code>{comp.competition_id}</code></td>
                      <td><strong>{comp.name}</strong></td>
                      <td><span className="badge badge-blue">{comp.mode}</span></td>
                      <td><span className="badge badge-neutral">{comp.format}</span></td>
                      <td>
                        <span className={`badge ${comp.status === 'ACTIVE' ? 'badge-green' : 'badge-neutral'}`}>
                          {comp.status}
                        </span>
                      </td>
                      <td>{comp.duration_minutes} mins</td>
                      <td>
                        {isCurrent ? (
                          <span className="badge badge-green">SELECTED</span>
                        ) : (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onSelectCompetition && onSelectCompetition(comp)}
                          >
                            Switch to Arena
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Target Hills Matrix */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Trophy size={16} />
            <span>Target Hill Allocations & Heterogeneous Environments</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {hills.length} Hills Configured
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Hill</th>
                <th>Target IP / Host</th>
                <th>Service Port</th>
                <th>Service Type</th>
                <th>Environment Type</th>
                <th>Controller</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {hills.map((h) => (
                <tr key={h.hill_id}>
                  <td><strong>Hill {h.hill_id}</strong></td>
                  <td><code>{h.target_host || '10.254.254.1' + h.hill_id}</code></td>
                  <td><code>{h.target_port || 80}</code></td>
                  <td>{h.service_name || 'koth-service'}</td>
                  <td>
                    <span className="badge badge-neutral">
                      {h.environment_type || 'LINUX'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${h.current_owner_side === 'RED' ? 'badge-red' : h.current_owner_side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                      {h.current_owner_team_id || h.assigned_agent_id || 'Unassigned'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${h.state === 'CAPTURED' ? 'badge-blue' : h.state === 'OWNED' ? 'badge-green' : 'badge-neutral'}`}>
                      {h.state || h.ownership_status || 'AVAILABLE'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
