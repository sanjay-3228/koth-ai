import React, { useState, useEffect, useCallback } from 'react';
import {
  Trophy,
  Swords,
  Flame,
  Clock,
  Users,
  Shield,
  Server,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Play,
  ArrowRight,
  ArrowLeft,
  RefreshCw,
  Award,
} from 'lucide-react';

export default function CompetitionLobby({
  coordinatorUrl,
  headers,
  competition,
  user,
  onEnterWorkspace,
  onBackToLauncher,
}) {
  const [compDetails, setCompDetails] = useState(competition);
  const [teams, setTeams] = useState([]);
  const [hills, setHills] = useState([]);
  const [loading, setLoading] = useState(false);
  const [starting, setStarting] = useState(false);
  const [lobbyError, setLobbyError] = useState('');

  const cid = compDetails?.competition_id;
  const isRvB = compDetails?.mode === 'RED_VS_BLUE';

  const fetchLobbyState = useCallback(async () => {
    if (!cid) return;
    setLoading(true);
    setLobbyError('');
    try {
      const hHeaders = headers ? headers() : { 'Content-Type': 'application/json' };

      // 1. Competition info
      const cRes = await fetch(`${coordinatorUrl}/api/competition/${cid}`, { headers: hHeaders });
      if (cRes.ok) {
        const cData = await cRes.json();
        setCompDetails(cData.competition);
      }

      // 2. Teams
      const tRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/teams`, { headers: hHeaders });
      if (tRes.ok) {
        const tData = await tRes.json();
        setTeams(tData.teams || []);
      }

      // 3. Hills
      const hRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/hills`, { headers: hHeaders });
      if (hRes.ok) {
        const hData = await hRes.json();
        setHills(hData.hills || []);
      }
    } catch (err) {
      console.error('Failed to load lobby details:', err);
      setLobbyError('Unable to sync live lobby state from coordinator.');
    } finally {
      setLoading(false);
    }
  }, [cid, coordinatorUrl, headers]);

  useEffect(() => {
    fetchLobbyState();
    const interval = setInterval(fetchLobbyState, 4000);
    return () => clearInterval(interval);
  }, [fetchLobbyState]);

  const handleStartCompetition = async () => {
    setStarting(true);
    setLobbyError('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/competition/${cid}/start`, {
        method: 'POST',
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to start competition');
      }
      await fetchLobbyState();
    } catch (err) {
      setLobbyError(err.message);
    } finally {
      setStarting(false);
    }
  };

  const redTeams = teams.filter((t) => t.side === 'RED');
  const blueTeams = teams.filter((t) => t.side === 'BLUE');
  const neutralTeams = teams.filter((t) => t.side === 'NEUTRAL' || !t.side);

  return (
    <div className="content-container" style={{ maxWidth: 1100, margin: '0 auto', padding: '24px 20px' }}>
      {/* Lobby Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <button className="btn btn-secondary" onClick={onBackToLauncher}>
          <ArrowLeft size={16} /> Back to Launcher
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={fetchLobbyState} title="Refresh">
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
          </button>
          <span className="badge badge-green" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#16A36A' }} />
            Coordinator Online
          </span>
        </div>
      </div>

      {lobbyError && (
        <div className="alert alert-danger" style={{ marginBottom: 20 }}>
          <AlertTriangle size={16} />
          <span>{lobbyError}</span>
        </div>
      )}

      {/* Main Banner Card */}
      <div
        className="card"
        style={{
          background: 'linear-gradient(135deg, #172536 0%, #203348 100%)',
          color: '#FFFFFF',
          padding: '24px 28px',
          marginBottom: 24,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <span className={`badge ${isRvB ? 'badge-blue' : 'badge-yellow'}`}>
                {compDetails?.mode === 'RED_VS_BLUE' ? 'Red Team vs Blue Team' : 'King of the Hill (KOTH)'}
              </span>
              <span className="badge badge-neutral" style={{ background: 'rgba(255,255,255,0.15)', color: '#FFFFFF' }}>
                Format: {compDetails?.format}
              </span>
              <span
                className={`badge ${
                  compDetails?.status === 'ACTIVE'
                    ? 'badge-green'
                    : compDetails?.status === 'DRAFT'
                    ? 'badge-yellow'
                    : 'badge-neutral'
                }`}
              >
                Status: {compDetails?.status || 'DRAFT'}
              </span>
            </div>

            <h1 style={{ fontSize: 24, fontWeight: 800, margin: '4px 0 6px', color: '#FFFFFF' }}>
              {compDetails?.name || 'Competition Arena'}
            </h1>
            <p style={{ margin: 0, fontSize: 13, color: '#CBD5E1', maxWidth: 640 }}>
              {compDetails?.description || 'Autonomous cybersecurity competition match lobby.'}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'flex-end' }}>
            {compDetails?.status === 'DRAFT' ? (
              <button
                className="btn btn-primary"
                style={{ padding: '12px 24px', fontSize: 14 }}
                onClick={handleStartCompetition}
                disabled={starting}
              >
                <Play size={16} />
                <span>{starting ? 'Starting Arena...' : 'Start Competition'}</span>
              </button>
            ) : (
              <button
                className="btn btn-primary"
                style={{ padding: '12px 28px', fontSize: 15 }}
                onClick={() => onEnterWorkspace(compDetails)}
              >
                <span>Enter Operational Workspace</span>
                <ArrowRight size={16} />
              </button>
            )}

            {compDetails?.status === 'ACTIVE' && (
              <span style={{ fontSize: 12, color: '#A0AEC0' }}>
                Match is LIVE — All systems ready for engagement
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Grid: Rules & Parameters Summary */}
      <div className="grid-3" style={{ marginBottom: 24 }}>
        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>MATCH TIMING</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4 }}>
            {compDetails?.duration_minutes || 60} Minutes
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            Scoring Tick: every {compDetails?.rules?.hold_interval_seconds || 60}s
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>ROSTER ALLOCATION</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4 }}>
            {teams.length} Teams Enrolled
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            {isRvB ? `Red: ${redTeams.length} | Blue: ${blueTeams.length}` : `${teams.length} Competitors`}
          </div>
        </div>

        <div className="card" style={{ marginBottom: 0 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>TERRITORY TERRAIN</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4 }}>
            {hills.length} Target Hills
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            Heterogeneous environments across local network
          </div>
        </div>
      </div>

      {/* Section: Participating Teams */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">
            <Users size={16} />
            <span>Participating Teams & Side Assignments</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {teams.length} Registered
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Team Identifier</th>
                <th>Team Name</th>
                <th>Side Alignment</th>
                <th>Initial Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {teams.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '20px 0' }}>
                    No teams enrolled in this match yet.
                  </td>
                </tr>
              ) : (
                teams.map((t) => (
                  <tr key={t.team_id}>
                    <td><code>{t.team_id}</code></td>
                    <td><strong>{t.team_name}</strong></td>
                    <td>
                      <span className={`badge ${t.side === 'RED' ? 'badge-red' : t.side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                        {t.side}
                      </span>
                    </td>
                    <td>{t.score} pts</td>
                    <td>
                      <span className="badge badge-green">READY</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section: Contested Hills Matrix */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">
            <Server size={16} />
            <span>Target Hills & Heterogeneous Infrastructure (9 Environments)</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {hills.length} Contested Assets
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Hill</th>
                <th>Target Host / IP</th>
                <th>Port</th>
                <th>Service</th>
                <th>Environment Type</th>
                <th>Initial Owner</th>
                <th>Holding Rate</th>
              </tr>
            </thead>
            <tbody>
              {hills.map((h) => (
                <tr key={h.hill_id}>
                  <td><strong>Hill {h.hill_id}: {h.name}</strong></td>
                  <td><code>{h.target_host}</code></td>
                  <td><code>{h.target_port}</code></td>
                  <td>{h.service_name}</td>
                  <td><span className="badge badge-neutral">{h.environment_type}</span></td>
                  <td>
                    <span className={`badge ${h.initial_owner_side === 'RED' ? 'badge-red' : h.initial_owner_side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                      {h.initial_owner_team_id || 'Unclaimed'} ({h.initial_owner_side || 'NEUTRAL'})
                    </span>
                  </td>
                  <td>+{h.points_per_interval} pts/tick</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section: Autonomous Agent Swarm Roles */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">
            <Cpu size={16} />
            <span>Autonomous Swarm Agent Roles (4 Nodes)</span>
          </div>
        </div>

        <div className="grid-2">
          <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="badge badge-blue">agent-01</span>
              <strong>Team Leader / Hill 1 Controller</strong>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Coordinates team strategy, submits master verifications, and directs swarm tasks.
            </div>
          </div>

          <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="badge badge-neutral">agent-02</span>
              <strong>Worker 1 / Hardening & Defense Specialist</strong>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Applies service patches, manages local firewall rules, and conducts health telemetry.
            </div>
          </div>

          <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="badge badge-neutral">agent-03</span>
              <strong>Worker 2 / Reconnaissance Sentinel</strong>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Monitors service availability, detects incoming compromise, and verifies integrity.
            </div>
          </div>

          <div className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="badge badge-neutral">agent-04</span>
              <strong>Worker 3 / Attack & Recapture Agent</strong>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Executes authorized attack objectives, retrieves proof flags, and executes recapture actions.
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Action Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <button className="btn btn-secondary" onClick={onBackToLauncher}>
          <ArrowLeft size={16} /> Exit to Launcher
        </button>

        <button
          className="btn btn-primary"
          style={{ padding: '12px 32px', fontSize: 15 }}
          onClick={() => onEnterWorkspace(compDetails)}
        >
          <span>Enter Operational Workspace</span>
          <ArrowRight size={16} />
        </button>
      </div>
    </div>
  );
}

