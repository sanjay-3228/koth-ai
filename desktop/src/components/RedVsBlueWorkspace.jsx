import React, { useState, useEffect, useCallback } from 'react';
import {
  Swords,
  Shield,
  Activity,
  Trophy,
  Server,
  Crosshair,
  Wrench,
  Clock,
  ListTodo,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Send,
  RefreshCw,
  Lock,
  Eye,
  Flame,
  ArrowRight,
  ArrowLeft,
  Radio,
  Bell,
  GitBranch,
} from 'lucide-react';
import AgentMonitoringView from './AgentMonitoringView';
import MultiAgentCoordinationView from './MultiAgentCoordinationView';
import NotificationFeed from './NotificationFeed';

export default function RedVsBlueWorkspace({
  coordinatorUrl,
  headers,
  user,
  competition,
  swarmStatus,
  teamId,
  onRefreshCompetition,
  onExitToLauncher,
}) {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'teams' | 'hills' | 'controlled' | 'opponent' | 'attack' | 'defense' | 'agents' | 'tasks' | 'history' | 'scoring' | 'audit'

  // Live state
  const [hills, setHills] = useState([]);
  const [teams, setTeams] = useState([]);
  const [leaderboard, setLeaderboard] = useState(null);
  const [history, setHistory] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [agents, setAgents] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [actionMsg, setActionMsg] = useState({ text: '', type: '' });

  // Attack form
  const [selectedAttackHill, setSelectedAttackHill] = useState(1);
  const [flagToken, setFlagToken] = useState('');
  const [attackAgent, setAttackAgent] = useState('agent-01');

  // Defense form
  const [selectedDefenseHill, setSelectedDefenseHill] = useState(1);
  const [patchSummary, setPatchSummary] = useState('');
  const [defenseServiceStatus, setDefenseServiceStatus] = useState('HEALTHY');
  const [defenseNotes, setDefenseNotes] = useState('');

  const cid = competition?.competition_id;
  const callerTeamId = user?.team_id || 'null_warriors';
  const callerSide = user?.side || (callerTeamId.includes('red') ? 'RED' : 'BLUE');

  // Load all workspace data
  const loadWorkspaceData = useCallback(async () => {
    if (!cid) return;
    setLoading(true);
    try {
      const hHeaders = headers ? headers() : { 'Content-Type': 'application/json' };

      // 1. Hills
      const hRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/hills`, { headers: hHeaders });
      if (hRes.ok) {
        const hData = await hRes.json();
        setHills(hData.hills || []);
      }

      // 2. Teams
      const tRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/teams`, { headers: hHeaders });
      if (tRes.ok) {
        const tData = await tRes.json();
        setTeams(tData.teams || []);
      }

      // 3. Leaderboard
      const lbRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/leaderboard`, { headers: hHeaders });
      if (lbRes.ok) {
        const lbData = await lbRes.json();
        setLeaderboard(lbData);
      }

      // 4. History
      const histRes = await fetch(`${coordinatorUrl}/api/competition/${cid}/history`, { headers: hHeaders });
      if (histRes.ok) {
        const histData = await histRes.json();
        setHistory(histData.history || []);
      }

      // 5. Swarm status / Agents / Tasks
      const sRes = await fetch(`${coordinatorUrl}/api/swarm/status`, { headers: hHeaders });
      if (sRes.ok) {
        const sData = await sRes.json();
        setAgents(sData.agents || []);
      }

      // 6. Tasks
      const tasksRes = await fetch(`${coordinatorUrl}/api/swarm/tasks`, { headers: hHeaders });
      if (tasksRes.ok) {
        const tasksData = await tasksRes.json();
        setTasks(tasksData.tasks || []);
      }

      // 7. Audit log
      const auditRes = await fetch(`${coordinatorUrl}/api/swarm/audit-log?limit=25`, { headers: hHeaders });
      if (auditRes.ok) {
        const auditData = await auditRes.json();
        setAuditLogs(auditData.events || []);
      }
    } catch (err) {
      console.error('Failed to load workspace data:', err);
    } finally {
      setLoading(false);
    }
  }, [cid, coordinatorUrl, headers]);

  useEffect(() => {
    loadWorkspaceData();
    const interval = setInterval(loadWorkspaceData, 5000);
    return () => clearInterval(interval);
  }, [loadWorkspaceData]);

  // Submit attack / capture
  const handleCaptureSubmit = async (e) => {
    e.preventDefault();
    if (!flagToken.trim()) return;
    setActionMsg({ text: 'Submitting flag for verification...', type: 'info' });

    try {
      const res = await fetch(`${coordinatorUrl}/api/competition/${cid}/capture`, {
        method: 'POST',
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hill_id: selectedAttackHill,
          flag: flagToken.trim(),
          agent_id: attackAgent,
          team_id: callerTeamId,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.message || 'Capture failed');
      }
      setActionMsg({ text: data.message || 'Capture verified successfully!', type: 'success' });
      setFlagToken('');
      loadWorkspaceData();
    } catch (err) {
      setActionMsg({ text: err.message, type: 'danger' });
    }
  };

  // Submit defense verification
  const handleDefenseSubmit = async (e) => {
    e.preventDefault();
    setActionMsg({ text: 'Submitting defense verification...', type: 'info' });

    try {
      const res = await fetch(`${coordinatorUrl}/api/competition/${cid}/defense`, {
        method: 'POST',
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hill_id: selectedDefenseHill,
          patch_summary: patchSummary || 'Hardening rules & firewall update verified',
          service_status: defenseServiceStatus,
          agent_id: attackAgent,
          team_id: callerTeamId,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.message || 'Defense submission failed');
      }
      setActionMsg({ text: data.message || 'Defense verified and points awarded!', type: 'success' });
      setPatchSummary('');
      loadWorkspaceData();
    } catch (err) {
      setActionMsg({ text: err.message, type: 'danger' });
    }
  };

  // Update private notes for controlled hill
  const handleUpdateNotes = async (hillId) => {
    try {
      const res = await fetch(`${coordinatorUrl}/api/competition/${cid}/hill/${hillId}/notes`, {
        method: 'POST',
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notes: defenseNotes,
          team_id: callerTeamId,
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActionMsg({ text: 'Private defense notes saved.', type: 'success' });
        loadWorkspaceData();
      } else {
        throw new Error(data.error || 'Failed to update notes');
      }
    } catch (err) {
      setActionMsg({ text: err.message, type: 'danger' });
    }
  };

  // Filter hills
  const myControlledHills = hills.filter(
    (h) => h.is_controlled_by_viewer || h.current_owner_team_id === callerTeamId
  );
  const opponentHills = hills.filter(
    (h) => !h.is_controlled_by_viewer && h.current_owner_team_id !== callerTeamId
  );

  const sections = [
    { id: 'overview', label: '1. Overview', icon: Trophy },
    { id: 'teams', label: '2. Teams', icon: Swords },
    { id: 'hills', label: '3. Hill Matrix', icon: Server },
    { id: 'controlled', label: '4. Controlled Hills', icon: Shield, badge: myControlledHills.length },
    { id: 'opponent', label: '5. Opponent Hills', icon: Crosshair, badge: opponentHills.length },
    { id: 'attack', label: '6. Attack Ops', icon: Flame },
    { id: 'defense', label: '7. Defense Ops', icon: Wrench },
    { id: 'agents', label: '8. Agent Telemetry', icon: Activity, badge: '4 Nodes' },
    { id: 'coordination', label: '9. Swarm Coordination', icon: GitBranch, badge: 'Swarm' },
    { id: 'notifications', label: '10. Live Event Feed', icon: Bell, badge: 'Live' },
    { id: 'tasks', label: '11. Task Pipeline', icon: ListTodo },
    { id: 'history', label: '12. Capture Log', icon: Clock },
    { id: 'scoring', label: '13. Leaderboard', icon: Trophy },
    { id: 'audit', label: '14. Audit Trail', icon: FileText },
  ];

  return (
    <div className="content-container">
      {/* Top Banner: Match & Red vs Blue Score Comparison */}
      <div
        className="card"
        style={{
          background: 'linear-gradient(135deg, #172536 0%, #22374E 100%)',
          color: '#FFFFFF',
          padding: '20px 24px',
          marginBottom: 20,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="badge badge-blue">{competition?.mode || 'RED_VS_BLUE'}</span>
              <span className="badge badge-neutral">{competition?.format || 'CLASSIC'}</span>
              <span className={`badge ${competition?.status === 'ACTIVE' ? 'badge-green' : 'badge-yellow'}`}>
                {competition?.status || 'ACTIVE'}
              </span>
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: '8px 0 4px', color: '#FFFFFF' }}>
              {competition?.name || 'Red vs Blue Cyber War'}
            </h1>
            <p style={{ margin: 0, fontSize: 13, color: '#A0AEC0' }}>
              Side Assignment: <strong style={{ color: callerSide === 'RED' ? '#FF8080' : '#80BFFF' }}>{callerSide} SIDE</strong> | Team: <strong>{callerTeamId}</strong>
            </p>
          </div>

          {/* Red vs Blue Score Clash Box */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#FF9999', textTransform: 'uppercase' }}>RED TOTAL</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: '#FF6666' }}>
                {leaderboard?.red_score ?? 0}
              </div>
              <div style={{ fontSize: 11, color: '#A0AEC0' }}>{leaderboard?.red_hills_count ?? 0} Hills</div>
            </div>

            <div style={{ fontSize: 20, fontWeight: 800, color: '#718096' }}>VS</div>

            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#99CCFF', textTransform: 'uppercase' }}>BLUE TOTAL</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: '#66B2FF' }}>
                {leaderboard?.blue_score ?? 0}
              </div>
              <div style={{ fontSize: 11, color: '#A0AEC0' }}>{leaderboard?.blue_hills_count ?? 0} Hills</div>
            </div>

            <button className="btn btn-secondary btn-sm" onClick={loadWorkspaceData} title="Refresh data">
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
            </button>

            {onExitToLauncher && (
              <button
                className="btn btn-secondary btn-sm"
                onClick={onExitToLauncher}
                style={{ background: 'rgba(255,255,255,0.1)', color: '#FFFFFF', borderColor: 'rgba(255,255,255,0.2)' }}
              >
                <ArrowLeft size={14} /> Exit to Launcher
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Action Notification Alert */}
      {actionMsg.text && (
        <div
          className={`alert ${
            actionMsg.type === 'success'
              ? 'alert-success'
              : actionMsg.type === 'danger'
              ? 'alert-danger'
              : 'alert-info'
          }`}
          style={{ marginBottom: 16 }}
        >
          {actionMsg.type === 'success' ? (
            <CheckCircle2 size={16} />
          ) : actionMsg.type === 'danger' ? (
            <AlertTriangle size={16} />
          ) : (
            <Radio size={16} />
          )}
          <span>{actionMsg.text}</span>
        </div>
      )}

      {/* 12-Section Navigation Bar */}
      <div
        className="card"
        style={{
          padding: '8px 12px',
          marginBottom: 20,
          display: 'flex',
          gap: 6,
          overflowX: 'auto',
          background: 'var(--panel-bg)',
        }}
      >
        {sections.map((sec) => {
          const Icon = sec.icon;
          const isActive = activeTab === sec.id;
          return (
            <button
              key={sec.id}
              onClick={() => setActiveTab(sec.id)}
              className={`btn ${isActive ? 'btn-primary' : 'btn-secondary'} btn-sm`}
              style={{
                whiteSpace: 'nowrap',
                fontSize: 12,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Icon size={14} />
              <span>{sec.label}</span>
              {sec.badge !== undefined && (
                <span
                  style={{
                    fontSize: 10,
                    padding: '1px 5px',
                    borderRadius: 10,
                    background: isActive ? 'rgba(255,255,255,0.3)' : 'var(--bg-main)',
                    color: isActive ? '#FFFFFF' : 'var(--text-secondary)',
                  }}
                >
                  {sec.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* =========================================================================
          SECTION 1: COMPETITION OVERVIEW
         ========================================================================= */}
      {activeTab === 'overview' && (
        <div>
          <div className="grid-3" style={{ marginBottom: 20 }}>
            <div className="card" style={{ marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>MATCH STATUS</div>
              <div style={{ fontSize: 20, fontWeight: 700, marginTop: 4, color: 'var(--green-success)' }}>
                {competition?.status || 'ACTIVE'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                Duration: {competition?.duration_minutes || 60}m | Time Remaining: {competition?.time_remaining_seconds ? `${Math.floor(competition.time_remaining_seconds / 60)}m` : 'In Progress'}
              </div>
            </div>

            <div className="card" style={{ marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>HILL OCCUPANCY</div>
              <div style={{ fontSize: 20, fontWeight: 700, marginTop: 4 }}>
                {hills.filter((h) => h.state === 'CAPTURED' || h.state === 'OWNED').length} / {hills.length} Controlled
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                Red: {leaderboard?.red_hills_count || 0} | Blue: {leaderboard?.blue_hills_count || 0} | Unclaimed: {leaderboard?.neutral_hills_count || 0}
              </div>
            </div>

            <div className="card" style={{ marginBottom: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>ENGAGEMENT FORMAT</div>
              <div style={{ fontSize: 20, fontWeight: 700, marginTop: 4 }}>
                {competition?.format || 'CLASSIC'}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                Symmetric Attack & Defense with Recapture
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Shield size={16} />
                <span>Operational Arena Territory Summary</span>
              </div>
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Hill ID</th>
                    <th>Asset Name</th>
                    <th>Environment</th>
                    <th>Target Endpoint</th>
                    <th>Current Controller</th>
                    <th>State</th>
                    <th>Health</th>
                    <th>Holding Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {hills.map((h) => (
                    <tr key={h.hill_id}>
                      <td><strong>Hill {h.hill_id}</strong></td>
                      <td>{h.name}</td>
                      <td><span className="badge badge-neutral">{h.environment_type}</span></td>
                      <td><code>{h.target_host}:{h.target_port}</code></td>
                      <td>
                        <span className={`badge ${h.current_owner_side === 'RED' ? 'badge-red' : h.current_owner_side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                          {h.current_owner_team_id || 'Unclaimed'} ({h.current_owner_side || 'NEUTRAL'})
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${h.state === 'CAPTURED' ? 'badge-blue' : h.state === 'OWNED' ? 'badge-green' : 'badge-neutral'}`}>
                          {h.state}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${h.health_status === 'HEALTHY' ? 'badge-green' : 'badge-red'}`}>
                          {h.health_status}
                        </span>
                      </td>
                      <td>+{h.points_per_interval} pts/tick</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 2: TEAM OVERVIEW
         ========================================================================= */}
      {activeTab === 'teams' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Swords size={16} />
              <span>Participating Teams & Side Allocations</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Team ID</th>
                  <th>Display Name</th>
                  <th>Side</th>
                  <th>Current Score</th>
                  <th>Captures</th>
                  <th>Recaptures</th>
                  <th>Defenses</th>
                  <th>Penalties</th>
                  <th>Elimination Status</th>
                </tr>
              </thead>
              <tbody>
                {teams.map((t) => (
                  <tr key={t.team_id}>
                    <td><code>{t.team_id}</code></td>
                    <td><strong>{t.team_name}</strong></td>
                    <td>
                      <span className={`badge ${t.side === 'RED' ? 'badge-red' : t.side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                        {t.side}
                      </span>
                    </td>
                    <td><strong style={{ fontSize: 15 }}>{t.score}</strong></td>
                    <td>{t.captures_count}</td>
                    <td>{t.recaptures_count}</td>
                    <td>{t.defenses_count}</td>
                    <td><span style={{ color: t.penalties_count > 0 ? 'var(--red-error)' : 'inherit' }}>{t.penalties_count}</span></td>
                    <td>
                      {t.eliminated ? (
                        <span className="badge badge-red">ELIMINATED ({t.eliminated_reason})</span>
                      ) : (
                        <span className="badge badge-green">ACTIVE IN ARENA</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 3: HILL MATRIX (ALL 9 ENVIRONMENTS)
         ========================================================================= */}
      {activeTab === 'hills' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={16} />
              <span>Contested Hill Infrastructure Matrix</span>
            </div>
          </div>
          <div className="grid-2">
            {hills.map((h) => (
              <div key={h.hill_id} className="card" style={{ background: 'var(--bg-main)', marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="badge badge-blue">Hill {h.hill_id}</span>
                    <strong style={{ fontSize: 14 }}>{h.name}</strong>
                  </div>
                  <span className={`badge ${h.current_owner_side === 'RED' ? 'badge-red' : h.current_owner_side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                    {h.current_owner_side || 'NEUTRAL'}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  Env: <strong>{h.environment_type}</strong> | Host: <code>{h.target_host}:{h.target_port}</code>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  Service: <code>{h.service_name}</code> | State: <strong>{h.state}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                  <span>Capture: +{h.capture_points} pts</span>
                  <span>Interval Hold: +{h.points_per_interval} pts</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 4: MY CONTROLLED HILLS
         ========================================================================= */}
      {activeTab === 'controlled' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Shield size={16} />
              <span>Hills Controlled by {callerTeamId} ({callerSide} Side)</span>
            </div>
          </div>

          {myControlledHills.length === 0 ? (
            <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
              Your side currently controls zero hills. Launch attack operations to capture contested terrain.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {myControlledHills.map((h) => (
                <div key={h.hill_id} className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                    <div>
                      <span className="badge badge-green" style={{ marginRight: 8 }}>CONTROLLED</span>
                      <strong>Hill {h.hill_id}: {h.name}</strong>
                    </div>
                    <span className="badge badge-neutral">+{h.points_per_interval} pts/tick</span>
                  </div>

                  <div className="grid-3" style={{ fontSize: 13, marginBottom: 12 }}>
                    <div>Environment: <strong>{h.environment_type}</strong></div>
                    <div>Target: <code>{h.target_host}:{h.target_port}</code></div>
                    <div>Health: <strong style={{ color: 'var(--green-success)' }}>{h.health_status}</strong></div>
                  </div>

                  {/* Private Defense Notes */}
                  <div style={{ marginTop: 8 }}>
                    <label className="form-label">Private Defense Hardening Notes (Protected from Opponents)</label>
                    <div style={{ display: 'flex', gap: 10 }}>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="e.g. IPTables DROP rule applied on port 22, patched CVE-2024-xxx"
                        defaultValue={h.defense_notes}
                        onChange={(e) => setDefenseNotes(e.target.value)}
                      />
                      <button className="btn btn-secondary" onClick={() => handleUpdateNotes(h.hill_id)}>
                        Save Notes
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          SECTION 5: OPPONENT HILLS
         ========================================================================= */}
      {activeTab === 'opponent' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Crosshair size={16} />
              <span>Opponent Target Reconnaissance & Contested Assets</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {opponentHills.map((h) => (
              <div key={h.hill_id} className="card" style={{ background: 'var(--bg-main)', marginBottom: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="badge badge-red">TARGET</span>
                    <strong>Hill {h.hill_id}: {h.name}</strong>
                  </div>
                  <span className="badge badge-neutral">{h.current_owner_team_id || 'Unclaimed'}</span>
                </div>

                <div className="grid-3" style={{ fontSize: 13, marginBottom: 8 }}>
                  <div>Environment: <strong>{h.environment_type}</strong></div>
                  <div>Endpoint: <code>{h.target_host}:{h.target_port}</code></div>
                  <div>Service: <code>{h.service_name}</code></div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    Capture Value: <strong>+{h.capture_points} pts</strong> (plus recapture bonus if held by opponent)
                  </span>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => {
                      setSelectedAttackHill(h.hill_id);
                      setActiveTab('attack');
                    }}
                  >
                    Target for Attack <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 6: ATTACK OPERATIONS
         ========================================================================= */}
      {activeTab === 'attack' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Flame size={16} />
              <span>Launch Attack / Submit Capture Flag Proof</span>
            </div>
          </div>

          <form onSubmit={handleCaptureSubmit}>
            <div className="grid-3" style={{ marginBottom: 16 }}>
              <div className="form-group">
                <label className="form-label">Contested Hill Target</label>
                <select
                  className="form-input"
                  value={selectedAttackHill}
                  onChange={(e) => setSelectedAttackHill(parseInt(e.target.value))}
                >
                  {hills.map((h) => (
                    <option key={h.hill_id} value={h.hill_id}>
                      Hill {h.hill_id} - {h.name} ({h.current_owner_side || 'NEUTRAL'})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Executing Agent Node</label>
                <select
                  className="form-input"
                  value={attackAgent}
                  onChange={(e) => setAttackAgent(e.target.value)}
                >
                  <option value="agent-01">Agent 01 (Team Leader / Primary)</option>
                  <option value="agent-02">Agent 02 (Worker 1)</option>
                  <option value="agent-03">Agent 03 (Worker 2)</option>
                  <option value="agent-04">Agent 04 (Worker 3)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Target Environment</label>
                <input
                  type="text"
                  className="form-input"
                  disabled
                  value={hills.find((h) => h.hill_id === selectedAttackHill)?.environment_type || 'LINUX'}
                />
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 20 }}>
              <label className="form-label">Hill Proof Flag Token</label>
              <input
                type="text"
                className="form-input"
                placeholder="FLAG{...}"
                value={flagToken}
                onChange={(e) => setFlagToken(e.target.value)}
                required
              />
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Tokens are validated via SHA-256 evidence hashing. Bad tokens incur rule penalties.
              </span>
            </div>

            <button type="submit" className="btn btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Send size={16} />
              <span>Submit Capture Verification</span>
            </button>
          </form>
        </div>
      )}

      {/* =========================================================================
          SECTION 7: DEFENSE OPERATIONS
         ========================================================================= */}
      {activeTab === 'defense' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Wrench size={16} />
              <span>Submit Defense & Hardening Verification</span>
            </div>
          </div>

          <form onSubmit={handleDefenseSubmit}>
            <div className="grid-2" style={{ marginBottom: 16 }}>
              <div className="form-group">
                <label className="form-label">Controlled Hill to Defend</label>
                <select
                  className="form-input"
                  value={selectedDefenseHill}
                  onChange={(e) => setSelectedDefenseHill(parseInt(e.target.value))}
                >
                  {myControlledHills.map((h) => (
                    <option key={h.hill_id} value={h.hill_id}>
                      Hill {h.hill_id} - {h.name}
                    </option>
                  ))}
                </select>
                {myControlledHills.length === 0 && (
                  <span style={{ fontSize: 12, color: 'var(--red-error)' }}>
                    No hills currently held to submit defense verification for.
                  </span>
                )}
              </div>

              <div className="form-group">
                <label className="form-label">Service Health Assessment</label>
                <select
                  className="form-input"
                  value={defenseServiceStatus}
                  onChange={(e) => setDefenseServiceStatus(e.target.value)}
                >
                  <option value="HEALTHY">HEALTHY (Service Responsive & Up)</option>
                  <option value="DEGRADED">DEGRADED (Partial Latency / Firewall Active)</option>
                  <option value="DOWN">DOWN (Offline)</option>
                </select>
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 20 }}>
              <label className="form-label">Patch & Hardening Summary</label>
              <textarea
                className="form-input"
                rows={3}
                placeholder="Describe security patches applied, firewall filters, or service verification..."
                value={patchSummary}
                onChange={(e) => setPatchSummary(e.target.value)}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={myControlledHills.length === 0}
              style={{ display: 'flex', alignItems: 'center', gap: 8 }}
            >
              <Shield size={16} />
              <span>Submit Defense Verification</span>
            </button>
          </form>
        </div>
      )}

      {/* =========================================================================
          SECTION 8: REAL-TIME AGENT MONITORING
         ========================================================================= */}
      {activeTab === 'agents' && (
        <AgentMonitoringView
          swarmStatus={swarmStatus}
          user={user}
          coordinatorUrl={coordinatorUrl}
          headers={headers}
        />
      )}

      {/* =========================================================================
          SECTION 9: MULTI-AGENT COORDINATION
         ========================================================================= */}
      {activeTab === 'coordination' && (
        <MultiAgentCoordinationView
          coordinatorUrl={coordinatorUrl}
          headers={headers}
          user={user}
          teamId={teamId || callerTeamId}
          competitionId={cid}
          swarmStatus={swarmStatus}
        />
      )}

      {/* =========================================================================
          SECTION 10: NOTIFICATIONS & EVENT FEED
         ========================================================================= */}
      {activeTab === 'notifications' && (
        <NotificationFeed
          coordinatorUrl={coordinatorUrl}
          headers={headers}
          teamId={teamId || callerTeamId}
          competitionId={cid}
        />
      )}

      {/* =========================================================================
          SECTION 9: TASK MANAGEMENT
         ========================================================================= */}
      {activeTab === 'tasks' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <ListTodo size={16} />
              <span>Authoritative Swarm Task Queue</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Task ID</th>
                  <th>Action Type</th>
                  <th>Target Host</th>
                  <th>Assigned Agent</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {tasks.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                      No active tasks in current phase queue.
                    </td>
                  </tr>
                ) : (
                  tasks.map((t) => (
                    <tr key={t.task_id}>
                      <td><code>{t.task_id}</code></td>
                      <td><strong>{t.action_type}</strong></td>
                      <td><code>{t.target_host}</code></td>
                      <td><span className="badge badge-blue">{t.assigned_agent_id || 'Unassigned'}</span></td>
                      <td><span className="badge badge-neutral">{t.status}</span></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 10: CAPTURE & RECAPTURE HISTORY
         ========================================================================= */}
      {activeTab === 'history' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Clock size={16} />
              <span>Authoritative Hill Capture & Recapture Chronology</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Hill</th>
                  <th>Event</th>
                  <th>New Controller</th>
                  <th>Previous Controller</th>
                  <th>Evidence Hash</th>
                </tr>
              </thead>
              <tbody>
                {history.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                      No captures or recaptures recorded yet.
                    </td>
                  </tr>
                ) : (
                  history.map((h) => (
                    <tr key={h.id}>
                      <td>{new Date(h.timestamp * 1000).toLocaleTimeString()}</td>
                      <td><strong>Hill {h.hill_id}</strong></td>
                      <td>
                        <span className={`badge ${h.event_type === 'RECAPTURE' ? 'badge-blue' : h.event_type === 'CAPTURE' ? 'badge-green' : 'badge-neutral'}`}>
                          {h.event_type}
                        </span>
                      </td>
                      <td><code>{h.new_owner_team_id} ({h.new_side})</code></td>
                      <td><code>{h.previous_owner_team_id || 'None'}</code></td>
                      <td><code>{h.evidence_hash}</code></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 11: SCORING & LEADERBOARD
         ========================================================================= */}
      {activeTab === 'scoring' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Trophy size={16} />
              <span>Official Competition Leaderboard & Tie-Breaker Standings</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Team</th>
                  <th>Side</th>
                  <th>Score</th>
                  <th>Captures</th>
                  <th>Defenses</th>
                  <th>Recaptures</th>
                  <th>Penalties</th>
                  <th>Uptime Held</th>
                </tr>
              </thead>
              <tbody>
                {leaderboard?.teams?.map((t, idx) => (
                  <tr key={t.team_id}>
                    <td><strong>#{idx + 1}</strong></td>
                    <td><strong>{t.team_name}</strong></td>
                    <td>
                      <span className={`badge ${t.side === 'RED' ? 'badge-red' : t.side === 'BLUE' ? 'badge-blue' : 'badge-neutral'}`}>
                        {t.side}
                      </span>
                    </td>
                    <td><strong style={{ fontSize: 16 }}>{t.score}</strong></td>
                    <td>{t.captures_count}</td>
                    <td>{t.defenses_count}</td>
                    <td>{t.recaptures_count}</td>
                    <td><span style={{ color: t.penalties_count > 0 ? 'var(--red-error)' : 'inherit' }}>{t.penalties_count}</span></td>
                    <td>{Math.round(t.uptime_seconds)}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =========================================================================
          SECTION 12: AUDIT HISTORY
         ========================================================================= */}
      {activeTab === 'audit' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <FileText size={16} />
              <span>Cryptographic Security Audit Log</span>
            </div>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Actor</th>
                  <th>Target</th>
                  <th>Audit ID</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id || log.event_id}>
                    <td>{new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
                    <td><span className="badge badge-neutral">{log.event_type}</span></td>
                    <td><strong>{log.actor}</strong></td>
                    <td><code>{log.target || 'N/A'}</code></td>
                    <td><code>{log.event_id}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

