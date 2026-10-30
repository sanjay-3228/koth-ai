import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Trophy,
  Swords,
  Flame,
  Plus,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  RefreshCw,
  Server,
  Users,
  Clock,
  Play,
  LogIn,
  Layers,
  HelpCircle,
} from 'lucide-react';
import CompetitionWizard from './CompetitionWizard';
import CompetitionLobby from './CompetitionLobby';

export default function CompetitionLauncher({
  coordinatorUrl,
  headers,
  user,
  onLaunchWorkspace,
}) {
  // Navigation states: 'landing' | 'format_select' | 'wizard' | 'lobby' | 'join_modal'
  const [screen, setScreen] = useState('landing');
  const [selectedMode, setSelectedMode] = useState('RED_VS_BLUE'); // 'KOTH' | 'RED_VS_BLUE'
  const [selectedFormat, setSelectedFormat] = useState('CLASSIC');
  const [activeCompetition, setActiveCompetition] = useState(null);

  // Available competitions from backend
  const [competitions, setCompetitions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Join form state
  const [joinCompId, setJoinCompId] = useState('');
  const [joinTeamName, setJoinTeamName] = useState(user?.team_name || 'My Squad');
  const [joinSide, setJoinSide] = useState('RED');
  const [joining, setJoining] = useState(false);

  // Fetch available competitions
  const fetchCompetitions = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const hHeaders = headers ? headers() : { 'Content-Type': 'application/json' };
      const res = await fetch(`${coordinatorUrl}/api/competitions`, { headers: hHeaders });
      if (res.ok) {
        const data = await res.json();
        setCompetitions(data.competitions || []);
      }
    } catch (err) {
      console.error('Failed to load competitions:', err);
    } finally {
      setLoading(false);
    }
  }, [coordinatorUrl, headers]);

  useEffect(() => {
    fetchCompetitions();
  }, [fetchCompetitions]);

  const handleSelectMode = (mode) => {
    setSelectedMode(mode);
    setSelectedFormat(mode === 'KOTH' ? 'SINGLE_HILL' : 'CLASSIC');
    setScreen('wizard');
  };

  const handleOpenLobby = (comp) => {
    setActiveCompetition(comp);
    setScreen('lobby');
  };

  const handleJoinSubmit = async (e) => {
    e.preventDefault();
    if (!joinCompId.trim()) return;
    setJoining(true);
    setErrorMsg('');

    try {
      const tid = joinTeamName.toLowerCase().replace(/[^a-z0-9]/g, '_');
      const res = await fetch(`${coordinatorUrl}/api/competition/${joinCompId.trim()}/join`, {
        method: 'POST',
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          team_id: tid,
          team_name: joinTeamName.trim(),
          side: joinSide,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || data.message || 'Failed to join competition');
      }

      // Fetch competition details and open lobby
      const cRes = await fetch(`${coordinatorUrl}/api/competition/${joinCompId.trim()}`, {
        headers: headers ? headers() : { 'Content-Type': 'application/json' },
      });
      if (cRes.ok) {
        const cData = await cRes.json();
        setActiveCompetition(cData.competition);
        setScreen('lobby');
      }
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setJoining(false);
    }
  };

  // --------------------------------------------------------------------------
  // COMPETITION LOBBY (Existing Matches)
  // --------------------------------------------------------------------------
  if (screen === 'lobby' && activeCompetition) {
    return (
      <CompetitionLobby
        coordinatorUrl={coordinatorUrl}
        headers={headers}
        competition={activeCompetition}
        user={user}
        onEnterWorkspace={(comp) => onLaunchWorkspace(comp)}
        onBackToLauncher={() => {
          fetchCompetitions();
          setScreen('landing');
        }}
      />
    );
  }

  // --------------------------------------------------------------------------
  // EXACTLY 4-STEP COMPETITION CREATION WIZARD
  // Step 1: Mode & Format -> Step 2: Target Hills -> Step 3: Review -> Step 4: Launch
  // --------------------------------------------------------------------------
  if (screen === 'wizard') {
    return (
      <CompetitionWizard
        coordinatorUrl={coordinatorUrl}
        headers={headers}
        initialMode={selectedMode}
        initialFormat={selectedFormat}
        onCompetitionCreated={(newComp) => {
          onLaunchWorkspace(newComp);
        }}
        onCancel={() => setScreen('landing')}
      />
    );
  }

  // --------------------------------------------------------------------------
  // SCREEN 1: COMPETITION LAUNCHER LANDING
  // --------------------------------------------------------------------------
  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-main)', padding: '36px 20px' }}>
      <div style={{ maxWidth: 1040, margin: '0 auto' }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 52,
              height: 52,
              borderRadius: 12,
              background: 'var(--blue-interactive)',
              color: '#FFFFFF',
              marginBottom: 14,
              boxShadow: '0 4px 12px rgba(40, 120, 200, 0.25)',
            }}
          >
            <Shield size={28} strokeWidth={2.5} />
          </div>

          <h1 style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', margin: '0 0 8px' }}>
            KOTH COMMAND
          </h1>
          <p style={{ fontSize: 14, color: 'var(--text-secondary)', margin: 0 }}>
            Authoritative Autonomous Cybersecurity Competition Platform
          </p>
        </div>

        {errorMsg && (
          <div className="alert alert-danger" style={{ marginBottom: 20 }}>
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Major Decision Header */}
        <div style={{ marginBottom: 16 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Select Competition Mode
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '4px 0 0' }}>
            Choose the fundamental competition paradigm to initialize or join
          </p>
        </div>

        {/* SCREEN 1: TWO PROMINENT MODE CARDS */}
        <div className="grid-2" style={{ gap: 20, marginBottom: 36 }}>
          {/* CARD 1: KING OF THE HILL (KOTH) */}
          <div
            className="card"
            onClick={() => handleSelectMode('KOTH')}
            style={{
              padding: '24px 28px',
              cursor: 'pointer',
              border: '2px solid var(--border-color)',
              borderRadius: 10,
              background: 'var(--panel-bg)',
              transition: 'all 0.2s ease-in-out',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              marginBottom: 0,
            }}
            onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--blue-interactive)')}
            onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-color)')}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: 10,
                    background: '#FFF3E0',
                    color: '#E65100',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Flame size={24} />
                </div>
                <span className="badge badge-yellow">5 Formats Available</span>
              </div>

              <h3 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: '0 0 8px' }}>
                King of the Hill (KOTH)
              </h3>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Competitive multi-team territory control. Multiple teams deploy autonomous swarms to seize and hold contested infrastructure, accumulating holding score intervals over time.
              </p>

              <div style={{ marginTop: 16, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {['Single-Hill', 'Multi-Hill', 'Team-vs-Team', 'Elimination', 'Timed'].map((f) => (
                  <span key={f} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: 'var(--bg-main)', color: 'var(--text-secondary)', fontWeight: 500 }}>
                    {f}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginTop: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--blue-interactive)' }}>
                Select KOTH Mode
              </span>
              <button className="btn btn-primary btn-sm">
                <span>Configure</span> <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* CARD 2: RED TEAM VS BLUE TEAM */}
          <div
            className="card"
            onClick={() => handleSelectMode('RED_VS_BLUE')}
            style={{
              padding: '24px 28px',
              cursor: 'pointer',
              border: '2px solid var(--border-color)',
              borderRadius: 10,
              background: 'var(--panel-bg)',
              transition: 'all 0.2s ease-in-out',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              marginBottom: 0,
            }}
            onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--blue-interactive)')}
            onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-color)')}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: 10,
                    background: 'var(--blue-bg-light)',
                    color: 'var(--blue-interactive)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Swords size={24} />
                </div>
                <span className="badge badge-blue">6 Formats Available</span>
              </div>

              <h3 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: '0 0 8px' }}>
                Red Team vs Blue Team
              </h3>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Two opposing sides in the same dynamic cyber warfare match. Both Red and Blue sides can attack, capture, defend, and recapture hills with active territory exchanges.
              </p>

              <div style={{ marginTop: 16, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {['Classic', 'Multi-Team', 'Multi-Hill', 'Elimination', 'Timed', 'Continuous'].map((f) => (
                  <span key={f} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: 'var(--bg-main)', color: 'var(--text-secondary)', fontWeight: 500 }}>
                    {f}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginTop: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--blue-interactive)' }}>
                Select Red vs Blue Mode
              </span>
              <button className="btn btn-primary btn-sm">
                <span>Configure</span> <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </div>

        {/* Quick Join Match Section */}
        <div className="card" style={{ padding: '16px 20px', marginBottom: 28, background: '#FFFFFF' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <LogIn size={16} />
              <strong style={{ fontSize: 14 }}>Join Existing Match by Identifier</strong>
            </div>
          </div>

          <form onSubmit={handleJoinSubmit} style={{ display: 'flex', gap: 10 }}>
            <input
              type="text"
              className="form-input"
              placeholder="Enter Competition ID (e.g. comp-xxxx or DEFCON-2026)"
              value={joinCompId}
              onChange={(e) => setJoinCompId(e.target.value)}
              style={{ flex: 2 }}
              required
            />
            <input
              type="text"
              className="form-input"
              placeholder="Your Team Display Name"
              value={joinTeamName}
              onChange={(e) => setJoinTeamName(e.target.value)}
              style={{ flex: 2 }}
              required
            />
            <select
              className="form-input"
              value={joinSide}
              onChange={(e) => setJoinSide(e.target.value)}
              style={{ flex: 1 }}
            >
              <option value="RED">RED Side</option>
              <option value="BLUE">BLUE Side</option>
              <option value="NEUTRAL">NEUTRAL Side</option>
            </select>
            <button type="submit" className="btn btn-primary" disabled={joining}>
              {joining ? 'Joining...' : 'Join Match'}
            </button>
          </form>
        </div>

        {/* Available Competitions List */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div className="card-title">
              <Trophy size={16} />
              <span>Available Active & Scheduled Competitions on Coordinator Network</span>
            </div>
            <button className="btn btn-secondary btn-sm" onClick={fetchCompetitions} title="Refresh">
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
            </button>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Competition Identifier</th>
                  <th>Competition Name</th>
                  <th>Mode</th>
                  <th>Format</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {competitions.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px 0' }}>
                      No active competitions found. Use the cards above to configure and launch a new match.
                    </td>
                  </tr>
                ) : (
                  competitions.map((comp) => (
                    <tr key={comp.competition_id}>
                      <td><code>{comp.competition_id}</code></td>
                      <td><strong>{comp.name}</strong></td>
                      <td>
                        <span className={`badge ${comp.mode === 'RED_VS_BLUE' ? 'badge-blue' : 'badge-yellow'}`}>
                          {comp.mode}
                        </span>
                      </td>
                      <td><span className="badge badge-neutral">{comp.format}</span></td>
                      <td>
                        <span className={`badge ${comp.status === 'ACTIVE' ? 'badge-green' : 'badge-neutral'}`}>
                          {comp.status}
                        </span>
                      </td>
                      <td>{comp.duration_minutes}m</td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleOpenLobby(comp)}
                          style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                        >
                          <span>Open Lobby</span> <ArrowRight size={13} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

