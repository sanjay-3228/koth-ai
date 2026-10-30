import React, { useState } from 'react';
import { Shield, Users, LogIn, UserPlus, CheckCircle2, AlertTriangle, ArrowRight, ArrowLeft } from 'lucide-react';

export default function AuthView({
  coordinatorUrl,
  setCoordinatorUrl,
  authMode,
  setAuthMode,
  authError,
  setAuthError,
  loginUsername,
  setLoginUsername,
  loginPassword,
  setLoginPassword,
  teamId,
  setTeamId,
  teamName,
  setTeamName,
  teamRegData,
  setTeamRegData,
  onLogin,
  onRegisterTeam,
  onJoinTeam,
  onBackToLauncher,
}) {
  const [regStep, setRegStep] = useState('section_a');

  const updateRegMember = (slot, key, val) => {
    setTeamRegData((prev) => ({
      ...prev,
      [slot]: { ...prev[slot], [key]: val },
    }));
  };

  const steps = [
    { id: 'section_a', label: 'Section A: Team' },
    { id: 'section_b', label: 'Section B: Leader (Agent 01)' },
    { id: 'section_c', label: 'Section C: TM1 (Agent 02)' },
    { id: 'section_d', label: 'Section D: TM2 (Agent 03)' },
    { id: 'section_e', label: 'Section E: TM3 (Agent 04)' },
    { id: 'summary', label: 'Review & Submit' },
  ];

  const isWide = authMode === 'register_team';

  return (
    <div
      style={{
        minHeight: '100vh',
        width: '100vw',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-main)',
        padding: '30px 20px',
        overflowY: 'auto',
      }}
    >
      <div
        className="card"
        style={{
          maxWidth: isWide ? 760 : 440,
          width: '100%',
          boxShadow: 'var(--shadow-md)',
          padding: 28,
        }}
      >
        {/* Back to Launcher Link */}
        {onBackToLauncher && (
          <div style={{ marginBottom: 14 }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onBackToLauncher}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12 }}
            >
              <ArrowLeft size={13} /> Back to Competition Launcher
            </button>
          </div>
        )}

        {/* Header Branding */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              backgroundColor: 'var(--bg-light-blue)',
              color: 'var(--accent-interactive-blue)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={18} strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
              KOTH Command
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              King-of-the-Hill Swarm Operations Center
            </div>
          </div>
        </div>

        <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 20 }}>
          Connect via local network (LAN) with PBKDF2 authenticated credentials.
        </p>

        {/* Coordinator LAN URL Input */}
        <label htmlFor="coordinator-url">Coordinator LAN URL</label>
        <input
          id="coordinator-url"
          type="text"
          value={coordinatorUrl}
          onChange={(e) => setCoordinatorUrl(e.target.value)}
          placeholder="http://192.168.1.100:5000"
          style={{ marginBottom: 16 }}
        />

        {/* Auth Mode Toggle Buttons */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
          <button
            type="button"
            className={authMode === 'login' ? 'btn-primary' : ''}
            style={{ flex: 1, fontSize: 12 }}
            onClick={() => { setAuthMode('login'); setAuthError(''); }}
          >
            <LogIn size={13} />
            <span>Member Login</span>
          </button>
          <button
            type="button"
            className={authMode === 'register_team' ? 'btn-primary' : ''}
            style={{ flex: 1, fontSize: 12 }}
            onClick={() => { setAuthMode('register_team'); setAuthError(''); }}
          >
            <Users size={13} />
            <span>Register Team (4)</span>
          </button>
          <button
            type="button"
            className={authMode === 'join_team' ? 'btn-primary' : ''}
            style={{ flex: 1, fontSize: 12 }}
            onClick={() => { setAuthMode('join_team'); setAuthError(''); }}
          >
            <UserPlus size={13} />
            <span>Join Team</span>
          </button>
        </div>

        {/* Auth Error Banner */}
        {authError && (
          <div className="alert-banner alert-danger" style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={15} />
              <span>{authError}</span>
            </div>
          </div>
        )}

        {/* Mode 1: Member Login */}
        {authMode === 'login' && (
          <form onSubmit={onLogin}>
            <label htmlFor="login-username">Username *</label>
            <input
              id="login-username"
              type="text"
              required
              autoFocus
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              placeholder="e.g. alice, bob"
            />

            <label htmlFor="login-password">Password *</label>
            <input
              id="login-password"
              type="password"
              required
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              placeholder="••••••••"
            />

            <button type="submit" className="btn-primary" style={{ width: '100%', marginTop: 4 }}>
              Authenticate & Enter Operations Center
            </button>
          </form>
        )}

        {/* Mode 2: Join Team */}
        {authMode === 'join_team' && (
          <form onSubmit={onJoinTeam}>
            <label htmlFor="join-team-id">Team Identifier (slug) *</label>
            <input
              id="join-team-id"
              type="text"
              required
              value={teamId}
              onChange={(e) => setTeamId(e.target.value)}
              placeholder="e.g. cyber_dragons"
            />

            <label htmlFor="join-username">Your Unique Username *</label>
            <input
              id="join-username"
              type="text"
              required
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              placeholder="e.g. charlie"
            />

            <label htmlFor="join-password">Your Password *</label>
            <input
              id="join-password"
              type="password"
              required
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              placeholder="••••••••"
            />

            <button type="submit" className="btn-primary" style={{ width: '100%', marginTop: 4 }}>
              Join Swarm Roster
            </button>
          </form>
        )}

        {/* Mode 3: Complete 4-Member Team Registration Wizard */}
        {authMode === 'register_team' && (
          <div>
            {/* Step Indicators */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 18, flexWrap: 'wrap' }}>
              {steps.map((st) => (
                <button
                  key={st.id}
                  type="button"
                  className={regStep === st.id ? 'btn-primary' : ''}
                  style={{ fontSize: 11, padding: '5px 10px' }}
                  onClick={() => setRegStep(st.id)}
                >
                  {st.label}
                </button>
              ))}
            </div>

            <form onSubmit={onRegisterTeam}>
              {/* Section A: Team Information */}
              {regStep === 'section_a' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 12 }}>
                    Section A — Team Information
                  </h4>

                  <label htmlFor="reg-team-name">Team Name *</label>
                  <input
                    id="reg-team-name"
                    type="text"
                    required
                    placeholder="e.g. Cyber Dragons"
                    value={teamRegData.team_name}
                    onChange={(e) => {
                      const name = e.target.value;
                      setTeamRegData((p) => ({
                        ...p,
                        team_name: name,
                        team_id: name.toLowerCase().replace(/[^a-z0-9_-]/g, '_'),
                      }));
                    }}
                  />

                  <label htmlFor="reg-team-id">Team Identifier (slug) *</label>
                  <input
                    id="reg-team-id"
                    type="text"
                    required
                    placeholder="e.g. cyber_dragons"
                    value={teamRegData.team_id}
                    onChange={(e) => setTeamRegData((p) => ({ ...p, team_id: e.target.value.toLowerCase() }))}
                  />

                  <label htmlFor="reg-team-desc">Team Description (Optional)</label>
                  <input
                    id="reg-team-desc"
                    type="text"
                    placeholder="Autonomous Defense & Hill Control Swarm"
                    value={teamRegData.description}
                    onChange={(e) => setTeamRegData((p) => ({ ...p, description: e.target.value }))}
                  />

                  <label htmlFor="reg-comp-id">Competition Identifier (Optional)</label>
                  <input
                    id="reg-comp-id"
                    type="text"
                    placeholder="e.g. DEFCON-KOTH-2026"
                    value={teamRegData.competition_id}
                    onChange={(e) => setTeamRegData((p) => ({ ...p, competition_id: e.target.value }))}
                  />

                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
                    <button type="button" className="btn-primary" onClick={() => setRegStep('section_b')}>
                      Next: Team Leader (Agent 01) ➔
                    </button>
                  </div>
                </div>
              )}

              {/* Section B: Leader (Agent 01) */}
              {regStep === 'section_b' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                    Section B — Team Leader (Agent 01 · Hill 1)
                  </h4>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
                    Assigned to Hill 1 with Swarm orchestration authority.
                  </p>

                  <label htmlFor="reg-leader-name">Leader Full Name *</label>
                  <input
                    id="reg-leader-name"
                    type="text"
                    required
                    placeholder="Alice Vance"
                    value={teamRegData.leader.full_name}
                    onChange={(e) => updateRegMember('leader', 'full_name', e.target.value)}
                  />

                  <label htmlFor="reg-leader-user">Leader Unique Username *</label>
                  <input
                    id="reg-leader-user"
                    type="text"
                    required
                    placeholder="alice"
                    value={teamRegData.leader.username}
                    onChange={(e) => updateRegMember('leader', 'username', e.target.value)}
                  />

                  <div style={{ display: 'flex', gap: 10 }}>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-leader-pwd">Password * (min 6 chars)</label>
                      <input
                        id="reg-leader-pwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.leader.password}
                        onChange={(e) => updateRegMember('leader', 'password', e.target.value)}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-leader-cpwd">Confirm Password *</label>
                      <input
                        id="reg-leader-cpwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.leader.confirm_password}
                        onChange={(e) => updateRegMember('leader', 'confirm_password', e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    <button type="button" onClick={() => setRegStep('section_a')}>
                      <ArrowLeft size={13} /> Back
                    </button>
                    <button type="button" className="btn-primary" onClick={() => setRegStep('section_c')}>
                      Next: Teammate 1 (Agent 02) <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              )}

              {/* Section C: Teammate 1 (Agent 02) */}
              {regStep === 'section_c' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                    Section C — Teammate 1 (Agent 02 · Hill 2)
                  </h4>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
                    Assigned to Hill 2 Portal with dedicated hill isolation.
                  </p>

                  <label htmlFor="reg-tm1-name">Full Name *</label>
                  <input
                    id="reg-tm1-name"
                    type="text"
                    required
                    placeholder="Bob Smith"
                    value={teamRegData.teammate_1.full_name}
                    onChange={(e) => updateRegMember('teammate_1', 'full_name', e.target.value)}
                  />

                  <label htmlFor="reg-tm1-user">Unique Username *</label>
                  <input
                    id="reg-tm1-user"
                    type="text"
                    required
                    placeholder="bob"
                    value={teamRegData.teammate_1.username}
                    onChange={(e) => updateRegMember('teammate_1', 'username', e.target.value)}
                  />

                  <div style={{ display: 'flex', gap: 10 }}>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm1-pwd">Password *</label>
                      <input
                        id="reg-tm1-pwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_1.password}
                        onChange={(e) => updateRegMember('teammate_1', 'password', e.target.value)}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm1-cpwd">Confirm Password *</label>
                      <input
                        id="reg-tm1-cpwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_1.confirm_password}
                        onChange={(e) => updateRegMember('teammate_1', 'confirm_password', e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    <button type="button" onClick={() => setRegStep('section_b')}>
                      <ArrowLeft size={13} /> Back
                    </button>
                    <button type="button" className="btn-primary" onClick={() => setRegStep('section_d')}>
                      Next: Teammate 2 (Agent 03) <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              )}

              {/* Section D: Teammate 2 (Agent 03) */}
              {regStep === 'section_d' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                    Section D — Teammate 2 (Agent 03 · Hill 3)
                  </h4>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
                    Assigned to Hill 3 Portal with dedicated hill isolation.
                  </p>

                  <label htmlFor="reg-tm2-name">Full Name *</label>
                  <input
                    id="reg-tm2-name"
                    type="text"
                    required
                    placeholder="Charlie Davis"
                    value={teamRegData.teammate_2.full_name}
                    onChange={(e) => updateRegMember('teammate_2', 'full_name', e.target.value)}
                  />

                  <label htmlFor="reg-tm2-user">Unique Username *</label>
                  <input
                    id="reg-tm2-user"
                    type="text"
                    required
                    placeholder="charlie"
                    value={teamRegData.teammate_2.username}
                    onChange={(e) => updateRegMember('teammate_2', 'username', e.target.value)}
                  />

                  <div style={{ display: 'flex', gap: 10 }}>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm2-pwd">Password *</label>
                      <input
                        id="reg-tm2-pwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_2.password}
                        onChange={(e) => updateRegMember('teammate_2', 'password', e.target.value)}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm2-cpwd">Confirm Password *</label>
                      <input
                        id="reg-tm2-cpwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_2.confirm_password}
                        onChange={(e) => updateRegMember('teammate_2', 'confirm_password', e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    <button type="button" onClick={() => setRegStep('section_c')}>
                      <ArrowLeft size={13} /> Back
                    </button>
                    <button type="button" className="btn-primary" onClick={() => setRegStep('section_e')}>
                      Next: Teammate 3 (Agent 04) <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              )}

              {/* Section E: Teammate 3 (Agent 04) */}
              {regStep === 'section_e' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                    Section E — Teammate 3 (Agent 04 · Hill 4)
                  </h4>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
                    Assigned to Hill 4 Portal with dedicated hill isolation.
                  </p>

                  <label htmlFor="reg-tm3-name">Full Name *</label>
                  <input
                    id="reg-tm3-name"
                    type="text"
                    required
                    placeholder="Diana Prince"
                    value={teamRegData.teammate_3.full_name}
                    onChange={(e) => updateRegMember('teammate_3', 'full_name', e.target.value)}
                  />

                  <label htmlFor="reg-tm3-user">Unique Username *</label>
                  <input
                    id="reg-tm3-user"
                    type="text"
                    required
                    placeholder="diana"
                    value={teamRegData.teammate_3.username}
                    onChange={(e) => updateRegMember('teammate_3', 'username', e.target.value)}
                  />

                  <div style={{ display: 'flex', gap: 10 }}>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm3-pwd">Password *</label>
                      <input
                        id="reg-tm3-pwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_3.password}
                        onChange={(e) => updateRegMember('teammate_3', 'password', e.target.value)}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label htmlFor="reg-tm3-cpwd">Confirm Password *</label>
                      <input
                        id="reg-tm3-cpwd"
                        type="password"
                        required
                        placeholder="••••••••"
                        value={teamRegData.teammate_3.confirm_password}
                        onChange={(e) => updateRegMember('teammate_3', 'confirm_password', e.target.value)}
                      />
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                    <button type="button" onClick={() => setRegStep('section_d')}>
                      <ArrowLeft size={13} /> Back
                    </button>
                    <button type="button" className="btn-primary" onClick={() => setRegStep('summary')}>
                      Review Summary ➔
                    </button>
                  </div>
                </div>
              )}

              {/* Section F: Summary & Submit */}
              {regStep === 'summary' && (
                <div>
                  <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                    📋 Section F — Registration Summary
                  </h4>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                    Verify team parameters and all 4 member assignments before atomic registration.
                  </p>

                  <div style={{ background: 'var(--bg-subtle)', padding: 12, borderRadius: 6, marginBottom: 14, border: '1px solid var(--border-color)', fontSize: 12 }}>
                    <div>Team Name: <strong>{teamRegData.team_name || '--'}</strong></div>
                    <div>Team ID: <code>{teamRegData.team_id || '--'}</code></div>
                    <div>Competition: <strong>{teamRegData.competition_id || '--'}</strong></div>
                  </div>

                  <div className="table-container" style={{ marginBottom: 14 }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Role</th>
                          <th>Agent</th>
                          <th>Hill</th>
                          <th>Full Name</th>
                          <th>Username</th>
                          <th>Password</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td><span className="badge badge-blue">LEADER</span></td>
                          <td><strong>agent-01</strong></td>
                          <td>Hill 1</td>
                          <td>{teamRegData.leader.full_name || '--'}</td>
                          <td><code>{teamRegData.leader.username || '--'}</code></td>
                          <td>{teamRegData.leader.password ? '••••••' : '❌'}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-neutral">MEMBER</span></td>
                          <td><strong>agent-02</strong></td>
                          <td>Hill 2</td>
                          <td>{teamRegData.teammate_1.full_name || '--'}</td>
                          <td><code>{teamRegData.teammate_1.username || '--'}</code></td>
                          <td>{teamRegData.teammate_1.password ? '••••••' : '❌'}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-neutral">MEMBER</span></td>
                          <td><strong>agent-03</strong></td>
                          <td>Hill 3</td>
                          <td>{teamRegData.teammate_2.full_name || '--'}</td>
                          <td><code>{teamRegData.teammate_2.username || '--'}</code></td>
                          <td>{teamRegData.teammate_2.password ? '••••••' : '❌'}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-neutral">MEMBER</span></td>
                          <td><strong>agent-04</strong></td>
                          <td>Hill 4</td>
                          <td>{teamRegData.teammate_3.full_name || '--'}</td>
                          <td><code>{teamRegData.teammate_3.username || '--'}</code></td>
                          <td>{teamRegData.teammate_3.password ? '••••••' : '❌'}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 16 }}>
                    <button type="button" onClick={() => setRegStep('section_e')}>
                      <ArrowLeft size={13} /> Edit Details
                    </button>
                    <button type="submit" className="btn-primary" style={{ padding: '8px 20px' }}>
                      Register 4-Member Team & Enter Portal
                    </button>
                  </div>
                </div>
              )}
            </form>
          </div>
        )}
      </div>
    </div>
  );
}

