import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import EmergencyStopModal from './components/EmergencyStopModal';
import DashboardView from './components/DashboardView';
import TeamManagementView from './components/TeamManagementView';
import HillPortalsView from './components/HillPortalsView';
import AgentMonitoringView from './components/AgentMonitoringView';
import CoordinatorView from './components/CoordinatorView';
import TaskManagementView from './components/TaskManagementView';
import CompetitionConfigView from './components/CompetitionConfigView';
import LLMSettingsView from './components/LLMSettingsView';
import AuditLogsView from './components/AuditLogsView';
import SecuritySettingsView from './components/SecuritySettingsView';
import AuthView from './components/AuthView';
import CompetitionWizard from './components/CompetitionWizard';
import RedVsBlueWorkspace from './components/RedVsBlueWorkspace';
import CompetitionLauncher from './components/CompetitionLauncher';
import NotificationFeed from './components/NotificationFeed';
import MultiAgentCoordinationView from './components/MultiAgentCoordinationView';

export default function App() {
  const [coordinatorUrl, setCoordinatorUrl] = useState(() => {
    return (window.kothDesktop && window.kothDesktop.backendUrl) || 'http://127.0.0.1:5000';
  });
  const [token, setToken] = useState(() => sessionStorage.getItem('koth_desktop_token') || '');
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem('koth_desktop_user') || 'null');
    } catch {
      return null;
    }
  });

  // Auth form state
  const [authMode, setAuthMode] = useState('login'); // 'login' | 'register_team' | 'join_team'
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [teamId, setTeamId] = useState(() => user?.team_id || '');
  const [teamName, setTeamName] = useState(() => user?.team_name || '');
  const [authError, setAuthError] = useState('');

  // 4-Member Team Registration State
  const [teamRegData, setTeamRegData] = useState({
    team_name: '',
    team_id: '',
    description: '',
    competition_id: '',
    leader: { full_name: '', username: '', password: '', confirm_password: '' },
    teammate_1: { full_name: '', username: '', password: '', confirm_password: '' },
    teammate_2: { full_name: '', username: '', password: '', confirm_password: '' },
    teammate_3: { full_name: '', username: '', password: '', confirm_password: '' },
  });

  // Team Management State
  const [teamMgmtData, setTeamMgmtData] = useState(null);
  const [mgmtError, setMgmtError] = useState('');
  const [incompleteTeammates, setIncompleteTeammates] = useState([
    { full_name: '', username: '', password: '', confirm_password: '' },
    { full_name: '', username: '', password: '', confirm_password: '' },
    { full_name: '', username: '', password: '', confirm_password: '' },
  ]);

  // Top-Level Application Layer: 'launcher' | 'workspace' | 'auth'
  const [appLayer, setAppLayer] = useState(() => {
    const savedToken = sessionStorage.getItem('koth_desktop_token');
    const savedComp = sessionStorage.getItem('koth_active_comp');
    const savedLayer = sessionStorage.getItem('koth_app_layer');
    if (savedToken && savedComp && savedLayer === 'workspace') {
      return 'workspace';
    }
    return 'launcher';
  });

  const [activeCompetition, setActiveCompetition] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem('koth_active_comp') || 'null');
    } catch {
      return null;
    }
  });

  // Dashboard live state
  const [swarmStatus, setSwarmStatus] = useState(null);
  const [hills, setHills] = useState([]);
  const [members, setMembers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [competitions, setCompetitions] = useState([]);
  const [showWizard, setShowWizard] = useState(false);
  const [activeView, setActiveView] = useState('overview'); // 'overview' | 'team_mgmt' | 'hills' | 'agents' | 'coordinator' | 'tasks' | 'competition' | 'llm' | 'audit' | 'security'
  const [lastSync, setLastSync] = useState(null);
  const [isOffline, setIsOffline] = useState(false);

  // Hill form state
  const [hillConfig, setHillConfig] = useState({
    service_name: '',
    target_host: '',
    target_port: 80,
    defense_endpoint: '',
  });
  const [flagInput, setFlagInput] = useState('');
  const [actionMsg, setActionMsg] = useState('');
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);

  const headers = useCallback(() => {
    return {
      'Content-Type': 'application/json',
      'X-Session-Token': token,
      'Authorization': `Bearer ${token}`,
    };
  }, [token]);

  // Sync coordinator data
  const fetchData = useCallback(async () => {
    if (!token) return;
    try {
      // 1. Swarm status
      const sRes = await fetch(`${coordinatorUrl}/api/swarm/status`, { headers: headers() });
      if (sRes.status === 401) {
        handleLogout();
        return;
      }
      if (sRes.ok) {
        const sData = await sRes.json();
        setSwarmStatus(sData);
        setIsOffline(false);
      }

      // 2. Hills
      const hRes = await fetch(`${coordinatorUrl}/api/hills`, { headers: headers() });
      if (hRes.ok) {
        const hData = await hRes.json();
        setHills(hData.hills || []);
      }

      // 3. Team members
      const mRes = await fetch(`${coordinatorUrl}/api/team/members?team_id=${teamId}`, { headers: headers() });
      if (mRes.ok) {
        const mData = await mRes.json();
        setMembers(mData.members || []);
      }

      // 4. Audit events
      const aRes = await fetch(`${coordinatorUrl}/api/swarm/audit-log?limit=50`, { headers: headers() });
      if (aRes.ok) {
        const aData = await aRes.json();
        setAuditLogs(aData.events || []);
      }

      // 5. Team Management Details (Leader only)
      if (user?.role === 'LEADER') {
        const tmRes = await fetch(`${coordinatorUrl}/api/team/management?team_id=${teamId}`, { headers: headers() });
        if (tmRes.ok) {
          const tmData = await tmRes.json();
          setTeamMgmtData(tmData);
        }
      }

      // 6. Competitions List
      const compRes = await fetch(`${coordinatorUrl}/api/competitions`, { headers: headers() });
      if (compRes.ok) {
        const compData = await compRes.json();
        setCompetitions(compData.competitions || []);
        if (!activeCompetition && compData.competitions && compData.competitions.length > 0) {
          setActiveCompetition(compData.competitions[0]);
        }
      }

      setLastSync(new Date());
    } catch {
      setIsOffline(true);
    }
  }, [coordinatorUrl, token, teamId, user, headers]);

  const fetchTeamMgmt = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`${coordinatorUrl}/api/team/management?team_id=${teamId}`, { headers: headers() });
      if (res.ok) {
        const data = await res.json();
        setTeamMgmtData(data);
      }
    } catch {}
  }, [coordinatorUrl, token, teamId, headers]);

  useEffect(() => {
    if (!token) return;
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, [token, fetchData]);

  // Auth Handlers
  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/team/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Login failed');

      setToken(data.session_token);
      setUser(data);
      if (data.team_id) setTeamId(data.team_id);
      if (data.team_name) setTeamName(data.team_name);
      sessionStorage.setItem('koth_desktop_token', data.session_token);
      sessionStorage.setItem('koth_desktop_user', JSON.stringify(data));
      setActiveView('overview');
      if (activeCompetition) {
        sessionStorage.setItem('koth_app_layer', 'workspace');
        setAppLayer('workspace');
      } else {
        sessionStorage.setItem('koth_app_layer', 'launcher');
        setAppLayer('launcher');
      }
      return true;
    } catch (err) {
      setAuthError(err.message);
      return false;
    }
  };

  const handleRegisterFourMemberTeam = async (e) => {
    e.preventDefault();
    setAuthError('');

    const tName = (teamRegData.team_name || '').trim();
    if (!tName || tName.length < 3) {
      setAuthError('Team name must be at least 3 characters.');
      return;
    }

    const membersToCheck = [
      { label: 'Team Leader (Agent 01)', data: teamRegData.leader },
      { label: 'Teammate 1 (Agent 02)', data: teamRegData.teammate_1 },
      { label: 'Teammate 2 (Agent 03)', data: teamRegData.teammate_2 },
      { label: 'Teammate 3 (Agent 04)', data: teamRegData.teammate_3 },
    ];

    const usernamesSeen = new Set();
    for (const m of membersToCheck) {
      const fn = (m.data.full_name || '').trim();
      const un = (m.data.username || '').trim();
      const pwd = m.data.password || '';
      const cpwd = m.data.confirm_password || '';

      if (!fn) {
        setAuthError(`Full name is required for ${m.label}.`);
        return;
      }
      if (!un || un.length < 3) {
        setAuthError(`Username for ${m.label} must be at least 3 characters.`);
        return;
      }
      const uNorm = un.toLowerCase();
      if (usernamesSeen.has(uNorm)) {
        setAuthError(`Duplicate username '${un}' detected. All four team members must have unique usernames.`);
        return;
      }
      usernamesSeen.add(uNorm);

      if (!pwd || pwd.length < 6) {
        setAuthError(`Password for ${m.label} must be at least 6 characters.`);
        return;
      }
      if (pwd !== cpwd) {
        setAuthError(`Password confirmation does not match for ${m.label}.`);
        return;
      }
    }

    try {
      const res = await fetch(`${coordinatorUrl}/api/team/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(teamRegData),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Team registration failed');

      setToken(data.session_token);
      const userObj = {
        ...data,
        ...data.leader,
        team_name: data.team_name,
        role: 'LEADER',
        agent_id: 'agent-01',
        hill_id: 1,
      };
      setUser(userObj);
      setTeamId(data.team_id);
      setTeamName(data.team_name);
      sessionStorage.setItem('koth_desktop_token', data.session_token);
      sessionStorage.setItem('koth_desktop_user', JSON.stringify(userObj));
      setActiveView('overview');
      if (activeCompetition) {
        sessionStorage.setItem('koth_app_layer', 'workspace');
        setAppLayer('workspace');
      } else {
        sessionStorage.setItem('koth_app_layer', 'launcher');
        setAppLayer('launcher');
      }
      return true;
    } catch (err) {
      setAuthError(err.message);
      return false;
    }
  };

  const handleJoinTeam = async (e) => {
    e.preventDefault();
    setAuthError('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/team/join`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          team_id: teamId,
          username: loginUsername,
          password: loginPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Join failed');
      await handleLogin(e);
    } catch (err) {
      setAuthError(err.message);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch(`${coordinatorUrl}/api/team/logout`, { method: 'POST', headers: headers() });
    } catch {}
    setToken('');
    setUser(null);
    sessionStorage.removeItem('koth_desktop_token');
    sessionStorage.removeItem('koth_desktop_user');
    sessionStorage.removeItem('koth_active_comp');
    sessionStorage.removeItem('koth_app_layer');
    setAppLayer('launcher');
  };

  const handleCompleteRegistration = async (e) => {
    e.preventDefault();
    setMgmtError('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/team/complete-registration`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          team_id: teamId,
          teammates: incompleteTeammates,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to complete registration');
      setActionMsg('Team registration completed! All 4 agent portals are now operational.');
      fetchTeamMgmt();
      fetchData();
    } catch (err) {
      setMgmtError(err.message);
    }
  };

  // Operations Handlers
  const handleAdvancePhase = async (phase) => {
    try {
      const res = await fetch(`${coordinatorUrl}/api/swarm/phase/advance`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ phase }),
      });
      const data = await res.json();
      if (!res.ok) alert(data.message || 'Phase transition failed');
      else fetchData();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const handleEmergencyStop = async (reason) => {
    try {
      const res = await fetch(`${coordinatorUrl}/api/swarm/kill-switch`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({
          reason: reason || `Operator manual kill triggered by ${user?.username || 'leader'}`,
        }),
      });
      const data = await res.json();
      if (!res.ok) alert(data.message || 'Kill switch failed');
      else fetchData();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const handleResetEmergencyStop = async () => {
    if (!confirm('Confirm reset of persistent emergency stop? Normal swarm operations will resume.')) return;
    try {
      const res = await fetch(`${coordinatorUrl}/api/swarm/kill-switch/reset`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ agent_id: user?.agent_id || 'operator' }),
      });
      const data = await res.json();
      if (!res.ok) alert(data.message || 'Reset failed');
      else fetchData();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  };

  const handleSaveHillConfig = async (hillId) => {
    setActionMsg('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/hill/${hillId}/config`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(hillConfig),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Config failed');
      setActionMsg(`Hill ${hillId} configuration saved.`);
      fetchData();
    } catch (err) {
      setActionMsg(`Error: ${err.message}`);
    }
  };

  const handleSetHillFlag = async (hillId) => {
    if (!flagInput) return;
    setActionMsg('');
    try {
      const res = await fetch(`${coordinatorUrl}/api/hill/${hillId}/flag`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ flag: flagInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Flag update failed');
      setFlagInput('');
      setActionMsg(`Hill ${hillId} flag hash registered successfully. Plaintext redacted.`);
      fetchData();
    } catch (err) {
      setActionMsg(`Error: ${err.message}`);
    }
  };

  const handleTriggerVerify = async (hillId) => {
    try {
      const res = await fetch(`${coordinatorUrl}/api/hill/${hillId}/verify`, {
        method: 'POST',
        headers: headers(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Verification failed');
      setActionMsg(`Hill ${hillId} verified: ${data.ownership_status} (${data.health_status})`);
      fetchData();
    } catch (err) {
      setActionMsg(`Error: ${err.message}`);
    }
  };

  const handleLaunchWorkspace = async (comp) => {
    if (!comp) return;

    // Check authentication
    if (!token || !user) {
      setActiveCompetition(comp);
      sessionStorage.setItem('koth_active_comp', JSON.stringify(comp));
      setAppLayer('auth');
      return;
    }

    // Authoritative backend verification
    try {
      const res = await fetch(`${coordinatorUrl}/api/competition/${comp.competition_id}/access`, {
        headers: headers(),
      });
      if (res.status === 403) {
        const data = await res.json();
        alert(`Access Denied: ${data.error || 'Your team is not authorized for this competition.'}`);
        return;
      }
    } catch (err) {
      console.warn('Backend authorization check network error:', err);
    }

    setActiveCompetition(comp);
    sessionStorage.setItem('koth_active_comp', JSON.stringify(comp));
    sessionStorage.setItem('koth_app_layer', 'workspace');
    setAppLayer('workspace');
    fetchData();
  };

  const handleExitToLauncher = () => {
    sessionStorage.setItem('koth_app_layer', 'launcher');
    setAppLayer('launcher');
  };

  // --------------------------------------------------------------------------
  // LAYER 1 — COMPETITION LAUNCHER (Application Entry Point)
  // --------------------------------------------------------------------------
  if (appLayer === 'launcher') {
    return (
      <CompetitionLauncher
        coordinatorUrl={coordinatorUrl}
        headers={headers}
        user={user}
        onLaunchWorkspace={handleLaunchWorkspace}
      />
    );
  }

  // --------------------------------------------------------------------------
  // AUTHENTICATION & SQUAD ONBOARDING GATEWAY
  // --------------------------------------------------------------------------
  if (appLayer === 'auth' || !token || !user) {
    return (
      <AuthView
        coordinatorUrl={coordinatorUrl}
        setCoordinatorUrl={setCoordinatorUrl}
        authMode={authMode}
        setAuthMode={setAuthMode}
        authError={authError}
        setAuthError={setAuthError}
        loginUsername={loginUsername}
        setLoginUsername={setLoginUsername}
        loginPassword={loginPassword}
        setLoginPassword={setLoginPassword}
        teamId={teamId}
        setTeamId={setTeamId}
        teamName={teamName}
        setTeamName={setTeamName}
        teamRegData={teamRegData}
        setTeamRegData={setTeamRegData}
        onLogin={handleLogin}
        onRegisterTeam={handleRegisterFourMemberTeam}
        onJoinTeam={handleJoinTeam}
        onBackToLauncher={handleExitToLauncher}
      />
    );
  }

  // --------------------------------------------------------------------------
  // LAYER 2 — OPERATIONAL WORKSPACES
  // --------------------------------------------------------------------------

  // A. Red Team vs Blue Team Operational Workspace
  if (activeCompetition?.mode === 'RED_VS_BLUE') {
    return (
      <RedVsBlueWorkspace
        coordinatorUrl={coordinatorUrl}
        headers={headers}
        user={user}
        competition={activeCompetition}
        swarmStatus={swarmStatus}
        teamId={teamId}
        onRefreshCompetition={fetchData}
        onExitToLauncher={handleExitToLauncher}
      />
    );
  }

  // B. KOTH Operational Agent Portal (Overview, Hills, Team, Agents, Tasks, Coordinator)
  const isLeader = user.role === 'LEADER';
  const killSwitchActive = swarmStatus?.kill_switch || false;

  return (
    <div className="app-layout">
      {/* Left Sidebar */}
      <Sidebar
        activeView={activeView}
        setActiveView={setActiveView}
        user={user}
        hills={hills}
        killSwitchActive={killSwitchActive}
        onExitToLauncher={handleExitToLauncher}
      />

      {/* Main Content Area */}
      <div className="main-wrapper">
        {/* Top Header */}
        <Header
          activeView={activeView}
          user={user}
          teamName={teamName}
          competitionId={activeCompetition?.competition_id || teamMgmtData?.competition_id}
          swarmStatus={swarmStatus}
          isOffline={isOffline}
          lastSync={lastSync}
          onRefresh={fetchData}
          onTriggerEmergencyStop={() => setIsEmergencyModalOpen(true)}
          onResetEmergencyStop={handleResetEmergencyStop}
          onLogout={handleLogout}
          onExitToLauncher={handleExitToLauncher}
        />

        {/* View Content Scroll Area */}
        <div className="content-scroll">
          {activeView === 'overview' && (
            <DashboardView
              user={user}
              teamName={teamName}
              teamId={teamId}
              swarmStatus={swarmStatus}
              hills={hills}
              auditLogs={auditLogs}
              onNavigate={setActiveView}
              onAdvancePhase={handleAdvancePhase}
            />
          )}

          {activeView === 'team_mgmt' && (
            <TeamManagementView
              isLeader={isLeader}
              user={user}
              teamId={teamId}
              teamMgmtData={teamMgmtData}
              onRefresh={fetchTeamMgmt}
              onCompleteRegistration={handleCompleteRegistration}
              mgmtError={mgmtError}
              incompleteTeammates={incompleteTeammates}
              setIncompleteTeammates={setIncompleteTeammates}
            />
          )}

          {activeView === 'hills' && (
            <HillPortalsView
              user={user}
              hills={hills}
              onSaveConfig={handleSaveHillConfig}
              onSetFlag={handleSetHillFlag}
              onVerify={handleTriggerVerify}
              hillConfig={hillConfig}
              setHillConfig={setHillConfig}
              flagInput={flagInput}
              setFlagInput={setFlagInput}
              actionMsg={actionMsg}
            />
          )}

          {activeView === 'agents' && (
            <AgentMonitoringView
              swarmStatus={swarmStatus}
              user={user}
              coordinatorUrl={coordinatorUrl}
              headers={headers}
            />
          )}

          {activeView === 'coordination' && (
            <MultiAgentCoordinationView
              coordinatorUrl={coordinatorUrl}
              headers={headers}
              user={user}
              teamId={teamId}
              competitionId={activeCompetition?.competition_id || teamMgmtData?.competition_id}
              swarmStatus={swarmStatus}
            />
          )}

          {activeView === 'notifications' && (
            <NotificationFeed
              coordinatorUrl={coordinatorUrl}
              headers={headers}
              teamId={teamId}
              competitionId={activeCompetition?.competition_id || teamMgmtData?.competition_id}
            />
          )}

          {activeView === 'coordinator' && (
            <CoordinatorView
              swarmStatus={swarmStatus}
              user={user}
              onAdvancePhase={handleAdvancePhase}
            />
          )}

          {activeView === 'tasks' && (
            <TaskManagementView
              swarmStatus={swarmStatus}
            />
          )}

          {activeView === 'competition' && (
            <CompetitionConfigView
              teamName={teamName}
              teamId={teamId}
              competitionId={activeCompetition?.competition_id || teamMgmtData?.competition_id}
              hills={hills}
              competitions={competitions}
              activeCompetition={activeCompetition}
              onSelectCompetition={(comp) => {
                setActiveCompetition(comp);
                sessionStorage.setItem('koth_active_comp', JSON.stringify(comp));
              }}
              onOpenWizard={handleExitToLauncher}
            />
          )}

          {activeView === 'llm' && (
            <LLMSettingsView
              user={user}
              coordinatorUrl={coordinatorUrl}
              headers={headers}
            />
          )}

          {activeView === 'audit' && (
            <AuditLogsView
              auditLogs={auditLogs}
              onRefresh={fetchData}
            />
          )}

          {activeView === 'security' && (
            <SecuritySettingsView
              user={user}
              swarmStatus={swarmStatus}
              onTriggerEmergencyStop={() => setIsEmergencyModalOpen(true)}
              onResetEmergencyStop={handleResetEmergencyStop}
            />
          )}
        </div>
      </div>

      {/* Emergency Stop Confirmation Modal */}
      <EmergencyStopModal
        isOpen={isEmergencyModalOpen}
        onClose={() => setIsEmergencyModalOpen(false)}
        onConfirm={handleEmergencyStop}
        user={user}
      />
    </div>
  );
}
