import React from 'react';
import {
  LayoutDashboard,
  Users,
  Shield,
  Activity,
  Cpu,
  ListTodo,
  Trophy,
  Bot,
  FileText,
  Lock,
  Swords,
  ArrowLeft,
  Bell,
  GitBranch,
} from 'lucide-react';

export default function Sidebar({
  activeView,
  setActiveView,
  user,
  hills,
  killSwitchActive,
  onExitToLauncher,
}) {
  const isLeader = user?.role === 'LEADER';
  const assignedHill = user?.assigned_hill || user?.hill_id || 1;

  const navItems = [
    {
      id: 'overview',
      label: 'Overview',
      icon: LayoutDashboard,
      roleRequired: null,
    },
    {
      id: 'team_mgmt',
      label: 'Team Management',
      icon: Users,
      roleRequired: 'LEADER',
      badge: isLeader ? '4/4' : 'Locked',
    },
    {
      id: 'hills',
      label: 'Hill Portals',
      icon: Shield,
      roleRequired: null,
      badge: isLeader ? 'All 4' : `Hill ${assignedHill}`,
    },
    {
      id: 'agents',
      label: 'Agent Monitoring',
      icon: Activity,
      roleRequired: null,
      badge: '4 Nodes',
    },
    {
      id: 'coordination',
      label: 'Swarm Coordination',
      icon: GitBranch,
      roleRequired: null,
      badge: '4 Agents',
    },
    {
      id: 'notifications',
      label: 'Live Event Feed',
      icon: Bell,
      roleRequired: null,
      badge: 'Live',
    },
    {
      id: 'coordinator',
      label: 'Coordinator',
      icon: Cpu,
      roleRequired: null,
    },
    {
      id: 'tasks',
      label: 'Task Management',
      icon: ListTodo,
      roleRequired: null,
    },
    {
      id: 'competition',
      label: 'Competition Config',
      icon: Trophy,
      roleRequired: null,
    },
    {
      id: 'llm',
      label: 'LLM Settings',
      icon: Bot,
      roleRequired: null,
      badge: user?.agent_id || 'Isolated',
    },
    {
      id: 'audit',
      label: 'Audit Logs',
      icon: FileText,
      roleRequired: null,
    },
    {
      id: 'security',
      label: 'Security Settings',
      icon: Lock,
      roleRequired: null,
      badge: killSwitchActive ? 'HALTED' : null,
      badgeColor: killSwitchActive ? 'badge-red' : null,
    },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Shield size={16} strokeWidth={2.5} />
          </div>
          <span>KOTH Command</span>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="sidebar-nav">
        <div className="sidebar-section-title">Operations</div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          const isRestricted = item.roleRequired === 'LEADER' && !isLeader;

          return (
            <button
              key={item.id}
              type="button"
              className={`sidebar-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveView(item.id)}
              title={isRestricted ? 'Restricted to Team Leader' : item.label}
            >
              <span className="sidebar-item-icon">
                <Icon size={16} strokeWidth={isActive ? 2.2 : 1.8} />
              </span>
              <span>{item.label}</span>
              {item.badge && (
                <span
                  className={`sidebar-item-badge ${item.badgeColor || ''}`}
                  style={{
                    backgroundColor: item.badgeColor ? undefined : isRestricted ? '#FEF2F2' : undefined,
                    color: item.badgeColor ? undefined : isRestricted ? '#DC5555' : undefined,
                  }}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* User Footer Profile */}
      <div className="sidebar-footer">
        {onExitToLauncher && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onExitToLauncher}
            style={{
              width: '100%',
              marginBottom: 10,
              fontSize: 12,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
            }}
          >
            <ArrowLeft size={13} /> Exit to Launcher
          </button>
        )}
        <div className="user-profile-card">
          <div className="user-avatar">
            {(user?.full_name || user?.username || 'U')[0].toUpperCase()}
          </div>
          <div className="user-info">
            <div className="user-name" title={user?.full_name || user?.username}>
              {user?.full_name || user?.username}
            </div>
            <div className="user-role-line">
              <span style={{ fontWeight: 600, color: isLeader ? '#2878C8' : '#16A36A' }}>
                {user?.role || 'MEMBER'}
              </span>
              {' · '}
              <span>{user?.agent_id || 'agent-01'}</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}

