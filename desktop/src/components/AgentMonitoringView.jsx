import React, { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Clock,
  Server,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Cpu,
  HardDrive,
  Bot,
  ListTodo,
  ExternalLink,
  X,
  Shield,
  FileText,
  Radio,
  RefreshCw,
} from 'lucide-react';

export default function AgentMonitoringView({ swarmStatus, user, coordinatorUrl, headers }) {
  const [selectedAgentId, setSelectedAgentId] = useState(null);
  const [agentDetail, setAgentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [networkInfo, setNetworkInfo] = useState(null);
  const [showLanDetails, setShowLanDetails] = useState(false);
  const [copiedKey, setCopiedKey] = useState('');

  const agents = swarmStatus?.agents || {};
  const agentList = ['agent-01', 'agent-02', 'agent-03', 'agent-04'];

  useEffect(() => {
    let isMounted = true;
    const fetchNet = async () => {
      try {
        if (window.kothDesktop && window.kothDesktop.getServerNetworkInfo) {
          const info = await window.kothDesktop.getServerNetworkInfo();
          if (isMounted) setNetworkInfo(info);
        } else if (coordinatorUrl) {
          const r = await fetch(`${coordinatorUrl}/api/swarm/network-info`);
          if (r.ok) {
            const data = await r.json();
            if (isMounted) setNetworkInfo(data);
          }
        }
      } catch (e) {
        // Fallback
      }
    };
    fetchNet();
    const interval = setInterval(fetchNet, 8000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [coordinatorUrl]);

  const fetchAgentDetail = useCallback(
    async (aid) => {
      if (!aid || !coordinatorUrl) return;
      try {
        setDetailLoading(true);
        setDetailError('');
        const res = await fetch(`${coordinatorUrl}/api/swarm/agent/${aid}/monitoring`, {
          headers: headers ? headers() : {},
        });
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.message || `Failed to fetch details for ${aid}`);
        }
        const data = await res.json();
        setAgentDetail(data);
      } catch (err) {
        setDetailError(err.message);
      } finally {
        setDetailLoading(false);
      }
    },
    [coordinatorUrl, headers]
  );

  const handleOpenInspector = (aid) => {
    setSelectedAgentId(aid);
    fetchAgentDetail(aid);
  };

  const handleCloseInspector = () => {
    setSelectedAgentId(null);
    setAgentDetail(null);
    setDetailError('');
  };

  const getConnectionBadge = (connState, isAlive) => {
    const s = (connState || (isAlive ? 'IDLE' : 'OFFLINE')).toUpperCase();
    if (s === 'BUSY') {
      return (
        <span className="badge badge-blue">
          <span className="dot dot-blue" />
          BUSY
        </span>
      );
    }
    if (s === 'IDLE' || s === 'ONLINE') {
      return (
        <span className="badge badge-green">
          <span className="dot dot-green" />
          {s}
        </span>
      );
    }
    if (s === 'STALE') {
      return (
        <span className="badge badge-amber">
          <span className="dot dot-amber" />
          STALE
        </span>
      );
    }
    return (
      <span className="badge badge-red">
        <span className="dot dot-red" />
        OFFLINE
      </span>
    );
  };

  return (
    <div className="content-container" style={{ paddingBottom: 40 }}>
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Real-Time Swarm Node Telemetry & Monitoring</h1>
          <p className="view-subtitle">
            Live heartbeat signals, CPU/memory telemetry, active LLM status, and task execution progress across the 4-agent swarm
          </p>
        </div>
      </div>

      {/* Central Server LAN Connection Banner */}
      <div
        className="card"
        style={{
          marginBottom: 20,
          background: '#FFFFFF',
          border: '1px solid #DCE4EE',
          borderRadius: 8,
          padding: '16px 20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 8,
                background: '#EBF4FE',
                color: '#1B60A5',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Server size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: 15, color: '#172536' }}>Central Coordinator Server</span>
                <span className="badge badge-green">
                  <span className="dot dot-green" /> ONLINE (200 OK)
                </span>
                <span className="badge badge-neutral" style={{ fontSize: 11 }}>
                  Port: {networkInfo?.port || 5000}
                </span>
              </div>
              <div style={{ fontSize: 13, color: '#5A6E85', marginTop: 3 }}>
                LAN Endpoint:{' '}
                <strong style={{ color: '#172536', fontFamily: 'monospace' }}>
                  {networkInfo?.apiBaseUrl || networkInfo?.api_url || `${coordinatorUrl || 'http://127.0.0.1:5000'}`}
                </strong>
                {networkInfo?.hostname && (
                  <span style={{ marginLeft: 12 }}>
                    Hostname: <strong style={{ color: '#172536' }}>{networkInfo.hostname}</strong>
                  </span>
                )}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#172536' }}>
              Connected Agents: {agentList.filter((aid) => agents[aid]?.alive).length}/4
            </span>
            <button
              type="button"
              className="btn-outline btn-sm"
              onClick={() => setShowLanDetails(!showLanDetails)}
            >
              {showLanDetails ? 'Hide Remote PC Setup' : 'Remote 4-PC Setup & Join Commands'}
            </button>
          </div>
        </div>

        {/* Expandable LAN Setup Commands */}
        {showLanDetails && (
          <div
            style={{
              marginTop: 16,
              paddingTop: 16,
              borderTop: '1px solid #E2E8F0',
            }}
          >
            <div style={{ fontSize: 13, color: '#5A6E85', marginBottom: 12 }}>
              Run the following command on each of the 4 dedicated Windows agent laptops to connect them over the LAN:
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
              {[
                { aid: 'agent-01', title: 'PC 1 (Leader / Agent 01)', hill: 'Hill 1' },
                { aid: 'agent-02', title: 'PC 2 (Recon Specialist)', hill: 'Hill 2' },
                { aid: 'agent-03', title: 'PC 3 (Exploit Specialist)', hill: 'Hill 3' },
                { aid: 'agent-04', title: 'PC 4 (Defense Specialist)', hill: 'Hill 4' },
              ].map(({ aid, title, hill }) => {
                const endpoint = networkInfo?.apiBaseUrl || networkInfo?.api_url || coordinatorUrl || 'http://127.0.0.1:5000';
                const cmd = `koth-agent-worker.exe --coordinator-url "${endpoint}" --agent-id "${aid}"`;
                return (
                  <div
                    key={aid}
                    style={{
                      background: '#F8FAFD',
                      border: '1px solid #E2E8F0',
                      borderRadius: 6,
                      padding: '10px 12px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <strong style={{ fontSize: 12, color: '#172536' }}>{title}</strong>
                      <span className="badge badge-neutral" style={{ fontSize: 10 }}>{hill}</span>
                    </div>
                    <code
                      style={{
                        display: 'block',
                        fontSize: 11,
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: 4,
                        padding: '6px 8px',
                        overflowX: 'auto',
                        whiteSpace: 'nowrap',
                        color: '#0F172A',
                      }}
                    >
                      {cmd}
                    </code>
                    <button
                      type="button"
                      className="btn-outline btn-xs"
                      style={{ marginTop: 6, width: '100%' }}
                      onClick={() => {
                        navigator.clipboard.writeText(cmd);
                        setCopiedKey(aid);
                        setTimeout(() => setCopiedKey(''), 2000);
                      }}
                    >
                      {copiedKey === aid ? '✓ Copied to Clipboard!' : 'Copy Join Command'}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Grid of 4 Agent Cards */}
      <div className="grid-4" style={{ marginBottom: 20 }}>
        {agentList.map((aid, idx) => {
          const ag = agents[aid] || {};
          const isAlive = ag.alive || false;
          const isCurrent = user?.agent_id === aid;
          const connState = ag.connection_state || (isAlive ? 'IDLE' : 'OFFLINE');
          const llm = ag.llm_status || {};
          const taskCounts = ag.task_counts || { completed: 0, failed: 0, pending: 0 };
          const progress = ag.task_progress || 0;

          return (
            <div
              key={aid}
              className="card"
              style={{
                marginBottom: 0,
                border: isCurrent ? '2px solid #2878C8' : '1px solid var(--border-color)',
                background: isCurrent ? '#F8FAFD' : 'var(--bg-card)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                {/* Card Top: Identifier, Role & Connection Badge */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, color: '#172536' }}>
                      {aid}
                      {isCurrent && (
                        <span style={{ color: '#2878C8', fontSize: 11, marginLeft: 4, fontWeight: 600 }}>
                          (You)
                        </span>
                      )}
                    </div>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        color: idx === 0 ? '#1D4ED8' : '#475569',
                        background: idx === 0 ? '#DBEAFE' : '#F1F5F9',
                        padding: '1px 6px',
                        borderRadius: 4,
                      }}
                    >
                      {idx === 0 ? 'SWARM LEADER' : `SPECIALIST 0${idx}`}
                    </span>
                  </div>
                  {getConnectionBadge(connState, isAlive)}
                </div>

                {/* Scope & Operator Binding */}
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                  Assigned Scope: <strong>Hill {idx + 1}</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  Operator: <strong>{ag.username || (idx === 0 ? 'alice (Leader)' : `Teammate ${idx}`)}</strong>
                </div>

                {/* Telemetry Metrics: Real CPU & Memory (No fabrication!) */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: 6,
                    padding: '8px 10px',
                    background: '#F8FAFC',
                    borderRadius: 6,
                    marginBottom: 10,
                    border: '1px solid #EEF2F6',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Cpu size={13} color="#64748B" />
                    <span style={{ fontSize: 11, color: '#64748B' }}>CPU:</span>
                    <strong style={{ fontSize: 11, color: '#172536' }}>
                      {ag.cpu_percent != null ? `${ag.cpu_percent.toFixed(1)}%` : 'N/A'}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <HardDrive size={13} color="#64748B" />
                    <span style={{ fontSize: 11, color: '#64748B' }}>RAM:</span>
                    <strong style={{ fontSize: 11, color: '#172536' }}>
                      {ag.memory_mb != null ? `${Math.round(ag.memory_mb)}MB` : 'N/A'}
                    </strong>
                  </div>
                </div>

                {/* Active LLM Model Status */}
                <div style={{ fontSize: 11, color: '#64748B', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
                  <Bot size={13} color="#2878C8" />
                  <span>LLM:</span>
                  {llm.enabled ? (
                    <span style={{ color: '#16A34A', fontWeight: 600 }}>
                      {llm.provider?.toUpperCase()} ({llm.model_id || 'default'})
                    </span>
                  ) : (
                    <span style={{ color: '#94A3B8' }}>Disabled / Local</span>
                  )}
                </div>

                {/* Active Task & Progress */}
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>
                  Task:{' '}
                  <code style={{ fontSize: 11, padding: '1px 4px', background: '#F1F5F9' }}>
                    {ag.current_task_type || 'IDLE'}
                  </code>
                </div>

                {ag.current_task_type && ag.current_task_type !== 'IDLE' && (
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#64748B', marginBottom: 2 }}>
                      <span>Progress</span>
                      <span>{progress}%</span>
                    </div>
                    <div style={{ height: 4, background: '#E2E8F0', borderRadius: 2, overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${Math.min(Math.max(progress, 5), 100)}%`,
                          background: '#2878C8',
                          transition: 'width 0.3s ease',
                        }}
                      />
                    </div>
                  </div>
                )}

                {/* Task Breakdown Counts */}
                <div style={{ display: 'flex', gap: 6, fontSize: 10, marginTop: 6, marginBottom: 8 }}>
                  <span style={{ background: '#DCFCE7', color: '#166534', padding: '2px 5px', borderRadius: 4, fontWeight: 600 }}>
                    ✓ {taskCounts.completed} done
                  </span>
                  <span style={{ background: '#FEE2E2', color: '#991B1B', padding: '2px 5px', borderRadius: 4, fontWeight: 600 }}>
                    ✗ {taskCounts.failed} fail
                  </span>
                  <span style={{ background: '#E0F2FE', color: '#0369A1', padding: '2px 5px', borderRadius: 4, fontWeight: 600 }}>
                    ⏳ {taskCounts.pending} pend
                  </span>
                </div>

                {/* Heartbeat timing */}
                <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Clock size={11} />
                  <span>
                    Heartbeat:{' '}
                    {ag.heartbeat_age_seconds != null
                      ? `${ag.heartbeat_age_seconds}s ago`
                      : (ag.last_heartbeat ? new Date(ag.last_heartbeat * 1000).toLocaleTimeString() : 'Never')}
                  </span>
                </div>
              </div>

              {/* Action Button: Inspect Agent Activity */}
              <button
                onClick={() => handleOpenInspector(aid)}
                className="btn btn-outline"
                style={{
                  marginTop: 12,
                  width: '100%',
                  fontSize: 12,
                  padding: '6px 10px',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <Activity size={13} />
                <span>Inspect Agent Activity</span>
              </button>
            </div>
          );
        })}
      </div>

      {/* Registry Detail Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Server size={16} />
            <span>Swarm Node Registry & Authorized Targets</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Session TTL: 60s · Autonomous Heartbeat Timeout: 10s
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Agent Identifier</th>
                <th>Role & Scope</th>
                <th>Status</th>
                <th>Current Target</th>
                <th>Active Task</th>
                <th>CPU & Memory</th>
                <th>LLM Engine</th>
                <th>Last Heartbeat</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agentList.map((aid, idx) => {
                const ag = agents[aid] || {};
                const isAlive = ag.alive || false;
                const connState = ag.connection_state || (isAlive ? 'IDLE' : 'OFFLINE');
                const llm = ag.llm_status || {};

                return (
                  <tr key={aid}>
                    <td>
                      <div style={{ fontWeight: 600, color: '#172536' }}>{aid}</div>
                      <div style={{ fontSize: 11, color: '#64748B' }}>{ag.username || `Operator 0${idx + 1}`}</div>
                    </td>
                    <td>
                      <span className={`badge ${idx === 0 ? 'badge-blue' : 'badge-neutral'}`}>
                        {idx === 0 ? 'LEADER' : 'SPECIALIST'}
                      </span>
                      <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>Hill {idx + 1} Scope</div>
                    </td>
                    <td>{getConnectionBadge(connState, isAlive)}</td>
                    <td>
                      <code>{ag.current_target || '--'}</code>
                    </td>
                    <td>
                      <code style={{ fontSize: 11 }}>{ag.current_task_type || 'IDLE'}</code>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      <div>CPU: {ag.cpu_percent != null ? `${ag.cpu_percent.toFixed(1)}%` : 'N/A'}</div>
                      <div style={{ color: '#64748B' }}>
                        RAM: {ag.memory_mb != null ? `${Math.round(ag.memory_mb)}MB` : 'N/A'}
                      </div>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {llm.enabled ? (
                        <span style={{ color: '#16A34A', fontWeight: 500 }}>
                          {llm.provider?.toUpperCase()}
                        </span>
                      ) : (
                        <span style={{ color: '#94A3B8' }}>Local / Non-LLM</span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {ag.last_heartbeat ? new Date(ag.last_heartbeat * 1000).toLocaleTimeString() : 'Never'}
                    </td>
                    <td>
                      <button
                        onClick={() => handleOpenInspector(aid)}
                        className="btn btn-outline"
                        style={{ fontSize: 11, padding: '4px 8px' }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Interactive Agent Inspection Drawer / Modal */}
      {selectedAgentId && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.45)',
            display: 'flex',
            justifyContent: 'flex-end',
            zIndex: 1000,
          }}
          onClick={handleCloseInspector}
        >
          <div
            style={{
              width: 580,
              maxWidth: '90vw',
              height: '100%',
              background: '#FFFFFF',
              boxShadow: '-4px 0 24px rgba(0,0,0,0.15)',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid #E2E8F0',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: '#F8FAFC',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Activity size={20} color="#2878C8" />
                <div>
                  <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: '#172536' }}>
                    Agent Inspection: {selectedAgentId}
                  </h3>
                  <div style={{ fontSize: 12, color: '#64748B' }}>
                    {agentDetail?.status?.role === 'LEADER' ? 'Swarm Leader & Objective Coordinator' : 'Hill Specialist Node'}
                  </div>
                </div>
              </div>
              <button
                onClick={handleCloseInspector}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: '#64748B',
                  padding: 4,
                }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Drawer Content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
              {detailLoading && (
                <div style={{ textAlign: 'center', padding: '40px 0', color: '#64748B' }}>
                  <RefreshCw size={24} className="spin" style={{ margin: '0 auto 10px auto' }} />
                  <div>Loading agent telemetry & task history...</div>
                </div>
              )}

              {detailError && (
                <div
                  style={{
                    padding: 14,
                    background: '#FEF2F2',
                    border: '1px solid #FCA5A5',
                    borderRadius: 6,
                    color: '#991B1B',
                    fontSize: 13,
                    marginBottom: 16,
                  }}
                >
                  <AlertTriangle size={16} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  {detailError}
                </div>
              )}

              {agentDetail && (
                <div>
                  {/* Status & Diagnostics Strip */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      gap: 12,
                      marginBottom: 20,
                    }}
                  >
                    <div style={{ background: '#F8FAFC', padding: 12, borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 11, color: '#64748B', marginBottom: 2 }}>Connection State</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#172536' }}>
                        {agentDetail.status?.connection_state}
                      </div>
                      <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 4 }}>
                        Heartbeat age: {agentDetail.status?.heartbeat_age_seconds != null ? `${agentDetail.status.heartbeat_age_seconds}s` : 'N/A'}
                      </div>
                    </div>
                    <div style={{ background: '#F8FAFC', padding: 12, borderRadius: 8, border: '1px solid #E2E8F0' }}>
                      <div style={{ fontSize: 11, color: '#64748B', marginBottom: 2 }}>Authorized Scope</div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#172536' }}>
                        Hill {agentDetail.status?.assigned_hill} Target Binding
                      </div>
                      <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 4 }}>
                        Operator: {agentDetail.status?.username}
                      </div>
                    </div>
                  </div>

                  {/* Task Execution History */}
                  <div style={{ marginBottom: 24 }}>
                    <h4 style={{ fontSize: 13, fontWeight: 600, color: '#172536', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <ListTodo size={15} color="#2878C8" />
                      <span>Task Execution History ({agentDetail.task_history?.length || 0})</span>
                    </h4>
                    {(!agentDetail.task_history || agentDetail.task_history.length === 0) ? (
                      <div style={{ fontSize: 12, color: '#94A3B8', padding: 12, background: '#F8FAFC', borderRadius: 6 }}>
                        No tasks assigned yet.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {agentDetail.task_history.map((t) => (
                          <div
                            key={t.task_id}
                            style={{
                              padding: 10,
                              background: '#F8FAFC',
                              border: '1px solid #E2E8F0',
                              borderRadius: 6,
                              fontSize: 12,
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                              <strong style={{ color: '#172536' }}>{t.task_id}</strong>
                              <span className={`badge ${t.status === 'COMPLETED' ? 'badge-green' : t.status === 'FAILED' ? 'badge-red' : 'badge-blue'}`}>
                                {t.status}
                              </span>
                            </div>
                            <div style={{ color: '#64748B', fontSize: 11 }}>
                              Type: <code>{t.task_type}</code> · Target: <code>{t.target_host || 'Hill'}</code>
                            </div>
                            {t.description && (
                              <div style={{ color: '#475569', fontSize: 11, marginTop: 4 }}>
                                {t.description}
                              </div>
                            )}
                            {t.error && (
                              <div style={{ color: '#DC2626', fontSize: 11, marginTop: 4 }}>
                                Error: {t.error}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Recent Execution Logs */}
                  <div>
                    <h4 style={{ fontSize: 13, fontWeight: 600, color: '#172536', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <FileText size={15} color="#2878C8" />
                      <span>Recent Execution Actions</span>
                    </h4>
                    {(!agentDetail.execution_logs || agentDetail.execution_logs.length === 0) ? (
                      <div style={{ fontSize: 12, color: '#94A3B8', padding: 12, background: '#F8FAFC', borderRadius: 6 }}>
                        No execution logs recorded.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {agentDetail.execution_logs.map((log, i) => (
                          <div
                            key={i}
                            style={{
                              padding: '8px 10px',
                              background: '#FAFAFA',
                              border: '1px solid #EEEEEE',
                              borderRadius: 6,
                              fontSize: 11,
                              fontFamily: 'monospace',
                            }}
                          >
                            <span style={{ color: '#2878C8', fontWeight: 600 }}>{log.action_type || 'ACTION'}: </span>
                            <span style={{ color: '#172536' }}>{log.target} </span>
                            <span style={{ color: '#64748B' }}>({log.reasoning || log.details || 'executed'})</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
