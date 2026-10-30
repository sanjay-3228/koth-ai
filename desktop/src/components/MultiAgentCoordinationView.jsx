import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  GitBranch,
  Send,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
  Layers,
  HelpCircle,
  FileText,
  RotateCw,
  Plus,
  ArrowRight,
  Sparkles,
  Lock,
} from 'lucide-react';

export default function MultiAgentCoordinationView({
  coordinatorUrl,
  headers,
  user,
  teamId,
  competitionId,
  swarmStatus,
}) {
  const isLeader = user?.role === 'LEADER' || user?.agent_id === 'agent-01';

  // Objective decomposition form state
  const [objectiveInput, setObjectiveInput] = useState('');
  const [objectivePhase, setObjectivePhase] = useState('ATTACK');
  const [isDecomposing, setIsDecomposing] = useState(false);
  const [objectiveMsg, setObjectiveMsg] = useState('');

  // Coordination messages & summary state
  const [summary, setSummary] = useState(null);
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  // Quick message post state
  const [msgType, setMsgType] = useState('STATUS_UPDATE');
  const [msgContent, setMsgContent] = useState('');
  const [msgHillId, setMsgHillId] = useState(1);
  const [isSendingMsg, setIsSendingMsg] = useState(false);

  // Reassignment modal state
  const [reassignModalOpen, setReassignModalOpen] = useState(false);
  const [reassignTaskId, setReassignTaskId] = useState('');
  const [reassignNewAgent, setReassignNewAgent] = useState('agent-02');
  const [reassignReason, setReassignReason] = useState('Reassigned by leader');
  const [reassignMsg, setReassignMsg] = useState('');

  const fetchCoordinationData = useCallback(async () => {
    if (!coordinatorUrl) return;
    try {
      setLoading(true);
      // 1. Summary
      const sumRes = await fetch(`${coordinatorUrl}/api/swarm/coordination/summary`, {
        headers: headers ? headers() : {},
      });
      if (sumRes.ok) {
        const sumData = await sumRes.json();
        setSummary(sumData);
      }

      // 2. Messages
      const msgRes = await fetch(`${coordinatorUrl}/api/swarm/coordination/messages?limit=40`, {
        headers: headers ? headers() : {},
      });
      if (msgRes.ok) {
        const msgData = await msgRes.json();
        setMessages(msgData.messages || []);
      }
    } catch (e) {
      console.warn('Coordination sync error:', e);
    } finally {
      setLoading(false);
    }
  }, [coordinatorUrl, headers]);

  useEffect(() => {
    fetchCoordinationData();
    const interval = setInterval(fetchCoordinationData, 3000);
    return () => clearInterval(interval);
  }, [fetchCoordinationData]);

  // Handle Objective Decomposition
  const handleDecomposeObjective = async (e) => {
    e.preventDefault();
    if (!objectiveInput.trim()) return;
    try {
      setIsDecomposing(true);
      setObjectiveMsg('');
      const res = await fetch(`${coordinatorUrl}/api/swarm/coordination/objective`, {
        method: 'POST',
        headers: headers ? headers() : {},
        body: JSON.stringify({
          objective: objectiveInput,
          phase: objectivePhase,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Decomposition failed');
      setObjectiveMsg(`Success: Decomposed into ${data.tasks_created} subtasks across the swarm.`);
      setObjectiveInput('');
      fetchCoordinationData();
    } catch (err) {
      setObjectiveMsg(`Error: ${err.message}`);
    } finally {
      setIsDecomposing(false);
    }
  };

  // Handle Send Coordination Message
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!msgContent.trim()) return;
    try {
      setIsSendingMsg(true);
      const res = await fetch(`${coordinatorUrl}/api/swarm/coordination/message`, {
        method: 'POST',
        headers: headers ? headers() : {},
        body: JSON.stringify({
          from_agent_id: user?.agent_id || 'agent-01',
          to_agent_id: 'ALL',
          message_type: msgType,
          content: msgContent,
          hill_id: parseInt(msgHillId, 10),
          team_id: teamId,
          competition_id: competitionId,
        }),
      });
      if (res.ok) {
        setMsgContent('');
        fetchCoordinationData();
      }
    } catch (err) {
      console.warn('Send message error:', err);
    } finally {
      setIsSendingMsg(false);
    }
  };

  // Handle Task Reassignment
  const handleExecuteReassignment = async (e) => {
    e.preventDefault();
    if (!reassignTaskId) return;
    try {
      setReassignMsg('');
      const res = await fetch(`${coordinatorUrl}/api/swarm/coordination/reassign`, {
        method: 'POST',
        headers: headers ? headers() : {},
        body: JSON.stringify({
          task_id: reassignTaskId,
          new_agent_id: reassignNewAgent,
          reason: reassignReason,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Reassignment failed');
      setReassignMsg(`Success: ${data.message}`);
      setTimeout(() => {
        setReassignModalOpen(false);
        setReassignMsg('');
        fetchCoordinationData();
      }, 1000);
    } catch (err) {
      setReassignMsg(`Error: ${err.message}`);
    }
  };

  const allTasks = summary?.tasks || [];
  const agentAssignments = summary?.agent_assignments || {};
  const agentList = ['agent-01', 'agent-02', 'agent-03', 'agent-04'];
  const sharedFindings = summary?.shared_findings || {};

  return (
    <div className="content-container" style={{ paddingBottom: 40 }}>
      {/* Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Multi-Agent Swarm Coordination</h1>
          <p className="view-subtitle">
            Autonomous multi-agent task distribution, objective decomposition, task dependency resolution, and inter-agent synchronization
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={fetchCoordinationData}
            className="btn btn-outline"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}
            disabled={loading}
          >
            <RotateCw size={14} className={loading ? 'spin' : ''} />
            <span>Sync Swarm</span>
          </button>
        </div>
      </div>

      {/* SECTION A: Objective & Task Decomposition (Leader Control) */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <div className="card-title">
            <Sparkles size={16} color="#2878C8" />
            <span>Leader Objective Decomposition Engine</span>
          </div>
          <span className={`badge ${isLeader ? 'badge-blue' : 'badge-neutral'}`}>
            {isLeader ? 'LEADER CONTROL AUTHORIZED' : 'READ-ONLY (SPECIALIST)'}
          </span>
        </div>

        {isLeader ? (
          <form onSubmit={handleDecomposeObjective}>
            <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 280 }}>
                <label className="form-label">Competition Strategic Objective</label>
                <input
                  type="text"
                  className="form-control"
                  placeholder="e.g., Capture Hill 2 web portal, audit defenses on Hill 1, and patch vulnerable services"
                  value={objectiveInput}
                  onChange={(e) => setObjectiveInput(e.target.value)}
                  disabled={isDecomposing}
                />
              </div>
              <div style={{ width: 140 }}>
                <label className="form-label">Phase</label>
                <select
                  className="form-control"
                  value={objectivePhase}
                  onChange={(e) => setObjectivePhase(e.target.value)}
                  disabled={isDecomposing}
                >
                  <option value="ATTACK">ATTACK</option>
                  <option value="DEFENSE">DEFENSE</option>
                </select>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{ height: 38, display: 'inline-flex', alignItems: 'center', gap: 6 }}
                  disabled={isDecomposing || !objectiveInput.trim()}
                >
                  <Layers size={15} />
                  <span>{isDecomposing ? 'Decomposing...' : 'Decompose & Assign'}</span>
                </button>
              </div>
            </div>

            {objectiveMsg && (
              <div
                style={{
                  fontSize: 12,
                  color: objectiveMsg.startsWith('Success') ? '#16A34A' : '#DC2626',
                  fontWeight: 500,
                  marginTop: 6,
                }}
              >
                {objectiveMsg}
              </div>
            )}
          </form>
        ) : (
          <div style={{ fontSize: 13, color: '#64748B', padding: '10px 0' }}>
            Swarm objectives are configured and decomposed by Team Leader (agent-01). Your specialist node will automatically receive and execute assigned subtasks.
          </div>
        )}
      </div>

      {/* SECTION B: 4-Agent Assignment Matrix & Dependencies */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <div className="card-title">
            <GitBranch size={16} color="#2878C8" />
            <span>Swarm Task Assignment Matrix & Dependencies</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Active Tasks: {summary?.active_tasks_count || 0} · Completed: {summary?.completed_tasks_count || 0}
          </span>
        </div>

        <div className="grid-4">
          {agentList.map((aid, idx) => {
            const tasks = agentAssignments[aid] || [];
            const isUser = user?.agent_id === aid;

            return (
              <div
                key={aid}
                style={{
                  background: isUser ? '#F8FAFD' : '#FFFFFF',
                  border: isUser ? '2px solid #2878C8' : '1px solid #E2E8F0',
                  borderRadius: 8,
                  padding: 12,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                {/* Agent Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #F1F5F9', paddingBottom: 6 }}>
                  <div>
                    <strong style={{ fontSize: 13, color: '#172536' }}>{aid}</strong>
                    <div style={{ fontSize: 10, color: '#64748B' }}>
                      {idx === 0 ? 'LEADER' : `SPECIALIST (Hill ${idx + 1})`}
                    </div>
                  </div>
                  <span className="badge badge-neutral" style={{ fontSize: 10 }}>
                    {tasks.length} tasks
                  </span>
                </div>

                {/* Task list for agent */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minHeight: 140 }}>
                  {tasks.length === 0 ? (
                    <div style={{ fontSize: 11, color: '#94A3B8', textAlign: 'center', margin: 'auto 0' }}>
                      No tasks assigned
                    </div>
                  ) : (
                    tasks.map((task) => {
                      const hasDeps = task.dependencies && task.dependencies.length > 0;
                      const isCompleted = task.status === 'COMPLETED';
                      const isLeased = task.status === 'LEASED' || task.status === 'RUNNING';

                      return (
                        <div
                          key={task.task_id}
                          style={{
                            padding: 8,
                            background: '#FFFFFF',
                            border: '1px solid #E2E8F0',
                            borderRadius: 6,
                            fontSize: 11,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
                            <strong style={{ color: '#172536' }}>{task.task_id.slice(0, 16)}...</strong>
                            <span
                              className={`badge ${
                                isCompleted ? 'badge-green' : isLeased ? 'badge-blue' : 'badge-neutral'
                              }`}
                              style={{ fontSize: 9, padding: '1px 5px' }}
                            >
                              {task.status}
                            </span>
                          </div>

                          <div style={{ color: '#64748B', fontSize: 10 }}>
                            {task.task_type} · {task.target_host || `Hill ${task.hill_id}`}
                          </div>

                          {/* Dependencies Notice */}
                          {hasDeps && (
                            <div
                              style={{
                                marginTop: 4,
                                fontSize: 10,
                                color: isCompleted ? '#16A34A' : '#D97706',
                                display: 'flex',
                                alignItems: 'center',
                                gap: 3,
                              }}
                            >
                              <GitBranch size={10} />
                              <span>Depends on: {task.dependencies.map((d) => d.slice(0, 10)).join(', ')}</span>
                            </div>
                          )}

                          {/* Reassign Button (Leader only) */}
                          {isLeader && !isCompleted && (
                            <button
                              onClick={() => {
                                setReassignTaskId(task.task_id);
                                setReassignModalOpen(true);
                              }}
                              style={{
                                marginTop: 6,
                                padding: '2px 6px',
                                fontSize: 10,
                                background: '#F1F5F9',
                                border: '1px solid #CBD5E1',
                                borderRadius: 4,
                                cursor: 'pointer',
                                color: '#334155',
                                width: '100%',
                              }}
                            >
                              Reassign Task
                            </button>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* SECTION C: Inter-Agent Coordination Stream & Blocker Reports */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 340px',
          gap: 20,
          marginBottom: 20,
        }}
      >
        {/* Messages Thread */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div className="card-title">
              <Users size={16} color="#2878C8" />
              <span>Inter-Agent Communication & Blocker Log</span>
            </div>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Real-time swarm synchronization
            </span>
          </div>

          <div style={{ maxHeight: 380, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10, paddingRight: 4 }}>
            {messages.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px 0', color: '#94A3B8', fontSize: 12 }}>
                No coordination messages recorded. Post a status update or blocker report below.
              </div>
            ) : (
              messages.map((msg, i) => {
                const isBlocker = msg.message_type === 'BLOCKER_REPORT';
                const isHelp = msg.message_type === 'ASSISTANCE_REQUEST';
                const isObjective = msg.message_type === 'OBJECTIVE';
                const dt = msg.timestamp ? new Date(msg.timestamp * 1000) : new Date();

                return (
                  <div
                    key={msg.message_id || i}
                    style={{
                      padding: 10,
                      background: isBlocker ? '#FEF2F2' : isHelp ? '#FFFBEB' : '#F8FAFC',
                      border: isBlocker ? '1px solid #FCA5A5' : isHelp ? '1px solid #FDE68A' : '1px solid #E2E8F0',
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <strong style={{ color: '#172536' }}>{msg.from_agent_id}</strong>
                        <ArrowRight size={10} color="#94A3B8" />
                        <span style={{ color: '#64748B', fontSize: 11 }}>{msg.to_agent_id || 'ALL'}</span>
                        <span
                          className={`badge ${
                            isBlocker ? 'badge-red' : isHelp ? 'badge-amber' : isObjective ? 'badge-blue' : 'badge-neutral'
                          }`}
                          style={{ fontSize: 9, padding: '1px 5px' }}
                        >
                          {msg.message_type}
                        </span>
                      </div>
                      <span style={{ fontSize: 10, color: '#94A3B8' }}>{dt.toLocaleTimeString()}</span>
                    </div>

                    <div style={{ color: '#334155', lineHeight: 1.4, marginTop: 4 }}>
                      {msg.content}
                    </div>

                    {msg.hill_id != null && (
                      <div style={{ marginTop: 4, fontSize: 10, color: '#64748B' }}>
                        Hill Reference: <strong>Hill {msg.hill_id}</strong>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Post Message / Blocker Panel */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div className="card-title">
              <Send size={15} color="#2878C8" />
              <span>Broadcast / Report</span>
            </div>
          </div>

          <form onSubmit={handleSendMessage} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label className="form-label">Message Intent</label>
              <select
                className="form-control"
                value={msgType}
                onChange={(e) => setMsgType(e.target.value)}
              >
                <option value="STATUS_UPDATE">Status Update</option>
                <option value="BLOCKER_REPORT">Report Blocker (Alert)</option>
                <option value="ASSISTANCE_REQUEST">Request Assistance</option>
                <option value="FINDING_SHARED">Share Finding / Scan</option>
              </select>
            </div>

            <div>
              <label className="form-label">Hill Context</label>
              <select
                className="form-control"
                value={msgHillId}
                onChange={(e) => setMsgHillId(e.target.value)}
              >
                <option value={1}>Hill 1 (Primary)</option>
                <option value={2}>Hill 2</option>
                <option value={3}>Hill 3</option>
                <option value={4}>Hill 4</option>
              </select>
            </div>

            <div>
              <label className="form-label">Description / Finding</label>
              <textarea
                className="form-control"
                rows={3}
                placeholder="e.g., Target port 80 requires authentication; specialist 02 requesting assistance"
                value={msgContent}
                onChange={(e) => setMsgContent(e.target.value)}
                style={{ resize: 'none', fontSize: 12 }}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 6 }}
              disabled={isSendingMsg || !msgContent.trim()}
            >
              <Send size={13} />
              <span>{isSendingMsg ? 'Broadcasting...' : 'Broadcast to Swarm'}</span>
            </button>
          </form>
        </div>
      </div>

      {/* SECTION D: Consolidated Shared Knowledge & Findings */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={16} color="#2878C8" />
            <span>Consolidated Swarm Knowledge Base (Shared Team State)</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Captured Flags: {sharedFindings.captured_flags_count || 0}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
          {/* Discovered Targets */}
          <div style={{ background: '#F8FAFC', padding: 12, borderRadius: 8, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#172536', marginBottom: 6 }}>
              Discovered Hosts & Ports
            </div>
            {Object.keys(sharedFindings.discovered_hosts || {}).length === 0 ? (
              <div style={{ fontSize: 11, color: '#94A3B8' }}>No hosts discovered yet</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {Object.entries(sharedFindings.discovered_hosts).map(([host, info]) => (
                  <div key={host} style={{ fontSize: 11, fontFamily: 'monospace' }}>
                    <strong>{host}</strong>: ports [{info.ports?.join(', ') || 'none'}]
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Compromised Targets */}
          <div style={{ background: '#F8FAFC', padding: 12, borderRadius: 8, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#172536', marginBottom: 6 }}>
              Compromised Target Hills
            </div>
            {Object.keys(sharedFindings.compromised_targets || {}).length === 0 ? (
              <div style={{ fontSize: 11, color: '#94A3B8' }}>No hills compromised yet</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {Object.entries(sharedFindings.compromised_targets).map(([host, info]) => (
                  <div key={host} style={{ fontSize: 11, fontFamily: 'monospace' }}>
                    <span style={{ color: '#16A34A', fontWeight: 600 }}>PWNED: {host}</span> (by {info.pwned_by})
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Patched Services */}
          <div style={{ background: '#F8FAFC', padding: 12, borderRadius: 8, border: '1px solid #E2E8F0' }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#172536', marginBottom: 6 }}>
              Defended & Patched Services
            </div>
            {Object.keys(sharedFindings.patched_services || {}).length === 0 ? (
              <div style={{ fontSize: 11, color: '#94A3B8' }}>No services patched yet</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {Object.entries(sharedFindings.patched_services).map(([svc, info]) => (
                  <div key={svc} style={{ fontSize: 11, fontFamily: 'monospace' }}>
                    <span style={{ color: '#2878C8', fontWeight: 600 }}>SECURED: {svc}</span> (by {info.patched_by})
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Task Reassignment Modal */}
      {reassignModalOpen && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(15, 23, 42, 0.45)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onClick={() => setReassignModalOpen(false)}
        >
          <div
            style={{
              width: 440,
              background: '#FFFFFF',
              borderRadius: 8,
              padding: 24,
              boxShadow: '0 8px 30px rgba(0,0,0,0.12)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ margin: '0 0 14px 0', fontSize: 16, fontWeight: 700, color: '#172536' }}>
              Reassign Swarm Task
            </h3>
            <div style={{ fontSize: 12, color: '#64748B', marginBottom: 14 }}>
              Reassigning task: <code>{reassignTaskId}</code>
            </div>

            <form onSubmit={handleExecuteReassignment}>
              <div style={{ marginBottom: 12 }}>
                <label className="form-label">Transfer Task To</label>
                <select
                  className="form-control"
                  value={reassignNewAgent}
                  onChange={(e) => setReassignNewAgent(e.target.value)}
                >
                  <option value="agent-01">agent-01 (Leader)</option>
                  <option value="agent-02">agent-02 (Specialist 1)</option>
                  <option value="agent-03">agent-03 (Specialist 2)</option>
                  <option value="agent-04">agent-04 (Specialist 3)</option>
                </select>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label className="form-label">Reassignment Reason</label>
                <input
                  type="text"
                  className="form-control"
                  value={reassignReason}
                  onChange={(e) => setReassignReason(e.target.value)}
                />
              </div>

              {reassignMsg && (
                <div
                  style={{
                    fontSize: 12,
                    marginBottom: 12,
                    color: reassignMsg.startsWith('Success') ? '#16A34A' : '#DC2626',
                  }}
                >
                  {reassignMsg}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => setReassignModalOpen(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Confirm Reassignment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

