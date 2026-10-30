import React from 'react';
import { ListTodo, ShieldCheck, CheckCircle2, Lock } from 'lucide-react';

export default function TaskManagementView({ swarmStatus }) {
  const activeLeases = swarmStatus?.active_leases || [];
  const activeCount = swarmStatus?.phase?.active_count || activeLeases.length;

  const gates = [
    {
      num: 1,
      name: 'Action Registry Gate',
      desc: 'Enforces whitelist of verified attack & defense modules. Arbitrary shell commands blocked.',
      status: 'ARMED',
    },
    {
      num: 2,
      name: 'Task Authorization Gate',
      desc: 'Cryptographic validation of agent token, lease signature, and team identifier.',
      status: 'ARMED',
    },
    {
      num: 3,
      name: 'Competition Policy Gate',
      desc: 'Enforces phase constraints (ATTACK/DEFENSE), assigned hill scope, and rate limits.',
      status: 'ARMED',
    },
    {
      num: 4,
      name: 'Final Execution Gate',
      desc: 'Simulated pre-flight validation, automatic rollback snapshot, and kill-switch check.',
      status: 'ARMED',
    },
  ];

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Task Management & Execution Gates</h1>
          <p className="view-subtitle">
            Deterministic security pipelines and active distributed worker task leases
          </p>
        </div>
        <span className="badge badge-blue" style={{ fontSize: 13, padding: '5px 12px' }}>
          Active Tasks: {activeCount}
        </span>
      </div>

      {/* 4 Deterministic Execution Gates */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ShieldCheck size={16} />
            <span>Four Deterministic Security Execution Gates</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            All tasks must pass Gates 1–4 before dispatching
          </span>
        </div>

        <div className="grid-4">
          {gates.map((g) => (
            <div
              key={g.num}
              style={{
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-color)',
                borderRadius: 6,
                padding: 14,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span className="badge badge-blue">Gate 0{g.num}</span>
                <span className="badge badge-green">
                  <CheckCircle2 size={11} /> {g.status}
                </span>
              </div>
              <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)', marginBottom: 4 }}>
                {g.name}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                {g.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Active Task Leases Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <ListTodo size={16} />
            <span>Active Worker Task Leases</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Time-bound cryptographic execution leases
          </span>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Lease ID</th>
                <th>Assigned Agent</th>
                <th>Task Type</th>
                <th>Target CIDR / Host</th>
                <th>Granted At</th>
                <th>Expires In</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {activeLeases.map((l) => (
                <tr key={l.lease_id || l.id}>
                  <td><code>{l.lease_id || l.id}</code></td>
                  <td><strong>{l.agent_id}</strong></td>
                  <td><span className="badge badge-neutral">{l.task_type}</span></td>
                  <td><code>{l.target || '--'}</code></td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    {l.granted_at ? new Date(l.granted_at * 1000).toLocaleTimeString() : 'Active'}
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                    {l.ttl ? `${l.ttl}s` : '60s'}
                  </td>
                  <td>
                    <span className="badge badge-green">
                      <span className="dot dot-green" /> ACTIVE
                    </span>
                  </td>
                </tr>
              ))}
              {activeLeases.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 18 }}>
                    No active task leases dispatched. Swarm is idle or awaiting next phase trigger.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

