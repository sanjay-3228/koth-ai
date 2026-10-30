import React, { useState } from 'react';
import { FileText, RefreshCw, Filter, Search, ShieldCheck } from 'lucide-react';

export default function AuditLogsView({
  auditLogs,
  onRefresh,
}) {
  const [filterText, setFilterText] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');

  const eventTypes = ['ALL', ...new Set(auditLogs.map((e) => e.event_type))];

  const filteredLogs = auditLogs.filter((ev) => {
    const matchesType = selectedType === 'ALL' || ev.event_type === selectedType;
    const searchLow = filterText.toLowerCase();
    const matchesSearch =
      !filterText ||
      ev.event_type?.toLowerCase().includes(searchLow) ||
      ev.actor?.toLowerCase().includes(searchLow) ||
      ev.target?.toLowerCase().includes(searchLow) ||
      JSON.stringify(ev.details || {}).toLowerCase().includes(searchLow);

    return matchesType && matchesSearch;
  });

  return (
    <div className="content-container">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h1 className="view-title">Immutable Audit Trail</h1>
          <p className="view-subtitle">
            Cryptographically logged operations with zero secret or password leakage
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button type="button" onClick={onRefresh} className="btn-sm">
            <RefreshCw size={13} />
            <span>Refresh Trail</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ padding: 14, marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 2, minWidth: 200, display: 'flex', alignItems: 'center', position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search by event type, actor, or target..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              style={{ margin: 0, paddingLeft: 30 }}
            />
          </div>

          <div style={{ flex: 1, minWidth: 160, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              style={{ margin: 0 }}
            >
              {eventTypes.map((t) => (
                <option key={t} value={t}>
                  {t === 'ALL' ? 'All Event Types' : t}
                </option>
              ))}
            </select>
          </div>

          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            Showing <strong>{filteredLogs.length}</strong> of {auditLogs.length} events
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Details Payload</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((ev) => (
                <tr key={ev.event_id}>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {new Date(ev.timestamp * 1000).toLocaleString()}
                  </td>
                  <td>
                    <span className="badge badge-neutral" style={{ fontSize: 11 }}>
                      {ev.event_type}
                    </span>
                  </td>
                  <td>
                    <strong>{ev.actor}</strong>
                  </td>
                  <td>
                    <code>{ev.target}</code>
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                    {JSON.stringify(ev.details || {})}
                  </td>
                </tr>
              ))}
              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>
                    No audit events match the current filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: 14, fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <ShieldCheck size={14} color="#16A36A" />
          <span>Zero Credential Leak Guarantee: Flags, secrets, and raw keys are strictly redacted before persistence.</span>
        </div>
      </div>
    </div>
  );
}

