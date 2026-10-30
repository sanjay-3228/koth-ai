import React, { useState } from 'react';
import { AlertTriangle, X, ShieldAlert } from 'lucide-react';

export default function EmergencyStopModal({
  isOpen,
  onClose,
  onConfirm,
  user,
}) {
  const [reason, setReason] = useState('Operator emergency kill initiated from desktop client');

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    onConfirm(reason);
    onClose();
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#DC5555' }}>
            <ShieldAlert size={18} />
            <span>Confirm Emergency Swarm Kill Switch</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', padding: 4 }}
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            <p style={{ marginBottom: 14 }}>
              Engaging the emergency stop will <strong>immediately revoke all active task leases</strong> across all 4 worker agents and transition the coordinator into a persistent <strong>HALTED</strong> state.
            </p>

            <div style={{ background: '#FDF2F2', border: '1px solid #F5B6B6', padding: 12, borderRadius: 6, marginBottom: 16 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#991B1B', marginBottom: 4 }}>
                Operator Authorization
              </div>
              <div style={{ fontSize: 12, color: '#7F1D1D' }}>
                Executing as: <strong>{user?.full_name || user?.username}</strong> ({user?.agent_id || 'operator'}) · Role: {user?.role || 'MEMBER'}
              </div>
            </div>

            <label htmlFor="kill-reason">Reason for Emergency Stop *</label>
            <textarea
              id="kill-reason"
              required
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Provide a mandatory operational justification for the audit trail..."
              style={{ resize: 'vertical' }}
            />

            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: -6 }}>
              This action creates an immutable, timestamped audit entry. Only the Team Leader (Agent 01) can reset the kill switch.
            </p>
          </div>

          <div className="modal-footer">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-danger">
              <AlertTriangle size={14} />
              Confirm Emergency Stop
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

