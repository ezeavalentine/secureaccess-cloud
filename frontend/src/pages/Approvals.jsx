import React, { useState } from 'react';
import { CheckSquare, CheckCircle, XCircle, AlertTriangle, ShieldAlert } from 'lucide-react';
import {Pagination} from '../components/Pagination';
import { StatusBadge } from '../components/StatusBadge';
import { RiskScoreCard } from '../components/RiskScoreCard';

export function Approvals({ pendingApprovals = [], onDecide, currentUser, page, onPage }) {
  const [rejectingId, setRejectingId] = useState(null);
  const [rejectReason, setRejectReason] = useState('');
  const [loading, setLoading] = useState(false);

  const handleApprove = async (id) => {
    setLoading(true);
    await onDecide(id, true);
    setLoading(false);
  };

  const handleRejectSubmit = async (e) => {
    e.preventDefault();
    if (!rejectingId) return;
    setLoading(true);
    await onDecide(rejectingId, false, rejectReason);
    setLoading(false);
    setRejectingId(null);
    setRejectReason('');
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <div>
          <h1 className="page-title">SecOps Approvals Inbox</h1>
          <p className="page-subtitle">Review High-Risk & Critical Elevation JIT Requests</p>
        </div>
      </div>

      {pendingApprovals.length === 0 ? (
        <div className="glass-panel" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
          <CheckCircle size={48} color="#34d399" style={{ margin: '0 auto 1rem auto' }} />
          <h3 style={{ fontSize: '1.25rem', fontWeight: '700' }}>Approvals Queue Clear</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.35rem' }}>
            There are currently no pending JIT access requests requiring manual authorization.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {pendingApprovals.map((req) => (
            <div key={req.id} className="glass-panel interactive-card" style={{ borderLeft: '4px solid var(--accent-amber)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <h3 style={{ fontSize: '1.15rem', fontWeight: '700', color: '#fff' }}>
                      Request by {req.username}
                    </h3>
                    <StatusBadge status={req.risk_level} />
                  </div>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
                    Approvals: {req.approval_count}/{req.required_approvals} · Submitted {new Date(req.created_at).toLocaleString()}
                  </p>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Environment</div>
                  <div style={{ fontSize: '1rem', fontWeight: '700', color: 'var(--accent-cyan)' }}>
                    {req.aws_account_name} ({req.aws_account_id})
                  </div>
                </div>
              </div>

              {/* Request Details Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem', padding: '1rem', background: 'rgba(0,0,0,0.3)', borderRadius: '10px' }}>
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>IAM ROLE REQUESTED</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: '#fff', fontSize: '0.95rem' }}>
                    {req.iam_role}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>REQUESTED TTL DURATION</span>
                  <span style={{ fontWeight: '700', color: '#fff', fontSize: '0.95rem' }}>
                    {req.duration_minutes} Minutes
                  </span>
                </div>
                <div style={{ gridColumn: 'span 2' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>JUSTIFICATION</span>
                  <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    {req.justification}
                  </p>
                </div>
                {req.ticket_ref && (
                  <div style={{ gridColumn: 'span 2' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>TICKETING REFERENCE</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{req.ticket_ref}</span>
                  </div>
                )}
              </div>

              {/* Action Bar */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                <button
                  className="btn btn-danger"
                  onClick={() => setRejectingId(req.id)}
                  disabled={loading}
                >
                  <XCircle size={18} /> Reject Request
                </button>
                <button
                  className="btn btn-success"
                  onClick={() => handleApprove(req.id)}
                  disabled={loading}
                >
                  <CheckCircle size={18} /> Record Approval
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Pagination page={page} count={pendingApprovals.length} onPage={onPage}/>
      {/* Reject Modal */}
      {rejectingId && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '1rem' }}>
              Reject Access Request
            </h3>
            <form onSubmit={handleRejectSubmit}>
              <div className="form-group">
                <label className="form-label">Reason for Rejection</label>
                <textarea
                  className="form-control"
                  rows="3"
                  placeholder="Provide explicit feedback or security reason..."
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  required
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setRejectingId(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-danger" disabled={loading}>
                  Confirm Rejection
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
