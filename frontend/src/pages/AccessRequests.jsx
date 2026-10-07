import React, { useState } from 'react';
import { Key, Plus, Filter, Search, Eye } from 'lucide-react';
import {Pagination} from '../components/Pagination';
import { StatusBadge } from '../components/StatusBadge';

export function AccessRequests({ requests = [], currentUser, onOpenRequestModal, page, onPage, onCancel }) {
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selectedReq, setSelectedReq] = useState(null);

  const filtered = requests.filter(req => {
    const matchesStatus = filterStatus === 'ALL' || req.status === filterStatus;
    const matchesSearch = 
      req.username.toLowerCase().includes(search.toLowerCase()) ||
      req.iam_role.toLowerCase().includes(search.toLowerCase()) ||
      req.aws_account_name.toLowerCase().includes(search.toLowerCase()) ||
      (req.ticket_ref && req.ticket_ref.toLowerCase().includes(search.toLowerCase()));
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <div>
          <h1 className="page-title">Access Requests</h1>
          <p className="page-subtitle">Historical & Active JIT Privilege Request Registry</p>
        </div>
        {currentUser?.role !== 'AUDITOR' && <button className="btn btn-primary" onClick={onOpenRequestModal}>
          <Plus size={18} /> Submit New Request
        </button>}
      </div>

      {/* Filter Toolbar */}
      <div className="glass-panel" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="form-control"
            style={{ paddingLeft: '2.5rem' }}
            placeholder="Search by role, account, username or ticket reference..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Filter size={16} color="var(--text-muted)" />
          <select 
            className="form-select" 
            style={{ width: '180px' }}
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="APPROVED">Approved</option>
            <option value="PENDING">Pending</option>
            <option value="REJECTED">Rejected</option>
            <option value="EXPIRED">Expired</option>
            <option value="REVOKED">Revoked</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="glass-panel">
        <div className="table-responsive">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Request ID</th>
                <th>Requester</th>
                <th>Target Account</th>
                <th>IAM Role</th>
                <th>Duration</th>
                <th>Ticket Ref</th>
                <th>Risk Score</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                    No access requests matching criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((req) => (
                  <tr key={req.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {req.id.slice(0, 8)}...
                    </td>
                    <td><strong>{req.username}</strong></td>
                    <td>{req.aws_account_name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{req.iam_role}</td>
                    <td>{req.duration_minutes} mins</td>
                    <td>
                      {req.ticket_ref ? (
                        <span style={{ fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.05)', padding: '0.2rem 0.4rem', borderRadius: '4px', fontSize: '0.8rem' }}>
                          {req.ticket_ref}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                    <td><StatusBadge status={req.risk_level} size="sm" /></td>
                    <td><StatusBadge status={req.status} size="sm" /></td>
                    <td>
                      <button 
                        className="btn btn-secondary"
                        onClick={() => setSelectedReq(req)}
                        style={{ padding: '0.35rem 0.6rem', fontSize: '0.75rem' }}
                      >
                        <Eye size={14} /> Details
                      </button>
                      {req.user_id === currentUser.id && req.status === "PENDING" && <button className="btn btn-secondary" onClick={() => onCancel(req.id)}>Cancel request</button>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <Pagination page={page} count={requests.length} onPage={onPage}/>
      <p className="page-subtitle">Search and status filters apply to this page.</p>
      {/* Details Modal */}
      {selectedReq && (
        <div className="modal-overlay">
          <div className="modal-card">
            <h3 style={{ fontSize: '1.2rem', fontWeight: '700', marginBottom: '1rem' }}>
              Request Details: {selectedReq.id}
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
              <div><strong>Requester:</strong> {selectedReq.username}</div>
              <div><strong>Target Role:</strong> {selectedReq.iam_role}</div>
              <div><strong>AWS Account:</strong> {selectedReq.aws_account_name} ({selectedReq.aws_account_id})</div>
              <div><strong>Duration:</strong> {selectedReq.duration_minutes} Minutes</div>
              <div><strong>Status:</strong> <StatusBadge status={selectedReq.status} size="sm" /></div>
              <div><strong>Risk Score:</strong> {selectedReq.risk_score}/100 ({selectedReq.risk_level})</div>
              <div>
                <strong>Justification:</strong>
                <p style={{ marginTop: '0.25rem', padding: '0.75rem', background: 'rgba(0,0,0,0.3)', borderRadius: '8px', color: 'var(--text-secondary)' }}>
                  {selectedReq.justification}
                </p>
              </div>
              {selectedReq.rejection_reason && (
                <div style={{ color: '#f87171' }}>
                  <strong>Rejection Reason:</strong> {selectedReq.rejection_reason}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={() => setSelectedReq(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
