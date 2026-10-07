import React from 'react';

export function StatusBadge({ status, size = 'md' }) {
  const normalized = (status || '').toUpperCase();
  
  const styles = {
    APPROVED: { bg: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: 'rgba(16, 185, 129, 0.3)', label: 'Approved' },
    ACTIVE: { bg: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: 'rgba(56, 189, 248, 0.3)', label: 'Active STS Session' },
    PENDING: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)', label: 'Pending Approval' },
    REJECTED: { bg: 'rgba(244, 63, 94, 0.15)', color: '#f87171', border: 'rgba(244, 63, 94, 0.3)', label: 'Rejected' },
    EXPIRED: { bg: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: 'rgba(148, 163, 184, 0.3)', label: 'Expired' },
    REVOKED: { bg: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: 'rgba(239, 68, 68, 0.4)', label: 'Revoked' },

    LOW: { bg: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: 'rgba(16, 185, 129, 0.3)', label: 'LOW RISK' },
    MEDIUM: { bg: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.3)', label: 'MEDIUM RISK' },
    HIGH: { bg: 'rgba(249, 115, 22, 0.15)', color: '#fb923c', border: 'rgba(249, 115, 22, 0.3)', label: 'HIGH RISK' },
    CRITICAL: { bg: 'rgba(244, 63, 94, 0.2)', color: '#f87171', border: 'rgba(244, 63, 94, 0.4)', label: 'CRITICAL RISK' }
  };

  const current = styles[normalized] || { bg: 'rgba(255,255,255,0.1)', color: '#fff', border: 'transparent', label: status };

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: size === 'sm' ? '0.2rem 0.5rem' : '0.35rem 0.75rem',
        fontSize: size === 'sm' ? '0.75rem' : '0.825rem',
        fontWeight: '700',
        borderRadius: '9999px',
        backgroundColor: current.bg,
        color: current.color,
        border: `1px solid ${current.border}`,
        textTransform: 'uppercase',
        letterSpacing: '0.04em'
      }}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: current.color,
          boxShadow: `0 0 8px ${current.color}`
        }}
      />
      {current.label}
    </span>
  );
}
