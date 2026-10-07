import React from 'react';
import { ShieldAlert, CheckCircle, AlertTriangle } from 'lucide-react';
import { StatusBadge } from './StatusBadge';

export function RiskScoreCard({ riskScore, riskLevel, autoApproved, reasons = [] }) {
  const getScoreColor = () => {
    if (riskScore <= 30) return '#10b981';
    if (riskScore <= 60) return '#f59e0b';
    if (riskScore <= 85) return '#f97316';
    return '#f43f5e';
  };

  return (
    <div className="glass-panel" style={{ background: 'rgba(15, 23, 42, 0.6)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Security Risk Assessment
          </h4>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.25rem' }}>
            <span style={{ fontSize: '2rem', fontWeight: '800', color: getScoreColor() }}>
              {riskScore}<span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/100</span>
            </span>
            <StatusBadge status={riskLevel} />
          </div>
        </div>

        <div style={{ textAlign: 'right' }}>
          {autoApproved === 'TRUE' || autoApproved === true ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#34d399', fontWeight: '600', fontSize: '0.85rem' }}>
              <CheckCircle size={18} />
              <span>Eligible for JIT Auto-Approval</span>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#fb923c', fontWeight: '600', fontSize: '0.85rem' }}>
              <AlertTriangle size={18} />
              <span>Requires SecOps Manual Approval</span>
            </div>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.08)', borderRadius: '4px', overflow: 'hidden', marginBottom: '1rem' }}>
        <div
          style={{
            width: `${riskScore}%`,
            height: '100%',
            background: `linear-gradient(90deg, #10b981 0%, ${getScoreColor()} 100%)`,
            transition: 'width 0.5s ease'
          }}
        />
      </div>

      {/* Policy Reasons */}
      {reasons.length > 0 && (
        <ul style={{ paddingLeft: '1.2rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
          {reasons.map((r, i) => (
            <li key={i} style={{ marginBottom: '0.25rem' }}>{r}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
