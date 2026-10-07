import React from 'react';
import { CheckCircle2, AlertCircle, X } from 'lucide-react';

export function NotificationToast({ message, type = 'success', onClose }) {
  if (!message) return null;

  const isSuccess = type === 'success';

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '2rem',
        right: '2rem',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem',
        padding: '0.9rem 1.25rem',
        borderRadius: '12px',
        background: isSuccess ? 'rgba(16, 185, 129, 0.95)' : 'rgba(244, 63, 94, 0.95)',
        color: '#ffffff',
        boxShadow: '0 10px 30px rgba(0,0,0,0.4)',
        animation: 'slideUp 0.3s ease'
      }}
    >
      {isSuccess ? <CheckCircle2 size={20} /> : <AlertCircle size={20} />}
      <span style={{ fontSize: '0.9rem', fontWeight: '600' }}>{message}</span>
      <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer', padding: '0.2rem' }}>
        <X size={16} />
      </button>
    </div>
  );
}
