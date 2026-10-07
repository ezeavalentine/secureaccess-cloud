import React from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  Key, 
  CheckSquare, 
  Clock, 
  FileText, 
  Users, 
  LogOut,
  ShieldCheck
} from 'lucide-react';

export function Sidebar({ activeTab, setActiveTab, currentUser, onLogout, pendingCount = 0, activeSessionCount = 0 }) {
  const role = currentUser?.role || 'REQUESTER';

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, roles: ['REQUESTER', 'APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
    { id: 'requests', label: 'Access Requests', icon: Key, roles: ['REQUESTER', 'APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
    { id: 'approvals', label: 'Approvals Inbox', icon: CheckSquare, badge: pendingCount, roles: ['APPROVER', 'SECURITY_ADMIN'] },
    { id: 'sessions', label: 'Active JIT Sessions', icon: Clock, badge: activeSessionCount, roles: ['REQUESTER', 'APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
    { id: 'audit', label: 'Audit Trail & Compliance', icon: FileText, roles: ['APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
    { id: 'security', label: 'Account Security', icon: ShieldCheck, roles: ['REQUESTER', 'APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
    { id: 'users', label: 'User & Policy Management', icon: Users, roles: ['APPROVER', 'SECURITY_ADMIN', 'AUDITOR'] },
  ];

  return (
    <aside
      style={{
        width: '260px',
        backgroundColor: 'var(--bg-surface)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        padding: '1.5rem 1rem',
        zIndex: 10
      }}
    >
      {/* Brand Logo Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0 0.5rem 1.5rem 0.5rem', borderBottom: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
        <div style={{ width: '40px', height: '40px', borderRadius: '12px', background: 'linear-gradient(135deg, #38bdf8 0%, #a855f7 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 15px rgba(56, 189, 248, 0.4)' }}>
          <Shield size={24} color="#04101e" />
        </div>
        <div>
          <h1 style={{ fontSize: '1.1rem', fontWeight: '800', color: '#fff', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
            SecureAccess
          </h1>
          <span style={{ fontSize: '0.725rem', color: 'var(--accent-cyan)', fontWeight: '600', letterSpacing: '0.05em' }}>
            CLOUD JIT PAM
          </span>
        </div>
      </div>

      {/* Navigation List */}
      <nav style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {menuItems
          .filter(item => item.roles.includes(role) && (!currentUser.must_change_password || item.id === 'security'))
          .map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  width: '100%',
                  padding: '0.75rem 1rem',
                  borderRadius: '10px',
                  border: '1px solid',
                  borderColor: isActive ? 'var(--border-glow)' : 'transparent',
                  backgroundColor: isActive ? 'rgba(56, 189, 248, 0.12)' : 'transparent',
                  color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  fontWeight: isActive ? '700' : '500',
                  fontSize: '0.9rem',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Icon size={18} color={isActive ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
                  <span>{item.label}</span>
                </div>
                {Boolean(item.badge) && item.badge > 0 && (
                  <span
                    style={{
                      padding: '0.15rem 0.5rem',
                      borderRadius: '9999px',
                      fontSize: '0.75rem',
                      fontWeight: '800',
                      backgroundColor: item.id === 'approvals' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                      color: item.id === 'approvals' ? '#fbbf24' : '#38bdf8',
                      border: '1px solid currentColor'
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
      </nav>

      {/* User Info & Logout */}
      <div style={{ paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 0.5rem 1rem 0.5rem' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: '#1e293b', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '700', color: 'var(--accent-cyan)' }}>
            {currentUser?.username?.charAt(0).toUpperCase() || 'A'}
          </div>
          <div style={{ overflow: 'hidden' }}>
            <div style={{ fontSize: '0.85rem', fontWeight: '700', color: '#fff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {currentUser?.username || 'alex.dev'}
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <ShieldCheck size={12} color="var(--accent-emerald)" />
              {role}
            </div>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="btn btn-secondary"
          style={{ width: '100%', justifyContent: 'center', fontSize: '0.85rem' }}
        >
          <LogOut size={16} /> Sign Out
        </button>
      </div>
    </aside>
  );
}
