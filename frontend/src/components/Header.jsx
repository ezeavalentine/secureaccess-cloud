import React from 'react';
export function Header({onOpenRequestModal, currentUser, status}) {
 return <header className="topbar"><span>SecureAccess Cloud · {status?.aws_region || 'Account security'}</span>{currentUser.role !== 'AUDITOR' && !currentUser.must_change_password && <button className="btn btn-primary" onClick={onOpenRequestModal}>Request JIT access</button>}</header>;
}
