import React, {useState, useEffect, useCallback, useRef} from 'react';
import {Sidebar} from './components/Sidebar';
import {Header} from './components/Header';
import {Login} from './pages/Login';
import {Dashboard} from './pages/Dashboard';
import {AccessRequests} from './pages/AccessRequests';
import {Approvals} from './pages/Approvals';
import {ActiveSessions} from './pages/ActiveSessions';
import {AuditLogs} from './pages/AuditLogs';
import {UserManagement} from './pages/UserManagement';
import {AccountSecurity} from './pages/AccountSecurity';
import {AccessRequestModal} from './components/AccessRequestModal';
import {AwsCliSnippetModal} from './components/AwsCliSnippetModal';
import {NotificationToast} from './components/NotificationToast';
import {authService, requestService, approvalService, sessionService, systemService, subscribeEvents} from './services/api';
export default function App() {
  const [user, setUser] = useState(null), [loading, setLoading] = useState(true), [tab, setTab] = useState('dashboard');
  const [requests, setRequests] = useState([]), [sessions, setSessions] = useState([]), [pending, setPending] = useState([]);
  const [status, setStatus] = useState(null), [notifications, setNotifications] = useState([]), [error, setError] = useState('');
  const [requestOpen, setRequestOpen] = useState(false), [snippet, setSnippet] = useState(null), [toast, setToast] = useState(null);
  const generation = useRef(0), fetchSequence = useRef(0);
  const [requestPage, setRequestPage] = useState(0), [approvalPage, setApprovalPage] = useState(0), [sessionPage, setSessionPage] = useState(0);
  const clear = useCallback(() => {
    generation.current++;
    setUser(null); setRequests([]); setSessions([]); setPending([]); setStatus(null); setNotifications([]); setSnippet(null); setRequestOpen(false); setTab('dashboard'); setError(''); setRequestPage(0); setApprovalPage(0); setSessionPage(0);
  }, []);
  useEffect(() => {
    // Remove prototype browser tokens; the application now uses an HttpOnly cookie.
    localStorage.removeItem('secureaccess_token'); localStorage.removeItem('secureaccess_user');
    let alive = true;
    authService.getCurrentUser().then(u => {if (alive) setUser(u);}).catch(() => {}).finally(() => {if (alive) setLoading(false);});
    const unauthorized = () => {clear(); setToast({message: 'Your session ended. Please sign in again.', type: 'error'});};
    window.addEventListener('secureaccess:unauthorized', unauthorized);
    return () => {alive = false; window.removeEventListener('secureaccess:unauthorized', unauthorized);};
  }, [clear]);
  const fetchData = useCallback(async () => {
    if (!user || user.must_change_password) return;
    const sequence = ++fetchSequence.current;
    const version = generation.current;
    try {
      const approver = !user.must_change_password && ['APPROVER','SECURITY_ADMIN'].includes(user.role);
      const results = await Promise.allSettled([requestService.getRequests({limit:25,offset:requestPage*25}), sessionService.getActiveSessions({limit:25,offset:sessionPage*25}), approver ? approvalService.getPending({limit:25,offset:approvalPage*25}) : Promise.resolve([]), systemService.status(), systemService.notifications()]);
      if (version !== generation.current || sequence !== fetchSequence.current) return;
      const setters = [setRequests, setSessions, setPending, setStatus, setNotifications];
      const errors = [];
      results.forEach((result, index) => {if (result.status === 'fulfilled') {setters[index](result.value); if(index===1) setSnippet(current => current && !result.value.some(s=>s.id===current.id) ? null : current);} else {setters[index](index === 3 ? null : []); errors.push(result.reason.message);}});
      setError([...new Set(errors)].join(' · '));
    } catch (err) {if (version === generation.current) setError(err.message);}
  }, [user, requestPage, approvalPage, sessionPage]);
  useEffect(() => {if (!user) return; fetchData(); const interval = setInterval(fetchData, 10000); return () => clearInterval(interval);}, [fetchData, user]);
  useEffect(() => {if (!user || user.must_change_password) return; return subscribeEvents(fetchData, clear);}, [user, fetchData, clear]);
  const login = async () => {generation.current++; const current = await authService.getCurrentUser(); setUser(current); setTab(current.must_change_password ? 'security' : 'dashboard');};
  const logout = async () => {try {await authService.logout(); clear();} catch (err) {setToast({message: err.message, type: 'error'});}};
  const decide = async (id, approved, reason) => {
    try {const result = await approvalService.decide(id, approved, reason); setToast({message: approved ? (result.status === 'APPROVED' ? 'Approved; credentials issued.' : `Approval recorded (${result.approval_count}/${result.required_approvals}).`) : 'Request rejected.', type: 'success'}); await fetchData();}
    catch (err) {setToast({message: err.message, type: 'error'});}
  };
  const revoke = async id => {try {const result = await sessionService.revokeSession(id); setSnippet(null); setToast({message: result.is_demo ? 'Demo session revoked.' : 'Revocation policy applied. AWS propagation may take time.', type: 'success'}); await fetchData();} catch (err) {setToast({message: err.message, type: 'error'});}};
  const credentials = async session => {const version = generation.current; try {const data = await sessionService.credentials(session.id); if (version === generation.current) setSnippet({...session, ...data});} catch (err) {setToast({message: err.message, type: 'error'});}};
  useEffect(() => {if (!snippet) return; const deadline = setTimeout(() => setSnippet(null), Math.max(0, new Date(snippet.expires_at) - Date.now())); return () => clearTimeout(deadline);}, [snippet]);
  useEffect(() => {
    if (user?.must_change_password) {setTab('security'); setRequestOpen(false); setSnippet(null);}
  }, [user]);
  const cancel = async id => {try {await requestService.cancel(id); await fetchData();} catch(e) {setToast({message:e.message,type:'error'});}};
  if (loading) return <div className="page-wrapper">Checking your session…</div>;
  if (!user) return <Login onLoginSuccess={login}/>;
  const privileged = ['APPROVER','SECURITY_ADMIN'].includes(user.role), audit = user.role !== 'REQUESTER';
  return <div className="app-container">
    <Sidebar activeTab={tab} setActiveTab={setTab} currentUser={user} onLogout={logout} pendingCount={pending.length} activeSessionCount={sessions.length}/>
    <main className="main-content">
      <Header onOpenRequestModal={() => setRequestOpen(true)} currentUser={user} status={status}/>
      {status?.demo_mode && <div className="mode-banner">LOCAL DEMO · AWS credentials are simulated and cannot access AWS. CloudTrail is disabled.</div>}
      {user.must_change_password && <div className="mode-banner">Change your temporary password in Account Security before requesting access.</div>}
      {error && <div className="error-banner" role="alert">{error} <button className="btn btn-secondary" onClick={fetchData}>Retry</button></div>}
      {tab === 'dashboard' && <Dashboard requests={requests} activeSessions={sessions} pendingApprovals={pending} status={status} currentUser={user} onOpenRequestModal={() => setRequestOpen(true)} setActiveTab={setTab} notifications={notifications} onRead={async id => {await systemService.read(id); fetchData();}}/>}
      {tab === 'requests' && <AccessRequests requests={requests} currentUser={user} onOpenRequestModal={() => setRequestOpen(true)} page={requestPage} onPage={setRequestPage} onCancel={cancel}/>}
      {tab === 'approvals' && privileged && <Approvals pendingApprovals={pending} onDecide={decide} currentUser={user} page={approvalPage} onPage={setApprovalPage}/>}
      {tab === 'sessions' && <ActiveSessions activeSessions={sessions} currentUser={user} onOpenSnippetModal={credentials} onRevokeSession={revoke} onRefresh={fetchData} page={sessionPage} onPage={setSessionPage}/>}
      {tab === 'audit' && audit && <AuditLogs/>}
      {tab === 'users' && audit && <UserManagement currentUser={user}/>}
      {tab === 'security' && <AccountSecurity currentUser={user} onChanged={async () => {setUser(await authService.getCurrentUser()); fetchData();}} onPasswordChanged={clear}/>}
    </main>
    <AccessRequestModal currentUser={user} isOpen={requestOpen} onClose={() => setRequestOpen(false)} onRequestCreated={() => {setToast({message:'Request submitted.', type:'success'}); fetchData();}}/>
    {snippet && <AwsCliSnippetModal session={snippet} onClose={() => setSnippet(null)}/>}
    {toast && <NotificationToast {...toast} onClose={() => setToast(null)}/>}
  </div>;
}
