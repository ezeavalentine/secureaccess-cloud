import React, {useState, useEffect} from 'react';
import {Shield, ArrowRight} from 'lucide-react';
import {authService, systemService} from '../services/api';
export function Login({onLoginSuccess}) {
  const [username, setUsername] = useState(''), [password, setPassword] = useState(''), [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false), [error, setError] = useState(''), [health, setHealth] = useState(null), [recoveryCode, setRecoveryCode] = useState('');
  useEffect(() => {let alive = true; systemService.health().then(h => {if(alive) setHealth(h);}).catch(e => {if(alive) setError(e.message);}); return () => {alive = false;};}, []);
  const submit = async event => {event.preventDefault(); setLoading(true); setError(''); try {await authService.login(username, password, otp, recoveryCode); setPassword(''); setOtp(''); setRecoveryCode(''); await onLoginSuccess();} catch(e) {setError(e.message);} finally {setLoading(false);}};
  return <div className="login-container"><div className="glass-panel login-card">
    <Shield size={42} color="var(--accent-cyan)"/><h1>SecureAccess Cloud</h1><p className="page-subtitle">Time-bound AWS access with verified approvals</p>
    {health?.demo_mode && <div className="mode-banner">Local demo · simulated AWS access</div>}
    {error && <div className="error-banner" role="alert">{error}</div>}
    <form onSubmit={submit}>
      <label className="form-label">Username<input className="form-control" autoComplete="username" required value={username} onChange={e=>setUsername(e.target.value)}/></label>
      <label className="form-label">Password<input className="form-control" type="password" autoComplete="current-password" required value={password} onChange={e=>setPassword(e.target.value)}/></label>
      <label className="form-label">Authenticator code (if MFA enabled)<input className="form-control" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={otp} onChange={e=>setOtp(e.target.value)}/></label>
      <details><summary>Use an MFA recovery code</summary><label className="form-label">Recovery code<input className="form-control" autoComplete="off" value={recoveryCode} onChange={e=>setRecoveryCode(e.target.value)} /></label></details>
      <p className="page-subtitle">For a forgotten password, contact your security administrator for verified account recovery.</p>
      <button className="btn btn-primary" disabled={loading}>{loading ? 'Signing in…' : 'Sign in'} <ArrowRight size={16}/></button>
    </form>
    {health?.sso_enabled && <a className="btn btn-secondary" href="/api/auth/sso">Sign in with company SSO</a>}
    {health?.demo_mode && <div className="demo-presets"><p>Demo accounts · password: <code>Password123!</code></p>{['alex.dev','sarah.sec','admin.sys','audit.user'].map(name=><button key={name} className="btn btn-secondary" type="button" onClick={()=>{setUsername(name);setPassword('Password123!');}}>{name}</button>)}</div>}
  </div></div>;
}
