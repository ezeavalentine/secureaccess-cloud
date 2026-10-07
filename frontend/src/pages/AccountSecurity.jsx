import React, {useState} from 'react';
import {authService} from '../services/api';

export function AccountSecurity({currentUser, onChanged, onPasswordChanged}) {
  const [setup,setSetup]=useState(null),[otp,setOtp]=useState(''),[message,setMessage]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [codes,setCodes]=useState(null),[recoveryPassword,setRecoveryPassword]=useState('');
  const [enrollmentPassword,setEnrollmentPassword]=useState('');
  const [password,setPassword]=useState({current_password:'',new_password:''});
  const run=async fn=>{setBusy(true);setError('');setMessage('');try{await fn();}catch(e){setError(e.message);}finally{setBusy(false);}};
  return <div className="page-wrapper"><h1 className="page-title">Account security</h1>
    {error&&<div className="error-banner" role="alert">{error}</div>}{message&&<p role="status">{message}</p>}
    {!currentUser.must_change_password&&<div className="glass-panel"><h2>Authenticator MFA</h2><p>MFA is {currentUser.mfa_enabled?'enabled':'not enabled'}. Live-mode approvers and administrators must verify MFA before privileged actions.</p>
      {!currentUser.mfa_enabled&&!setup&&<form onSubmit={e=>{e.preventDefault();run(async()=>{setSetup(await authService.setupMfa(enrollmentPassword));setEnrollmentPassword('');});}}><label className="form-label">Current password to set up MFA<input className="form-control" type="password" autoComplete="current-password" required maxLength={128} value={enrollmentPassword} onChange={e=>setEnrollmentPassword(e.target.value)}/></label><button className="btn btn-primary" disabled={busy}>Set up MFA</button></form>}
      {setup&&<><p>Add this key to your authenticator app:</p><code>{setup.secret}</code><details><summary>Enrollment URI</summary><code className="break-text">{setup.provisioning_uri}</code></details></>}
      {(setup||currentUser.mfa_enabled)&&<form onSubmit={e=>{e.preventDefault();run(async()=>{if(setup){const result=await authService.enableMfa(otp);setCodes(result.recovery_codes);setSetup(null);}else await authService.verifyMfa(otp);setOtp('');setMessage('MFA verified for this session.');await onChanged();});}}>
        <label className="form-label">Six-digit code<input className="form-control" required pattern="[0-9]{6}" inputMode="numeric" autoComplete="one-time-code" value={otp} onChange={e=>setOtp(e.target.value)}/></label>
        <button className="btn btn-primary" disabled={busy}>{setup?'Enable MFA':'Verify MFA'}</button>
      </form>}
    </div>}
    {currentUser.mfa_enabled&&!currentUser.must_change_password&&<form className="glass-panel" onSubmit={e=>{e.preventDefault();run(async()=>{const result=await authService.recoveryCodes({current_password:recoveryPassword,otp});setCodes(result.recovery_codes);setRecoveryPassword('');setOtp('');});}}>
      <h2>Replace recovery codes</h2><p>Replacing codes invalidates all previously saved codes. Use a fresh authenticator code.</p>
      <label className="form-label">Password to replace recovery codes<input className="form-control" type="password" autoComplete="current-password" required value={recoveryPassword} onChange={e=>setRecoveryPassword(e.target.value)}/></label>
      <label className="form-label">Authenticator code for recovery codes<input className="form-control" required pattern="[0-9]{6}" value={otp} onChange={e=>setOtp(e.target.value)}/></label>
      <button className="btn btn-secondary" disabled={busy}>Generate new recovery codes</button>
    </form>}
    {codes&&<div className="glass-panel"><h2>Save these recovery codes</h2><p>Each code can be used once instead of an authenticator code at sign-in. Store them securely; they will not be shown again.</p><pre className="code-block">{codes.join('\n')}</pre><button className="btn btn-secondary" onClick={()=>setCodes(null)}>I saved my codes; clear them</button></div>}
    <form className="glass-panel" onSubmit={e=>{e.preventDefault();run(async()=>{await authService.changePassword(password);setPassword({current_password:'',new_password:''});onPasswordChanged();});}}>
      <h2>Change password</h2><p>This signs you out and revokes existing AWS sessions.</p>
      <label className="form-label">Current password<input className="form-control" type="password" autoComplete="current-password" required value={password.current_password} onChange={e=>setPassword(p=>({...p,current_password:e.target.value}))}/></label>
      <label className="form-label">New password (at least 12 characters)<input className="form-control" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password.new_password} onChange={e=>setPassword(p=>({...p,new_password:e.target.value}))}/></label>
      <button className="btn btn-primary" disabled={busy}>Change password and sign out</button>
    </form>
  </div>;
}
