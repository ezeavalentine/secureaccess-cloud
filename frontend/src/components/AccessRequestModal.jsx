import React, {useState, useEffect} from 'react';
import {requestService, userService} from '../services/api';
import {RiskScoreCard} from './RiskScoreCard';

export function AccessRequestModal({isOpen, onClose, onRequestCreated, currentUser}) {
  const [accounts, setAccounts] = useState([]), [roles, setRoles] = useState([]), [grants, setGrants] = useState([]);
  const [form, setForm] = useState({aws_account_id:'', aws_account_name:'', iam_role:'', duration_minutes:60, justification:'', ticket_ref:''});
  const [preview, setPreview] = useState(null), [error, setError] = useState(''), [busy, setBusy] = useState(false), [ready, setReady] = useState(false);
  const [key, setKey] = useState('');
  useEffect(() => {
    if (!isOpen || !currentUser) return;
    let alive = true;
    setReady(false); setError(''); setPreview(null); setKey(crypto.randomUUID());
    Promise.all([userService.accounts(), userService.roles(), userService.entitlements(currentUser.id)]).then(([a,r,g]) => {
      if (!alive) return;
      // Preserve reviewed catalog order instead of sorting by grant/account IDs.
      // In the demo this starts with sandbox read-only access, not administrator access.
      const eligible = a.flatMap(account => r.flatMap(role => role.allowed_environments.includes(account.environment)
        ? g.filter(grant => grant.aws_account_id === account.id && grant.iam_role === role.role_name) : []));
      setAccounts(a); setRoles(r); setGrants(eligible);
      const first=eligible[0], account=a.find(a=>a.id===first?.aws_account_id), role=r.find(r=>r.role_name===first?.iam_role);
      setForm({aws_account_id:account?.id||'', aws_account_name:account?.name||'', iam_role:role?.role_name||'', duration_minutes:Math.min(60,first?.max_duration_minutes||60,role?.max_duration_minutes||60), justification:'', ticket_ref:''});
      setReady(true);
    }).catch(e=>{if(alive){setError(e.message);setReady(true);}});
    return ()=>{alive=false;};
  }, [isOpen, currentUser?.id]);
  useEffect(() => {
    if (!isOpen || !form.aws_account_id || !form.iam_role) return;
    let alive=true; setPreview(null);
    const timer=setTimeout(()=>requestService.evaluate({...form, justification:form.justification.trim().length>=5?form.justification:'Policy preview', ticket_ref:form.ticket_ref||null})
      .then(p=>{if(alive){setPreview(p);setError('');}}).catch(e=>{if(alive)setError(e.message);}),400);
    return ()=>{alive=false;clearTimeout(timer);};
  }, [isOpen, form]);
  if (!isOpen) return null;
  const allowedAccounts=accounts.filter(a=>grants.some(g=>g.aws_account_id===a.id));
  const allowedRoles=roles.filter(r=>grants.some(g=>g.aws_account_id===form.aws_account_id&&g.iam_role===r.role_name));
  const selectedGrant=grants.find(g=>g.aws_account_id===form.aws_account_id&&g.iam_role===form.iam_role);
  const selectedRole=roles.find(r=>r.role_name===form.iam_role);
  const max=Math.min(selectedGrant?.max_duration_minutes||15,selectedRole?.max_duration_minutes||15);
  const change=(field,value)=>{setForm(f=>({...f,[field]:value}));setKey(crypto.randomUUID());};
  const submit=async e=>{e.preventDefault();setBusy(true);setError('');try{await requestService.createRequest({...form,ticket_ref:form.ticket_ref.trim()||null},key);onRequestCreated();onClose();}catch(e){setError(e.message);}finally{setBusy(false);}};
  return <div className="modal-overlay"><div className="modal-card" role="dialog" aria-modal="true" aria-labelledby="request-title">
    <h2 id="request-title">Request temporary access</h2>{error&&<div className="error-banner" role="alert">{error}</div>}
    {!ready?<p>Loading your access grants…</p>:!grants.length?<><p>No eligible access grants. Ask your administrator to grant an account and role.</p><button className="btn btn-secondary" onClick={onClose}>Close</button></>:<form onSubmit={submit}>
      <label className="form-label" htmlFor="target-account">Account</label>
      <select id="target-account" className="form-select" value={form.aws_account_id} onChange={e=>{const a=accounts.find(a=>a.id===e.target.value),g=grants.find(g=>g.aws_account_id===a.id),r=roles.find(r=>r.role_name===g.iam_role);setForm(f=>({...f,aws_account_id:a.id,aws_account_name:a.name,iam_role:g.iam_role,duration_minutes:Math.min(f.duration_minutes,g.max_duration_minutes,r.max_duration_minutes)}));setKey(crypto.randomUUID());}}>{allowedAccounts.map(a=><option key={a.id} value={a.id}>{a.name} ({a.id})</option>)}</select>
      <label className="form-label" htmlFor="target-role">Role</label>
      <select id="target-role" className="form-select" value={form.iam_role} onChange={e=>{const r=roles.find(r=>r.role_name===e.target.value),g=grants.find(g=>g.aws_account_id===form.aws_account_id&&g.iam_role===r.role_name);setForm(f=>({...f,iam_role:r.role_name,duration_minutes:Math.min(f.duration_minutes,r.max_duration_minutes,g.max_duration_minutes)}));setKey(crypto.randomUUID());}}>{allowedRoles.map(r=><option key={r.role_name}>{r.role_name}</option>)}</select>
      <label className="form-label">Duration · {form.duration_minutes} minutes (max {max})<input type="range" min="15" max={max} step="1" value={form.duration_minutes} onChange={e=>change('duration_minutes',Number(e.target.value))}/></label>
      <label className="form-label">Business justification<textarea className="form-control" required minLength={5} maxLength={2000} value={form.justification} onChange={e=>change('justification',e.target.value)}/></label>
      <label className="form-label">Ticket reference {preview?.requires_ticket?'(required)':'(optional)'}<input className="form-control" required={preview?.requires_ticket} placeholder="SEC-123 or INC123456" value={form.ticket_ref} onChange={e=>change('ticket_ref',e.target.value)}/></label>
      {preview&&<RiskScoreCard riskScore={preview.risk_score} riskLevel={preview.risk_level} autoApproved={preview.auto_approved} reasons={preview.reasons}/>}
      <div className="action-group"><button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Cancel</button><button className="btn btn-primary" disabled={busy||!preview}>{busy?'Submitting…':'Submit request'}</button></div>
    </form>}
  </div></div>;
}
