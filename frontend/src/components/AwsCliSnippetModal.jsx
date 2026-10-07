import React,{useState} from 'react';
import {sessionService} from '../services/api';
export function AwsCliSnippetModal({session,onClose}) {
 const [tab,setTab]=useState('bash'),[message,setMessage]=useState('');
 const values={AWS_ACCESS_KEY_ID:session.aws_access_key_id,AWS_SECRET_ACCESS_KEY:session.aws_secret_access_key,AWS_SESSION_TOKEN:session.aws_session_token,AWS_DEFAULT_REGION:session.aws_region};
 const code=Object.entries(values).map(([key,value])=>tab==='bash'?`export ${key}='${value.replaceAll("'", "'\\''")}'`:`$env:${key}='${value.replaceAll("'", "''")}'`).join('\n')+'\naws sts get-caller-identity';
 const copy=async()=>{try{await navigator.clipboard.writeText(code);setMessage('Copied.');}catch{setMessage('Clipboard unavailable. Select and copy the snippet manually.');}};
 const consoleUrl=async()=>{try{const {url}=await sessionService.console(session.id);window.location.assign(url);}catch(e){setMessage(e.message);}};
 return <div className="modal-overlay"><div className="modal-card" role="dialog" aria-modal="true"><h2>Temporary credentials</h2><p>{session.iam_role} · {session.aws_account_id}</p>{session.is_demo&&<div className="mode-banner">DEMO ONLY · These values cannot access AWS.</div>}<div className="action-group"><button className="btn btn-secondary" onClick={()=>setTab('bash')}>Bash</button><button className="btn btn-secondary" onClick={()=>setTab('powershell')}>PowerShell</button></div><pre className="code-block">{code}</pre><p role="status">{message}</p><div className="action-group"><button className="btn btn-secondary" onClick={copy}>Copy</button>{!session.is_demo&&<button className="btn btn-secondary" onClick={consoleUrl}>Open AWS console</button>}<button className="btn btn-primary" onClick={onClose}>Close and clear</button></div></div></div>;
}
