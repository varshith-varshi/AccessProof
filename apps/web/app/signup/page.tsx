"use client";
import Brand from "@/components/Brand";
import Link from "next/link";
import {FormEvent,useState} from "react";
import {useRouter} from "next/navigation";
import {api,saveSession} from "@/lib/api";

type SignupResult={organization_id:string;email_verification_required:boolean;development_verification_token?:string;session_token?:string};
export default function Signup(){
  const router=useRouter();
  const [organizationName,setOrganizationName]=useState("");const [email,setEmail]=useState("");const [password,setPassword]=useState("");const [confirm,setConfirm]=useState("");
  const [error,setError]=useState("");const [busy,setBusy]=useState(false);const [devToken,setDevToken]=useState("");
  async function submit(e:FormEvent){e.preventDefault();setError("");if(password!==confirm){setError("Passwords do not match.");return;}setBusy(true);try{
    const r=await api<SignupResult>("/api/v1/auth/signup",{method:"POST",body:JSON.stringify({email,password,organization_name:organizationName||undefined})});
    if(r.session_token) saveSession({organizationId:r.organization_id});
    setDevToken(r.development_verification_token||"");
    if(!r.development_verification_token)router.push(`/verify-email?pending=1&email=${encodeURIComponent(email)}`);
  }catch(e){setError(e instanceof Error?e.message:"Unable to create account")}finally{setBusy(false)}}
  return <div style={{maxWidth:460,margin:"8vh auto",padding:24}}><Brand/><h1>Create account</h1><p>Use your work email to create an AccessProof workspace.</p>
    <form className="stack form" onSubmit={submit}><div className="field"><label htmlFor="signup-org">Organization name</label><input id="signup-org" value={organizationName} onChange={e=>setOrganizationName(e.target.value)} autoComplete="organization" placeholder="Your company"/></div><div className="field"><label htmlFor="signup-field-1">Email</label><input id="signup-field-1" type="email" autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} required/></div><div className="field"><label htmlFor="signup-field-2">Password</label><input id="signup-field-2" type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} minLength={12} required/><small className="muted">Use at least 12 characters.</small></div><div className="field"><label htmlFor="signup-field-3">Confirm</label><input id="signup-field-3" type="password" autoComplete="new-password" value={confirm} onChange={e=>setConfirm(e.target.value)} minLength={12} required/></div>{error&&<div className="error">{error}</div>}<button disabled={busy} className="btn primary">{busy?"Creating account…":"Create organization"}</button></form>
    {devToken&&<div className="card section"><div className="label">Development verification token</div><div className="code">{devToken}</div><button className="btn section" onClick={()=>router.push(`/verify-email?token=${encodeURIComponent(devToken)}`)}>Verify development account</button></div>}
    <p className="section muted">Already have an account? <Link href="/login">Sign in</Link></p></div>;
}
