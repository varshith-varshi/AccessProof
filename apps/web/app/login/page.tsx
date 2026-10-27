"use client";
import Brand from "@/components/Brand";
import Link from "next/link";
import {FormEvent,useState} from "react";
import {useRouter} from "next/navigation";
import {api,saveSession} from "@/lib/api";

export default function Login(){
  const router=useRouter();
  const [nextPath]=useState(()=>typeof window!=="undefined"?new URLSearchParams(window.location.search).get("next")||"":"");
  const [email,setEmail]=useState("");
  const [password,setPassword]=useState("");
  const [organizationId,setOrganizationId]=useState("");
  const [error,setError]=useState(()=>typeof window!=="undefined"&&new URLSearchParams(window.location.search).get("reason")==="expired"?"Your session expired. Please sign in again.":"");
  async function submit(e:FormEvent){
    e.preventDefault();setError("");
    try{
      const r=await api<{organizations:{id:string}[]}>('/api/v1/auth/login',{method:'POST',body:JSON.stringify({email,password,organization_id:organizationId||undefined})});
      if(!r.organizations.length)throw new Error('No organization membership');
      const selected=organizationId||r.organizations[0].id;
      saveSession({organizationId:selected});router.push(nextPath&&nextPath.startsWith("/")&&!nextPath.startsWith("//")?nextPath:'/overview');
    }catch(err){setError(err instanceof Error?err.message:'Login failed')}
  }
  return <div style={{maxWidth:430,margin:"10vh auto",padding:24}}><Brand/><h1>Sign in</h1><p>Real-time authorization enforcement for enterprise AI.</p><form onSubmit={submit} className="stack form"><div className="field"><label htmlFor="login-field-1">Organization ID <span className="muted">(needed when you belong to multiple organizations)</span></label><input id="login-field-1" value={organizationId} onChange={e=>setOrganizationId(e.target.value)} placeholder="Optional organization ID"/></div><div className="field"><label htmlFor="login-field-2">Email</label><input id="login-field-2" type="email" autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} required/></div><div className="field"><label htmlFor="login-field-3">Password</label><input id="login-field-3" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required/></div>{error&&<div className="error">{error}</div>}<button className="btn primary">Sign in with password</button></form><div className="row between section"><Link href="/forgot-password">Forgot password?</Link><Link href="/register">Create account</Link></div></div>
}
