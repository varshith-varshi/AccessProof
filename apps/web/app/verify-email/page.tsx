"use client";
import {useSearchParams} from "next/navigation";
import Brand from "@/components/Brand";
import Link from "next/link";import {Suspense,useEffect,useState} from "react";import {api} from "@/lib/api";
function VerifyEmailContent(){const params=useSearchParams();const token=params.get("token");const pending=params.get("pending");const email=params.get("email")||"";const [status,setStatus]=useState(token?"Verifying email…":"Check your email");const [error,setError]=useState("");useEffect(()=>{if(!token)return;api("/api/v1/auth/verify-email",{method:"POST",body:JSON.stringify({token})}).then(()=>setStatus("Email verified successfully.")).catch(e=>setError(e.message));},[token]);return <div style={{maxWidth:520,margin:"10vh auto",padding:24}}><Brand/><h1>{token?"Email verification":"Check your email"}</h1>{error?<div className="error">{error}</div>:<div className="card section">{status}{pending&&<p>We sent a verification link to {email}.</p>}</div>}{!token&&<p className="section"><Link href={`/resend-verification?email=${encodeURIComponent(email)}`}>Resend verification email</Link></p>}<p className="section"><Link href="/login">Continue to sign in</Link></p></div>}

export default function VerifyEmail(){return <Suspense fallback={<p>Loading…</p>}><VerifyEmailContent/></Suspense>;}
