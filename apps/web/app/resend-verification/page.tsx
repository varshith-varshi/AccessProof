"use client";
import Brand from "@/components/Brand";
import Link from "next/link";
import { FormEvent, useState } from "react";
import { api } from "@/lib/api";

export default function ResendVerification() {
  const [email, setEmail] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault(); setError("");
    try { await api("/api/v1/auth/resend-verification", { method: "POST", body: JSON.stringify({ email }) }); setNotice("If the account needs verification, a new email has been sent."); }
    catch (err) { setError(err instanceof Error ? err.message : "We couldn't send the email right now."); }
  }
  return <div style={{maxWidth:440,margin:"10vh auto",padding:24}}><Brand/><h1>Resend verification</h1><p>Enter your account email and we’ll send a fresh verification link.</p><form onSubmit={submit} className="stack form"><div className="field"><label htmlFor="resend-email">Email</label><input id="resend-email" type="email" autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} required /></div><button className="btn primary">Send verification email</button></form>{notice&&<p className="section">{notice}</p>}{error&&<p className="error section">{error}</p>}<p className="section"><Link href="/login">Back to sign in</Link></p></div>;
}
