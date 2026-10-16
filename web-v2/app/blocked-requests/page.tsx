"use client";

import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

type Decision = { id:string; application_id:string; subject_id:string; layer:string; result:string; reason:string; policy_version:number; created_at:string };

export default function BlockedRequests(){
  const [rows,setRows]=useState<Decision[]>([]); const [error,setError]=useState("");
  useEffect(()=>{api<Decision[]>("/api/v1/current/protection-decisions").then(setRows).catch(error=>setError(error.message));},[]);
  const blocked=rows.filter(row=>row.result==="block"||row.result==="would_block");
  return <ProtectedPage><PageHeader eyebrow="ENFORCEMENT EVIDENCE" title="Blocked requests" description="Actual Guard decisions. Only metadata is retained: no prompts, document contents, answers, or tokens."/>{error&&<p className="error">{error}</p>}<section className="card section"><div className="section-head"><h2>Protect blocks and Shadow would-blocks</h2><span className="badge">{blocked.length}</span></div>{!blocked.length?<p className="muted">No blocked Guard decisions have been recorded yet.</p>:<div className="table-wrap"><table className="table"><thead><tr><th>Time</th><th>Layer</th><th>Decision</th><th>Application</th><th>Subject</th><th>Reason</th><th>Policy</th></tr></thead><tbody>{blocked.map(row=><tr key={row.id}><td>{new Date(row.created_at).toLocaleString()}</td><td>{row.layer}</td><td><span className="badge">{row.result}</span></td><td>{row.application_id}</td><td className="code">{row.subject_id}</td><td>{row.reason}</td><td>v{row.policy_version}</td></tr>)}</tbody></table></div>}</section></ProtectedPage>
}
