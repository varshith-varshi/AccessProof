"use client";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { AITarget, api, Project } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Applications() {
  const [rows,setRows]=useState<AITarget[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
  async function load(){setLoading(true);setError("");try{const projects=await api<Project[]>("/api/v1/projects");setRows(projects[0]?await api<AITarget[]>(`/api/v1/targets?project_id=${encodeURIComponent(projects[0].id)}`):[])}catch(e){setError(e instanceof Error?e.message:"Unable to load AI applications.")}finally{setLoading(false)}}
  useEffect(()=>{queueMicrotask(()=>void load())},[]);
  return <ProtectedPage><PageHeader eyebrow="AI SURFACES" title="AI applications" description="RAG and AI systems that AccessProof evaluates and protects." action={<button className="button compact">Add application</button>}/><section className="card table-card">{loading?<Skeleton rows={5}/>:error?<ErrorState message={error} retry={load}/>:!rows.length?<EmptyState title="Add your first AI application" description="Register an application, bind it to a Guard, then begin in Shadow mode." action={<button className="button compact">Add application</button>}/>:<table><thead><tr><th>Application</th><th>Connection</th><th>Execution</th><th>Authentication</th><th>Protect readiness</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td><b>{row.name}</b><small>{row.id}</small></td><td className="table-muted">{new URL(row.url).host}</td><td>{row.runner_mode?"Private network":"Direct"}</td><td><StatusBadge value={row.auth_configured?"Configured":"Unknown"}/></td><td><StatusBadge value="Not available"/></td></tr>)}</tbody></table>}</section></ProtectedPage>
}
