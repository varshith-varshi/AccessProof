"use client";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { api, Project, Source } from "../../lib/api";
import { formatTimestamp } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Sources() {
  const [rows,setRows]=useState<Source[]>([]), [projects,setProjects]=useState<Project[]>([]); const [loading,setLoading]=useState(true), [error,setError]=useState("");
  async function load(){setLoading(true);setError("");try{const p=await api<Project[]>("/api/v1/projects");setProjects(p);setRows(p[0]?await api<Source[]>(`/api/v1/sources?project_id=${encodeURIComponent(p[0].id)}`):[]);}catch(e){setError(e instanceof Error?e.message:"Unable to load permission sources.");}finally{setLoading(false)}}
  useEffect(()=>{queueMicrotask(()=>void load())},[]);
  return <ProtectedPage><PageHeader eyebrow="AUTHORITATIVE ACCESS" title="Permission sources" description="Connections that supply the authorization state AccessProof turns into enforceable policy." action={<button className="button compact" disabled={!projects.length}>Connect source</button>}/><section className="card table-card">{loading?<Skeleton rows={5}/>:error?<ErrorState message={error} retry={load}/>:rows.length===0?<EmptyState title="Connect your first permission source" description="Add an enterprise source of truth before creating enforceable policy." action={<button className="button compact" disabled={!projects.length}>Connect source</button>}/>:<table><thead><tr><th>Source</th><th>Provider</th><th>Status</th><th>Last validation</th><th>Health detail</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td><b>{row.name}</b><small>{row.id}</small></td><td>{row.provider}</td><td><StatusBadge value={row.status}/></td><td>{formatTimestamp(row.last_validated_at)}</td><td className="table-muted">{row.last_error??"No active error"}</td></tr>)}</tbody></table>}</section></ProtectedPage>
}
