"use client";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton } from "../../components/ui";
import { api, AuditEvent } from "../../lib/api";
import { formatTimestamp, shortId, titleCase } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Audit() {
  const [rows,setRows]=useState<AuditEvent[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
  async function load(){setLoading(true);setError("");try{setRows(await api<AuditEvent[]>("/api/v1/audit"))}catch(e){setError(e instanceof Error?e.message:"Unable to load audit events.")}finally{setLoading(false)}}
  useEffect(()=>{queueMicrotask(()=>void load())},[]);
  return <ProtectedPage><PageHeader eyebrow="EVIDENCE" title="Audit" description="Tenant-scoped security and administration activity, ordered by exact event time."/><section className="filter-bar"><input aria-label="Search audit events" placeholder="Search events"/><button className="button secondary compact">Export unavailable</button></section><section className="card table-card">{loading?<Skeleton rows={6}/>:error?<ErrorState message={error} retry={load}/>:!rows.length?<EmptyState title="No audit events" description="Security-sensitive control-plane actions will appear here."/>:<table><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Actor</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{formatTimestamp(row.created_at)}</td><td><b>{titleCase(row.action)}</b></td><td>{titleCase(row.target_type)} <small title={row.target_id}>{shortId(row.target_id)}</small></td><td>{row.actor?shortId(row.actor):"System"}</td></tr>)}</tbody></table>}</section></ProtectedPage>
}
