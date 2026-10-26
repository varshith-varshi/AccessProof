"use client";
import { useEffect,useState } from "react";
import { EmptyState,ErrorState,Skeleton,StatusBadge } from "../../components/ui";
import { api,PermissionEvent } from "../../lib/api";
import { shortId,titleCase } from "../../lib/format";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function PermissionEvents() {
  const [rows,setRows]=useState<PermissionEvent[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
  async function load(){setLoading(true);try{setRows(await api<PermissionEvent[]>("/api/v1/guard/permission-events"));setError("")}catch(e){setError(e instanceof Error?e.message:"Unable to load permission events.")}finally{setLoading(false)}}
  useEffect(()=>{queueMicrotask(()=>void load())},[]);
  return <ProtectedPage><PageHeader eyebrow="AUTHORIZATION PIPELINE" title="Permission events" description="Changes observed from permission sources and their current processing state."/><section className="card table-card">{loading?<Skeleton rows={6}/>:error?<ErrorState message={error} retry={load}/>:!rows.length?<EmptyState title="No permission events" description="Provider changes will appear after a source begins synchronization."/>:<table><thead><tr><th>Change</th><th>Subject</th><th>Resource</th><th>Source</th><th>Revision</th><th>Status</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td><b>{titleCase(row.change_type)}</b></td><td title={row.subject_id}>{shortId(row.subject_id)}</td><td title={row.resource_id}>{shortId(row.resource_id)}</td><td>{row.provider}</td><td className="number">{row.provider_revision}</td><td><StatusBadge value={row.status}/></td></tr>)}</tbody></table>}</section></ProtectedPage>
}
