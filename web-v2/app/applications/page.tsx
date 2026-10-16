"use client";

import { useCallback, useEffect, useState } from "react";
import { EmptyState, ErrorState, Skeleton, StatusBadge } from "../../components/ui";
import { CurrentDashboard, api } from "../../lib/api";
import { PageHeader } from "../app-shell";
import { ProtectedPage } from "../protected-page";

export default function Applications() {
  const [rows, setRows] = useState<Array<{ id: string; blocked: number; latest: string | null }>>([]), [loading, setLoading] = useState(true), [error, setError] = useState("");
  const load = useCallback(async () => { setLoading(true); setError(""); try { const dashboard = await api<CurrentDashboard>("/api/v1/current/dashboard"); const observed = new Map<string, { id: string; blocked: number; latest: string | null }>(); for (const item of dashboard.recent_activity) { if (!item.application_id) continue; const row = observed.get(item.application_id) ?? { id: item.application_id, blocked: 0, latest: item.timestamp }; row.blocked += item.type.includes("BLOCK") ? 1 : 0; if (!row.latest || item.timestamp > row.latest) row.latest = item.timestamp; observed.set(item.application_id, row); } setRows([...observed.values()].sort((left, right) => (right.latest ?? "").localeCompare(left.latest ?? ""))); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to load AI applications."); } finally { setLoading(false); } }, []);
  useEffect(() => { queueMicrotask(() => void load()); }, [load]);
  return <ProtectedPage><PageHeader eyebrow="AI SURFACES" title="AI applications" description="Applications appear automatically after a Guard records an authorization decision."/><section className="card table-card">{loading ? <Skeleton rows={5}/> : error ? <ErrorState message={error} retry={load}/> : !rows.length ? <EmptyState title="No AI applications observed" description="Enroll a Guard and route an AI application's authorization check through it. The application will appear here after its first decision."/> : <table><thead><tr><th>Application</th><th>Protection activity</th><th>Latest decision</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><b>{row.id}</b><small>Observed by Guard</small></td><td><StatusBadge value={row.blocked ? `${row.blocked} blocked` : "Observed"}/></td><td className="table-muted">{row.latest ? new Date(row.latest).toLocaleString() : "Not available"}</td></tr>)}</tbody></table>}</section></ProtectedPage>
}
