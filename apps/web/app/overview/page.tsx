"use client";
import {useEffect,useState} from "react";
import {api} from "@/lib/api";

type Dashboard={
  projects:number;
  latest_release_status:string|null;
  outcomes:Record<string,number>;
  slo_failures:number;
  median_revocation_latency_seconds:number|null;
  p95_revocation_latency_seconds:number|null;
  worst_source:{name:string;average_seconds:number}|null;
  worst_scenario:{name:string;average_seconds:number}|null;
  runner_health:{online:number;offline:number;total:number};
  broken_connections:number;
  recent_runs:{id:string;release:string;outcome:string|null;state:string;created_at:string;stable_propagation_latency_seconds:number|null}[];
};
function sec(v:number|null){return v==null?"—":`${v.toFixed(1)}s`}
function cls(v:string|null){return v==="PASS"?"pass":v==="FAIL"||v==="ERROR"?"fail":"warn"}
export default function Overview(){
  const [data,setData]=useState<Dashboard|null>(null);const [error,setError]=useState("");
  useEffect(()=>{api<Dashboard>("/api/v1/dashboard").then(setData).catch(e=>setError(e.message))},[]);
  return <><h1>Overview</h1><p>Measured permission behavior, not configuration assumptions.</p>
  <div className="grid">
    <div className="card"><div className="label">Latest release status</div><div className={`metric ${cls(data?.latest_release_status||null)}`}>{data?.latest_release_status||"—"}</div></div>
    <div className="card"><div className="label">SLO failures</div><div className={`metric ${data?.slo_failures?"fail":""}`}>{data?.slo_failures??"—"}</div></div>
    <div className="card"><div className="label">Median revocation latency</div><div className="metric">{sec(data?.median_revocation_latency_seconds??null)}</div></div>
    <div className="card"><div className="label">P95 revocation latency</div><div className="metric">{sec(data?.p95_revocation_latency_seconds??null)}</div></div>
  </div>
  <div className="grid">
    <div className="card"><div className="label">Projects</div><div className="metric">{data?.projects??"—"}</div></div>
    <div className="card"><div className="label">Runner health</div><div className="metric">{data?`${data.runner_health.online}/${data.runner_health.total}`:"—"}</div><small className="muted">{data?.runner_health.offline??0} offline</small></div>
    <div className="card"><div className="label">Worst source</div><div className="metric metric-small">{data?.worst_source?.name||"—"}</div><small className="muted">{data?.worst_source?`${data.worst_source.average_seconds.toFixed(1)}s avg`:"No measured data"}</small></div>
    <div className="card"><div className="label">Broken connections</div><div className={`metric ${data?.broken_connections?"fail":""}`}>{data?.broken_connections??"—"}</div></div>
  </div>
  <section className="section card"><div className="row between"><div><div className="label">Recent measured runs</div><h2>Permission propagation history</h2></div><span className="badge">{data?.recent_runs.length??0} runs</span></div>
    {data?.recent_runs.length?<div className="table-wrap"><table className="table"><thead><tr><th>Release</th><th>Result</th><th>Stable denial</th><th>Started</th></tr></thead><tbody>{data.recent_runs.map(r=><tr key={r.id}><td>{r.release}</td><td className={cls(r.outcome)}>{r.outcome||r.state}</td><td>{sec(r.stable_propagation_latency_seconds)}</td><td>{new Date(r.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>:<div className="empty">No measured runs yet. No release status or latency data is fabricated.</div>}
  </section>
  <section className="section card"><div className="label">Measured reality</div><p>Source denial confirmed → repeated AI probes → stable denial → SLO comparison. A run is never marked PASS merely because a permission-change API call succeeded.</p></section>
  {error&&<p className="error">{error}</p>}</>;
}
