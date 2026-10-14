"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { api, clearSession } from "@/lib/api";
import Brand from "@/components/Brand";

const nav = [
  ["Overview","/overview"],["Projects","/projects"],["Sources","/sources"],["Test identities","/test-identities"],["AI Targets","/targets"],
  ["Test Suites","/suites"],["Runs","/runs"],["Releases","/releases"],["Reports","/reports"],
  ["Runners","/runners"],["Integrations","/integrations"],["Audit Log","/audit"],["Organization","/organization"],
  ["Billing","/billing"],["Settings","/settings"],
];
export default function Shell({children}:{children:React.ReactNode}) {
  const path=usePathname(); const router=useRouter();
  if(["/login","/signup","/register","/verify-email","/resend-verification","/forgot-password","/reset-password","/accept-invitation"].includes(path)) return <>{children}</>;
  return <div className="shell"><aside className="sidebar"><Brand/><nav className="nav">
    {nav.map(([label,href])=><Link key={href} href={href} style={path===href?{background:"var(--panel2)",color:"var(--text)"}:{}}>{label}</Link>)}
  </nav></aside><main className="main"><div className="topbar"><div className="muted">Enterprise AI permission regression testing</div><button className="btn" onClick={async()=>{try{await api("/api/v1/auth/logout",{method:"POST"})}finally{clearSession();router.push("/login")}}}>Sign out</button></div><div className="content">{children}</div></main></div>
}
