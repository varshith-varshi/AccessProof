"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Activity, Bot, BriefcaseBusiness, ChevronDown, CircleStop, Fingerprint, LayoutDashboard, LockKeyhole, Menu, ScrollText, Settings2, ShieldCheck, Users, X, Boxes, Link2, Rocket } from "lucide-react";
import { useState } from "react";
import { api, clearActiveOrganization } from "../lib/api";

const items = [
  ["Get Started", "/onboarding", Rocket],
  ["Overview", "/dashboard", LayoutDashboard], ["Employees", "/employees", Users], ["Permission sources", "/sources", BriefcaseBusiness],
  ["Permission events", "/permission-events", Activity], ["Identity mappings", "/identity-mappings", Link2], ["AI applications", "/applications", Bot], ["Gateway setup", "/integrations", Boxes], ["Guards", "/guards", ShieldCheck],
  ["Protection", "/protection", LockKeyhole], ["Blocked requests", "/blocked-requests", CircleStop], ["Audit", "/audit", ScrollText],
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  async function logout() { try { await api("/api/v1/auth/logout", { method: "POST" }); } finally { clearActiveOrganization(); router.replace("/login"); } }
  return <div className="app"><button className="mobile-menu" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={20}/></button>{open && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setOpen(false)}/>}<aside className={open ? "open" : ""}><div className="sidebar-head"><Link className="brand" href="/dashboard"><span className="brand-mark"><Fingerprint size={16}/></span>AccessProof</Link><button className="close-menu" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={18}/></button></div><button className="organization-switcher"><span className="avatar">AP</span><span><b>AccessProof</b><small>Production workspace</small></span><ChevronDown size={14}/></button><p className="workspace">Control plane</p><nav aria-label="Primary navigation">{items.map(([label, href, Icon]) => <Link className={pathname === href ? "active" : ""} href={href} key={href} onClick={() => setOpen(false)}><Icon size={16}/>{label}</Link>)}</nav><p className="workspace diagnostic-label">Operations</p><nav><Link className={pathname === "/reports" ? "active" : ""} href="/reports"><ScrollText size={16}/>Reports</Link><Link className={pathname === "/diagnostics" ? "active" : ""} href="/diagnostics"><Activity size={16}/>Diagnostics</Link></nav><div className="aside-bottom"><Link href="/settings"><Settings2 size={16}/>Settings</Link><button className="account-button" onClick={logout}><span className="avatar">AP</span><span><b>Workspace admin</b><small>Sign out</small></span></button></div></aside><main className="content">{children}</main></div>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <header className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></div>{action}</header>;
}
