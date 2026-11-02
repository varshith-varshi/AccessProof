"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity, Bot, Boxes, BriefcaseBusiness, Check, ChevronsUpDown, CircleStop, Fingerprint, LayoutDashboard,
  Link2, LockKeyhole, LogOut, Menu, Rocket, ScrollText, Settings2, ShieldCheck, Stethoscope, Users, X,
} from "lucide-react";
import { createContext, useContext, useEffect, useRef, useState } from "react";
import { api, clearActiveOrganization, setActiveOrganization } from "../lib/api";

export type Account = {
  user: { id: string; email: string; email_verified: boolean; mfa_enabled: boolean };
  active_organization_id: string;
  role: string;
  organizations: Array<{ id: string; name: string; role: string }>;
};

type ShellState = { account: Account | null; refreshAccount: () => Promise<void> };
const ShellContext = createContext<ShellState>({ account: null, refreshAccount: async () => {} });
export const useAccount = () => useContext(ShellContext);

type NavItem = readonly [label: string, href: string, icon: typeof Rocket];
const groups: ReadonlyArray<readonly [string, ReadonlyArray<NavItem>]> = [
  ["Monitor", [
    ["Overview", "/dashboard", LayoutDashboard],
    ["Protection", "/protection", LockKeyhole],
    ["Blocked requests", "/blocked-requests", CircleStop],
    ["Audit", "/audit", ScrollText],
  ]],
  ["Configure", [
    ["Permission sources", "/sources", BriefcaseBusiness],
    ["AI applications", "/applications", Bot],
    ["Guards", "/guards", ShieldCheck],
    ["Gateway setup", "/integrations", Boxes],
  ]],
  ["Directory", [
    ["Employees", "/employees", Users],
    ["Identity mappings", "/identity-mappings", Link2],
    ["Permission events", "/permission-events", Activity],
  ]],
  ["Reports", [
    ["Reports", "/reports", ScrollText],
    ["Diagnostics", "/diagnostics", Stethoscope],
  ]],
];

const roleLabel: Record<string, string> = {
  OWNER: "Owner", ADMIN: "Admin", ENGINEER: "Engineer", VIEWER: "Viewer", AUDITOR: "Auditor",
};

function initials(text: string) {
  const parts = text.replace(/@.*/, "").split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "A") + (parts[1]?.[0] ?? parts[0]?.[1] ?? "P")).toUpperCase();
}

function WorkspaceSwitcher({ account }: { account: Account | null }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => { if (!ref.current?.contains(event.target as Node)) setOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => { document.removeEventListener("mousedown", close); document.removeEventListener("keydown", escape); };
  }, [open]);
  const active = account?.organizations.find(org => org.id === account.active_organization_id);
  const name = active?.name ?? "Your workspace";
  const switchTo = (id: string) => {
    if (id === account?.active_organization_id) { setOpen(false); return; }
    setActiveOrganization(id);
    // Every page refetches under the new workspace. Pages remount on
    // navigation; when already on the dashboard, reload it in place.
    if (window.location.pathname === "/dashboard") window.location.reload();
    else router.push("/dashboard");
  };
  return <div className="workspace-switcher" ref={ref}>
    <button className="organization-switcher" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(value => !value)}>
      <span className="avatar">{initials(name)}</span>
      <span><b>{name}</b><small>{account ? `${roleLabel[account.role] ?? account.role} · workspace` : "Loading workspace…"}</small></span>
      <ChevronsUpDown size={14}/>
    </button>
    {open && <div className="workspace-menu" role="menu">
      <p>Switch workspace</p>
      {(account?.organizations ?? []).map(org => <button role="menuitem" key={org.id} onClick={() => switchTo(org.id)}>
        <span className="avatar small">{initials(org.name)}</span>
        <span><b>{org.name}</b><small>{roleLabel[org.role] ?? org.role}</small></span>
        {org.id === account?.active_organization_id && <Check size={14}/>}
      </button>)}
      <Link role="menuitem" href="/settings" onClick={() => setOpen(false)}><Settings2 size={14}/>Workspace settings</Link>
    </div>}
  </div>;
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [account, setAccount] = useState<Account | null>(null);
  const refreshAccount = async () => {
    try { setAccount(await api<Account>("/api/v1/auth/me")); } catch { /* shell stays usable without it */ }
  };
  useEffect(() => { queueMicrotask(() => void refreshAccount()); }, []);
  async function logout() {
    try { await api("/api/v1/auth/logout", { method: "POST" }); } finally { clearActiveOrganization(); router.replace("/login"); }
  }
  const navLink = ([label, href, Icon]: NavItem) => <Link
    className={pathname === href ? "active" : ""} aria-current={pathname === href ? "page" : undefined}
    href={href} key={href} onClick={() => setOpen(false)}><Icon size={16}/>{label}</Link>;
  return <ShellContext.Provider value={{ account, refreshAccount }}>
    <div className="app">
      <header className="mobile-topbar">
        <button className="mobile-menu" aria-label="Open navigation" onClick={() => setOpen(true)}><Menu size={20}/></button>
        <Link className="brand dark" href="/dashboard"><span className="brand-mark"><Fingerprint size={15}/></span>AccessProof</Link>
      </header>
      {open && <button className="nav-backdrop" aria-label="Close navigation" onClick={() => setOpen(false)}/>}
      <aside className={open ? "open" : ""}>
        <div className="sidebar-head">
          <Link className="brand" href="/dashboard"><span className="brand-mark"><Fingerprint size={16}/></span>AccessProof</Link>
          <button className="close-menu" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={18}/></button>
        </div>
        <WorkspaceSwitcher account={account}/>
        <nav aria-label="Primary navigation" className="nav-groups">
          <Link className={`get-started-link ${pathname === "/onboarding" ? "active" : ""}`} href="/onboarding" onClick={() => setOpen(false)}>
            <Rocket size={16}/>Get Started
          </Link>
          {groups.map(([group, items]) => <div className="nav-group" key={group}>
            <p className="workspace">{group}</p>
            {items.map(navLink)}
          </div>)}
        </nav>
        <div className="aside-bottom">
          <Link className={pathname === "/settings" ? "active" : ""} href="/settings" onClick={() => setOpen(false)}><Settings2 size={16}/>Settings</Link>
          <div className="account-row">
            <span className="avatar">{account ? initials(account.user.email) : "··"}</span>
            <span className="account-meta"><b title={account?.user.email}>{account?.user.email ?? "Signed in"}</b>
              <small>{account ? (account.user.mfa_enabled ? "Two-factor on" : "Two-factor off") : " "}</small></span>
            <button className="icon-button" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={15}/></button>
          </div>
        </div>
      </aside>
      <main className="content" id="main">{children}</main>
    </div>
  </ShellContext.Provider>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <header className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></div>{action}</header>;
}
