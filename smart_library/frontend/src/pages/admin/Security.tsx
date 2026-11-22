import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clsx } from "clsx";
import { ChevronDown, Lock, RefreshCw, ShieldCheck, ShieldX, Trash2, UserPlus, Plus, X } from "lucide-react";
import { Fragment, useState } from "react";
import { Badge, Button, Card, ConfirmDialog, EmptyState, ErrorMessage, Notice, PageHeader, Pagination, SectionTitle, Skeleton, StatusBadge, useToast } from "../../components/ui";
import { api, friendlyError, type AuditEntry, type GuardStatus } from "../../lib/api";
import { fmtDateTime, humanize } from "../../lib/format";

interface AuditPage {
  items: AuditEntry[];
  total: number;
  page: number;
  pages: number;
  actions: string[];
}

const ACTION_LABEL: Record<string, string> = {
  layer1_filter: "Search filter (Layer 1)",
  layer2_checkout: "Checkout check (Layer 2)",
  layer2_reserve: "Reserve check (Layer 2)",
  layer2_renew: "Renew check (Layer 2)",
  layer2_read_digital: "E-book check (Layer 2)",
  policy_sync: "Policy sync",
  authenticate: "Authentication",
  borrow: "Borrow",
  return: "Return",
  reserve: "Reservation",
  renew: "Renewal",
  cancel_reservation: "Reservation cancelled",
  demo_data: "Demo data",
};

function toTs(date: string, end = false) {
  if (!date) return undefined;
  const d = new Date(`${date}T${end ? "23:59:59" : "00:00:00"}`);
  return Math.floor(d.getTime() / 1000);
}

export function AdminAudit() {
  const [member, setMember] = useState("");
  const [action, setAction] = useState("");
  const [decision, setDecision] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<number | null>(null);
  const members = useQuery({ queryKey: ["admin", "members", ""], queryFn: () => api<{ id: string; name: string }[]>("/admin/members") });
  const qs = new URLSearchParams({ page: String(page), page_size: "20" });
  if (member) qs.set("member", member);
  if (action) qs.set("action", action);
  if (decision) qs.set("decision", decision);
  const since = toTs(from);
  const until = toTs(to, true);
  if (since) qs.set("since", String(since));
  if (until) qs.set("until", String(until));
  const audit = useQuery({ queryKey: ["admin", "audit", qs.toString()], queryFn: () => api<AuditPage>(`/admin/audit/search?${qs}`), placeholderData: keepPreviousData });
  const reset = (fn: () => void) => {
    fn();
    setPage(1);
  };
  const filtered = member || action || decision || from || to;

  return (
    <>
      <PageHeader eyebrow="Security" title="Audit log" subtitle="Every allow and deny decision, with its reason and policy revision. The log is append-only: the database rejects updates and deletes." />
      <Card className="mb-4 grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-5">
        <div>
          <label className="label" htmlFor="a-member">Member</label>
          <select id="a-member" className="input" value={member} onChange={(e) => reset(() => setMember(e.target.value))}>
            <option value="">All members</option>
            {members.data?.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-action">Action</label>
          <select id="a-action" className="input" value={action} onChange={(e) => reset(() => setAction(e.target.value))}>
            <option value="">All actions</option>
            {audit.data?.actions.map((a) => <option key={a} value={a}>{ACTION_LABEL[a] ?? humanize(a)}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-decision">Decision</label>
          <select id="a-decision" className="input" value={decision} onChange={(e) => reset(() => setDecision(e.target.value))}>
            <option value="">All decisions</option>
            <option value="allow">Allowed</option>
            <option value="deny">Denied</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-from">From</label>
          <input id="a-from" type="date" className="input" value={from} onChange={(e) => reset(() => setFrom(e.target.value))} />
        </div>
        <div>
          <label className="label" htmlFor="a-to">To</label>
          <input id="a-to" type="date" className="input" value={to} onChange={(e) => reset(() => setTo(e.target.value))} />
        </div>
      </Card>
      <div className="mb-3 flex items-center justify-between">
        <p className="text-sm text-ink-500">{audit.data ? `${audit.data.total} events` : "Loading…"}</p>
        {filtered && <Button size="sm" variant="ghost" icon={X} onClick={() => reset(() => { setMember(""); setAction(""); setDecision(""); setFrom(""); setTo(""); })}>Clear filters</Button>}
      </div>
      {audit.isError && <ErrorMessage error={audit.error} />}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="border-b border-ink-100 bg-ink-50/70">
              <tr>
                {["Timestamp", "Member", "Action", "Resource", "Decision", "Reason", ""].map((h) => (
                  <th key={h} scope="col" className="px-4 py-3 text-xs font-semibold tracking-wide text-ink-500 uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-100">
              {audit.isLoading && Array.from({ length: 8 }).map((_, i) => <tr key={i}><td colSpan={7} className="px-4 py-3"><Skeleton className="h-4" /></td></tr>)}
              {audit.data?.items.map((e) => (
                <Fragment key={e.id}>
                  <tr className={clsx("cursor-pointer transition-colors hover:bg-royal-50/40", e.decision === "deny" && "bg-rose-50/30")} onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <td className="px-4 py-3 whitespace-nowrap text-ink-600 tabular-nums">{fmtDateTime(e.at)}</td>
                    <td className="px-4 py-3 font-medium text-ink-900">{e.member_name ?? <span className="text-ink-400">system</span>}</td>
                    <td className="px-4 py-3 text-ink-700">{ACTION_LABEL[e.action] ?? humanize(e.action)}</td>
                    <td className="px-4 py-3"><code className="text-xs text-ink-600">{e.resource ?? "—"}</code></td>
                    <td className="px-4 py-3"><StatusBadge status={e.decision} /></td>
                    <td className="max-w-[260px] truncate px-4 py-3 text-ink-600">{e.reason}</td>
                    <td className="px-4 py-3 text-right">
                      <button aria-label="Show event details" aria-expanded={open === e.id} className="rounded p-1 text-ink-400 hover:text-ink-700">
                        <ChevronDown className={clsx("size-4 transition", open === e.id && "rotate-180")} />
                      </button>
                    </td>
                  </tr>
                  {open === e.id && (
                    <tr className="bg-ink-50/60">
                      <td colSpan={7} className="px-4 py-4">
                        <dl className="grid gap-3 text-xs sm:grid-cols-4">
                          <div><dt className="text-ink-500">Event ID</dt><dd className="font-mono text-ink-900">#{e.id}</dd></div>
                          <div><dt className="text-ink-500">Member ID</dt><dd className="font-mono text-ink-900">{e.member_id ?? "—"}</dd></div>
                          <div><dt className="text-ink-500">Raw action</dt><dd className="font-mono text-ink-900">{e.action}</dd></div>
                          <div><dt className="text-ink-500">Policy revision</dt><dd className="font-mono text-ink-900">{e.policy_revision ?? "—"}</dd></div>
                          <div className="sm:col-span-4"><dt className="text-ink-500">Reason</dt><dd className="text-ink-900">{e.reason}</dd></div>
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        {audit.data?.items.length === 0 && <div className="p-6"><EmptyState icon={ShieldCheck} title="No events match these filters" /></div>}
      </Card>
      {audit.data && <div className="mt-6"><Pagination page={audit.data.page} pages={audit.data.pages} onChange={setPage} /></div>}
    </>
  );
}

// --- Access policy & settings ---------------------------------------------------------------
interface AccessData {
  collections: { id: string; name: string; description: string; grants: { principal_type: string; principal_id: string }[]; books: number }[];
  groups: { id: string; name: string; members: string[] }[];
  revisions: { revision: number; created_at: number; reason: string }[];
  guard: GuardStatus;
}

export function AdminSettings() {
  const qc = useQueryClient();
  const toast = useToast();
  const access = useQuery({ queryKey: ["admin", "access"], queryFn: () => api<AccessData>("/admin/access") });
  const config = useQuery({ queryKey: ["auth-config"], queryFn: () => api<{ loan_days: number; max_active_loans: number; fine_per_day: number; token_ttl_seconds: number; demo_login: boolean }>("/auth/config") });
  const members = useQuery({ queryKey: ["admin", "members", ""], queryFn: () => api<{ id: string; name: string }[]>("/admin/members") });
  const [confirm, setConfirm] = useState<{ title: string; run: () => Promise<unknown> } | null>(null);
  const [grantFor, setGrantFor] = useState<string | null>(null);
  const [grantValue, setGrantValue] = useState("");
  const [memberFor, setMemberFor] = useState<string | null>(null);
  const [memberValue, setMemberValue] = useState("");

  const policy = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: (r) => {
      const rev = (r as { policy_revision?: number; installed_revision?: number })?.policy_revision ?? (r as { installed_revision?: number })?.installed_revision;
      toast("success", "Policy updated", rev ? `Revision ${rev} pushed to the access guard.` : undefined);
      qc.invalidateQueries();
    },
    onError: (e) => toast("error", "Policy change failed", friendlyError(e)),
    onSettled: () => setConfirm(null),
  });
  const name = (id: string) => members.data?.find((m) => m.id === id)?.name ?? id;
  const g = access.data?.guard;

  return (
    <>
      <PageHeader eyebrow="Settings" title="Access & settings" subtitle="Collection grants and group memberships decide who can see and borrow what. Every change creates a new policy revision and takes effect immediately." />
      {access.isError && <ErrorMessage error={access.error} />}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-1">
          <SectionTitle title="Access guard" />
          {g ? (
            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                {g.ready ? <ShieldCheck className="size-5 text-emerald-600" /> : <ShieldX className="size-5 text-rose-600" />}
                <span className="font-semibold">{g.ready ? "Ready — deciding requests" : `Not ready: ${g.not_ready_reason}`}</span>
              </div>
              <dl className="grid grid-cols-2 gap-2 text-xs">
                <dt className="text-ink-500">Installed revision</dt><dd className="font-mono">{g.installed_revision}</dd>
                <dt className="text-ink-500">Authoritative revision</dt><dd className="font-mono">{g.authoritative_revision}</dd>
                <dt className="text-ink-500">Policy age</dt><dd className="font-mono">{g.policy_age_seconds !== null ? `${Math.round(g.policy_age_seconds)} s` : "—"}</dd>
                <dt className="text-ink-500">Max staleness</dt><dd className="font-mono">{g.max_staleness_seconds} s (fail closed)</dd>
              </dl>
              <Button size="sm" variant="secondary" icon={RefreshCw} loading={policy.isPending} onClick={() => policy.mutate(() => api("/admin/guard/sync", { method: "POST" }))}>Sync policy now</Button>
            </div>
          ) : <Skeleton className="h-32" />}
        </Card>
        <Card className="p-5">
          <SectionTitle title="Lending rules" />
          {config.data && (
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between"><dt className="text-ink-500">Loan period</dt><dd className="font-semibold">{config.data.loan_days} days</dd></div>
              <div className="flex justify-between"><dt className="text-ink-500">Max active loans</dt><dd className="font-semibold">{config.data.max_active_loans}</dd></div>
              <div className="flex justify-between"><dt className="text-ink-500">Late fine</dt><dd className="font-semibold">${config.data.fine_per_day.toFixed(2)} / day</dd></div>
              <div className="flex justify-between"><dt className="text-ink-500">Session lifetime</dt><dd className="font-semibold">{Math.round(config.data.token_ttl_seconds / 60)} min</dd></div>
              <div className="flex justify-between"><dt className="text-ink-500">Demo sign-in</dt><dd><Badge tone={config.data.demo_login ? "amber" : "green"}>{config.data.demo_login ? "Enabled" : "Disabled"}</Badge></dd></div>
            </dl>
          )}
          <p className="mt-4 text-xs text-ink-400">Configured with SLMS_* environment variables on the server.</p>
        </Card>
        <Card className="p-5">
          <SectionTitle title="Recent policy revisions" />
          <ol className="space-y-2 text-sm">
            {access.data?.revisions.map((r) => (
              <li key={r.revision} className="flex gap-3">
                <span className="font-mono text-xs text-royal-600">r{r.revision}</span>
                <span className="min-w-0 flex-1 truncate text-ink-700" title={r.reason}>{r.reason}</span>
              </li>
            ))}
          </ol>
        </Card>
      </div>

      <div className="mt-6">
        <Notice icon={Lock} title="Try the revocation demo">
          Sign in as Alice in another browser and search “Forecast”. Then remove Alice from the <strong>finance</strong> group below. Alice's next borrow or read is refused (Layer 2), and the title disappears from her search (Layer 1).
        </Notice>
      </div>

      <section className="mt-8">
        <SectionTitle title="Collections & grants" subtitle="Who may use each collection. A grant can target a group or a single member." />
        <div className="grid gap-4 md:grid-cols-2">
          {access.data?.collections.map((c) => (
            <Card key={c.id} className="p-5">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-ink-950">{c.name}</h3>
                  <p className="text-xs text-ink-500">{c.description} · {c.books} titles</p>
                </div>
                <Button size="sm" variant="soft" icon={Plus} onClick={() => { setGrantFor(c.id); setGrantValue(""); }}>Grant</Button>
              </div>
              <ul className="mt-4 flex flex-wrap gap-2">
                {c.grants.map((gr) => (
                  <li key={gr.principal_type + gr.principal_id} className="inline-flex items-center gap-1.5 rounded-full bg-ink-100 py-1 pr-1 pl-3 text-xs font-medium text-ink-700">
                    {gr.principal_type === "group" ? `group: ${gr.principal_id}` : `member: ${name(gr.principal_id)}`}
                    <button
                      className="rounded-full p-1 text-ink-400 hover:bg-rose-100 hover:text-rose-600"
                      aria-label={`Revoke ${gr.principal_id} from ${c.name}`}
                      onClick={() => setConfirm({ title: `Revoke ${gr.principal_type} “${gr.principal_id}” from ${c.name}?`, run: () => api("/admin/grants", { method: "DELETE", json: { collection_id: c.id, ...gr } }) })}
                    >
                      <Trash2 className="size-3" />
                    </button>
                  </li>
                ))}
                {c.grants.length === 0 && <li className="text-xs text-ink-400">No grants — nobody can see this collection.</li>}
              </ul>
              {grantFor === c.id && (
                <form className="mt-4 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (!grantValue) return; const [principal_type, principal_id] = grantValue.split(":"); policy.mutate(() => api("/admin/grants", { method: "POST", json: { collection_id: c.id, principal_type, principal_id } })); setGrantFor(null); }}>
                  <select className="input" value={grantValue} onChange={(e) => setGrantValue(e.target.value)} aria-label="Grant to">
                    <option value="">Choose group or member…</option>
                    <optgroup label="Groups">{access.data?.groups.map((gr) => <option key={gr.id} value={`group:${gr.id}`}>{gr.name}</option>)}</optgroup>
                    <optgroup label="Members">{members.data?.map((m) => <option key={m.id} value={`member:${m.id}`}>{m.name}</option>)}</optgroup>
                  </select>
                  <Button type="submit" size="md">Add</Button>
                  <Button type="button" variant="ghost" onClick={() => setGrantFor(null)}>Cancel</Button>
                </form>
              )}
            </Card>
          ))}
        </div>
      </section>

      <section className="mt-8">
        <SectionTitle title="Groups & memberships" subtitle="Members inherit every grant given to their groups." />
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {access.data?.groups.map((gr) => (
            <Card key={gr.id} className="p-5">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-ink-950">{gr.name}</h3>
                  <p className="font-mono text-xs text-ink-400">{gr.id}</p>
                </div>
                {gr.id !== "everyone" && <Button size="sm" variant="ghost" icon={UserPlus} onClick={() => { setMemberFor(gr.id); setMemberValue(""); }} aria-label={`Add member to ${gr.name}`} />}
              </div>
              <ul className="mt-3 flex flex-wrap gap-2">
                {gr.id === "everyone" && <li className="text-xs text-ink-500">Every active member, implicitly.</li>}
                {gr.members.map((m) => (
                  <li key={m} className="inline-flex items-center gap-1.5 rounded-full bg-royal-50 py-1 pr-1 pl-3 text-xs font-medium text-royal-700">
                    {name(m)}
                    <button
                      className="rounded-full p-1 text-royal-400 hover:bg-rose-100 hover:text-rose-600"
                      aria-label={`Remove ${name(m)} from ${gr.name}`}
                      onClick={() => setConfirm({ title: `Remove ${name(m)} from ${gr.name}?`, run: () => api("/admin/memberships", { method: "DELETE", json: { member_id: m, group_id: gr.id } }) })}
                    >
                      <X className="size-3" />
                    </button>
                  </li>
                ))}
              </ul>
              {memberFor === gr.id && (
                <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); if (!memberValue) return; policy.mutate(() => api("/admin/memberships", { method: "POST", json: { member_id: memberValue, group_id: gr.id } })); setMemberFor(null); }}>
                  <select className="input" value={memberValue} onChange={(e) => setMemberValue(e.target.value)} aria-label="Member to add">
                    <option value="">Choose member…</option>
                    {members.data?.filter((m) => !gr.members.includes(m.id)).map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
                  </select>
                  <Button type="submit">Add</Button>
                </form>
              )}
            </Card>
          ))}
        </div>
      </section>

      <ConfirmDialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        danger
        title="Confirm access change"
        confirmLabel="Apply change"
        loading={policy.isPending}
        onConfirm={() => confirm && policy.mutate(confirm.run)}
        message={<><p className="font-medium text-ink-900">{confirm?.title}</p><p className="mt-2">A new policy revision is created and pushed to the guard immediately. Requests that depend on this access are refused from now on — even for items already on screen.</p></>}
      />
    </>
  );
}
