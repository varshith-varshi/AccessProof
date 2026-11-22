import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BookCopy,
  BookMarked,
  CalendarClock,
  CircleDollarSign,
  CreditCard,
  Pencil,
  Plus,
  Search,
  UserCheck,
  UserX,
  Users,
  XCircle,
  Library,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { BookCover, useDebounced } from "../../components/books";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  DataTable,
  EmptyState,
  ErrorMessage,
  Modal,
  Notice,
  PageHeader,
  Pagination,
  SectionTitle,
  Segmented,
  StatCard,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { api, friendlyError, type Book, type Loan, type Page, type Reservation } from "../../lib/api";
import { useCancelReservation } from "../../lib/actions";
import { daysLeftLabel, fmtDate, fmtDateTime, fmtMoney } from "../../lib/format";
import { BorrowingChart, CategoryChart, ChartCard, ReservationChart, StatusChart, type Reports } from "./charts";

interface Stats {
  books: number;
  copies: number;
  available_copies: number;
  members: number;
  active_members: number;
  active_loans: number;
  overdue_loans: number;
  waiting_reservations: number;
  ready_reservations: number;
  ebooks: number;
  denied_decisions: number;
  outstanding_fines: number;
  policy_revision: number;
}

interface Overdue {
  loan_id: number;
  member_id: string;
  member_name: string;
  book_id: string;
  title: string;
  due_at: number;
  days_overdue: number;
  fine_so_far: number;
}

interface MemberRow {
  id: string;
  name: string;
  email: string;
  active: boolean;
  groups: string[];
  role: string;
  active_loans: number;
  overdue_loans: number;
  reservations: number;
  outstanding_fines: number;
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative w-full sm:w-72">
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-400" />
      <input className="input pl-9" type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} />
    </div>
  );
}

// --- Dashboard ------------------------------------------------------------------------------
export function AdminDashboard() {
  const stats = useQuery({ queryKey: ["admin", "stats"], queryFn: () => api<Stats>("/admin/stats") });
  const reports = useQuery({ queryKey: ["admin", "reports"], queryFn: () => api<Reports>("/admin/reports") });
  const overdue = useQuery({ queryKey: ["admin", "overdue"], queryFn: () => api<Overdue[]>("/admin/overdue") });
  const s = stats.data;
  const r = reports.data;
  return (
    <>
      <PageHeader eyebrow="Librarian console" title="Library overview" subtitle="Live figures from the circulation database." />
      {stats.isError && <ErrorMessage error={stats.error} onRetry={() => stats.refetch()} />}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 2xl:grid-cols-6">
        <StatCard label="Total titles" value={s?.books} icon={Library} loading={stats.isLoading} hint={`${s?.copies ?? 0} copies · ${s?.ebooks ?? 0} e-books`} />
        <StatCard label="Available copies" value={s?.available_copies} icon={BookCopy} tone="green" loading={stats.isLoading} hint="On the shelf now" />
        <StatCard label="Borrowed" value={s?.active_loans} icon={BookMarked} tone="violet" loading={stats.isLoading} hint="Active loans" />
        <StatCard label="Active members" value={s?.active_members} icon={Users} tone="navy" loading={stats.isLoading} hint={`${s?.members ?? 0} registered`} />
        <StatCard label="Pending reservations" value={s?.waiting_reservations} icon={CalendarClock} tone="amber" loading={stats.isLoading} hint={`${s?.ready_reservations ?? 0} on hold shelf`} />
        <StatCard label="Overdue loans" value={s?.overdue_loans} icon={AlertTriangle} tone="red" loading={stats.isLoading} hint={`${s?.denied_decisions ?? 0} access denials logged`} />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <ChartCard title="Monthly borrowing activity" subtitle="Loans and returns over the last six months" loading={reports.isLoading} empty={!!r && r.monthly.every((m) => !m.borrowed && !m.returned)}>
          {r && <BorrowingChart data={r.monthly} />}
        </ChartCard>
        <ChartCard title="Popular categories" subtitle="All-time loans by subject" loading={reports.isLoading} empty={!!r && r.categories.length === 0}>
          {r && <CategoryChart data={r.categories} />}
        </ChartCard>
        <ChartCard title="Loan status distribution" subtitle="Every loan in the database" loading={reports.isLoading} empty={!!r && r.loan_status.every((x) => !x.count)}>
          {r && <StatusChart data={r.loan_status} />}
        </ChartCard>
        <ChartCard title="Reservation trends" subtitle="Placed, fulfilled and cancelled per month" loading={reports.isLoading} empty={!!r && r.reservations.every((x) => !x.placed)}>
          {r && <ReservationChart data={r.reservations} />}
        </ChartCard>
      </div>

      <section className="mt-8">
        <SectionTitle title="Overdue loans" subtitle="Members who need a reminder." action={<Link to="/admin/loans?status=overdue" className="text-sm font-semibold text-royal-600">View all →</Link>} />
        <DataTable
          loading={overdue.isLoading}
          rows={overdue.data}
          rowKey={(o) => o.loan_id}
          empty={<EmptyState icon={BookMarked} title="Nothing overdue">Every loan is on time.</EmptyState>}
          columns={[
            { key: "m", header: "Member", render: (o) => <span className="font-medium text-ink-900">{o.member_name}</span> },
            { key: "b", header: "Book", render: (o) => o.title },
            { key: "d", header: "Due", render: (o) => fmtDate(o.due_at) },
            { key: "o", header: "Overdue", render: (o) => <Badge tone="red">{o.days_overdue} days</Badge> },
            { key: "f", header: "Fine so far", className: "text-right", render: (o) => <span className="font-semibold text-rose-600">{fmtMoney(o.fine_so_far)}</span> },
          ]}
        />
      </section>
    </>
  );
}

// --- Reports --------------------------------------------------------------------------------
export function AdminReports() {
  const [months, setMonths] = useState("6");
  const reports = useQuery({ queryKey: ["admin", "reports", months], queryFn: () => api<Reports>(`/admin/reports?months=${months}`), placeholderData: keepPreviousData });
  const r = reports.data;
  const total = r ? r.decisions.allow + r.decisions.deny : 0;
  return (
    <>
      <PageHeader
        eyebrow="Analytics"
        title="Reports"
        subtitle="Circulation, collection usage and access-control decisions, computed from the database."
        actions={<Segmented label="Period" value={months} onChange={setMonths} options={[{ value: "3", label: "3 months" }, { value: "6", label: "6 months" }, { value: "12", label: "12 months" }]} />}
      />
      {reports.isError && <ErrorMessage error={reports.error} onRetry={() => reports.refetch()} />}
      <div className="grid gap-6 xl:grid-cols-2">
        <ChartCard title="Borrowing activity" loading={reports.isLoading}>{r && <BorrowingChart data={r.monthly} />}</ChartCard>
        <ChartCard title="Reservation trends" loading={reports.isLoading}>{r && <ReservationChart data={r.reservations} />}</ChartCard>
        <ChartCard title="Loans by category" loading={reports.isLoading} empty={!!r && !r.categories.length}>{r && <CategoryChart data={r.categories} />}</ChartCard>
        <ChartCard title="Loan status" loading={reports.isLoading}>{r && <StatusChart data={r.loan_status} />}</ChartCard>
      </div>
      <div className="mt-6 grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Card className="p-5">
          <h3 className="font-semibold text-ink-950">Most borrowed titles</h3>
          <ol className="mt-4 space-y-2">
            {r?.top_books.map((b, i) => (
              <li key={b.book_id} className="flex items-center gap-3 rounded-xl p-2 hover:bg-ink-50">
                <span className="grid size-7 place-items-center rounded-lg bg-ink-100 text-xs font-bold text-ink-600">{i + 1}</span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-ink-900">{b.title}</p>
                  <p className="truncate text-xs text-ink-500">{b.author}</p>
                </div>
                <span className="text-sm font-semibold text-ink-700 tabular-nums">{b.loans}</span>
              </li>
            ))}
          </ol>
        </Card>
        <Card className="p-5">
          <h3 className="font-semibold text-ink-950">Access-control decisions</h3>
          <p className="mt-0.5 text-xs text-ink-500">From the append-only audit log</p>
          {r && (
            <div className="mt-5 space-y-4">
              {(
                [
                  ["Allowed", r.decisions.allow, "bg-emerald-500"],
                  ["Denied", r.decisions.deny, "bg-rose-500"],
                ] as const
              ).map(([label, n, cls]) => (
                <div key={label}>
                  <div className="flex justify-between text-sm">
                    <span className="font-medium text-ink-700">{label}</span>
                    <span className="font-semibold tabular-nums">{n}</span>
                  </div>
                  <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-ink-100">
                    <div className={`h-full rounded-full ${cls}`} style={{ width: `${total ? (n / total) * 100 : 0}%` }} />
                  </div>
                </div>
              ))}
              <p className="text-xs text-ink-500">{r.decisions.info} informational events (loans, returns, policy syncs).</p>
              <Link to="/admin/audit" className="inline-block text-sm font-semibold text-royal-600">Open audit log →</Link>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

// --- Inventory ------------------------------------------------------------------------------
type InventoryBook = Book & { on_loan: number; held: number };
const EMPTY_FORM = { id: "", isbn: "", title: "", author: "", category: "", year: "", collection_id: "general", copies: "1", description: "", cover_url: "", digital_content: "" };

function BookForm({ initial, editing, onDone }: { initial?: InventoryBook; editing: boolean; onDone: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const access = useQuery({ queryKey: ["admin", "access"], queryFn: () => api<{ collections: { id: string; name: string }[] }>("/admin/access") });
  const cats = useQuery({ queryKey: ["admin", "books", ""], queryFn: () => api<InventoryBook[]>("/admin/books") });
  const [f, setF] = useState(() =>
    initial
      ? { ...EMPTY_FORM, ...initial, year: initial.year?.toString() ?? "", copies: String(initial.copies_total), cover_url: initial.cover_url ?? "", digital_content: "" }
      : EMPTY_FORM,
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const set = (k: keyof typeof EMPTY_FORM) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        isbn: f.isbn.trim(),
        title: f.title.trim(),
        author: f.author.trim(),
        category: f.category.trim(),
        year: f.year ? Number(f.year) : null,
        collection_id: f.collection_id,
        description: f.description.trim() || null,
        cover_url: f.cover_url.trim() || null,
      };
      if (f.digital_content.trim()) body.digital_content = f.digital_content;
      if (editing) return api<Book>(`/admin/books/${initial!.id}`, { method: "PATCH", json: { ...body, copies_total: Number(f.copies) } });
      return api<Book>("/admin/books", { method: "POST", json: { ...body, id: f.id.trim(), copies: Number(f.copies) } });
    },
    onSuccess: (b) => {
      toast("success", editing ? "Book updated" : "Book added", `“${b.title}” saved to the catalogue.`);
      qc.invalidateQueries();
      onDone();
    },
    onError: (e) => toast("error", "Could not save", friendlyError(e)),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!editing && !/^[a-z0-9-]{2,40}$/i.test(f.id.trim())) errs.id = "2–40 letters, digits or dashes";
    for (const k of ["isbn", "title", "author", "category"] as const) if (!f[k].trim()) errs[k] = "Required";
    const copies = Number(f.copies);
    if (!Number.isInteger(copies) || copies < 0 || copies > 1000) errs.copies = "Whole number 0–1000";
    if (editing && initial && copies < initial.on_loan + initial.held) errs.copies = `At least ${initial.on_loan + initial.held} (on loan or held)`;
    if (!editing && copies === 0 && !f.digital_content.trim()) errs.copies = "E-book only titles need digital content";
    if (f.year && (!/^\d{1,4}$/.test(f.year) || Number(f.year) > 3000)) errs.year = "Enter a valid year";
    if (f.cover_url && !/^https?:\/\//.test(f.cover_url)) errs.cover_url = "Must start with http:// or https://";
    setErrors(errs);
    if (!Object.keys(errs).length) save.mutate();
  }

  const field = (k: keyof typeof EMPTY_FORM, label: string, props: React.InputHTMLAttributes<HTMLInputElement> = {}) => (
    <div>
      <label className="label" htmlFor={`bf-${k}`}>{label}</label>
      <input id={`bf-${k}`} className="input" value={f[k]} onChange={set(k)} aria-invalid={!!errors[k]} aria-describedby={errors[k] ? `bf-${k}-err` : undefined} {...props} />
      {errors[k] && <p id={`bf-${k}-err`} className="mt-1 text-xs font-medium text-rose-600">{errors[k]}</p>}
    </div>
  );

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <div className="grid gap-4 sm:grid-cols-2">
        {!editing && field("id", "Book ID", { placeholder: "b-041" })}
        {field("isbn", "ISBN")}
        <div className="sm:col-span-2">{field("title", "Title")}</div>
        {field("author", "Author")}
        <div>
          <label className="label" htmlFor="bf-category">Category</label>
          <input id="bf-category" list="bf-cats" className="input" value={f.category} onChange={set("category")} aria-invalid={!!errors.category} placeholder="Choose or type a new category" />
          <datalist id="bf-cats">
            {[...new Set(cats.data?.map((b) => b.category))].sort().map((c) => (
              <option key={c} value={c} />
            ))}
          </datalist>
          {errors.category && <p className="mt-1 text-xs font-medium text-rose-600">{errors.category}</p>}
        </div>
        {field("year", "Publication year", { inputMode: "numeric" })}
        {field("copies", editing ? "Total copies" : "Number of copies", { type: "number", min: 0, max: 1000 })}
        <div className="sm:col-span-2">
          <label className="label" htmlFor="bf-col">Collection (controls who can see it)</label>
          <select id="bf-col" className="input" value={f.collection_id} onChange={set("collection_id")}>
            {access.data?.collections.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>
        <div className="sm:col-span-2">
          <label className="label" htmlFor="bf-desc">Description</label>
          <textarea id="bf-desc" className="input h-24 py-2" value={f.description} onChange={set("description")} />
        </div>
        <div className="sm:col-span-2">{field("cover_url", "Cover image URL (optional)", { placeholder: "https://…" })}</div>
        <div className="sm:col-span-2">
          <label className="label" htmlFor="bf-dig">E-book content (optional{editing ? ", replaces existing" : ""})</label>
          <textarea id="bf-dig" className="input h-24 py-2 font-mono text-xs" value={f.digital_content} onChange={set("digital_content")} placeholder={"## Chapter 1\nOnly public-domain or licensed text."} />
        </div>
      </div>
      {editing && initial && (
        <Notice>
          {initial.on_loan} on loan and {initial.held} held for reservations. Available copies are recalculated automatically, so stock can never go negative.
        </Notice>
      )}
      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="secondary" onClick={onDone}>Cancel</Button>
        <Button type="submit" loading={save.isPending}>{editing ? "Save changes" : "Add book"}</Button>
      </div>
    </form>
  );
}

export function AdminInventory() {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [modal, setModal] = useState<{ book?: InventoryBook } | null>(null);
  const books = useQuery({ queryKey: ["admin", "books", dq], queryFn: () => api<InventoryBook[]>(`/admin/books?q=${encodeURIComponent(dq)}`), placeholderData: keepPreviousData });
  return (
    <>
      <PageHeader eyebrow="Inventory" title="Book inventory" subtitle="All titles in every collection, with live stock levels." actions={<Button icon={Plus} onClick={() => setModal({})}>Add book</Button>} />
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <SearchInput value={q} onChange={setQ} placeholder="Search title, author, ISBN, category" />
        <p className="text-sm text-ink-500">{books.data?.length ?? "…"} titles</p>
      </div>
      {books.isError && <ErrorMessage error={books.error} />}
      <DataTable
        loading={books.isLoading}
        rows={books.data}
        rowKey={(b) => b.id}
        columns={[
          {
            key: "t",
            header: "Title",
            render: (b) => (
              <div className="flex items-center gap-3">
                <div className="w-8 shrink-0"><BookCover book={b} size="xs" /></div>
                <div className="min-w-0">
                  <p className="line-clamp-1 font-semibold text-ink-900">{b.title}</p>
                  <p className="line-clamp-1 text-xs text-ink-500">{b.author} · {b.isbn}</p>
                </div>
              </div>
            ),
          },
          { key: "c", header: "Category", render: (b) => b.category },
          { key: "col", header: "Collection", render: (b) => <Badge tone={b.collection_id === "general" ? "gray" : b.collection_id === "research" ? "blue" : "violet"}>{b.collection_id}</Badge> },
          { key: "s", header: "Stock", render: (b) => <span className="tabular-nums"><strong className={b.copies_available ? "text-emerald-700" : "text-amber-700"}>{b.copies_available}</strong> / {b.copies_total}</span> },
          { key: "l", header: "Out / held", render: (b) => <span className="tabular-nums text-ink-600">{b.on_loan} / {b.held}</span> },
          { key: "d", header: "E-book", render: (b) => (b.has_digital ? <Badge tone="violet">Yes</Badge> : <span className="text-ink-400">—</span>) },
          { key: "a", header: "", className: "text-right", render: (b) => <Button size="sm" variant="ghost" icon={Pencil} onClick={() => setModal({ book: b })} aria-label={`Edit ${b.title}`}>Edit</Button> },
        ]}
      />
      <Modal open={!!modal} onClose={() => setModal(null)} title={modal?.book ? `Edit “${modal.book.title}”` : "Add a new book"} wide>
        {modal && <BookForm initial={modal.book} editing={!!modal.book} onDone={() => setModal(null)} />}
      </Modal>
    </>
  );
}

// --- Members --------------------------------------------------------------------------------
export function AdminMembers() {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const toast = useToast();
  const qc = useQueryClient();
  const members = useQuery({ queryKey: ["admin", "members", dq], queryFn: () => api<MemberRow[]>(`/admin/members?q=${encodeURIComponent(dq)}`), placeholderData: keepPreviousData });
  const [target, setTarget] = useState<MemberRow | null>(null);
  const toggle = useMutation({
    mutationFn: (m: MemberRow) => api<{ policy_revision: number }>(`/admin/members/${m.id}/${m.active ? "suspend" : "reinstate"}`, { method: "POST" }),
    onSuccess: (r, m) => {
      toast("success", m.active ? "Member suspended" : "Member reinstated", `Policy revision ${r.policy_revision} is now in force.`);
      qc.invalidateQueries();
    },
    onError: (e) => toast("error", "Could not update member", friendlyError(e)),
    onSettled: () => setTarget(null),
  });
  return (
    <>
      <PageHeader eyebrow="Members" title="Member directory" subtitle="Loans, reservations and account status. Passwords and signing secrets are never stored or shown here." />
      <div className="mb-4"><SearchInput value={q} onChange={setQ} placeholder="Search by name, ID or email" /></div>
      {members.isError && <ErrorMessage error={members.error} />}
      <DataTable
        loading={members.isLoading}
        rows={members.data}
        rowKey={(m) => m.id}
        columns={[
          {
            key: "n",
            header: "Member",
            render: (m) => (
              <div className="flex items-center gap-3">
                <span className="grid size-8 place-items-center rounded-full bg-gradient-to-br from-royal-400 to-violet-500 text-xs font-bold text-white">{m.name[0]}</span>
                <div>
                  <p className="font-semibold text-ink-900">{m.name}</p>
                  <p className="text-xs text-ink-500">{m.email}</p>
                </div>
              </div>
            ),
          },
          { key: "id", header: "Member ID", render: (m) => <code className="text-xs">{m.id}</code> },
          { key: "r", header: "Role", render: (m) => <div className="flex flex-wrap gap-1"><Badge tone={m.role === "Librarian" ? "violet" : "blue"}>{m.role}</Badge>{m.groups.filter((g) => g !== "librarians").map((g) => <Badge key={g}>{g}</Badge>)}</div> },
          { key: "l", header: "Loans", render: (m) => <span className="tabular-nums">{m.active_loans}{m.overdue_loans > 0 && <span className="ml-1.5 text-xs font-semibold text-rose-600">({m.overdue_loans} overdue)</span>}</span> },
          { key: "res", header: "Reservations", render: (m) => <span className="tabular-nums">{m.reservations}</span> },
          { key: "f", header: "Fines", render: (m) => (m.outstanding_fines ? <span className="font-semibold text-rose-600">{fmtMoney(m.outstanding_fines)}</span> : <span className="text-ink-400">—</span>) },
          { key: "s", header: "Status", render: (m) => <StatusBadge status={m.active ? "active" : "suspended"} /> },
          {
            key: "a",
            header: "",
            className: "text-right",
            render: (m) =>
              m.role === "Librarian" ? null : (
                <Button size="sm" variant={m.active ? "ghost" : "soft"} icon={m.active ? UserX : UserCheck} onClick={() => setTarget(m)}>
                  {m.active ? "Suspend" : "Reinstate"}
                </Button>
              ),
          },
        ]}
      />
      <ConfirmDialog
        open={!!target}
        onClose={() => setTarget(null)}
        danger={target?.active}
        title={target?.active ? `Suspend ${target?.name}?` : `Reinstate ${target?.name}?`}
        confirmLabel={target?.active ? "Suspend member" : "Reinstate member"}
        loading={toggle.isPending}
        onConfirm={() => target && toggle.mutate(target)}
        message={target?.active ? "A new policy revision is issued and pushed to the access guard. The member is locked out of every request immediately, including searches already on screen." : "The member regains access according to their group grants."}
      />
    </>
  );
}

// --- Borrowing records ----------------------------------------------------------------------
export function AdminLoans() {
  const params = new URLSearchParams(location.search);
  const [status, setStatus] = useState(params.get("status") ?? "open");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const dq = useDebounced(q);
  const loans = useQuery({
    queryKey: ["admin", "loans", status, dq, page],
    queryFn: () => api<Page<Loan>>(`/admin/loans?status=${status}&q=${encodeURIComponent(dq)}&page=${page}&page_size=15`),
    placeholderData: keepPreviousData,
  });
  return (
    <>
      <PageHeader eyebrow="Circulation" title="Borrowing records" subtitle="Every loan, past and present." />
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Segmented
          label="Loan status"
          value={status}
          onChange={(v) => { setStatus(v); setPage(1); }}
          options={[{ value: "open", label: "On loan" }, { value: "due_soon", label: "Due soon" }, { value: "overdue", label: "Overdue" }, { value: "returned", label: "Returned" }, { value: "all", label: "All" }]}
        />
        <SearchInput value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search book or member" />
      </div>
      {loans.isError && <ErrorMessage error={loans.error} />}
      <DataTable
        loading={loans.isLoading}
        rows={loans.data?.items}
        rowKey={(l) => l.loan_id}
        empty={<EmptyState icon={BookMarked} title="No loans match" />}
        columns={[
          { key: "b", header: "Book", render: (l) => <div><p className="line-clamp-1 font-semibold text-ink-900">{l.title}</p><p className="text-xs text-ink-500">{l.category}</p></div> },
          { key: "m", header: "Member", render: (l) => l.member_name },
          { key: "o", header: "Borrowed", render: (l) => fmtDate(l.borrowed_at) },
          { key: "d", header: "Due", render: (l) => <div>{fmtDate(l.due_at)}{l.status !== "returned" && <p className="text-xs text-ink-500">{daysLeftLabel(l.days_left)}</p>}</div> },
          { key: "r", header: "Returned", render: (l) => fmtDate(l.returned_at) },
          { key: "s", header: "Status", render: (l) => <StatusBadge status={l.status} /> },
          { key: "f", header: "Fine", className: "text-right", render: (l) => (l.fine ? <span className="font-semibold text-rose-600">{fmtMoney(l.fine)}</span> : <span className="text-ink-400">—</span>) },
        ]}
      />
      {loans.data && <div className="mt-6"><Pagination page={loans.data.page} pages={loans.data.pages} onChange={setPage} /></div>}
    </>
  );
}

// --- Reservations ---------------------------------------------------------------------------
export function AdminReservations() {
  const [status, setStatus] = useState("open");
  const res = useQuery({ queryKey: ["admin", "reservations", status], queryFn: () => api<Reservation[]>(`/admin/reservations?status=${status}`) });
  const cancel = useCancelReservation(true);
  const [target, setTarget] = useState<Reservation | null>(null);
  return (
    <>
      <PageHeader eyebrow="Circulation" title="Reservation management" subtitle="Queues are served first come, first served. Cancelling a ready reservation passes the held copy to the next member." />
      <div className="mb-4">
        <Segmented label="Reservation status" value={status} onChange={setStatus} options={[{ value: "open", label: "Open" }, { value: "waiting", label: "Waiting" }, { value: "ready", label: "Ready" }, { value: "fulfilled", label: "Fulfilled" }, { value: "cancelled", label: "Cancelled" }, { value: "all", label: "All" }]} />
      </div>
      {res.isError && <ErrorMessage error={res.error} />}
      <DataTable
        loading={res.isLoading}
        rows={res.data}
        rowKey={(r) => r.id}
        empty={<EmptyState icon={CalendarClock} title="No reservations" />}
        columns={[
          { key: "b", header: "Book", render: (r) => <span className="font-semibold text-ink-900">{r.title}</span> },
          { key: "m", header: "Member", render: (r) => r.member_name },
          { key: "c", header: "Placed", render: (r) => fmtDateTime(r.created_at) },
          { key: "q", header: "Queue", render: (r) => (r.queue_position ? `#${r.queue_position}` : "—") },
          { key: "s", header: "Status", render: (r) => <StatusBadge status={r.status} /> },
          { key: "a", header: "", className: "text-right", render: (r) => (r.status === "waiting" || r.status === "ready" ? <Button size="sm" variant="ghost" icon={XCircle} onClick={() => setTarget(r)}>Cancel</Button> : null) },
        ]}
      />
      <ConfirmDialog
        open={!!target}
        onClose={() => setTarget(null)}
        danger
        title="Cancel this reservation?"
        confirmLabel="Cancel reservation"
        loading={cancel.isPending}
        onConfirm={() => target && cancel.mutate(target.id, { onSettled: () => setTarget(null) })}
        message={<p>{target?.member_name}'s reservation for <strong>{target?.title}</strong> will be cancelled and recorded in the audit log.</p>}
      />
    </>
  );
}

// --- Fines ----------------------------------------------------------------------------------
export function AdminFines() {
  const fines = useQuery({
    queryKey: ["admin", "fines"],
    queryFn: () => api<{ outstanding_total: number; accruing_total: number; fine_per_day: number; members: MemberRow[]; records: (Loan & { member_name: string })[]; overdue: Overdue[] }>("/admin/fines"),
  });
  const f = fines.data;
  return (
    <>
      <PageHeader eyebrow="Fines" title="Fines & overdue loans" subtitle={f ? `Fine rate: ${fmtMoney(f.fine_per_day)} per day late, rounded up.` : undefined} />
      {fines.isError && <ErrorMessage error={fines.error} />}
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Outstanding fines" value={fmtMoney(f?.outstanding_total ?? 0)} icon={CircleDollarSign} tone="red" loading={fines.isLoading} hint="Recorded on returned loans" />
        <StatCard label="Accruing on overdue loans" value={fmtMoney(f?.accruing_total ?? 0)} icon={AlertTriangle} tone="amber" loading={fines.isLoading} />
        <StatCard label="Members affected" value={f?.members.length ?? 0} icon={Users} tone="navy" loading={fines.isLoading} />
      </div>
      <div className="mt-6"><Notice tone="amber" icon={CreditCard} title="Payment processing is not implemented">Fines are recorded and reported. Collection happens at the desk; this system does not take or simulate payments.</Notice></div>
      <section className="mt-8">
        <SectionTitle title="Overdue loans" />
        <DataTable rows={f?.overdue} loading={fines.isLoading} rowKey={(o) => o.loan_id} empty={<p className="text-center text-sm text-ink-500">Nothing overdue.</p>}
          columns={[
            { key: "m", header: "Member", render: (o) => <span className="font-medium text-ink-900">{o.member_name}</span> },
            { key: "b", header: "Book", render: (o) => o.title },
            { key: "d", header: "Days overdue", render: (o) => <Badge tone="red">{o.days_overdue}</Badge> },
            { key: "f", header: "Fine so far", className: "text-right", render: (o) => <span className="font-semibold text-rose-600">{fmtMoney(o.fine_so_far)}</span> },
          ]} />
      </section>
      <section className="mt-8">
        <SectionTitle title="Member summary" />
        <DataTable rows={f?.members} loading={fines.isLoading} rowKey={(m) => m.id}
          columns={[
            { key: "m", header: "Member", render: (m) => <span className="font-medium text-ink-900">{m.name}</span> },
            { key: "l", header: "Active loans", render: (m) => m.active_loans },
            { key: "o", header: "Overdue", render: (m) => m.overdue_loans || "—" },
            { key: "f", header: "Outstanding", className: "text-right", render: (m) => fmtMoney(m.outstanding_fines) },
          ]} />
      </section>
      <section className="mt-8">
        <SectionTitle title="Fine records" subtitle="Every loan that carries a fine." />
        <DataTable rows={f?.records} loading={fines.isLoading} rowKey={(r) => r.loan_id}
          columns={[
            { key: "m", header: "Member", render: (r) => r.member_name },
            { key: "b", header: "Book", render: (r) => r.title },
            { key: "d", header: "Due", render: (r) => fmtDate(r.due_at) },
            { key: "r", header: "Returned", render: (r) => (r.returned_at ? fmtDate(r.returned_at) : <StatusBadge status="overdue" />) },
            { key: "f", header: "Fine", className: "text-right", render: (r) => <span className="font-semibold text-rose-600">{fmtMoney(r.fine)}</span> },
          ]} />
      </section>
    </>
  );
}

