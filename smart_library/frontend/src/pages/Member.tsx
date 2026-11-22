import { useQuery } from "@tanstack/react-query";
import {
  BookMarked,
  BookOpenText,
  CalendarClock,
  CircleDollarSign,
  CreditCard,
  History,
  KeyRound,
  Layers,
  Mail,
  MonitorSmartphone,
  ShieldCheck,
  Sparkles,
  UserRound,
  Users,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { BookCard, BookCover, BookGridSkeleton } from "../components/books";
import { LoanRow } from "../components/loans";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  DataTable,
  EmptyState,
  ErrorMessage,
  Notice,
  PageHeader,
  SectionTitle,
  Segmented,
  Skeleton,
  StatCard,
  StatusBadge,
} from "../components/ui";
import { api, type Book, type Fines, type Loan, type Reservation } from "../lib/api";
import { useCancelReservation } from "../lib/actions";
import { useAuth } from "../lib/auth";
import { fmtDate, fmtMoney, relative } from "../lib/format";
import { BookAction } from "./Catalog";

// --- My books -------------------------------------------------------------------------------
export function MyBooks() {
  const [tab, setTab] = useState<"current" | "history">("current");
  const loans = useQuery({ queryKey: ["loans"], queryFn: () => api<Loan[]>("/me/loans") });
  const history = useQuery({ queryKey: ["history"], queryFn: () => api<Loan[]>("/me/history"), enabled: tab === "history" });
  const q = tab === "current" ? loans : history;
  const rows = tab === "current" ? loans.data : history.data?.filter((l) => l.status === "returned");
  return (
    <>
      <PageHeader eyebrow="Borrowing" title="My borrowed books" subtitle="Loans last 14 days. You can hold up to 5 at a time, and renew unless someone is waiting." />
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <Segmented
          label="Loans"
          value={tab}
          onChange={setTab}
          options={[
            { value: "current", label: "Current", count: loans.data?.length },
            { value: "history", label: "History" },
          ]}
        />
        <div className="flex flex-wrap gap-2 text-xs">
          <StatusBadge status="active" />
          <StatusBadge status="due_soon" />
          <StatusBadge status="overdue" />
          <StatusBadge status="returned" />
        </div>
      </div>
      <Card className="divide-y divide-ink-100">
        {q.isLoading && [0, 1, 2].map((i) => <Skeleton key={i} className="m-5 h-20" />)}
        {q.isError && <ErrorMessage className="m-4" error={q.error} onRetry={() => q.refetch()} />}
        {rows?.length === 0 && (
          <div className="p-4">
            <EmptyState icon={tab === "current" ? BookMarked : History} title={tab === "current" ? "No books on loan" : "No returned books yet"} action={<Link className="text-sm font-semibold text-royal-600" to="/books">Browse the catalogue →</Link>}>
              {tab === "current" ? "When you borrow a book it appears here with its due date." : "Returned loans and any fines are listed here."}
            </EmptyState>
          </div>
        )}
        {rows?.map((l) => <LoanRow key={l.loan_id} loan={l} />)}
      </Card>
    </>
  );
}

// --- Reservations ---------------------------------------------------------------------------
export function Reservations() {
  const [tab, setTab] = useState<"open" | "all">("open");
  const res = useQuery({ queryKey: ["reservations", tab], queryFn: () => api<Reservation[]>(`/me/reservations${tab === "all" ? "?all=true" : ""}`) });
  const cancel = useCancelReservation();
  const [target, setTarget] = useState<Reservation | null>(null);
  return (
    <>
      <PageHeader eyebrow="Reservations" title="My reservations" subtitle="Queues are first come, first served. When a copy is returned it is held for the first member in line." />
      <div className="mb-5">
        <Segmented label="Reservations" value={tab} onChange={setTab} options={[{ value: "open", label: "Active" }, { value: "all", label: "All, including past" }]} />
      </div>
      {res.isError && <ErrorMessage error={res.error} onRetry={() => res.refetch()} />}
      {res.isLoading && <Skeleton className="h-40" />}
      {res.data?.length === 0 && (
        <EmptyState icon={CalendarClock} title="No reservations" action={<Link className="text-sm font-semibold text-royal-600" to="/books">Find a book to reserve →</Link>}>
          When every copy of a book is on loan, you can reserve it from the catalogue.
        </EmptyState>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        {res.data?.map((r) => (
          <Card key={r.id} className="flex gap-4 p-5">
            <Link to={`/books/${r.book_id}`} className="w-16 shrink-0">
              <BookCover book={{ ...r, id: r.book_id }} size="xs" />
            </Link>
            <div className="min-w-0 flex-1">
              <div className="flex items-start justify-between gap-2">
                <Link to={`/books/${r.book_id}`} className="line-clamp-2 font-semibold text-ink-950 hover:text-royal-600">
                  {r.title}
                </Link>
                <StatusBadge status={r.status} />
              </div>
              <p className="text-sm text-ink-500">{r.author}</p>
              <p className="mt-2 text-xs text-ink-500">Reserved {fmtDate(r.created_at)}{r.updated_at && r.status !== "waiting" ? ` · updated ${relative(r.updated_at)}` : ""}</p>
              {r.status === "waiting" && r.queue_position && (
                <p className="mt-2 text-sm text-violet-700">
                  Position <strong>#{r.queue_position}</strong> in the queue
                </p>
              )}
              {r.status === "ready" && <p className="mt-2 text-sm font-medium text-emerald-700">A copy is on the hold shelf for you. Borrow it to collect.</p>}
              {(r.status === "waiting" || r.status === "ready") && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {r.status === "ready" && (
                    <Link to={`/books/${r.book_id}`} className="inline-flex h-8 items-center rounded-xl bg-emerald-600 px-3 text-xs font-semibold text-white">
                      Borrow now
                    </Link>
                  )}
                  <Button size="sm" variant="secondary" icon={XCircle} onClick={() => setTarget(r)}>
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>
      <ConfirmDialog
        open={!!target}
        onClose={() => setTarget(null)}
        title="Cancel reservation?"
        danger
        confirmLabel="Cancel reservation"
        loading={cancel.isPending}
        onConfirm={() => target && cancel.mutate(target.id, { onSettled: () => setTarget(null) })}
        message={
          <p>
            You will leave the queue for <strong className="text-ink-900">{target?.title}</strong>.{target?.status === "ready" && " The copy held for you will pass to the next member in line."}
          </p>
        }
      />
    </>
  );
}

// --- Digital library ------------------------------------------------------------------------
export function Ebooks() {
  const list = useQuery({ queryKey: ["catalog", "ebooks"], queryFn: () => api<{ items: Book[] }>("/catalog?format=digital&page_size=60") });
  return (
    <>
      <PageHeader
        eyebrow="Digital library"
        title="E-books"
        subtitle="Digital editions you can read online. Public-domain classics and original study material — no copyrighted text."
      />
      <Notice icon={ShieldCheck} tone="violet">
        Your access is checked at the moment you open a book, not just when the list loads. If your access is revoked, the reader will refuse to open it.
      </Notice>
      <div className="mt-6">
        {list.isLoading && <BookGridSkeleton count={4} />}
        {list.isError && <ErrorMessage error={list.error} onRetry={() => list.refetch()} />}
        {list.data?.items.length === 0 && <EmptyState icon={MonitorSmartphone} title="No digital editions available to you" />}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {list.data?.items.map((b) => (
            <Card key={b.id} className="group flex gap-5 p-5 transition hover:-translate-y-0.5 hover:shadow-lift">
              <div className="w-24 shrink-0 transition group-hover:-rotate-2">
                <BookCover book={b} size="sm" />
              </div>
              <div className="flex min-w-0 flex-1 flex-col">
                <Badge tone="violet" className="self-start">
                  {b.category}
                </Badge>
                <h3 className="mt-2 line-clamp-2 font-semibold text-ink-950">{b.title}</h3>
                <p className="text-sm text-ink-500">{b.author}</p>
                <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-ink-500">{b.description}</p>
                <div className="mt-auto pt-3">
                  <Link to={`/ebooks/${b.id}/read`} className="inline-flex h-9 items-center gap-2 rounded-xl bg-gradient-to-b from-violet-500 to-violet-600 px-3.5 text-sm font-semibold text-white shadow-md shadow-violet-600/25 transition hover:to-violet-700">
                    <BookOpenText className="size-4" /> Read now
                  </Link>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </>
  );
}

// --- Recommendations ------------------------------------------------------------------------
export function Recommendations() {
  const recs = useQuery({ queryKey: ["recs", 12], queryFn: () => api<Book[]>("/me/recommendations?limit=12") });
  return (
    <>
      <PageHeader
        eyebrow="For you"
        title="Recommended reading"
        subtitle="Ranked by titles co-borrowed by readers like you, then your favourite categories, then overall popularity. Every suggestion passes the same access check as search."
      />
      <div className="mb-6 flex flex-wrap gap-2 text-xs text-ink-600">
        {["Similar readers", "Your categories", "Popular titles"].map((t, i) => (
          <span key={t} className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1.5 font-medium ring-1 ring-ink-200">
            <Sparkles className="size-3.5 text-violet-500" /> {i + 1}. {t}
          </span>
        ))}
      </div>
      {recs.isLoading && <BookGridSkeleton />}
      {recs.isError && <ErrorMessage error={recs.error} onRetry={() => recs.refetch()} />}
      {recs.data?.length === 0 && <EmptyState icon={Sparkles} title="No recommendations yet">Borrow a few books and suggestions will appear here.</EmptyState>}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-4">
        {recs.data?.map((b) => (
          <BookCard
            key={b.id}
            book={b}
            action={
              <>
                <Link to={`/books/${b.id}`} className="inline-flex h-8 flex-1 items-center justify-center rounded-xl border border-ink-200 text-xs font-semibold text-ink-700 hover:bg-ink-50">
                  View book
                </Link>
                <BookAction book={b} />
              </>
            }
          />
        ))}
      </div>
    </>
  );
}

// --- Fines ----------------------------------------------------------------------------------
export function FinesPage() {
  const fines = useQuery({ queryKey: ["fines"], queryFn: () => api<Fines>("/me/fines") });
  const f = fines.data;
  return (
    <>
      <PageHeader eyebrow="Fines" title="Fines & due dates" subtitle={f ? `Late returns are charged ${fmtMoney(f.fine_per_day)} per day, rounded up to whole days.` : undefined} />
      {fines.isError && <ErrorMessage error={fines.error} onRetry={() => fines.refetch()} />}
      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Outstanding fines" value={fmtMoney(f?.outstanding ?? 0)} icon={CircleDollarSign} tone={f?.outstanding ? "red" : "green"} loading={fines.isLoading} hint="From returned late loans" />
        <StatCard label="Accruing now" value={fmtMoney(f?.accruing ?? 0)} icon={CalendarClock} tone={f?.accruing ? "amber" : "green"} loading={fines.isLoading} hint="On loans that are overdue" />
        <StatCard label="Overdue books" value={f?.overdue_loans.length ?? 0} icon={BookMarked} tone={f?.overdue_loans.length ? "red" : "blue"} loading={fines.isLoading} hint="Return to stop fines growing" />
      </div>
      <div className="mt-6">
        <Notice tone="amber" icon={CreditCard} title="Online payment is not available">
          This system records fines but does not process payments. Please pay at the library desk. No payment is simulated here.
        </Notice>
      </div>
      {f && f.overdue_loans.length > 0 && (
        <section className="mt-8">
          <SectionTitle title="Overdue books" subtitle="Fines keep growing until these are returned." />
          <Card className="divide-y divide-ink-100">
            {f.overdue_loans.map((l) => (
              <LoanRow key={l.loan_id} loan={l} />
            ))}
          </Card>
        </section>
      )}
      <section className="mt-8">
        <SectionTitle title="Fine history" />
        <DataTable
          loading={fines.isLoading}
          rows={f?.history}
          rowKey={(l) => l.loan_id}
          empty={<EmptyState icon={CircleDollarSign} title="No fines">You have always returned on time. 🎉</EmptyState>}
          columns={[
            { key: "t", header: "Book", render: (l) => <span className="font-medium text-ink-900">{l.title}</span> },
            { key: "d", header: "Due", render: (l) => fmtDate(l.due_at) },
            { key: "r", header: "Returned", render: (l) => fmtDate(l.returned_at) },
            { key: "days", header: "Days late", render: (l) => (l.returned_at ? Math.ceil((l.returned_at - l.due_at) / 86400) : "—") },
            { key: "f", header: "Fine", className: "text-right", render: (l) => <span className="font-semibold text-rose-600">{fmtMoney(l.fine)}</span> },
          ]}
        />
      </section>
    </>
  );
}

// --- Profile --------------------------------------------------------------------------------
export function Profile() {
  const { me } = useAuth();
  const access = useQuery({ queryKey: ["access"], queryFn: () => api<{ collection_id: string; name: string; description: string; reason: string }[]>("/me/access") });
  const loans = useQuery({ queryKey: ["history"], queryFn: () => api<Loan[]>("/me/history") });
  if (!me) return null;
  return (
    <>
      <PageHeader eyebrow="Profile" title="My profile" />
      <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
        <Card className="overflow-hidden">
          <div className="h-24 bg-gradient-to-r from-royal-600 to-violet-600" />
          <div className="px-6 pb-6">
            <div className="-mt-10 grid size-20 place-items-center rounded-2xl bg-white text-3xl font-bold text-royal-600 shadow-lg ring-4 ring-white">{me.name[0]}</div>
            <h2 className="mt-4 text-xl font-bold text-ink-950">{me.name}</h2>
            <div className="mt-1 flex flex-wrap gap-2">
              <Badge tone={me.librarian ? "violet" : "blue"}>{me.librarian ? "Librarian" : "Library member"}</Badge>
              <Badge tone={me.active ? "green" : "red"}>{me.active ? "Active" : "Suspended"}</Badge>
            </div>
            <dl className="mt-6 space-y-3 text-sm">
              <div className="flex items-center gap-3">
                <KeyRound className="size-4 text-ink-400" />
                <dt className="w-24 text-ink-500">Member ID</dt>
                <dd className="font-mono text-ink-900">{me.id}</dd>
              </div>
              <div className="flex items-center gap-3">
                <Mail className="size-4 text-ink-400" />
                <dt className="w-24 text-ink-500">Email</dt>
                <dd className="truncate text-ink-900">{me.email}</dd>
              </div>
              <div className="flex items-center gap-3">
                <Users className="size-4 text-ink-400" />
                <dt className="w-24 text-ink-500">Groups</dt>
                <dd className="flex flex-wrap gap-1">{me.groups.map((g) => <Badge key={g}>{g}</Badge>)}</dd>
              </div>
              <div className="flex items-center gap-3">
                <History className="size-4 text-ink-400" />
                <dt className="w-24 text-ink-500">Total loans</dt>
                <dd className="text-ink-900">{loans.data?.length ?? "…"}</dd>
              </div>
            </dl>
          </div>
        </Card>
        <div className="space-y-6">
          <Card className="p-6">
            <SectionTitle title="My access" subtitle="Collections your account can use, and why. This is decided by the server's policy, not by this page." />
            {access.isLoading && <Skeleton className="h-24" />}
            <ul className="space-y-3">
              {access.data?.map((a) => (
                <li key={a.collection_id} className="flex items-start gap-3 rounded-xl bg-ink-50 p-4">
                  <Layers className="mt-0.5 size-5 text-royal-600" />
                  <div>
                    <p className="font-semibold text-ink-900">{a.name}</p>
                    <p className="text-sm text-ink-500">{a.description}</p>
                    <p className="mt-1 text-xs font-medium text-emerald-700">✓ {a.reason}</p>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
          <Notice icon={UserRound} tone="amber" title="Demonstration identity">
            You are signed in with a demo account. In production, your identity would come from the university's single sign-on, and your groups from the campus directory.
          </Notice>
        </div>
      </div>
    </>
  );
}
