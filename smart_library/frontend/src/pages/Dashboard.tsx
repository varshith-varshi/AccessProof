import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  BookCheck,
  BookMarked,
  CalendarClock,
  CircleDollarSign,
  Clock,
  Library,
  MonitorSmartphone,
  RotateCcw,
  ShieldX,
  Sparkles,
  Undo2,
  XCircle,
  CheckCircle2,
} from "lucide-react";
import { Link } from "react-router-dom";
import { BookCover } from "../components/books";
import { LoanRow } from "../components/loans";
import { Card, EmptyState, ErrorMessage, PageHeader, SectionTitle, Skeleton, StatCard, StatusBadge, AvailabilityBadge } from "../components/ui";
import { api, type ActivityEvent, type Book, type Loan, type Reservation } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtDate, fmtMoney, relative } from "../lib/format";

const EVENT: Record<string, { icon: typeof BookCheck; label: string; cls: string }> = {
  borrowed: { icon: BookCheck, label: "Borrowed", cls: "bg-royal-50 text-royal-600" },
  returned: { icon: Undo2, label: "Returned", cls: "bg-emerald-50 text-emerald-600" },
  reserved: { icon: CalendarClock, label: "Reserved", cls: "bg-violet-50 text-violet-600" },
  reservation_ready: { icon: CheckCircle2, label: "Ready for pickup", cls: "bg-emerald-50 text-emerald-600" },
  reservation_fulfilled: { icon: RotateCcw, label: "Reservation fulfilled", cls: "bg-ink-100 text-ink-600" },
  reservation_cancelled: { icon: XCircle, label: "Reservation cancelled", cls: "bg-ink-100 text-ink-600" },
  denied: { icon: ShieldX, label: "Access denied", cls: "bg-rose-50 text-rose-600" },
};

export default function Dashboard() {
  const { me } = useAuth();
  const loans = useQuery({ queryKey: ["loans"], queryFn: () => api<Loan[]>("/me/loans") });
  const res = useQuery({ queryKey: ["reservations"], queryFn: () => api<Reservation[]>("/me/reservations") });
  const recs = useQuery({ queryKey: ["recs", 4], queryFn: () => api<Book[]>("/me/recommendations?limit=4") });
  const activity = useQuery({ queryKey: ["activity"], queryFn: () => api<ActivityEvent[]>("/me/activity") });
  const fines = useQuery({ queryKey: ["fines"], queryFn: () => api<{ outstanding: number; accruing: number }>("/me/fines") });

  const nextDue = loans.data?.[0];
  const dueSoon = loans.data?.filter((l) => l.status === "due_soon" || l.status === "overdue").length ?? 0;
  const ready = res.data?.filter((r) => r.status === "ready") ?? [];
  const hour = new Date().getHours();

  return (
    <>
      <PageHeader
        eyebrow={hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening"}
        title={`Welcome back, ${me?.name ?? ""}`}
        subtitle="Here's what's happening in your library today."
        actions={
          <Link to="/books" className="inline-flex h-10 items-center gap-2 rounded-xl bg-gradient-to-b from-royal-500 to-royal-600 px-4 text-sm font-semibold text-white shadow-lg shadow-royal-600/25">
            <Library className="size-4" /> Browse catalogue
          </Link>
        }
      />

      {ready.length > 0 && (
        <div className="mb-6 flex items-center gap-3 rounded-2xl border border-emerald-200 bg-gradient-to-r from-emerald-50 to-white p-4">
          <CheckCircle2 className="size-6 shrink-0 text-emerald-600" />
          <p className="flex-1 text-sm text-emerald-900">
            <strong>{ready.map((r) => r.title).join(", ")}</strong> {ready.length === 1 ? "is" : "are"} on the hold shelf for you. Borrow {ready.length === 1 ? "it" : "them"} before someone else's turn.
          </p>
          <Link to="/reservations" className="text-sm font-semibold text-emerald-700 hover:underline">
            View
          </Link>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label="Books borrowed" value={loans.data?.length ?? 0} icon={BookMarked} loading={loans.isLoading} hint={`of ${5} allowed`} />
        <StatCard label="Books reserved" value={res.data?.length ?? 0} icon={CalendarClock} tone="violet" loading={res.isLoading} hint={ready.length ? `${ready.length} ready for pickup` : "in reservation queues"} />
        <StatCard
          label="Upcoming returns"
          value={dueSoon}
          icon={Clock}
          tone="amber"
          loading={loans.isLoading}
          hint={nextDue ? `Next: ${fmtDate(nextDue.due_at)}` : "Nothing due"}
        />
        <StatCard
          label="Outstanding fines"
          value={fmtMoney((fines.data?.outstanding ?? 0) + (fines.data?.accruing ?? 0))}
          icon={CircleDollarSign}
          tone={(fines.data?.outstanding ?? 0) + (fines.data?.accruing ?? 0) > 0 ? "red" : "green"}
          loading={fines.isLoading}
          hint={fines.data?.accruing ? `${fmtMoney(fines.data.accruing)} still accruing` : "Late fees recorded"}
        />
      </div>

      <div className="mt-8 grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <section>
          <SectionTitle
            title="Current loans"
            subtitle="Renew or return straight from here."
            action={
              <Link to="/my-books" className="inline-flex items-center gap-1 text-sm font-semibold text-royal-600">
                All loans <ArrowRight className="size-4" />
              </Link>
            }
          />
          <Card className="divide-y divide-ink-100">
            {loans.isLoading && [0, 1].map((i) => <Skeleton key={i} className="m-5 h-20" />)}
            {loans.isError && <ErrorMessage className="m-4" error={loans.error} onRetry={() => loans.refetch()} />}
            {loans.data?.length === 0 && (
              <div className="p-4">
                <EmptyState icon={BookMarked} title="No books on loan" action={<Link className="text-sm font-semibold text-royal-600" to="/books">Find something to read →</Link>}>
                  Borrowed books appear here with their due dates.
                </EmptyState>
              </div>
            )}
            {loans.data?.map((l) => <LoanRow key={l.loan_id} loan={l} />)}
          </Card>
        </section>

        <div className="space-y-6">
          <section>
            <SectionTitle title="Quick actions" />
            <div className="grid grid-cols-2 gap-3">
              {[
                { to: "/books", icon: Library, label: "Search Books", cls: "from-royal-500 to-royal-600" },
                { to: "/books?available=1", icon: BookCheck, label: "Borrow a Book", cls: "from-emerald-500 to-emerald-600" },
                { to: "/reservations", icon: CalendarClock, label: "My Reservations", cls: "from-violet-500 to-violet-600" },
                { to: "/ebooks", icon: MonitorSmartphone, label: "Read E-Books", cls: "from-ink-700 to-ink-900" },
              ].map(({ to, icon: Icon, label, cls }) => (
                <Link key={label} to={to} className="group card flex flex-col gap-3 p-4 transition hover:-translate-y-0.5 hover:shadow-lift">
                  <span className={`grid size-10 place-items-center rounded-xl bg-gradient-to-br ${cls} text-white shadow-md transition group-hover:scale-105`}>
                    <Icon className="size-5" />
                  </span>
                  <span className="text-sm font-semibold text-ink-900">{label}</span>
                </Link>
              ))}
            </div>
          </section>

          <section>
            <SectionTitle title="Recent activity" />
            <Card className="p-2">
              {activity.isLoading && <Skeleton className="m-3 h-32" />}
              {activity.data?.length === 0 && <p className="p-4 text-sm text-ink-500">No activity yet.</p>}
              <ul>
                {activity.data?.slice(0, 7).map((e, i) => {
                  const meta = EVENT[e.type] ?? EVENT.borrowed;
                  const Icon = meta.icon;
                  return (
                    <li key={i} className="flex items-start gap-3 rounded-xl p-3 hover:bg-ink-50">
                      <span className={`grid size-8 shrink-0 place-items-center rounded-lg ${meta.cls}`}>
                        <Icon className="size-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-ink-800">
                          <span className="font-semibold">{meta.label}</span>
                          {e.title && <> · <span className="text-ink-600">{e.title}</span></>}
                        </p>
                        <p className="text-xs text-ink-400">
                          {relative(e.at)}
                          {e.detail && <> · {e.detail}</>}
                        </p>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </Card>
          </section>
        </div>
      </div>

      <section className="mt-10">
        <SectionTitle
          title="Recommended for you"
          subtitle="Based on your history and what similar readers borrow — only from collections you can access."
          action={
            <Link to="/recommendations" className="inline-flex items-center gap-1 text-sm font-semibold text-royal-600">
              More <ArrowRight className="size-4" />
            </Link>
          }
        />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {recs.isLoading && [0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-36" />)}
          {recs.data?.map((b) => (
            <Link key={b.id} to={`/books/${b.id}`} className="group card flex gap-4 p-4 transition hover:-translate-y-0.5 hover:shadow-lift">
              <div className="w-16 shrink-0 transition group-hover:-rotate-2">
                <BookCover book={b} size="xs" />
              </div>
              <div className="min-w-0">
                <p className="line-clamp-2 text-sm font-semibold text-ink-950">{b.title}</p>
                <p className="mt-0.5 line-clamp-1 text-xs text-ink-500">{b.author}</p>
                <p className="mt-1.5 line-clamp-2 text-xs text-violet-700">
                  <Sparkles className="mr-1 inline size-3" />
                  {b.reason}
                </p>
                <div className="mt-2">
                  <AvailabilityBadge available={b.copies_available} total={b.copies_total} digital={b.has_digital} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </section>

      {res.data && res.data.length > 0 && (
        <section className="mt-10">
          <SectionTitle title="Your reservations" />
          <div className="flex flex-wrap gap-3">
            {res.data.map((r) => (
              <Link to="/reservations" key={r.id} className="card flex items-center gap-3 px-4 py-3 hover:shadow-lift">
                <span className="text-sm font-semibold text-ink-900">{r.title}</span>
                <StatusBadge status={r.status} />
                {r.queue_position && <span className="text-xs text-ink-500">#{r.queue_position} in queue</span>}
              </Link>
            ))}
          </div>
        </section>
      )}
    </>
  );
}
