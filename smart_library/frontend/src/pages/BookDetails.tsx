import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, BookCheck, BookOpenText, CalendarPlus, Hash, Layers, ShieldCheck, Tag, CalendarDays, Copy, Info } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { BookCover } from "../components/books";
import { AvailabilityBadge, Badge, Button, Card, EmptyState, ErrorMessage, Notice, Skeleton } from "../components/ui";
import { api, ApiError, type Book, type Loan, type Me, type Reservation } from "../lib/api";
import { useBorrow, useReserve } from "../lib/actions";
import { useAuth } from "../lib/auth";
import { fmtDate } from "../lib/format";

function eligibility(book: Book, me: Me | undefined, loans: Loan[] | undefined, res: Reservation[] | undefined) {
  const mine = loans?.find((l) => l.book_id === book.id);
  const myRes = res?.find((r) => r.book_id === book.id);
  if (mine) return { kind: "loan" as const, text: `You have this book on loan, due ${fmtDate(mine.due_at)}.` };
  if (myRes?.status === "ready") return { kind: "borrow" as const, text: "Your reserved copy is on the hold shelf — borrow it now." };
  if (myRes) return { kind: "reserved" as const, text: `You are number ${myRes.queue_position} in the reservation queue.` };
  if (book.copies_total === 0) return { kind: "digital" as const, text: "This title is available as an e-book only." };
  if ((loans?.length ?? 0) >= 5) return { kind: "blocked" as const, text: "You have reached the limit of 5 active loans." };
  if (loans?.some((l) => l.status === "overdue")) return { kind: "blocked" as const, text: "Return your overdue items before borrowing more." };
  if (!me?.active) return { kind: "blocked" as const, text: "Your membership is suspended." };
  if (book.copies_available > 0) return { kind: "borrow" as const, text: "You are eligible to borrow this book for 14 days." };
  return { kind: "reserve" as const, text: "All copies are on loan. Reserve it and the next returned copy is held for you." };
}

export default function BookDetails() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { me } = useAuth();
  const book = useQuery({ queryKey: ["book", id], queryFn: () => api<Book>(`/books/${encodeURIComponent(id)}`), retry: false });
  const loans = useQuery({ queryKey: ["loans"], queryFn: () => api<Loan[]>("/me/loans") });
  const res = useQuery({ queryKey: ["reservations"], queryFn: () => api<Reservation[]>("/me/reservations") });
  const borrow = useBorrow();
  const reserve = useReserve();

  const back = (
    <button onClick={() => (history.length > 1 ? navigate(-1) : navigate("/books"))} className="mb-6 inline-flex items-center gap-1.5 text-sm font-semibold text-ink-500 hover:text-ink-900">
      <ArrowLeft className="size-4" /> Return to catalogue
    </button>
  );

  if (book.isLoading)
    return (
      <>
        {back}
        <div className="grid gap-10 md:grid-cols-[280px_1fr]">
          <Skeleton className="aspect-[2/3]" />
          <div className="space-y-4">
            <Skeleton className="h-8 w-2/3" />
            <Skeleton className="h-5 w-1/3" />
            <Skeleton className="h-32 w-full" />
          </div>
        </div>
      </>
    );

  if (book.isError) {
    const notFound = book.error instanceof ApiError && book.error.status === 404;
    return (
      <>
        {back}
        {notFound ? (
          <EmptyState icon={Info} title="Book not found" action={<Link className="font-semibold text-royal-600" to="/books">Back to the catalogue</Link>}>
            This title does not exist or is not available to your account. For privacy, the library gives the same answer in both cases.
          </EmptyState>
        ) : (
          <ErrorMessage error={book.error} onRetry={() => book.refetch()} />
        )}
      </>
    );
  }

  const b = book.data!;
  const e = eligibility(b, me, loans.data, res.data);
  const facts = [
    { icon: Hash, label: "ISBN", value: b.isbn },
    { icon: Tag, label: "Category", value: b.category },
    { icon: CalendarDays, label: "Published", value: b.year ?? "—" },
    { icon: Copy, label: "Total copies", value: b.copies_total },
    { icon: BookCheck, label: "Available copies", value: b.copies_available },
    { icon: Layers, label: "Collection", value: b.collection_id },
  ];

  return (
    <>
      {back}
      <div className="grid gap-10 md:grid-cols-[minmax(220px,300px)_1fr]">
        <div>
          <div className="relative mx-auto max-w-[300px]">
            <div className="absolute -inset-6 -z-10 rounded-[40px] bg-gradient-to-br from-royal-200/50 to-violet-200/50 blur-2xl" />
            <BookCover book={b} size="lg" />
          </div>
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap gap-2">
            <Badge tone="blue">{b.category}</Badge>
            {b.has_digital && <Badge tone="violet">E-book available</Badge>}
            <AvailabilityBadge available={b.copies_available} total={b.copies_total} digital={b.has_digital} />
          </div>
          <h1 className="mt-4 text-3xl font-bold tracking-tight text-ink-950 sm:text-4xl">{b.title}</h1>
          <p className="mt-2 text-lg text-ink-500">by {b.author}</p>
          {b.description && <p className="mt-6 max-w-2xl text-[15px] leading-relaxed text-ink-700">{b.description}</p>}

          <Card className="mt-8 p-5">
            <p className="text-sm font-semibold text-ink-900">Borrowing eligibility</p>
            <p className="mt-1 text-sm text-ink-600">{e.text}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {e.kind === "borrow" && (
                <Button icon={BookCheck} loading={borrow.isPending} onClick={() => borrow.mutate(b.id)}>
                  Borrow book
                </Button>
              )}
              {e.kind === "reserve" && (
                <Button icon={CalendarPlus} loading={reserve.isPending} onClick={() => reserve.mutate(b.id)}>
                  Reserve book
                </Button>
              )}
              {e.kind === "loan" && (
                <Link to="/my-books" className="inline-flex h-10 items-center rounded-xl bg-royal-50 px-4 text-sm font-semibold text-royal-700">
                  Manage my loan
                </Link>
              )}
              {e.kind === "reserved" && (
                <Link to="/reservations" className="inline-flex h-10 items-center rounded-xl bg-violet-50 px-4 text-sm font-semibold text-violet-700">
                  View reservation
                </Link>
              )}
              {b.has_digital && (
                <Link to={`/ebooks/${b.id}/read`} className="inline-flex h-10 items-center gap-2 rounded-xl border border-ink-200 bg-white px-4 text-sm font-semibold text-ink-800 hover:bg-ink-50">
                  <BookOpenText className="size-4" /> Read e-book
                </Link>
              )}
            </div>
          </Card>

          <dl className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3">
            {facts.map(({ icon: Icon, label, value }) => (
              <div key={label} className="rounded-xl border border-ink-200/70 bg-white p-4">
                <dt className="flex items-center gap-1.5 text-xs font-medium text-ink-500">
                  <Icon className="size-3.5" /> {label}
                </dt>
                <dd className="mt-1 truncate font-semibold text-ink-900">{value}</dd>
              </div>
            ))}
          </dl>

          <div className="mt-6">
            <Notice icon={ShieldCheck}>
              You can see this title because your account has access to its collection. When you borrow, reserve or read it, the library checks your access again at that moment.
            </Notice>
          </div>
        </div>
      </div>
    </>
  );
}
