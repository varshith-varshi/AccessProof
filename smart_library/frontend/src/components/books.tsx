import { clsx } from "clsx";
import { BookOpen, MonitorSmartphone, Search, ShieldCheck, ShieldAlert, X } from "lucide-react";
import { memo, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Book, type GuardStatus, type PublicBook } from "../lib/api";
import { AvailabilityBadge, Badge, Skeleton } from "./ui";

// Original generated covers: a deterministic palette per title, so every book has a
// consistent, recognisable cover without depending on external image services.
const PALETTES = [
  ["#1a36b8", "#3b5cf5", "#c7d2fe"],
  ["#4c1d95", "#7c3aed", "#ddd6fe"],
  ["#0c1636", "#24336a", "#93c5fd"],
  ["#134e4a", "#0f766e", "#99f6e4"],
  ["#7c2d12", "#c2410c", "#fed7aa"],
  ["#831843", "#be185d", "#fbcfe8"],
  ["#1e3a8a", "#6d28d9", "#e0e7ff"],
  ["#14532d", "#15803d", "#bbf7d0"],
];

function hash(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export const BookCover = memo(function BookCover({
  book,
  size = "md",
  className,
}: {
  book: { id: string; title: string; author: string; category: string; cover_url?: string | null };
  size?: "xs" | "sm" | "md" | "lg";
  className?: string;
}) {
  const [imgFailed, setImgFailed] = useState(false);
  const h = hash(book.id + book.title);
  const [a, b, c] = PALETTES[h % PALETTES.length];
  const pattern = h % 3;
  const text = { xs: "text-[7px]", sm: "text-[10px]", md: "text-[13px]", lg: "text-xl" }[size];
  const pad = { xs: "p-1.5", sm: "p-2.5", md: "p-4", lg: "p-7" }[size];
  return (
    <div
      className={clsx("relative aspect-[2/3] overflow-hidden rounded-[6px] shadow-[0_10px_24px_-10px_rgb(12_22_54/0.55)] ring-1 ring-black/5", className)}
      style={{ background: `linear-gradient(150deg, ${a} 0%, ${b} 100%)` }}
      aria-hidden
    >
      {book.cover_url && !imgFailed ? (
        <img src={book.cover_url} alt="" loading="lazy" onError={() => setImgFailed(true)} className="absolute inset-0 size-full object-cover" />
      ) : (
        <>
          <svg className="absolute inset-0 size-full opacity-[0.16]" viewBox="0 0 100 150" preserveAspectRatio="none">
            {pattern === 0 && <circle cx="85" cy="20" r="45" fill={c} />}
            {pattern === 1 && (
              <g stroke={c} strokeWidth="0.8" fill="none">
                {Array.from({ length: 9 }).map((_, i) => (
                  <path key={i} d={`M-10 ${60 + i * 9} Q 50 ${40 + i * 9} 110 ${70 + i * 9}`} />
                ))}
              </g>
            )}
            {pattern === 2 && <rect x="58" y="-10" width="70" height="170" fill={c} transform="rotate(18 60 60)" />}
          </svg>
          <div className="absolute inset-y-0 left-0 w-[6%] bg-black/20" />
          <div className={clsx("relative flex h-full flex-col justify-between text-white", pad)}>
            <span className={clsx("font-semibold tracking-[0.16em] uppercase opacity-75", size === "lg" ? "text-xs" : "text-[8px]", size === "xs" && "hidden")}>{book.category}</span>
            <div>
              <p className={clsx("line-clamp-4 leading-tight font-bold", text)}>{book.title}</p>
              <p className={clsx("mt-1 line-clamp-1 opacity-75", size === "lg" ? "text-sm" : "text-[9px]", size === "xs" && "hidden")}>{book.author}</p>
            </div>
          </div>
        </>
      )}
    </div>
  );
});

export function BookCard({ book, action }: { book: Book; action?: React.ReactNode }) {
  return (
    <article className="group card flex flex-col overflow-hidden p-4 transition duration-200 hover:-translate-y-1 hover:border-royal-200 hover:shadow-lift">
      <Link to={`/books/${book.id}`} className="block rounded-lg focus-visible:outline-offset-4" aria-label={`${book.title} by ${book.author}`}>
        <div className="mx-auto w-[62%] transition duration-300 group-hover:scale-[1.03] group-hover:-rotate-1">
          <BookCover book={book} size="sm" />
        </div>
      </Link>
      <div className="mt-4 flex flex-1 flex-col">
        <div className="mb-2 flex flex-wrap items-center gap-1.5">
          <Badge tone="blue">{book.category}</Badge>
          {book.has_digital && (
            <Badge tone="violet">
              <MonitorSmartphone className="size-3" /> E-book
            </Badge>
          )}
        </div>
        <Link to={`/books/${book.id}`} className="line-clamp-2 font-semibold leading-snug text-ink-950 hover:text-royal-600">
          {book.title}
        </Link>
        <p className="mt-0.5 line-clamp-1 text-sm text-ink-500">{book.author}</p>
        {book.reason && <p className="mt-2 line-clamp-2 text-xs text-violet-700">✦ {book.reason}</p>}
        <div className="mt-auto pt-3">
          <AvailabilityBadge available={book.copies_available} total={book.copies_total} digital={book.has_digital} />
        </div>
        {action && <div className="mt-3 flex gap-2">{action}</div>}
      </div>
    </article>
  );
}

export function PublicBookCard({ book }: { book: PublicBook }) {
  return (
    <article className="group">
      <div className="transition duration-300 group-hover:-translate-y-1.5 group-hover:-rotate-1">
        <BookCover book={book} size="sm" />
      </div>
      <h3 className="mt-3 line-clamp-2 text-sm font-semibold leading-snug text-ink-900">{book.title}</h3>
      <p className="mt-0.5 line-clamp-1 text-xs text-ink-500">{book.author}</p>
    </article>
  );
}

export function BookGridSkeleton({ count = 8 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="card p-4">
          <Skeleton className="mx-auto aspect-[2/3] w-[62%]" />
          <Skeleton className="mt-4 h-4 w-20" />
          <Skeleton className="mt-3 h-4 w-full" />
          <Skeleton className="mt-2 h-3 w-2/3" />
          <Skeleton className="mt-4 h-5 w-28 rounded-full" />
        </div>
      ))}
    </div>
  );
}

export function SearchBar({ value, onChange, placeholder = "Search by title, author, ISBN, category or keyword", autoFocus }: { value: string; onChange: (v: string) => void; placeholder?: string; autoFocus?: boolean }) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute top-1/2 left-4 size-5 -translate-y-1/2 text-ink-400" aria-hidden />
      <input
        type="search"
        value={value}
        autoFocus={autoFocus}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label="Search the catalogue"
        className="h-12 w-full rounded-2xl border border-ink-200 bg-white pr-11 pl-12 text-[15px] shadow-card transition placeholder:text-ink-400 focus:border-royal-500 focus:outline-none focus:ring-4 focus:ring-royal-100 [&::-webkit-search-cancel-button]:hidden"
      />
      {value && (
        <button onClick={() => onChange("")} className="absolute top-1/2 right-3 -translate-y-1/2 rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700" aria-label="Clear search">
          <X className="size-4" />
        </button>
      )}
    </div>
  );
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function GuardPill({ compact }: { compact?: boolean }) {
  const { data, isError } = useQuery({
    queryKey: ["guard"],
    queryFn: () => api<GuardStatus>("/guard/status"),
    refetchInterval: 30_000,
  });
  const ready = data?.ready && !isError;
  return (
    <div
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
        ready ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20" : "bg-rose-50 text-rose-700 ring-rose-600/20",
      )}
      title={ready ? "Every request is checked by the access guard" : "The guard cannot decide safely; protected requests are refused"}
    >
      {ready ? <ShieldCheck className="size-3.5" aria-hidden /> : <ShieldAlert className="size-3.5" aria-hidden />}
      {data ? (ready ? (compact ? "Guard ready" : `Access guard ready · policy rev ${data.installed_revision}`) : `Guard: ${data.not_ready_reason ?? "unavailable"}`) : "Checking guard…"}
    </div>
  );
}

export const Logo = ({ light }: { light?: boolean }) => (
  <span className="inline-flex items-center gap-2.5">
    <span className="grid size-9 place-items-center rounded-xl bg-gradient-to-br from-royal-600 to-violet-600 text-white shadow-lg shadow-royal-600/30">
      <BookOpen className="size-[18px]" aria-hidden />
    </span>
    <span className={clsx("text-[17px] font-bold tracking-tight", light ? "text-white" : "text-ink-950")}>
      Smart<span className={light ? "text-royal-400" : "text-royal-600"}>Library</span>
    </span>
  </span>
);
