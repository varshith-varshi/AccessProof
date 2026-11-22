import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { ArrowLeft, ChevronLeft, ChevronRight, Minus, Moon, Plus, ShieldX, Sun, Coffee } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Button, ErrorMessage, Skeleton } from "../components/ui";
import { api, ApiError, freshAttestation, friendlyError } from "../lib/api";

interface Content {
  book_id: string;
  title: string;
  author: string;
  content: string;
}

type Theme = "light" | "sepia" | "dark";
const THEMES: Record<Theme, string> = {
  light: "bg-white text-ink-900",
  sepia: "bg-[#f7f0e1] text-[#3d3020]",
  dark: "bg-[#0f1424] text-[#d9deec]",
};

function load<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}
function save(key: string, v: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* preferences are a convenience only */
  }
}

export default function Reader() {
  const { id = "" } = useParams();
  // Content is requested through Layer 2 every time the reader opens and is never cached.
  const content = useQuery({
    queryKey: ["read", id],
    queryFn: async () => {
      const attestation = await freshAttestation(id);
      return api<Content>(`/books/${encodeURIComponent(id)}/read`, { method: "POST", json: { attestation } });
    },
    gcTime: 0,
    staleTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const [size, setSize] = useState<number>(() => load("sl.reader.size", 19));
  const [theme, setTheme] = useState<Theme>(() => load("sl.reader.theme", "light"));
  const [page, setPage] = useState<number>(() => load(`sl.reader.pos.${id}`, 0));
  useEffect(() => save("sl.reader.size", size), [size]);
  useEffect(() => save("sl.reader.theme", theme), [theme]);
  useEffect(() => save(`sl.reader.pos.${id}`, page), [id, page]);

  const sections = useMemo(() => {
    const text = content.data?.content ?? "";
    const parts = text.split(/^## /m).filter((p) => p.trim());
    return parts.map((p) => {
      const hasHeading = text.includes(`## ${p.split("\n")[0]}`);
      const [first, ...rest] = p.split("\n");
      return hasHeading ? { heading: first.trim(), body: rest.join("\n").trim() } : { heading: "", body: p.trim() };
    });
  }, [content.data]);
  const current = Math.min(page, Math.max(0, sections.length - 1));
  const progress = sections.length ? ((current + 1) / sections.length) * 100 : 0;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === "INPUT") return;
      if (e.key === "ArrowRight") setPage((p) => Math.min(p + 1, sections.length - 1));
      if (e.key === "ArrowLeft") setPage((p) => Math.max(p - 1, 0));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sections.length]);

  const denied = content.error instanceof ApiError && (content.error.status === 403 || content.error.status === 503 || content.error.status === 404);

  return (
    <div className={clsx("min-h-screen transition-colors", THEMES[theme])}>
      <header className={clsx("sticky top-0 z-10 border-b backdrop-blur", theme === "dark" ? "border-white/10 bg-[#0f1424]/90" : theme === "sepia" ? "border-black/10 bg-[#f7f0e1]/90" : "border-ink-200 bg-white/90")}>
        <div className="mx-auto flex h-14 max-w-4xl items-center gap-3 px-4">
          <Link to="/ebooks" className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-sm font-semibold opacity-80 hover:opacity-100" aria-label="Back to the digital library">
            <ArrowLeft className="size-4" /> <span className="hidden sm:inline">Library</span>
          </Link>
          <p className="min-w-0 flex-1 truncate text-center text-sm font-semibold">{content.data?.title ?? "Opening…"}</p>
          <div className="flex items-center gap-1" role="group" aria-label="Reading settings">
            <button className="rounded-lg p-2 opacity-80 hover:opacity-100" onClick={() => setSize((s) => Math.max(14, s - 1))} aria-label="Smaller text">
              <Minus className="size-4" />
            </button>
            <span className="w-8 text-center text-xs tabular-nums opacity-70">{size}</span>
            <button className="rounded-lg p-2 opacity-80 hover:opacity-100" onClick={() => setSize((s) => Math.min(28, s + 1))} aria-label="Larger text">
              <Plus className="size-4" />
            </button>
            {(
              [
                ["light", Sun],
                ["sepia", Coffee],
                ["dark", Moon],
              ] as const
            ).map(([t, Icon]) => (
              <button key={t} onClick={() => setTheme(t)} aria-pressed={theme === t} aria-label={`${t} page`} className={clsx("rounded-lg p-2 transition", theme === t ? "bg-royal-500/15 text-royal-500" : "opacity-70 hover:opacity-100")}>
                <Icon className="size-4" />
              </button>
            ))}
          </div>
        </div>
        <div className="h-0.5 bg-current/10">
          <div className="h-full bg-gradient-to-r from-royal-500 to-violet-500 transition-all" style={{ width: `${progress}%` }} />
        </div>
      </header>

      <main className="mx-auto max-w-2xl px-5 py-12 sm:py-16">
        {content.isLoading && (
          <div className="space-y-4">
            <Skeleton className="h-8 w-2/3" />
            {[0, 1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        )}
        {content.isError &&
          (denied ? (
            <div className="rounded-2xl border border-rose-200 bg-rose-50 p-8 text-center text-rose-900">
              <ShieldX className="mx-auto size-10 text-rose-500" />
              <h1 className="mt-4 text-lg font-bold">This e-book cannot be opened</h1>
              <p className="mt-2 text-sm">{friendlyError(content.error)}</p>
              <p className="mt-2 text-xs text-rose-700">The library re-checks your access each time content is requested. This attempt has been recorded.</p>
              <Link to="/ebooks" className="mt-5 inline-flex h-10 items-center rounded-xl bg-white px-4 text-sm font-semibold text-ink-800 shadow-sm">
                Back to the digital library
              </Link>
            </div>
          ) : (
            <ErrorMessage error={content.error} onRetry={() => content.refetch()} />
          ))}
        {content.data && sections[current] && (
          <article style={{ fontSize: `${size}px` }} className="font-serif leading-[1.75]">
            {current === 0 && (
              <div className="mb-10 text-center font-sans">
                <h1 className="text-3xl font-bold tracking-tight">{content.data.title}</h1>
                <p className="mt-2 opacity-70">{content.data.author}</p>
              </div>
            )}
            {sections[current].heading && <h2 className="mb-6 font-sans text-[1.25em] font-bold">{sections[current].heading}</h2>}
            {sections[current].body.split(/\n\s*\n/).map((para, i) => (
              <p key={i} className="mb-5 [text-wrap:pretty]">
                {para}
              </p>
            ))}
          </article>
        )}
        {content.data && sections.length > 0 && (
          <nav className="mt-12 flex items-center justify-between gap-4 font-sans" aria-label="Chapters">
            <Button variant="secondary" icon={ChevronLeft} disabled={current === 0} onClick={() => setPage(current - 1)}>
              Previous
            </Button>
            <span className="text-sm opacity-70">
              Section {current + 1} of {sections.length}
            </span>
            <Button variant="secondary" disabled={current >= sections.length - 1} onClick={() => setPage(current + 1)}>
              Next <ChevronRight className="size-4" />
            </Button>
          </nav>
        )}
      </main>
    </div>
  );
}
