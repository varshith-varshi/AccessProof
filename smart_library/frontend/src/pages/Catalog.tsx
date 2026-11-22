import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { BookCheck, CalendarPlus, Filter, SearchX, ShieldCheck, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { BookCard, BookGridSkeleton, SearchBar, useDebounced } from "../components/books";
import { Button, EmptyState, ErrorMessage, PageHeader, Pagination } from "../components/ui";
import { api, type Book, type Page } from "../lib/api";
import { useBorrow, useReserve } from "../lib/actions";

interface Facets {
  categories: string[];
  authors: string[];
  total: number;
  digital: number;
}

export function BookAction({ book, size = "sm" }: { book: Book; size?: "sm" | "md" }) {
  const borrow = useBorrow();
  const reserve = useReserve();
  if (book.copies_total === 0) return null;
  return book.copies_available > 0 ? (
    <Button size={size} className="flex-1" icon={BookCheck} loading={borrow.isPending} onClick={() => borrow.mutate(book.id)}>
      Borrow
    </Button>
  ) : (
    <Button size={size} variant="soft" className="flex-1" icon={CalendarPlus} loading={reserve.isPending} onClick={() => reserve.mutate(book.id)}>
      Reserve
    </Button>
  );
}

const SORTS = [
  { value: "title", label: "Title A–Z" },
  { value: "recent", label: "Recently added" },
  { value: "year", label: "Newest publication" },
  { value: "year_asc", label: "Oldest publication" },
  { value: "popular", label: "Most borrowed" },
  { value: "author", label: "Author A–Z" },
];

export default function Catalog() {
  const [params, setParams] = useSearchParams();
  const [text, setText] = useState(params.get("q") ?? "");
  const q = useDebounced(text, 300);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const category = params.get("category") ?? "";
  const author = params.get("author") ?? "";
  const available = params.get("available") === "1";
  const format = params.get("format") ?? "";
  const sort = params.get("sort") ?? "title";
  const page = Number(params.get("page") ?? "1") || 1;

  function update(next: Record<string, string | null>, resetPage = true) {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(next)) (v ? p.set(k, v) : p.delete(k));
    if (resetPage && !("page" in next)) p.delete("page");
    setParams(p, { replace: true });
  }

  useEffect(() => {
    if ((params.get("q") ?? "") !== q) update({ q: q || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  const facets = useQuery({ queryKey: ["facets"], queryFn: () => api<Facets>("/catalog/facets"), staleTime: 60_000 });
  const qs = new URLSearchParams({ q, sort, page: String(page), page_size: "12" });
  if (category) qs.set("category", category);
  if (author) qs.set("author", author);
  if (available) qs.set("available", "true");
  if (format) qs.set("format", format);
  const result = useQuery({
    queryKey: ["catalog", qs.toString()],
    queryFn: () => api<Page<Book>>(`/catalog?${qs}`),
    placeholderData: keepPreviousData,
  });

  const activeFilters = [category && `Category: ${category}`, author && `Author: ${author}`, available && "Available now", format && (format === "digital" ? "E-books" : "Physical books")].filter(Boolean) as string[];
  const clearAll = () => {
    setText("");
    setParams(new URLSearchParams({ sort }), { replace: true });
  };

  const filterPanel = (
    <div className="space-y-5">
      <div>
        <label className="label" htmlFor="f-category">Category</label>
        <select id="f-category" className="input" value={category} onChange={(e) => update({ category: e.target.value || null })}>
          <option value="">All categories</option>
          {facets.data?.categories.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </div>
      <div>
        <label className="label" htmlFor="f-author">Author</label>
        <select id="f-author" className="input" value={author} onChange={(e) => update({ author: e.target.value || null })}>
          <option value="">All authors</option>
          {facets.data?.authors.map((a) => (
            <option key={a}>{a}</option>
          ))}
        </select>
      </div>
      <div>
        <span className="label">Format</span>
        <div className="grid grid-cols-3 gap-1 rounded-xl bg-ink-100 p-1">
          {[
            ["", "All"],
            ["physical", "Print"],
            ["digital", "E-book"],
          ].map(([v, l]) => (
            <button key={v} onClick={() => update({ format: v || null })} aria-pressed={format === v} className={clsx("rounded-lg py-1.5 text-xs font-semibold transition", format === v ? "bg-white text-ink-900 shadow-sm" : "text-ink-500 hover:text-ink-800")}>
              {l}
            </button>
          ))}
        </div>
      </div>
      <label className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-ink-200 bg-white px-3 py-2.5">
        <span className="text-sm font-medium text-ink-800">Available now only</span>
        <input type="checkbox" className="size-4 accent-royal-600" checked={available} onChange={(e) => update({ available: e.target.checked ? "1" : null })} />
      </label>
      {activeFilters.length > 0 && (
        <Button variant="ghost" size="sm" className="w-full" onClick={clearAll} icon={X}>
          Clear all filters
        </Button>
      )}
      <div className="rounded-xl bg-royal-50/70 p-3 text-xs text-ink-600">
        <ShieldCheck className="mb-1 size-4 text-royal-600" />
        Results are filtered by the access guard for your account. Restricted titles never appear, even if they match your search.
      </div>
    </div>
  );

  return (
    <>
      <PageHeader eyebrow="Catalogue" title="Explore books" subtitle={facets.data ? `${facets.data.total} titles available to you across ${facets.data.categories.length} categories.` : "Search the collections you have access to."} />

      <div className="mb-6 flex flex-col gap-3 sm:flex-row">
        <div className="flex-1">
          <SearchBar value={text} onChange={setText} />
        </div>
        <div className="flex gap-2">
          <select aria-label="Sort by" className="input h-12 w-auto rounded-2xl" value={sort} onChange={(e) => update({ sort: e.target.value })}>
            {SORTS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          <Button variant="secondary" className="h-12 rounded-2xl lg:hidden" icon={SlidersHorizontal} onClick={() => setFiltersOpen(!filtersOpen)} aria-expanded={filtersOpen}>
            Filters
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-[240px_1fr]">
        <aside className={clsx("lg:block", filtersOpen ? "block" : "hidden")} aria-label="Filters">
          <div className="card p-5 lg:sticky lg:top-24">
            <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-ink-900">
              <Filter className="size-4" /> Filters
            </h2>
            {filterPanel}
          </div>
        </aside>

        <section aria-live="polite" aria-busy={result.isFetching}>
          <div className="mb-4 flex min-h-8 flex-wrap items-center gap-2">
            <p className="text-sm text-ink-500">{result.data ? <><strong className="text-ink-900">{result.data.total}</strong> result{result.data.total === 1 ? "" : "s"}{q && <> for “{q}”</>}</> : "Searching…"}</p>
            {activeFilters.map((f) => (
              <span key={f} className="rounded-full bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700">
                {f}
              </span>
            ))}
          </div>
          {result.isError && <ErrorMessage error={result.error} onRetry={() => result.refetch()} />}
          {result.isLoading && <BookGridSkeleton count={8} />}
          {result.data && result.data.items.length === 0 && (
            <EmptyState icon={SearchX} title="No books found" action={<Button variant="secondary" onClick={clearAll}>Clear search and filters</Button>}>
              Try a different keyword or remove some filters. Titles from collections you cannot access are never shown.
            </EmptyState>
          )}
          {result.data && result.data.items.length > 0 && (
            <div className={clsx("grid grid-cols-2 gap-4 transition-opacity sm:grid-cols-3 xl:grid-cols-4", result.isFetching && "opacity-60")}>
              {result.data.items.map((b) => (
                <BookCard key={b.id} book={b} action={<BookAction book={b} />} />
              ))}
            </div>
          )}
          {result.data && (
            <div className="mt-8">
              <Pagination page={result.data.page} pages={result.data.pages} onChange={(p) => update({ page: String(p) }, false)} />
            </div>
          )}
        </section>
      </div>
    </>
  );
}
