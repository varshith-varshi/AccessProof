import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  BookCheck,
  CalendarClock,
  CheckCircle2,
  Fingerprint,
  GraduationCap,
  Library,
  LineChart,
  MonitorSmartphone,
  Search,
  ShieldCheck,
  Sparkles,
  ScrollText,
  Users,
} from "lucide-react";
import { Link } from "react-router-dom";
import { BookCover, PublicBookCard } from "../components/books";
import { Skeleton } from "../components/ui";
import { api, type PublicBook } from "../lib/api";
import { useAuth } from "../lib/auth";

interface Overview {
  titles: number;
  copies: number;
  ebooks: number;
  categories: number;
  members: number;
  loans_served: number;
}

const FEATURES = [
  { icon: Search, title: "Smart Book Search", text: "Search titles, authors, ISBNs, categories and keywords, with filters for availability and format." },
  { icon: BookCheck, title: "Easy Borrowing & Returns", text: "Borrow in one click, renew online and see due dates and fines before they surprise you." },
  { icon: MonitorSmartphone, title: "Digital E-Book Library", text: "Read digital editions in a comfortable reader with adjustable text and light or dark pages." },
  { icon: Sparkles, title: "Personalized Recommendations", text: "Suggestions from your borrowing history and similar readers — each with a reason you can see." },
  { icon: CalendarClock, title: "Online Reservations", text: "Join a fair, first-come queue. A returned copy is held for you and nobody else." },
  { icon: ShieldCheck, title: "Secure Access Management", text: "Access is checked before a title is shown and again before it is released. Revocations apply instantly." },
];

function Hero({ books }: { books: PublicBook[] | undefined }) {
  const { me } = useAuth();
  const covers = books?.slice(0, 3) ?? [];
  return (
    <section id="top" className="relative overflow-hidden pt-28 pb-20 sm:pt-36 lg:pb-28">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(60%_50%_at_70%_10%,rgb(124_58_237/0.13),transparent),radial-gradient(50%_60%_at_10%_20%,rgb(35_70_224/0.12),transparent)]" />
      <div className="absolute inset-0 -z-10 bg-[linear-gradient(to_right,rgb(12_22_54/0.04)_1px,transparent_1px),linear-gradient(to_bottom,rgb(12_22_54/0.04)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />
      <div className="mx-auto grid max-w-7xl items-center gap-14 px-4 sm:px-6 lg:grid-cols-[1.1fr_1fr] lg:px-8">
        <div className="animate-fade-up">
          <span className="inline-flex items-center gap-2 rounded-full border border-royal-100 bg-white/80 px-3 py-1 text-xs font-semibold text-royal-700 shadow-sm backdrop-blur">
            <span className="size-1.5 rounded-full bg-emerald-500" /> University digital library platform
          </span>
          <h1 className="mt-6 text-[42px] leading-[1.05] font-extrabold tracking-tight text-ink-950 sm:text-6xl">
            Your Library.
            <br />
            <span className="text-gradient">Smarter Than Ever.</span>
          </h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-ink-500">
            Discover books, manage your borrowing, access digital resources, and explore knowledge through one intelligent library platform.
          </p>
          <div className="mt-9 flex flex-wrap gap-3">
            <Link to={me ? "/books" : "/login"} className="inline-flex h-12 items-center gap-2 rounded-xl bg-gradient-to-b from-royal-500 to-royal-600 px-6 text-[15px] font-semibold text-white shadow-xl shadow-royal-600/30 transition hover:-translate-y-0.5 hover:to-royal-700">
              Explore Library <ArrowRight className="size-4" />
            </Link>
            <Link to={me ? "/dashboard" : "/login"} className="inline-flex h-12 items-center rounded-xl border border-ink-200 bg-white px-6 text-[15px] font-semibold text-ink-800 shadow-sm transition hover:-translate-y-0.5 hover:border-ink-300">
              Get Started
            </Link>
          </div>
          <div className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-ink-500">
            {["Member-level access control", "Fail-closed security", "Full audit trail"].map((t) => (
              <span key={t} className="inline-flex items-center gap-1.5">
                <CheckCircle2 className="size-4 text-emerald-500" /> {t}
              </span>
            ))}
          </div>
        </div>

        <div className="relative mx-auto h-[420px] w-full max-w-[480px] sm:h-[460px]" aria-hidden>
          <div className="absolute inset-6 rounded-[32px] bg-gradient-to-br from-royal-600 via-royal-500 to-violet-600 opacity-95 shadow-2xl shadow-royal-600/30" />
          <div className="absolute inset-6 rounded-[32px] bg-[radial-gradient(circle_at_30%_20%,rgb(255_255_255/0.25),transparent_45%)]" />
          {covers.length > 0 ? (
            <div className="absolute inset-x-0 top-16 flex justify-center gap-4 px-10">
              {covers.map((b, i) => (
                <div key={b.id} className={i === 1 ? "w-[34%] -translate-y-4 animate-float" : "w-[28%] translate-y-6 animate-float-slow"} style={{ ["--r" as string]: `${(i - 1) * 4}deg` }}>
                  <BookCover book={b} size="sm" className="shadow-2xl" />
                </div>
              ))}
            </div>
          ) : (
            <div className="absolute inset-x-16 top-20 flex gap-4">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="aspect-[2/3] flex-1 bg-white/20" />
              ))}
            </div>
          )}
          <div className="absolute -left-2 bottom-24 w-56 rounded-2xl border border-white/60 bg-white/90 p-3.5 shadow-xl backdrop-blur animate-float-slow sm:-left-6">
            <div className="flex items-center gap-2 rounded-xl bg-ink-50 px-3 py-2 text-xs text-ink-400">
              <Search className="size-3.5" /> machine learning
            </div>
            <div className="mt-2.5 space-y-1.5">
              {["Deep Learning", "Hands-On Machine Learning"].map((t) => (
                <div key={t} className="flex items-center justify-between text-xs">
                  <span className="truncate font-medium text-ink-700">{t}</span>
                  <span className="ml-2 rounded-full bg-emerald-50 px-1.5 text-[10px] font-semibold text-emerald-700">In</span>
                </div>
              ))}
            </div>
          </div>
          <div className="absolute -right-1 bottom-8 w-52 rounded-2xl border border-white/60 bg-white/90 p-3.5 shadow-xl backdrop-blur animate-float sm:-right-4">
            <div className="flex items-center gap-2.5">
              <div className="grid size-9 place-items-center rounded-xl bg-emerald-50 text-emerald-600">
                <ShieldCheck className="size-5" />
              </div>
              <div>
                <p className="text-xs font-semibold text-ink-900">Access verified</p>
                <p className="text-[11px] text-ink-500">Layer 2 check · just now</p>
              </div>
            </div>
          </div>
          <div className="absolute top-3 right-2 rounded-2xl border border-white/60 bg-white/90 px-3.5 py-2.5 shadow-xl backdrop-blur animate-float-slow sm:right-0">
            <p className="text-[11px] text-ink-500">Due back</p>
            <p className="text-sm font-bold text-ink-900">in 12 days</p>
          </div>
        </div>
      </div>
    </section>
  );
}

function Stat({ value, label, loading }: { value: number | undefined; label: string; loading: boolean }) {
  return (
    <div className="text-center">
      {loading ? <Skeleton className="mx-auto h-10 w-20 bg-white/10" /> : <p className="text-4xl font-extrabold tracking-tight text-white tabular-nums">{value?.toLocaleString() ?? "—"}</p>}
      <p className="mt-1 text-sm text-ink-300">{label}</p>
    </div>
  );
}

function Shelf({ id, title, subtitle, books, loading }: { id: string; title: string; subtitle: string; books: PublicBook[] | undefined; loading: boolean }) {
  return (
    <section id={id} className="mx-auto max-w-7xl scroll-mt-20 px-4 py-14 sm:px-6 lg:px-8">
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-ink-950 sm:text-3xl">{title}</h2>
          <p className="mt-1 text-ink-500">{subtitle}</p>
        </div>
        <Link to="/books" className="inline-flex items-center gap-1 text-sm font-semibold text-royal-600 hover:text-royal-700">
          Browse the full catalogue <ArrowRight className="size-4" />
        </Link>
      </div>
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-4 lg:grid-cols-6">
        {loading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div key={i}>
                <Skeleton className="aspect-[2/3]" />
                <Skeleton className="mt-3 h-4 w-4/5" />
              </div>
            ))
          : books?.slice(0, 6).map((b) => <PublicBookCard key={b.id} book={b} />)}
      </div>
    </section>
  );
}

export default function Landing() {
  const overview = useQuery({ queryKey: ["public", "overview"], queryFn: () => api<Overview>("/public/overview") });
  const popular = useQuery({ queryKey: ["public", "popular"], queryFn: () => api<PublicBook[]>("/public/books?sort=popular&limit=6") });
  const recent = useQuery({ queryKey: ["public", "recent"], queryFn: () => api<PublicBook[]>("/public/books?sort=recent&limit=6") });
  const o = overview.data;

  return (
    <>
      <Hero books={popular.data} />

      <section id="features" className="scroll-mt-16 bg-white py-20">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-semibold tracking-[0.14em] text-royal-600 uppercase">Features</p>
            <h2 className="mt-2 text-3xl font-bold tracking-tight text-ink-950 sm:text-4xl">Everything your library needs, in one place</h2>
            <p className="mt-4 text-lg text-ink-500">Built for students who want to find and borrow quickly, and for librarians who need control and visibility.</p>
          </div>
          <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <div key={title} className="group relative overflow-hidden rounded-2xl border border-ink-200/70 bg-gradient-to-b from-white to-ink-50/60 p-6 transition duration-300 hover:-translate-y-1 hover:border-royal-200 hover:shadow-lift">
                <div className="absolute -top-10 -right-10 size-32 rounded-full bg-gradient-to-br from-royal-100 to-violet-100 opacity-0 blur-2xl transition duration-500 group-hover:opacity-100" />
                <div className="relative grid size-12 place-items-center rounded-xl bg-gradient-to-br from-royal-600 to-violet-600 text-white shadow-lg shadow-royal-600/25 transition group-hover:scale-110">
                  <Icon className="size-[22px]" aria-hidden />
                </div>
                <h3 className="relative mt-5 text-lg font-semibold text-ink-950">{title}</h3>
                <p className="relative mt-2 text-[15px] leading-relaxed text-ink-500">{text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <Shelf id="explore" title="Popular with members" subtitle="The most borrowed titles from our open collections." books={popular.data} loading={popular.isLoading} />

      <section className="relative overflow-hidden bg-ink-950 py-16">
        <div className="absolute inset-0 bg-[radial-gradient(50%_80%_at_20%_0%,rgb(35_70_224/0.35),transparent),radial-gradient(40%_80%_at_90%_100%,rgb(124_58_237/0.3),transparent)]" />
        <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <h2 className="text-center text-sm font-semibold tracking-[0.14em] text-royal-400 uppercase">The library in numbers</h2>
          <div className="mt-8 grid grid-cols-2 gap-8 md:grid-cols-5">
            <Stat value={o?.titles} label="Titles on open shelves" loading={overview.isLoading} />
            <Stat value={o?.copies} label="Physical copies" loading={overview.isLoading} />
            <Stat value={o?.ebooks} label="Digital editions" loading={overview.isLoading} />
            <Stat value={o?.categories} label="Subject areas" loading={overview.isLoading} />
            <Stat value={o?.loans_served} label="Loans served" loading={overview.isLoading} />
          </div>
          <p className="mt-8 text-center text-xs text-ink-500">Live figures from the library database. Restricted collections are not counted.</p>
        </div>
      </section>

      <Shelf id="recent" title="Recently added" subtitle="New arrivals on the open shelves." books={recent.data} loading={recent.isLoading} />

      <section className="bg-white py-20">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-2xl text-center">
            <p className="text-sm font-semibold tracking-[0.14em] text-royal-600 uppercase">How it works</p>
            <h2 className="mt-2 text-3xl font-bold tracking-tight text-ink-950 sm:text-4xl">From search to shelf in four steps</h2>
          </div>
          <ol className="mt-14 grid gap-6 md:grid-cols-4">
            {[
              { icon: Fingerprint, t: "Sign in", d: "Your verified identity decides what you can see — never just an email address." },
              { icon: Search, t: "Discover", d: "Search and filter. Only titles you are allowed to use ever appear." },
              { icon: BookCheck, t: "Borrow or reserve", d: "Access is re-checked at the moment of release, so revoked access is refused." },
              { icon: MonitorSmartphone, t: "Read & return", d: "Read e-books online, renew loans and return on time to avoid fines." },
            ].map(({ icon: Icon, t, d }, i) => (
              <li key={t} className="relative rounded-2xl border border-ink-200/70 p-6">
                <span className="absolute top-5 right-5 text-5xl font-extrabold text-ink-100">{i + 1}</span>
                <Icon className="size-7 text-royal-600" aria-hidden />
                <h3 className="mt-4 font-semibold text-ink-950">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-ink-500">{d}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section id="about" className="scroll-mt-16 py-20">
        <div className="mx-auto grid max-w-7xl gap-6 px-4 sm:px-6 lg:grid-cols-2 lg:px-8">
          <div className="rounded-3xl bg-gradient-to-br from-royal-600 to-royal-700 p-8 text-white shadow-xl shadow-royal-600/20 sm:p-10">
            <GraduationCap className="size-9 text-royal-200" aria-hidden />
            <h3 className="mt-5 text-2xl font-bold">For students</h3>
            <ul className="mt-6 space-y-3 text-[15px] text-royal-50">
              {["Find the right book in seconds with smart search and filters", "Track due dates, renew online and avoid late fines", "Reserve titles that are out and get the next copy held for you", "Read digital editions anywhere, on any device", "Discover books through transparent recommendations"].map((x) => (
                <li key={x} className="flex gap-3">
                  <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-royal-200" /> {x}
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-3xl bg-gradient-to-br from-ink-900 to-ink-950 p-8 text-white shadow-xl sm:p-10">
            <Library className="size-9 text-violet-300" aria-hidden />
            <h3 className="mt-5 text-2xl font-bold">For librarians</h3>
            <ul className="mt-6 space-y-3 text-[15px] text-ink-200">
              {[
                [LineChart, "Live circulation dashboards and reports"],
                [BookCheck, "Inventory management with stock-safe edits"],
                [Users, "Member overview, suspensions and group access"],
                [ShieldCheck, "Grant or revoke collection access with instant effect"],
                [ScrollText, "Append-only audit log of every allow and deny decision"],
              ].map(([Icon, x]) => {
                const I = Icon as typeof LineChart;
                return (
                  <li key={x as string} className="flex gap-3">
                    <I className="mt-0.5 size-5 shrink-0 text-violet-300" /> {x as string}
                  </li>
                );
              })}
            </ul>
          </div>
        </div>
        <div className="mx-auto mt-6 max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-3xl border border-ink-200/70 bg-white p-8 sm:p-10">
            <div className="grid gap-8 lg:grid-cols-[1fr_1.4fr]">
              <div>
                <p className="text-sm font-semibold tracking-[0.14em] text-royal-600 uppercase">About the platform</p>
                <h3 className="mt-2 text-2xl font-bold text-ink-950">Security that the library can prove</h3>
                <p className="mt-3 text-ink-500">Smart Library applies the AccessProof access model to library resources. Every decision is made by the server and recorded.</p>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                {[
                  ["Verified identity", "Signed member tokens. An email address alone is never accepted."],
                  ["Two checks", "Before a title is shown, and again right before it is borrowed, reserved or read."],
                  ["Instant revocation", "Removing access blocks the next request, even mid-checkout."],
                  ["Fail closed", "If permissions cannot be verified — stale policy or guard down — the answer is no."],
                ].map(([t, d]) => (
                  <div key={t} className="rounded-2xl bg-ink-50 p-5">
                    <p className="font-semibold text-ink-900">{t}</p>
                    <p className="mt-1 text-sm text-ink-500">{d}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="px-4 pb-20 sm:px-6 lg:px-8">
        <div className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl bg-gradient-to-r from-royal-600 via-royal-600 to-violet-600 px-8 py-14 text-center shadow-2xl shadow-royal-600/25">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_0%,rgb(255_255_255/0.2),transparent_40%)]" />
          <h2 className="relative text-3xl font-bold text-white sm:text-4xl">Ready to explore?</h2>
          <p className="relative mx-auto mt-3 max-w-xl text-royal-100">Sign in with a demo identity to search, borrow, reserve and read — or open the librarian console.</p>
          <Link to="/login" className="relative mt-8 inline-flex h-12 items-center gap-2 rounded-xl bg-white px-6 font-semibold text-royal-700 shadow-lg transition hover:-translate-y-0.5">
            Get Started <ArrowRight className="size-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
