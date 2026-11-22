import { clsx } from "clsx";
import {
  BarChart3,
  BookMarked,
  BookOpen,
  CalendarClock,
  ClipboardList,
  Gauge,
  Library,
  LogOut,
  Menu,
  MonitorSmartphone,
  Receipt,
  ScrollText,
  Settings2,
  Sparkles,
  UserRound,
  Users,
  X,
  LayoutDashboard,
  ArrowLeftRight,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, Navigate, Outlet, useLocation, useNavigate } from "react-router-dom";
import { GuardPill, Logo } from "../components/books";
import { Skeleton } from "../components/ui";
import { useAuth } from "../lib/auth";

// --- Public site ----------------------------------------------------------------------------
export function PublicNavbar() {
  const { me } = useAuth();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 8);
    on();
    window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);
  const links = [
    { href: "/#top", label: "Home" },
    { href: me ? "/books" : "/#explore", label: "Explore Books" },
    { href: "/#features", label: "Features" },
    { href: "/#about", label: "About" },
  ];
  return (
    <header className={clsx("fixed inset-x-0 top-0 z-40 transition-all duration-300", scrolled ? "border-b border-ink-200/60 bg-white/80 shadow-sm backdrop-blur-xl" : "bg-transparent")}>
      <nav className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8" aria-label="Main">
        <Link to="/" aria-label="Smart Library home">
          <Logo />
        </Link>
        <div className="hidden items-center gap-1 md:flex">
          {links.map((l) => (
            <a key={l.label} href={l.href} className="rounded-lg px-3 py-2 text-sm font-medium text-ink-600 transition hover:bg-ink-100/70 hover:text-ink-950">
              {l.label}
            </a>
          ))}
        </div>
        <div className="hidden items-center gap-2 md:flex">
          {me ? (
            <Link to={me.librarian ? "/admin" : "/dashboard"} className="inline-flex h-10 items-center rounded-xl bg-ink-950 px-4 text-sm font-semibold text-white transition hover:bg-ink-800">
              Open my library
            </Link>
          ) : (
            <>
              <Link to="/login" className="inline-flex h-10 items-center rounded-xl px-4 text-sm font-semibold text-ink-700 hover:bg-ink-100">
                Sign In
              </Link>
              <Link to="/login" className="inline-flex h-10 items-center rounded-xl bg-gradient-to-b from-royal-500 to-royal-600 px-4 text-sm font-semibold text-white shadow-lg shadow-royal-600/25 transition hover:to-royal-700">
                Explore Library
              </Link>
            </>
          )}
        </div>
        <button className="rounded-lg p-2 text-ink-700 hover:bg-ink-100 md:hidden" onClick={() => setOpen(!open)} aria-expanded={open} aria-label="Toggle menu">
          {open ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </nav>
      {open && (
        <div className="border-t border-ink-200 bg-white px-4 pb-4 shadow-lg md:hidden">
          {links.map((l) => (
            <a key={l.label} href={l.href} onClick={() => setOpen(false)} className="block rounded-lg px-3 py-3 text-[15px] font-medium text-ink-700 hover:bg-ink-50">
              {l.label}
            </a>
          ))}
          <Link to={me ? "/dashboard" : "/login"} onClick={() => setOpen(false)} className="mt-2 flex h-11 items-center justify-center rounded-xl bg-royal-600 text-sm font-semibold text-white">
            {me ? "Open my library" : "Sign In"}
          </Link>
        </div>
      )}
    </header>
  );
}

export function Footer() {
  return (
    <footer className="bg-ink-950 text-ink-300">
      <div className="mx-auto grid max-w-7xl gap-10 px-4 py-14 sm:px-6 md:grid-cols-4 lg:px-8">
        <div className="md:col-span-2">
          <Logo light />
          <p className="mt-4 max-w-sm text-sm leading-relaxed text-ink-400">
            A university library platform for discovering, borrowing and reading — with member-level access control on every request.
          </p>
          <p className="mt-6 text-xs text-ink-500">Demo deployment · sign-in uses demonstration identities.</p>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Library</h3>
          <ul className="mt-4 space-y-2.5 text-sm">
            <li><Link className="hover:text-white" to="/books">Catalogue</Link></li>
            <li><Link className="hover:text-white" to="/ebooks">Digital library</Link></li>
            <li><Link className="hover:text-white" to="/recommendations">Recommendations</Link></li>
            <li><Link className="hover:text-white" to="/my-books">My loans</Link></li>
          </ul>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Platform</h3>
          <ul className="mt-4 space-y-2.5 text-sm">
            <li><a className="hover:text-white" href="/#features">Features</a></li>
            <li><a className="hover:text-white" href="/#about">About & security</a></li>
            <li><a className="hover:text-white" href="/docs">API documentation</a></li>
            <li><Link className="hover:text-white" to="/login">Sign in</Link></li>
          </ul>
        </div>
      </div>
      <div className="border-t border-white/5 py-5 text-center text-xs text-ink-500">© {new Date().getFullYear()} Smart Library Management System</div>
    </footer>
  );
}

export function PublicLayout() {
  return (
    <div className="flex min-h-screen flex-col">
      <PublicNavbar />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

// --- App shell ------------------------------------------------------------------------------
interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
}

const MEMBER_NAV: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/books", label: "Catalogue", icon: Library },
  { to: "/my-books", label: "My Books", icon: BookMarked },
  { to: "/reservations", label: "Reservations", icon: CalendarClock },
  { to: "/ebooks", label: "Digital Library", icon: MonitorSmartphone },
  { to: "/recommendations", label: "For You", icon: Sparkles },
  { to: "/fines", label: "Fines", icon: Receipt },
  { to: "/profile", label: "Profile", icon: UserRound },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/admin", label: "Dashboard", icon: Gauge, end: true },
  { to: "/admin/books", label: "Book Inventory", icon: BookOpen },
  { to: "/admin/members", label: "Members", icon: Users },
  { to: "/admin/loans", label: "Borrowing Records", icon: ClipboardList },
  { to: "/admin/reservations", label: "Reservations", icon: CalendarClock },
  { to: "/admin/fines", label: "Fines", icon: Receipt },
  { to: "/admin/reports", label: "Reports", icon: BarChart3 },
  { to: "/admin/audit", label: "Audit Logs", icon: ScrollText },
  { to: "/admin/settings", label: "Access & Settings", icon: Settings2 },
];

function Sidebar({ admin, onNavigate }: { admin: boolean; onNavigate?: () => void }) {
  const { me, signOut } = useAuth();
  const navigate = useNavigate();
  const items = admin ? ADMIN_NAV : MEMBER_NAV;
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-16 items-center px-5">
        <Link to="/" onClick={onNavigate} aria-label="Smart Library home">
          <Logo light />
        </Link>
      </div>
      <p className="px-6 pt-4 pb-2 text-[11px] font-semibold tracking-[0.14em] text-ink-500 uppercase">{admin ? "Administration" : "Library"}</p>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3" aria-label={admin ? "Administration" : "Member"}>
        {items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              clsx(
                "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition",
                isActive ? "bg-gradient-to-r from-royal-600/90 to-violet-600/70 text-white shadow-lg shadow-royal-900/40" : "text-ink-300 hover:bg-white/5 hover:text-white",
              )
            }
          >
            <Icon className="size-[18px] shrink-0" aria-hidden />
            {label}
          </NavLink>
        ))}
        {me?.librarian && (
          <div className="pt-4">
            <NavLink
              to={admin ? "/dashboard" : "/admin"}
              onClick={onNavigate}
              className="flex items-center gap-3 rounded-xl border border-white/10 px-3 py-2.5 text-sm font-medium text-ink-300 transition hover:bg-white/5 hover:text-white"
            >
              <ArrowLeftRight className="size-[18px]" aria-hidden />
              {admin ? "Member view" : "Librarian console"}
            </NavLink>
          </div>
        )}
      </nav>
      <div className="m-3 rounded-2xl bg-white/5 p-3">
        <div className="flex items-center gap-3">
          <div className="grid size-9 shrink-0 place-items-center rounded-full bg-gradient-to-br from-royal-400 to-violet-500 text-sm font-bold text-white">{me?.name?.[0] ?? "?"}</div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-white">{me?.name ?? "…"}</p>
            <p className="truncate text-xs text-ink-400">{me?.librarian ? "Librarian" : "Member"} · demo identity</p>
          </div>
          <button
            onClick={() => {
              signOut();
              navigate("/login");
            }}
            className="rounded-lg p-2 text-ink-400 transition hover:bg-white/10 hover:text-white"
            aria-label="Sign out"
            title="Sign out"
          >
            <LogOut className="size-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

export function AppShell({ admin = false }: { admin?: boolean }) {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => {
    setOpen(false);
    window.scrollTo({ top: 0 });
  }, [location.pathname]);
  return (
    <div className="min-h-screen bg-ink-50">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 bg-ink-950 lg:block">
        <Sidebar admin={admin} />
      </aside>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-ink-950/50 backdrop-blur-sm" onClick={() => setOpen(false)} aria-hidden />
          <aside className="relative h-full w-72 max-w-[85%] bg-ink-950 shadow-2xl animate-[fade-up_.2s_ease-out]">
            <button onClick={() => setOpen(false)} className="absolute top-4 right-3 rounded-lg p-2 text-ink-300 hover:bg-white/10" aria-label="Close menu">
              <X className="size-5" />
            </button>
            <Sidebar admin={admin} onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-ink-200/70 bg-white/80 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <button className="-ml-1 rounded-lg p-2 text-ink-700 hover:bg-ink-100 lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu className="size-5" />
          </button>
          <span className="text-sm font-semibold text-ink-500 lg:hidden">{admin ? "Librarian console" : "Smart Library"}</span>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden rounded-full bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-800 ring-1 ring-amber-600/20 ring-inset sm:inline">Demo mode</span>
            <GuardPill />
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 animate-fade-up" key={location.pathname}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// --- Route guards (UX only — the API enforces every permission independently) ----------------
export function RequireAuth({ children, librarian }: { children: ReactNode; librarian?: boolean }) {
  const { token, me, loading } = useAuth();
  const location = useLocation();
  if (!token) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (loading || !me)
    return (
      <div className="mx-auto max-w-5xl space-y-4 p-8">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  if (librarian && !me.librarian) return <Navigate to="/403" replace />;
  return <>{children}</>;
}
