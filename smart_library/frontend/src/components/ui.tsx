import { clsx } from "clsx";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Info,
  Loader2,
  X,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { friendlyError } from "../lib/api";

// --- Button ---------------------------------------------------------------------------------
type Variant = "primary" | "secondary" | "ghost" | "danger" | "soft";
const variants: Record<Variant, string> = {
  primary:
    "bg-gradient-to-b from-royal-500 to-royal-600 text-white shadow-[0_1px_0_rgb(255_255_255/0.2)_inset,0_6px_16px_-6px_rgb(35_70_224/0.6)] hover:from-royal-500 hover:to-royal-700",
  secondary: "border border-ink-200 bg-white text-ink-800 hover:border-ink-300 hover:bg-ink-50",
  ghost: "text-ink-600 hover:bg-ink-100 hover:text-ink-900",
  danger: "bg-rose-600 text-white hover:bg-rose-700 shadow-[0_6px_16px_-8px_rgb(225_29_72/0.7)]",
  soft: "bg-royal-50 text-royal-700 hover:bg-royal-100",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "sm" | "md" | "lg";
  loading?: boolean;
  icon?: LucideIcon;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", size = "md", loading, icon: Icon, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-xl font-semibold whitespace-nowrap transition-all duration-150 active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50",
        size === "sm" && "h-8 px-3 text-xs",
        size === "md" && "h-10 px-4 text-sm",
        size === "lg" && "h-12 px-6 text-[15px]",
        variants[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="size-4 animate-spin" aria-hidden /> : Icon ? <Icon className="size-4" aria-hidden /> : null}
      {children}
    </button>
  );
});

// --- Badges ---------------------------------------------------------------------------------
type Tone = "green" | "amber" | "red" | "blue" | "violet" | "gray";
const tones: Record<Tone, string> = {
  green: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  amber: "bg-amber-50 text-amber-800 ring-amber-600/25",
  red: "bg-rose-50 text-rose-700 ring-rose-600/20",
  blue: "bg-royal-50 text-royal-700 ring-royal-600/20",
  violet: "bg-violet-50 text-violet-700 ring-violet-600/20",
  gray: "bg-ink-100 text-ink-600 ring-ink-500/15",
};

export function Badge({ tone = "gray", children, dot, className }: { tone?: Tone; children: ReactNode; dot?: boolean; className?: string }) {
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset", tones[tone], className)}>
      {dot && <span className="size-1.5 rounded-full bg-current" aria-hidden />}
      {children}
    </span>
  );
}

const STATUS: Record<string, [Tone, string]> = {
  active: ["blue", "Active"],
  due_soon: ["amber", "Due soon"],
  overdue: ["red", "Overdue"],
  returned: ["gray", "Returned"],
  waiting: ["violet", "Waiting"],
  ready: ["green", "Ready for pickup"],
  fulfilled: ["gray", "Fulfilled"],
  cancelled: ["gray", "Cancelled"],
  allow: ["green", "Allowed"],
  deny: ["red", "Denied"],
  info: ["blue", "Info"],
  available: ["green", "Available"],
  unavailable: ["amber", "On loan"],
  suspended: ["red", "Suspended"],
};

export function StatusBadge({ status }: { status: string }) {
  const [tone, label] = STATUS[status] ?? ["gray", status];
  return (
    <Badge tone={tone} dot>
      {label}
    </Badge>
  );
}

export function AvailabilityBadge({ available, total, digital }: { available: number; total: number; digital?: boolean }) {
  if (total === 0 && digital) return <Badge tone="violet">E-book only</Badge>;
  return available > 0 ? (
    <Badge tone="green" dot>
      {available} of {total} available
    </Badge>
  ) : (
    <Badge tone="amber" dot>
      All copies on loan
    </Badge>
  );
}

// --- Cards ----------------------------------------------------------------------------------
export function Card({ className, children, ...rest }: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={clsx("card", className)} {...rest}>
      {children}
    </div>
  );
}

export function SectionTitle({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-lg font-semibold tracking-tight text-ink-900">{title}</h2>
        {subtitle && <p className="mt-0.5 text-sm text-ink-500">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions, eyebrow }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: string }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <p className="mb-1 text-xs font-semibold tracking-[0.14em] text-royal-600 uppercase">{eyebrow}</p>}
        <h1 className="text-2xl font-bold tracking-tight text-ink-950 sm:text-[28px]">{title}</h1>
        {subtitle && <p className="mt-1.5 max-w-2xl text-[15px] text-ink-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

const statTones = {
  blue: "from-royal-500 to-royal-600 shadow-royal-500/30",
  violet: "from-violet-500 to-violet-600 shadow-violet-500/30",
  amber: "from-amber-400 to-orange-500 shadow-amber-500/30",
  green: "from-emerald-400 to-emerald-600 shadow-emerald-500/30",
  red: "from-rose-400 to-rose-600 shadow-rose-500/30",
  navy: "from-ink-700 to-ink-900 shadow-ink-900/30",
};

export function StatCard({
  label,
  value,
  icon: Icon,
  tone = "blue",
  hint,
  loading,
}: {
  label: string;
  value: ReactNode;
  icon: LucideIcon;
  tone?: keyof typeof statTones;
  hint?: ReactNode;
  loading?: boolean;
}) {
  return (
    <Card className="group relative overflow-hidden p-5 transition hover:-translate-y-0.5 hover:shadow-lift">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-ink-500">{label}</p>
          {loading ? <div className="skeleton mt-2 h-8 w-16" /> : <p className="mt-1 text-3xl font-bold tracking-tight text-ink-950 tabular-nums">{value}</p>}
          {hint && <p className="mt-1 text-xs text-ink-400">{hint}</p>}
        </div>
        <div className={clsx("grid size-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br text-white shadow-lg", statTones[tone])}>
          <Icon className="size-5" aria-hidden />
        </div>
      </div>
    </Card>
  );
}

// --- Feedback states ------------------------------------------------------------------------
export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx("skeleton", className)} aria-hidden />;
}

export function EmptyState({ icon: Icon, title, children, action }: { icon: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-ink-200 bg-white/60 px-6 py-12 text-center">
      <div className="mb-4 grid size-14 place-items-center rounded-2xl bg-gradient-to-br from-royal-50 to-violet-50 text-royal-600 ring-1 ring-royal-100">
        <Icon className="size-6" aria-hidden />
      </div>
      <h3 className="text-base font-semibold text-ink-900">{title}</h3>
      {children && <div className="mt-1 max-w-sm text-sm text-ink-500">{children}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorMessage({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  return (
    <div role="alert" className={clsx("flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800", className)}>
      <XCircle className="mt-0.5 size-5 shrink-0" aria-hidden />
      <div className="flex-1">
        <p className="font-semibold">Something went wrong</p>
        <p className="mt-0.5">{friendlyError(error)}</p>
      </div>
      {onRetry && (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Notice({ tone = "blue", icon: Icon = Info, title, children }: { tone?: "blue" | "amber" | "green" | "violet"; icon?: LucideIcon; title?: string; children: ReactNode }) {
  const cls = {
    blue: "border-royal-100 bg-royal-50/70 text-ink-700 [&_svg]:text-royal-600",
    amber: "border-amber-200 bg-amber-50 text-amber-900 [&_svg]:text-amber-600",
    green: "border-emerald-200 bg-emerald-50 text-emerald-900 [&_svg]:text-emerald-600",
    violet: "border-violet-100 bg-violet-50 text-ink-700 [&_svg]:text-violet-600",
  }[tone];
  return (
    <div className={clsx("flex gap-3 rounded-xl border p-4 text-sm", cls)}>
      <Icon className="mt-0.5 size-[18px] shrink-0" aria-hidden />
      <div>
        {title && <p className="font-semibold">{title}</p>}
        <div className={title ? "mt-0.5" : ""}>{children}</div>
      </div>
    </div>
  );
}

// --- Pagination -----------------------------------------------------------------------------
export function Pagination({ page, pages, onChange }: { page: number; pages: number; onChange: (p: number) => void }) {
  if (pages <= 1) return null;
  const nums: (number | "…")[] = [];
  for (let i = 1; i <= pages; i++) {
    if (i === 1 || i === pages || Math.abs(i - page) <= 1) nums.push(i);
    else if (nums[nums.length - 1] !== "…") nums.push("…");
  }
  return (
    <nav className="flex items-center justify-center gap-1" aria-label="Pagination">
      <Button variant="ghost" size="sm" onClick={() => onChange(page - 1)} disabled={page <= 1} aria-label="Previous page">
        <ChevronLeft className="size-4" />
      </Button>
      {nums.map((n, i) =>
        n === "…" ? (
          <span key={`e${i}`} className="px-2 text-ink-400">
            …
          </span>
        ) : (
          <button
            key={n}
            onClick={() => onChange(n)}
            aria-current={n === page ? "page" : undefined}
            className={clsx(
              "size-8 rounded-lg text-sm font-semibold transition",
              n === page ? "bg-ink-900 text-white" : "text-ink-600 hover:bg-ink-100",
            )}
          >
            {n}
          </button>
        ),
      )}
      <Button variant="ghost" size="sm" onClick={() => onChange(page + 1)} disabled={page >= pages} aria-label="Next page">
        <ChevronRight className="size-4" />
      </Button>
    </nav>
  );
}

// --- Modal + confirmation -------------------------------------------------------------------
export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    setTimeout(() => ref.current?.querySelector<HTMLElement>("input,select,textarea,button:not([data-close])")?.focus(), 30);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      prev?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-end justify-center p-0 sm:items-center sm:p-4">
      <div className="absolute inset-0 bg-ink-950/40 backdrop-blur-[2px] animate-[fade-up_.2s_ease-out]" onClick={onClose} aria-hidden />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={clsx(
          "relative max-h-[92vh] w-full overflow-y-auto rounded-t-2xl bg-white shadow-2xl animate-fade-up sm:rounded-2xl",
          wide ? "sm:max-w-2xl" : "sm:max-w-md",
        )}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-ink-100 bg-white/95 px-6 py-4 backdrop-blur">
          <h2 className="text-base font-semibold text-ink-950">{title}</h2>
          <button data-close onClick={onClose} className="rounded-lg p-1.5 text-ink-400 hover:bg-ink-100 hover:text-ink-700" aria-label="Close dialog">
            <X className="size-4" />
          </button>
        </div>
        <div className="px-6 py-5">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-ink-100 bg-ink-50/60 px-6 py-4">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  danger,
  loading,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="text-sm text-ink-600">{message}</div>
    </Modal>
  );
}

// --- Toasts ---------------------------------------------------------------------------------
type ToastKind = "success" | "error" | "info" | "warning";
interface ToastItem {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}
const ToastContext = createContext<(kind: ToastKind, title: string, message?: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((kind: ToastKind, title: string, message?: string) => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs.slice(-3), { id, kind, title, message }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), kind === "error" ? 7000 : 4500);
  }, []);
  const icons = { success: CheckCircle2, error: XCircle, info: Info, warning: AlertTriangle };
  const colors = { success: "text-emerald-500", error: "text-rose-500", info: "text-royal-500", warning: "text-amber-500" };
  return (
    <ToastContext.Provider value={push}>
      {children}
      {createPortal(
        <div className="pointer-events-none fixed inset-x-0 bottom-0 z-[60] flex flex-col items-center gap-2 p-4 sm:items-end" aria-live="polite">
          {items.map((t) => {
            const Icon = icons[t.kind];
            return (
              <div key={t.id} role={t.kind === "error" ? "alert" : "status"} className="pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-xl border border-ink-200/80 bg-white p-4 shadow-xl animate-fade-up">
                <Icon className={clsx("mt-0.5 size-5 shrink-0", colors[t.kind])} aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-ink-900">{t.title}</p>
                  {t.message && <p className="mt-0.5 text-sm text-ink-500">{t.message}</p>}
                </div>
                <button onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))} className="text-ink-400 hover:text-ink-700" aria-label="Dismiss">
                  <X className="size-4" />
                </button>
              </div>
            );
          })}
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

// --- DataTable ------------------------------------------------------------------------------
export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  className?: string;
}

export function DataTable<T>({ columns, rows, rowKey, loading, empty }: { columns: Column<T>[]; rows: T[] | undefined; rowKey: (r: T) => string | number; loading?: boolean; empty?: ReactNode }) {
  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="border-b border-ink-100 bg-ink-50/70">
            <tr>
              {columns.map((c) => (
                <th key={c.key} scope="col" className={clsx("px-4 py-3 text-xs font-semibold tracking-wide text-ink-500 uppercase", c.className)}>
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-100">
            {loading &&
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  {columns.map((c) => (
                    <td key={c.key} className="px-4 py-3.5">
                      <Skeleton className="h-4 w-3/4" />
                    </td>
                  ))}
                </tr>
              ))}
            {!loading &&
              rows?.map((r) => (
                <tr key={rowKey(r)} className="transition-colors hover:bg-royal-50/40">
                  {columns.map((c) => (
                    <td key={c.key} className={clsx("px-4 py-3 align-middle text-ink-700", c.className)}>
                      {c.render(r)}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      {!loading && rows && rows.length === 0 && <div className="p-6">{empty ?? <p className="text-center text-sm text-ink-500">No records.</p>}</div>}
    </div>
  );
}

// --- Tabs (segmented control) ---------------------------------------------------------------
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string; count?: number }[]; label: string }) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex flex-wrap gap-1 rounded-xl bg-ink-100/80 p-1">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={value === o.value}
          onClick={() => onChange(o.value)}
          className={clsx(
            "rounded-lg px-3 py-1.5 text-sm font-semibold transition",
            value === o.value ? "bg-white text-ink-900 shadow-sm" : "text-ink-500 hover:text-ink-800",
          )}
        >
          {o.label}
          {o.count !== undefined && <span className="ml-1.5 text-xs text-ink-400 tabular-nums">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
