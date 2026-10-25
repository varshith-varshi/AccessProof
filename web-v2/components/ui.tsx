import { AlertTriangle, CheckCircle2, CircleSlash2, Info, LoaderCircle } from "lucide-react";
import { titleCase } from "../lib/format";

export function StatusBadge({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const tone = /online|healthy|connected|allow|installed|protected/.test(normalized) ? "success" : /error|revoked|blocked|deny/.test(normalized) ? "danger" : /degraded|unknown|offline|pending|sync|not_enrolled/.test(normalized) ? "warning" : "neutral";
  const Icon = tone === "success" ? CheckCircle2 : tone === "danger" ? CircleSlash2 : tone === "warning" ? AlertTriangle : Info;
  return <span className={`status-badge ${tone}`}><Icon size={12}/>{titleCase(value)}</span>;
}

export function ProtectionStateBadge({ value }: { value: string }) {
  const tone = value === "PROTECTED_VERIFIED" ? "success" : /BLOCKED|DEGRADED/.test(value) ? "danger" : /VALIDATING|PROTECT_PENDING|STALE|CERTIFICATION_EXPIRED|CONNECTED|UNKNOWN/.test(value) ? "warning" : "neutral";
  const Icon = tone === "success" ? CheckCircle2 : tone === "danger" ? CircleSlash2 : tone === "warning" ? AlertTriangle : Info;
  return <span className={`status-badge ${tone}`}><Icon size={12}/>{titleCase(value)}</span>;
}

export function Skeleton({ rows = 3 }: { rows?: number }) { return <div className="skeleton-stack" aria-label="Loading" aria-live="polite">{Array.from({ length: rows }, (_, index) => <span className="skeleton" key={index}/>)}</div>; }

export function EmptyState({ title, description, action }: { title: string; description: string; action?: React.ReactNode }) { return <div className="empty-state"><div className="empty-symbol" aria-hidden="true">AP</div><h2>{title}</h2><p>{description}</p>{action}</div>; }

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) { return <div className="alert error-alert" role="alert"><AlertTriangle size={18}/><div><b>Unable to load this view</b><p>{message}</p>{retry && <button className="text-button" onClick={retry}>Try again</button>}</div></div>; }

export function PendingButton({ pending, children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { pending?: boolean }) { return <button {...props} disabled={pending || props.disabled}>{pending && <LoaderCircle className="spin" size={15}/>} {children}</button>; }
