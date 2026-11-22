import { clsx } from "clsx";
import { CalendarDays, RefreshCw, Undo2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { Loan } from "../lib/api";
import { useRenew, useReturn } from "../lib/actions";
import { daysLeftLabel, fmtDate, fmtMoney } from "../lib/format";
import { BookCover } from "./books";
import { Button, ConfirmDialog, StatusBadge } from "./ui";

export function LoanRow({ loan, compact }: { loan: Loan; compact?: boolean }) {
  const renew = useRenew();
  const ret = useReturn();
  const [confirm, setConfirm] = useState(false);
  const open = loan.status !== "returned";
  const total = 14;
  const pct = loan.days_left === null ? 100 : Math.max(4, Math.min(100, ((total - loan.days_left) / total) * 100));
  return (
    <div className="flex gap-4 p-4 sm:p-5">
      <Link to={`/books/${loan.book_id}`} className="w-14 shrink-0 sm:w-16">
        <BookCover book={{ ...loan, id: loan.book_id }} size="xs" />
      </Link>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <Link to={`/books/${loan.book_id}`} className="line-clamp-1 font-semibold text-ink-950 hover:text-royal-600">
              {loan.title}
            </Link>
            <p className="line-clamp-1 text-sm text-ink-500">{loan.author}</p>
          </div>
          <StatusBadge status={loan.status} />
        </div>
        <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-500">
          <span className="inline-flex items-center gap-1">
            <CalendarDays className="size-3.5" /> Borrowed {fmtDate(loan.borrowed_at)}
          </span>
          <span>Due {fmtDate(loan.due_at)}</span>
          {loan.returned_at && <span>Returned {fmtDate(loan.returned_at)}</span>}
          {loan.renewals > 0 && <span>Renewed {loan.renewals}×</span>}
          {loan.fine > 0 && <span className="font-semibold text-rose-600">{open ? "Fine so far" : "Fine"} {fmtMoney(loan.fine)}</span>}
        </div>
        {open && (
          <>
            <div className="mt-3 flex items-center gap-3">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-100">
                <div
                  className={clsx("h-full rounded-full", loan.status === "overdue" ? "bg-rose-500" : loan.status === "due_soon" ? "bg-amber-500" : "bg-royal-500")}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className={clsx("text-xs font-semibold whitespace-nowrap", loan.status === "overdue" ? "text-rose-600" : loan.status === "due_soon" ? "text-amber-700" : "text-ink-600")}>
                {daysLeftLabel(loan.days_left)}
              </span>
            </div>
            {!compact && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant="soft"
                  icon={RefreshCw}
                  loading={renew.isPending}
                  disabled={!loan.renewable}
                  onClick={() => renew.mutate({ loanId: loan.loan_id, bookId: loan.book_id })}
                  title={loan.renew_blocked_reason ?? "Extend by 14 days"}
                >
                  Renew
                </Button>
                <Button size="sm" variant="secondary" icon={Undo2} onClick={() => setConfirm(true)}>
                  Return
                </Button>
                {!loan.renewable && loan.renew_blocked_reason && <span className="text-xs text-ink-400">Renewal unavailable: {loan.renew_blocked_reason}</span>}
              </div>
            )}
          </>
        )}
      </div>
      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Return this book?"
        confirmLabel="Confirm return"
        loading={ret.isPending}
        onConfirm={() => ret.mutate(loan.loan_id, { onSettled: () => setConfirm(false) })}
        message={
          <>
            <p>
              You are returning <strong className="text-ink-900">{loan.title}</strong>.
            </p>
            {loan.fine > 0 ? (
              <p className="mt-2 text-rose-700">This loan is overdue. A late fine of {fmtMoney(loan.fine)} will be recorded.</p>
            ) : (
              <p className="mt-2">It is on time — no fine will be charged.</p>
            )}
            <p className="mt-2 text-xs text-ink-400">In a physical library this is done at the return desk; here it records the return immediately.</p>
          </>
        }
      />
    </div>
  );
}
