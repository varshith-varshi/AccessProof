import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, freshAttestation, friendlyError } from "./api";
import { fmtDate } from "./format";
import { useToast } from "../components/ui";

/** Runs a Layer 2 action with a fresh attestation. If the title is no longer visible (Layer 1
 * hides it), the request is still sent so the server records the denial, and the member is
 * told plainly that their access has changed. */
async function guarded<T>(bookId: string, run: (attestation: string | null) => Promise<T>): Promise<T> {
  const attestation = await freshAttestation(bookId);
  try {
    return await run(attestation);
  } catch (e) {
    if (attestation === null && e instanceof ApiError && e.code === "missing_attestation")
      throw new ApiError(403, "access_revoked", "access revoked");
    throw e;
  }
}

// Every action asks the server for a fresh, member-specific attestation (Layer 1) and then
// sends it with the request (Layer 2). Success messages only appear after the server confirms.

function useInvalidate() {
  const qc = useQueryClient();
  return () =>
    Promise.all(
      ["catalog", "book", "loans", "reservations", "history", "fines", "activity", "recs", "me", "admin", "facets"].map((k) =>
        qc.invalidateQueries({ queryKey: [k] }),
      ),
    );
}

export function useBorrow() {
  const toast = useToast();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async (bookId: string) => {
      return guarded(bookId, (attestation) =>
        api<{ loan_id: number; title: string; due_at: number }>(`/books/${bookId}/checkout`, { method: "POST", json: { attestation } }),
      );
    },
    onSuccess: (r) => {
      toast("success", "Book borrowed", `“${r.title}” is due back on ${fmtDate(r.due_at)}.`);
      invalidate();
    },
    onError: (e) => {
      toast("error", "Could not borrow", friendlyError(e));
      invalidate();
    },
  });
}

export function useReserve() {
  const toast = useToast();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async (bookId: string) => {
      return guarded(bookId, (attestation) =>
        api<{ reservation_id: number; queue_position: number }>(`/books/${bookId}/reserve`, { method: "POST", json: { attestation } }),
      );
    },
    onSuccess: (r) => {
      toast("success", "Reservation placed", `You are number ${r.queue_position} in the queue.`);
      invalidate();
    },
    onError: (e) => {
      toast("error", "Could not reserve", friendlyError(e));
      invalidate();
    },
  });
}

export function useRenew() {
  const toast = useToast();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: async ({ loanId, bookId }: { loanId: number; bookId: string }) => {
      return guarded(bookId, (attestation) => api<{ due_at: number }>(`/loans/${loanId}/renew`, { method: "POST", json: { attestation } }));
    },
    onSuccess: (r) => {
      toast("success", "Loan renewed", `New due date: ${fmtDate(r.due_at)}.`);
      invalidate();
    },
    onError: (e) => {
      toast("error", "Could not renew", friendlyError(e));
      invalidate();
    },
  });
}

export function useReturn() {
  const toast = useToast();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (loanId: number) => api<{ fine: number; held_for_next_reservation: boolean }>(`/loans/${loanId}/return`, { method: "POST" }),
    onSuccess: (r) => {
      const parts = [r.fine > 0 ? `A late fine of $${r.fine.toFixed(2)} was recorded.` : "No fine — thank you for returning on time."];
      if (r.held_for_next_reservation) parts.push("The copy is now held for the next member in the queue.");
      toast(r.fine > 0 ? "warning" : "success", "Book returned", parts.join(" "));
      invalidate();
    },
    onError: (e) => toast("error", "Could not return", friendlyError(e)),
  });
}

export function useCancelReservation(asLibrarian = false) {
  const toast = useToast();
  const invalidate = useInvalidate();
  return useMutation({
    mutationFn: (id: number) => api<{ held_copy_passed_to: string | null }>(asLibrarian ? `/admin/reservations/${id}` : `/me/reservations/${id}`, { method: "DELETE" }),
    onSuccess: (r) => {
      toast("success", "Reservation cancelled", r.held_copy_passed_to ? "The held copy has passed to the next member in the queue." : undefined);
      invalidate();
    },
    onError: (e) => toast("error", "Could not cancel", friendlyError(e)),
  });
}
