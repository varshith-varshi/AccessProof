// Typed client for the FastAPI backend. Every protected call carries the signed member token;
// the server enforces all permissions — the UI only reflects what the server allows.

const TOKEN_KEY = "sl.token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the session lasts for this page only */
  }
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function normalise(status: number, body: unknown): ApiError {
  const b = body as Record<string, unknown> | null;
  if (b && typeof b.error === "string") return new ApiError(status, b.error, String(b.detail ?? b.error));
  const d = b?.detail as Record<string, unknown> | unknown[] | string | undefined;
  if (d && !Array.isArray(d) && typeof d === "object" && typeof d.error === "string")
    return new ApiError(status, d.error, String(d.detail ?? d.error));
  if (Array.isArray(d)) {
    const first = d[0] as { loc?: unknown[]; msg?: string } | undefined;
    const field = first?.loc?.slice(1).join(".") ?? "";
    return new ApiError(status, "validation_error", `${field ? field + ": " : ""}${first?.msg ?? "invalid input"}`);
  }
  return new ApiError(status, `http_${status}`, typeof d === "string" ? d : `Request failed (${status})`);
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let body = init.body;
  if (init.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, headers: { ...headers, ...(init.headers as object) }, body });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the library server. Is it running?");
  }
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const err = normalise(res.status, data);
    if (res.status === 401 && token) onUnauthorized?.();
    throw err;
  }
  return data as T;
}

const FRIENDLY: Record<string, string> = {
  missing_attestation: "This item was not obtained through an authorised search, so the library refused it.",
  invalid_attestation: "The access proof for this item did not verify, so the request was refused.",
  attestation_expired: "Your access check expired. Please try again.",
  access_revoked: "Your access to this title has been revoked. The library blocked the request.",
  policy_stale: "The access guard cannot verify permissions right now (policy is stale). Request denied for safety.",
  guard_unavailable: "The access guard is unavailable. Requests are refused until it is back.",
  policy_not_installed: "The access guard has no policy installed yet. Request denied for safety.",
  loan_limit: "You have reached the limit of active loans. Return a book to borrow another.",
  overdue_items: "Please return your overdue items before borrowing more.",
  already_borrowed: "You already have this title on loan.",
  unavailable: "No copies are available right now. You can reserve it instead.",
  held_for_other: "The returned copy is being held for another member's reservation.",
  available: "A copy is available — you can borrow it straight away.",
  already_reserved: "You have already reserved this title.",
  reserved: "Another member is waiting for this title, so it cannot be renewed.",
  digital_only: "This title is available as an e-book only.",
  no_digital: "This title has no digital edition.",
  unknown_book: "This book does not exist or is not available to you.",
  member_suspended: "This membership is suspended.",
  unverified_identity: "Your session could not be verified. Please sign in again.",
  not_librarian: "This area is for librarians only.",
  invalid_copies: "That copy count would conflict with copies currently on loan or on hold.",
  network_error: "Cannot reach the library server. Is it running?",
};

export function friendlyError(err: unknown): string {
  if (err instanceof ApiError) {
    const base = FRIENDLY[err.code];
    if (err.code === "invalid_copies" || err.code === "loan_limit" || err.code === "validation_error") return err.message;
    return base ?? err.message;
  }
  return err instanceof Error ? err.message : "Something went wrong.";
}

// --- types ----------------------------------------------------------------------------------
export interface Book {
  id: string;
  isbn: string;
  title: string;
  author: string;
  category: string;
  year: number | null;
  collection_id: string;
  copies_total: number;
  copies_available: number;
  has_digital: boolean;
  description: string;
  cover_url: string | null;
  added_at: number | null;
  loan_count: number | null;
  attestation?: string;
  reason?: string;
}

export interface PublicBook {
  id: string;
  title: string;
  author: string;
  category: string;
  year: number | null;
  cover_url: string | null;
  has_digital: boolean;
  description: string;
  added_at: number | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export type LoanStatus = "active" | "due_soon" | "overdue" | "returned";

export interface Loan {
  loan_id: number;
  book_id: string;
  title: string;
  author: string;
  category: string;
  cover_url: string | null;
  member_id: string;
  member_name?: string;
  borrowed_at: number;
  due_at: number;
  returned_at: number | null;
  status: LoanStatus;
  days_left: number | null;
  renewals: number;
  renewable: boolean;
  renew_blocked_reason: string | null;
  fine: number;
  overdue?: boolean;
  fine_if_returned_now?: number;
}

export interface Reservation {
  id: number;
  book_id: string;
  title: string;
  author: string;
  category: string;
  cover_url: string | null;
  status: "waiting" | "ready" | "fulfilled" | "cancelled";
  created_at: number;
  updated_at: number | null;
  queue_position: number | null;
  member_id: string;
  member_name: string | null;
}

export interface Me {
  id: string;
  name: string;
  email: string;
  active: boolean;
  groups: string[];
  outstanding_fines: number;
  librarian: boolean;
}

export interface DemoMember {
  id: string;
  name: string;
  role: string;
  groups: string[];
  active: boolean;
  description: string;
}

export interface GuardStatus {
  enabled: boolean;
  installed_revision: number;
  authoritative_revision: number;
  policy_age_seconds: number | null;
  max_staleness_seconds: number;
  ready: boolean;
  not_ready_reason: string | null;
}

export interface Fines {
  outstanding: number;
  accruing: number;
  fine_per_day: number;
  history: Loan[];
  overdue_loans: Loan[];
  payment_available: boolean;
}

export interface ActivityEvent {
  at: number;
  type: string;
  book_id: string | null;
  title: string | null;
  detail?: string | null;
}

export interface AuditEntry {
  id: number;
  at: number;
  member_id: string | null;
  member_name: string | null;
  action: string;
  resource: string | null;
  decision: "allow" | "deny" | "info";
  reason: string;
  policy_revision: number | null;
}

/** Layer 1 then Layer 2: fetch a fresh, member-specific attestation right before an action.
 * Returns null when the title is no longer visible; the server then refuses the action itself. */
export async function freshAttestation(bookId: string): Promise<string | null> {
  try {
    const b = await api<Book>(`/books/${encodeURIComponent(bookId)}`);
    return b.attestation ?? null;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}
