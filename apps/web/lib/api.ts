"use client";

export type Session = { organizationId: string };
const KEY = "accessproof.session";

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as Session; } catch { return null; }
}
export function saveSession(session: Session) { localStorage.setItem(KEY, JSON.stringify(session)); }
export function clearSession() { localStorage.removeItem(KEY); }

function csrfToken(): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split("; ").find((row) => row.startsWith("accessproof_csrf="));
  return match ? decodeURIComponent(match.split("=").slice(1).join("=")) : null;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = getSession();
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (session) headers.set("X-Organization-ID", session.organizationId);
  const method = (init.method ?? "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = csrfToken();
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(path, {...init, headers, credentials:"include", cache:"no-store"});
  if (!response.ok) {
    const body = await response.json().catch(() => ({detail: response.statusText}));
    if (response.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/v1/auth/")) {
      clearSession();
      const next = `${window.location.pathname}${window.location.search}`;
      window.location.assign(`/login?next=${encodeURIComponent(next)}&reason=expired`);
    }
    throw new Error(typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? `HTTP ${response.status}`));
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
