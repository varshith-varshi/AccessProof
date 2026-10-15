"use client";

export class ApiError extends Error {
  constructor(public status: number, message: string, public code?: string) { super(message); this.name = "ApiError"; }
}

export function setActiveOrganization(organizationId: string) {
  if (typeof document === "undefined") return;
  document.cookie = `accessproof_organization=${encodeURIComponent(organizationId)}; Path=/; SameSite=Lax`;
}

export function clearActiveOrganization() {
  if (typeof document === "undefined") return;
  document.cookie = "accessproof_organization=; Path=/; Max-Age=0; SameSite=Lax";
}

export type Dashboard = {
  projects: number;
  outcomes: Record<string, number>;
  runner_health: { online: number; total: number; offline: number };
  broken_connections: number;
  recent_runs: Array<{ id: string; outcome: string | null; state: string; created_at: string }>;
};

export type Guard = {
  id: string; name: string; environment: string; version: string | null;
  status: string; health: string; active_policy_version: number | null;
  last_heartbeat_at: string | null; enrolled_at: string | null; revoked_at: string | null;
};

export type Project = { id: string; name: string; status?: string };
export type Source = { id: string; project_id: string; name: string; provider: string; status: string; capabilities?: Record<string,string>; last_validated_at?: string | null; last_error?: string | null };
export type AITarget = { id: string; project_id: string; name: string; url: string; runner_mode: boolean; auth_configured: boolean; config: Record<string,unknown> };
export type PermissionEvent = { id: string; source_id: string; provider: string; subject_id: string; resource_id: string; change_type: string; provider_revision: number; status: string; error_code: string | null; policy_id: string | null };
export type AuditEvent = { id: string; actor: string | null; action: string; target_type: string; target_id: string; created_at: string; metadata: Record<string,unknown> };

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && typeof document !== "undefined") {
    const csrf = document.cookie.split("; ").find(value => value.startsWith("accessproof_csrf="))?.split("=").slice(1).join("=");
    if (csrf) headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }
  const response = await fetch(path, { ...init, headers, credentials: "include", cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string | { code?: string } } | null;
    const detail = body?.detail;
    const message = typeof detail === "string" ? detail : response.status === 401 ? "Your session has expired. Please sign in again." : response.status === 403 ? "You do not have permission to perform this action." : `Request failed (${response.status}).`;
    const code = typeof detail === "object" ? detail.code : undefined;
    if (response.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/v1/auth/")) window.location.replace(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError(response.status, message, code);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
