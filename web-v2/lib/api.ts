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
export type CurrentDashboard = {
  ai_applications: number; guards_online: number; guards_total: number; permission_sources: number; blocked_requests: number;
  recent_activity: Array<{ id: string; type: string; severity: string; timestamp: string; summary: string; guard_id?: string | null; application_id?: string | null; policy_version?: number | null }>;
  protection: {
    applications_registered: number; applications_protected_verified: number;
    applications_not_verified: number; applications_unsupported: number;
    guards: Record<string, number>; sources_fresh: number; sources_total: number;
    decisions_24h: ProtectionDecisionWindow; latest_decision_at: string | null;
  };
};
export type ApplicationReadinessCheck = { code: string; ok: boolean; reason: string | null };
export type ProtectionDecisionBucket = { allow: number; block: number; would_allow: number; would_block: number };
export type ProtectionDecisionTelemetry = {
  telemetry: "OBSERVED" | "NO_DATA"; window_hours: number;
  layer1: ProtectionDecisionBucket | null; layer2: ProtectionDecisionBucket | null;
};
export type ProtectionDecisionWindow = {
  telemetry: "OBSERVED" | "NO_DATA"; total: number;
  layer1: ProtectionDecisionBucket; layer2: ProtectionDecisionBucket;
};
export type ProtectionOverviewApplication = {
  application_id: string; name: string; mode: string;
  effective_state: string; state_message: string; reason_code: string;
  adapter: { type: string; contract_version: string; protect_capable: boolean };
  guard: { id: string | null; name: string | null; health: string; heartbeat_age_seconds: number | null; policy_version: number | null };
  source: {
    id: string | null; name: string | null; provider: string | null; status: string | null;
    acl_sync_age_seconds: number | null; directory_sync_age_seconds: number | null;
    acl_fresh: boolean; directory_fresh: boolean;
  };
  route_certification: { required: boolean; expired: boolean; status: string; certified: boolean; age_seconds: number | null; evidence_level: string | null; certification_scope: string };
  decision_telemetry: ProtectionDecisionTelemetry;
  latest_decision_at: string | null;
  failed_checks: Array<{ code: string; reason: string | null }>;
  checks: ApplicationReadinessCheck[];
};
export type ProtectionOverview = {
  generated_at: string;
  state_counts: Record<string, number>;
  totals: {
    applications_registered: number; applications_protected_verified: number;
    applications_not_verified: number; applications_unsupported: number;
    guards_total: number; guards_online: number; guards: Record<string, number>;
    sources_total: number; sources_fresh: number; sources_stale: number;
  };
  applications: ProtectionOverviewApplication[];
};
export type ProtectionStatus = { application_id: string; state: string; checks: ApplicationReadinessCheck[]; reason_code: string; message: string; last_checked_at: string | null; run_id: string | null; guard_acknowledged: boolean };
export type AIApplication = { id: string; application_id: string; name: string; mode: string; guard_id: string | null; source_id: string | null; adapter_type: string; adapter_contract_version: string; readiness: ApplicationReadinessCheck[] };

export type Guard = {
  id: string; name: string; environment: string; version: string | null;
  status: string; health: string; active_policy_version: number | null;
  last_heartbeat_at: string | null; enrolled_at: string | null; revoked_at: string | null;
};

export type SourceSyncStatus = { status: string; fresh: boolean; last_success_at: string | null; last_error_code: string | null };
export type Source = { id: string; name: string; provider: string; boundary: string; status: string; capabilities?: Record<string,string>; last_validated_at?: string | null; last_error?: string | null; directory_sync?: SourceSyncStatus; acl_sync?: SourceSyncStatus };
export type Employee = { id: string; name: string; email: string | null; provider: string; stable_id: string; status: string; last_synced_at: string | null; groups: Array<{ id: string; name: string; provider: string; stable_id: string }> };
export type PermissionEvent = { id: string; source_id: string; provider: string; subject_id: string; resource_id: string; change_type: string; provider_revision: number; status: string; error_code: string | null; policy_id: string | null };
export type AuditEvent = { id: string; actor: string | null; action: string; target_type: string; target_id: string; created_at: string; metadata: Record<string,unknown> };
export type ReportType = "APPLICATION_COVERAGE" | "GUARD_HEALTH" | "AUTHORIZATION_ACTIVITY";
export type ReportEvidenceLevels = {
  control_plane_state: string; guard_decisions: string;
  provider_effective_permissions: string; revocation_to_first_denial_timing: string;
};
export type ReportVerification = {
  report_id: string; report_type: ReportType; verified: boolean;
  signature_valid: boolean; scope_valid: boolean; expired: boolean;
  generated_at: string; expires_at: string; report_hash: string; key_id: string | null;
  evidence_levels: ReportEvidenceLevels; limitations: string[];
};
export type ReportSummary = {
  id: string; report_type: ReportType; generated_at: string; expires_at: string;
  report_hash: string; key_id: string | null;
  evidence_levels: ReportEvidenceLevels; summary: Record<string, unknown>;
};
export type ReportEnvelope = {
  report: {
    schema: string; report_id: string; report_type: ReportType;
    organization_id: string; generated_at: string; expires_at: string;
    evidence_levels: ReportEvidenceLevels; summary: Record<string, unknown>;
    limitations: string[];
    [key: string]: unknown;
  };
  signature: { algorithm: string; key_id: string; payload_sha256: string; public_key: string; signature: string };
  verification: ReportVerification;
};

export function apiErrorMessage(cause: unknown, fallback: string) {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && typeof document !== "undefined") {
    const csrf = document.cookie.split("; ").find(value => value.startsWith("accessproof_csrf="))?.split("=").slice(1).join("=");
    if (csrf) headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }
  const response = await fetch(path, { ...init, headers, credentials: "include", cache: "no-store" });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string | { code?: string; message?: string } } | null;
    const detail = body?.detail;
    const message = typeof detail === "string"
      ? detail
      : typeof detail?.message === "string"
        ? detail.message
        : response.status === 401 ? "Your session has expired. Please sign in again."
        : response.status === 403 ? "You do not have permission to perform this action."
        : `Request failed (${response.status}).`;
    const code = typeof detail === "object" ? detail.code : undefined;
    if (response.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/v1/auth/")) window.location.replace(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError(response.status, message, code);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
