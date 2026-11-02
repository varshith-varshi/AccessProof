"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, api, setActiveOrganization } from "../../lib/api";
import { AuthFrame } from "../auth-frame";

type Accepted = { organization_id: string; role: string };
type State =
  | { kind: "working" }
  | { kind: "signin" }
  | { kind: "error"; message: string }
  | { kind: "done"; role: string };

function AcceptInvitation() {
  const params = useSearchParams();
  const router = useRouter();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<State>(token ? { kind: "working" } : { kind: "error", message: "This invitation link is incomplete. Ask your admin to send a new one." });
  const here = `/accept-invitation?token=${encodeURIComponent(token)}`;

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    (async () => {
      try {
        const result = await api<Accepted>("/api/v1/auth/invitations/accept", { method: "POST", body: JSON.stringify({ token }) });
        if (cancelled) return;
        setActiveOrganization(result.organization_id);
        setState({ kind: "done", role: result.role });
        setTimeout(() => router.replace("/dashboard"), 1200);
      } catch (cause) {
        if (cancelled) return;
        if (cause instanceof ApiError && cause.status === 401) setState({ kind: "signin" });
        else if (cause instanceof ApiError && cause.status === 403) setState({ kind: "error", message: "This invitation was sent to a different email address. Sign in with the invited email, or ask your admin to re-invite you." });
        else setState({ kind: "error", message: cause instanceof ApiError && /expired/i.test(cause.message) ? "This invitation has expired. Ask your admin to send a new one." : "This invitation is invalid or has already been used." });
      }
    })();
    return () => { cancelled = true; };
  }, [token, router]);

  return <AuthFrame title="Join your team's workspace" description="Accept your invitation to AccessProof.">
    <div className="invite-state" role="status" aria-live="polite">
      {state.kind === "working" && <p className="muted">Checking your invitation…</p>}
      {state.kind === "done" && <p><b>You’re in.</b> You joined as {state.role.toLowerCase()}. Taking you to your dashboard…</p>}
      {state.kind === "error" && <p className="form-error" role="alert">{state.message}</p>}
      {state.kind === "signin" && <>
        <p>Sign in with the email address your invitation was sent to. You’ll come straight back here to finish joining.</p>
        <div className="invite-actions">
          <Link className="button auth-button" href={`/login?next=${encodeURIComponent(here)}`}>Sign in to accept</Link>
          <Link className="button secondary auth-button" href={`/register?next=${encodeURIComponent(here)}`}>Create an account first</Link>
        </div>
      </>}
    </div>
  </AuthFrame>;
}

export default function AcceptInvitationPage() {
  return <Suspense fallback={null}><AcceptInvitation/></Suspense>;
}
