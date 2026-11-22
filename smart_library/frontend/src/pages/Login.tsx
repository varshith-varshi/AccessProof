import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { ArrowLeft, Check, FlaskConical, KeyRound, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Logo } from "../components/books";
import { Badge, Button, ErrorMessage, Notice, Skeleton } from "../components/ui";
import { api, type DemoMember } from "../lib/api";
import { useAuth } from "../lib/auth";

export default function Login() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  const members = useQuery({ queryKey: ["demo-members"], queryFn: () => api<DemoMember[]>("/auth/demo-members"), retry: false });
  const [selected, setSelected] = useState<string>("m-alice");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const me = await signIn(selected);
      navigate(from && from !== "/login" ? from : me.librarian ? "/admin" : "/dashboard", { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_1.1fr]">
      <div className="relative hidden overflow-hidden bg-ink-950 p-12 text-white lg:flex lg:flex-col">
        <div className="absolute inset-0 bg-[radial-gradient(60%_50%_at_20%_10%,rgb(35_70_224/0.45),transparent),radial-gradient(50%_50%_at_90%_90%,rgb(124_58_237/0.4),transparent)]" />
        <Link to="/" className="relative">
          <Logo light />
        </Link>
        <div className="relative mt-auto max-w-md">
          <h1 className="text-4xl leading-tight font-bold">Welcome to your university library.</h1>
          <p className="mt-4 text-lg text-ink-300">Search, borrow, reserve and read — with access checked on every request.</p>
          <ul className="mt-10 space-y-4 text-ink-200">
            {[
              "Your identity is verified with a signed token, never an email alone",
              "You only ever see titles you are allowed to use",
              "Access is re-checked at the moment of every loan and read",
            ].map((t) => (
              <li key={t} className="flex gap-3">
                <span className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-emerald-500/20 text-emerald-300">
                  <Check className="size-3.5" />
                </span>
                {t}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="flex flex-col px-4 py-8 sm:px-10">
        <div className="flex items-center justify-between">
          <Link to="/" className="inline-flex items-center gap-1.5 text-sm font-medium text-ink-500 hover:text-ink-900">
            <ArrowLeft className="size-4" /> Back to home
          </Link>
          <span className="lg:hidden">
            <Logo />
          </span>
        </div>
        <div className="mx-auto my-auto w-full max-w-lg py-10">
          <h2 className="text-3xl font-bold tracking-tight text-ink-950">Sign in</h2>
          <p className="mt-2 text-ink-500">Choose a demonstration account to explore the library.</p>

          <div className="mt-6">
            <Notice tone="amber" icon={FlaskConical} title="Demo Mode">
              This deployment signs you in as a demonstration member — it is not production authentication. In production the library uses the institution's identity provider (OIDC / SSO), and this screen is disabled with <code className="rounded bg-amber-100 px-1">SLMS_DEMO_LOGIN=0</code>.
            </Notice>
          </div>

          <form onSubmit={submit} className="mt-6">
            <fieldset>
              <legend className="label">Demo identity</legend>
              {members.isLoading && (
                <div className="space-y-2">
                  {[0, 1, 2, 3].map((i) => (
                    <Skeleton key={i} className="h-[68px]" />
                  ))}
                </div>
              )}
              {members.isError && <ErrorMessage error={members.error} onRetry={() => members.refetch()} />}
              <div className="grid max-h-[46vh] gap-2 overflow-y-auto pr-1">
                {members.data?.map((m) => (
                  <label
                    key={m.id}
                    className={clsx(
                      "flex cursor-pointer items-center gap-3 rounded-xl border p-3 transition",
                      selected === m.id ? "border-royal-500 bg-royal-50/60 ring-4 ring-royal-100" : "border-ink-200 bg-white hover:border-ink-300",
                      !m.active && "opacity-60",
                    )}
                  >
                    <input type="radio" name="member" value={m.id} checked={selected === m.id} onChange={() => setSelected(m.id)} className="sr-only" />
                    <span className={clsx("grid size-10 shrink-0 place-items-center rounded-full text-sm font-bold text-white", m.role === "Librarian" ? "bg-gradient-to-br from-violet-500 to-violet-700" : "bg-gradient-to-br from-royal-400 to-royal-600")}>
                      {m.name[0]}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="font-semibold text-ink-900">{m.name}</span>
                        <Badge tone={m.role === "Librarian" ? "violet" : "blue"}>{m.role}</Badge>
                        {!m.active && <Badge tone="red">Suspended</Badge>}
                      </span>
                      <span className="mt-0.5 block truncate text-xs text-ink-500">{m.description}</span>
                    </span>
                    {selected === m.id && <Check className="size-5 text-royal-600" aria-hidden />}
                  </label>
                ))}
              </div>
            </fieldset>
            {error ? <ErrorMessage error={error} className="mt-4" /> : null}
            <Button type="submit" size="lg" className="mt-6 w-full" loading={busy} icon={KeyRound} disabled={!members.data}>
              {busy ? "Verifying identity…" : "Sign in"}
            </Button>
            <p className="mt-4 flex items-center justify-center gap-1.5 text-xs text-ink-400">
              <ShieldCheck className="size-3.5" /> The server issues a signed, expiring token for the selected member.
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
