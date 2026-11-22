import { Compass, ShieldX, TriangleAlert } from "lucide-react";
import { Component, type ReactNode } from "react";
import { Link } from "react-router-dom";

function ErrorScreen({ code, title, text, icon: Icon }: { code: string; title: string; text: string; icon: typeof Compass }) {
  return (
    <div className="grid min-h-[70vh] place-items-center px-4 py-16">
      <div className="max-w-md text-center">
        <div className="mx-auto grid size-16 place-items-center rounded-2xl bg-gradient-to-br from-royal-50 to-violet-50 text-royal-600 ring-1 ring-royal-100">
          <Icon className="size-7" />
        </div>
        <p className="mt-6 text-sm font-semibold tracking-[0.14em] text-royal-600 uppercase">{code}</p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight text-ink-950">{title}</h1>
        <p className="mt-3 text-ink-500">{text}</p>
        <div className="mt-8 flex justify-center gap-3">
          <Link to="/" className="inline-flex h-10 items-center rounded-xl border border-ink-200 bg-white px-4 text-sm font-semibold text-ink-800">
            Home
          </Link>
          <Link to="/dashboard" className="inline-flex h-10 items-center rounded-xl bg-royal-600 px-4 text-sm font-semibold text-white">
            My dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}

export const NotFound = () => <ErrorScreen code="404" title="Page not found" text="The page you are looking for does not exist or has moved." icon={Compass} />;
export const Forbidden = () => (
  <ErrorScreen code="403" title="Access denied" text="This area is restricted to librarians. Permissions are enforced by the server, so the data behind it is protected too." icon={ShieldX} />
);

export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error)
      return (
        <div className="grid min-h-screen place-items-center px-4">
          <div className="max-w-md text-center">
            <TriangleAlert className="mx-auto size-10 text-amber-500" />
            <h1 className="mt-4 text-2xl font-bold text-ink-950">Something went wrong</h1>
            <p className="mt-2 text-ink-500">The page hit an unexpected error. Reloading usually fixes it.</p>
            <pre className="mt-4 overflow-auto rounded-xl bg-ink-100 p-3 text-left text-xs text-ink-600">{this.state.error.message}</pre>
            <button onClick={() => location.reload()} className="mt-6 h-10 rounded-xl bg-royal-600 px-4 text-sm font-semibold text-white">
              Reload
            </button>
          </div>
        </div>
      );
    return this.props.children;
  }
}
