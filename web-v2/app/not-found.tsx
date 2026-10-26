import Link from "next/link";
export default function NotFound(){return <main className="standalone-state"><p className="eyebrow">404</p><h1>Page not found</h1><p className="muted">The page may have moved or you may not have access to it.</p><Link className="button compact" href="/dashboard">Return to dashboard</Link></main>}
