import { AppShell } from "./app-shell";
export function ProtectedPage({ children }: { children: React.ReactNode }) { return <AppShell>{children}</AppShell>; }
