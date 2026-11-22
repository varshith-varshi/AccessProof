import "@fontsource-variable/inter";
import "./index.css";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ToastProvider, Skeleton } from "./components/ui";
import { AppShell, PublicLayout, RequireAuth } from "./layouts/layouts";
import { ApiError } from "./lib/api";
import { AuthProvider } from "./lib/auth";
import { ErrorBoundary, Forbidden, NotFound } from "./pages/Errors";
import Landing from "./pages/Landing";
import Login from "./pages/Login";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Catalog = lazy(() => import("./pages/Catalog"));
const BookDetails = lazy(() => import("./pages/BookDetails"));
const Reader = lazy(() => import("./pages/Reader"));
const member = () => import("./pages/Member");
const MyBooks = lazy(() => member().then((m) => ({ default: m.MyBooks })));
const Reservations = lazy(() => member().then((m) => ({ default: m.Reservations })));
const Ebooks = lazy(() => member().then((m) => ({ default: m.Ebooks })));
const Recommendations = lazy(() => member().then((m) => ({ default: m.Recommendations })));
const FinesPage = lazy(() => member().then((m) => ({ default: m.FinesPage })));
const Profile = lazy(() => member().then((m) => ({ default: m.Profile })));
const admin = () => import("./pages/admin/Admin");
const security = () => import("./pages/admin/Security");
const AdminDashboard = lazy(() => admin().then((m) => ({ default: m.AdminDashboard })));
const AdminInventory = lazy(() => admin().then((m) => ({ default: m.AdminInventory })));
const AdminMembers = lazy(() => admin().then((m) => ({ default: m.AdminMembers })));
const AdminLoans = lazy(() => admin().then((m) => ({ default: m.AdminLoans })));
const AdminReservations = lazy(() => admin().then((m) => ({ default: m.AdminReservations })));
const AdminFines = lazy(() => admin().then((m) => ({ default: m.AdminFines })));
const AdminReports = lazy(() => admin().then((m) => ({ default: m.AdminReports })));
const AdminAudit = lazy(() => security().then((m) => ({ default: m.AdminAudit })));
const AdminSettings = lazy(() => security().then((m) => ({ default: m.AdminSettings })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: true,
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
    },
  },
});

const Loading = () => (
  <div className="space-y-4 p-2">
    <Skeleton className="h-8 w-64" />
    <Skeleton className="h-4 w-96 max-w-full" />
    <Skeleton className="mt-6 h-48 w-full" />
  </div>
);

const Member = () => (
  <RequireAuth>
    <AppShell />
  </RequireAuth>
);
const Librarian = () => (
  <RequireAuth librarian>
    <AppShell admin />
  </RequireAuth>
);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <BrowserRouter>
            <AuthProvider>
              <Suspense fallback={<Loading />}>
                <Routes>
                  <Route element={<PublicLayout />}>
                    <Route index element={<Landing />} />
                    <Route path="403" element={<Forbidden />} />
                    <Route path="*" element={<NotFound />} />
                  </Route>
                  <Route path="login" element={<Login />} />
                  <Route
                    path="ebooks/:id/read"
                    element={
                      <RequireAuth>
                        <Reader />
                      </RequireAuth>
                    }
                  />
                  <Route element={<Member />}>
                    <Route path="dashboard" element={<Dashboard />} />
                    <Route path="books" element={<Catalog />} />
                    <Route path="books/:id" element={<BookDetails />} />
                    <Route path="my-books" element={<MyBooks />} />
                    <Route path="reservations" element={<Reservations />} />
                    <Route path="ebooks" element={<Ebooks />} />
                    <Route path="recommendations" element={<Recommendations />} />
                    <Route path="fines" element={<FinesPage />} />
                    <Route path="profile" element={<Profile />} />
                  </Route>
                  <Route path="admin" element={<Librarian />}>
                    <Route index element={<AdminDashboard />} />
                    <Route path="books" element={<AdminInventory />} />
                    <Route path="members" element={<AdminMembers />} />
                    <Route path="loans" element={<AdminLoans />} />
                    <Route path="reservations" element={<AdminReservations />} />
                    <Route path="fines" element={<AdminFines />} />
                    <Route path="reports" element={<AdminReports />} />
                    <Route path="audit" element={<AdminAudit />} />
                    <Route path="settings" element={<AdminSettings />} />
                    <Route path="*" element={<Navigate to="/admin" replace />} />
                  </Route>
                </Routes>
              </Suspense>
            </AuthProvider>
          </BrowserRouter>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
);
