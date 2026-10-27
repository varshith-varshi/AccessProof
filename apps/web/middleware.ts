import { NextRequest, NextResponse } from "next/server";

const publicRoutes = new Set([
  "/login", "/signup", "/register", "/verify-email", "/resend-verification",
  "/forgot-password", "/reset-password", "/accept-invitation",
]);

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (pathname.startsWith("/_next/") || pathname === "/favicon.ico" || pathname.startsWith("/api/")) {
    return NextResponse.next();
  }
  if (publicRoutes.has(pathname)) return NextResponse.next();
  if (!request.cookies.has("accessproof_session")) {
    const login = new URL("/login", request.url);
    const next = `${pathname}${request.nextUrl.search}`;
    if (next !== "/") login.searchParams.set("next", next);
    return NextResponse.redirect(login);
  }
  if (pathname === "/") return NextResponse.redirect(new URL("/overview", request.url));
  return NextResponse.next();
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
