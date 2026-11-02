import { NextRequest, NextResponse } from "next/server";

const publicRoutes = new Set(["/", "/login", "/register", "/verify", "/forgot-password", "/reset-password", "/accept-invitation", "/security", "/pricing"]);

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (publicRoutes.has(pathname) || pathname.startsWith("/_next/") || pathname.startsWith("/api/")) return NextResponse.next();
  if (!request.cookies.has("accessproof_session")) return NextResponse.redirect(new URL(`/login?next=${encodeURIComponent(pathname)}`, request.url));
  return NextResponse.next();
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"] };
