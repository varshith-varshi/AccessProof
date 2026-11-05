import { NextRequest, NextResponse } from "next/server";

const publicRoutes = new Set(["/", "/login", "/register", "/verify", "/forgot-password", "/reset-password", "/accept-invitation", "/security"]);

function loginRedirect(request: NextRequest): NextResponse {
  const target = request.nextUrl.pathname + request.nextUrl.search;
  const response = NextResponse.redirect(new URL(`/login?next=${encodeURIComponent(target)}`, request.url));
  response.headers.set("Cache-Control", "no-store");
  return response;
}

/**
 * Installer archives are customer downloads, not public Next.js assets. A
 * session-cookie *presence* check is not authentication: any arbitrary cookie
 * previously permitted downloading the 98 MB production ZIP. Revalidate the
 * interactive organization session against the existing API before every
 * download or range/HEAD request; never put a reusable token in the URL.
 */
async function authenticatedInstallerRequest(request: NextRequest): Promise<NextResponse> {
  const upstream = (process.env.ACCESSPROOF_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
  const headers = new Headers();
  headers.set("cookie", request.headers.get("cookie") ?? "");
  // Mirror the existing server-side /api/v1 proxy's trusted-host and active
  // organization handling. The backend checks membership and session expiry.
  headers.set("host", process.env.ACCESSPROOF_API_HOST ?? "api.accessproof.in");
  headers.set("x-forwarded-host", request.headers.get("host") ?? "");
  headers.set("x-forwarded-proto", request.nextUrl.protocol.replace(":", ""));
  const organizationId = request.cookies.get("accessproof_organization")?.value;
  if (organizationId) headers.set("x-organization-id", organizationId);
  try {
    const result = await fetch(`${upstream}/api/v1/auth/me`, {
      method: "GET",
      headers,
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(4500),
    });
    if (result.status === 401 || result.status === 403) return loginRedirect(request);
    if (!result.ok) return new NextResponse("Installer authorization is temporarily unavailable.", {
      status: 503, headers: { "Cache-Control": "no-store" },
    });
    const response = NextResponse.next();
    response.headers.set("Cache-Control", "private, no-store, max-age=0");
    return response;
  } catch {
    // A control-plane outage MUST NOT open the ZIP download gate.
    return new NextResponse("Installer authorization is temporarily unavailable.", {
      status: 503, headers: { "Cache-Control": "no-store" },
    });
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (publicRoutes.has(pathname) || pathname.startsWith("/_next/") || pathname.startsWith("/api/")) return NextResponse.next();
  if (!request.cookies.has("accessproof_session")) return loginRedirect(request);
  if (pathname === "/downloads" || pathname.startsWith("/downloads/")) {
    return authenticatedInstallerRequest(request);
  }
  return NextResponse.next();
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"] };
