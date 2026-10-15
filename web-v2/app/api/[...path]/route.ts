import { NextRequest } from "next/server";

const hopByHopHeaders = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function setCookieValues(headers: Headers): string[] {
  const nativeValues = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  if (nativeValues.length) return nativeValues;
  const combined = headers.get("set-cookie");
  // Some fetch implementations combine Set-Cookie values. The lookahead only
  // accepts a new cookie-name assignment, so commas inside an Expires value do
  // not split the header.
  return combined ? combined.split(/,(?=\s*[^;,\s]+=)/).map(value => value.trim()) : [];
}

async function forward(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const upstream = (process.env.ACCESSPROOF_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
  const url = new URL(`${upstream}/api/${path.map(encodeURIComponent).join("/")}`);
  request.nextUrl.searchParams.forEach((value, key) => url.searchParams.append(key, value));

  const headers = new Headers(request.headers);
  hopByHopHeaders.forEach(header => headers.delete(header));
  headers.delete("x-organization-id");
  const organizationId = request.cookies.get("accessproof_organization")?.value;
  if (organizationId) headers.set("x-organization-id", organizationId);
  headers.set("x-forwarded-host", request.headers.get("host") ?? "");
  headers.set("x-forwarded-proto", request.nextUrl.protocol.replace(":", ""));

  try {
    const response = await fetch(url, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer(),
      redirect: "manual",
      cache: "no-store",
    });
    const responseHeaders = new Headers(response.headers);
    hopByHopHeaders.forEach(header => responseHeaders.delete(header));
    // Undici exposes multiple Set-Cookie values separately. Preserve that boundary
    // so a login response installs both the HttpOnly session and CSRF cookie.
    const cookieHeaders = setCookieValues(response.headers);
    responseHeaders.delete("set-cookie");
    cookieHeaders.forEach(cookie => responseHeaders.append("set-cookie", cookie));
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch {
    return Response.json({ detail: "The AccessProof API is currently unavailable." }, { status: 503 });
  }
}

export const dynamic = "force-dynamic";
export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
export const OPTIONS = forward;
