import type { NextConfig } from "next";
// API_URL is intentionally server-only: browser requests use this application's
// same-origin /api proxy so host-only CSRF/session cookies continue to work.
// NEXT_PUBLIC_API_URL documents the external API URL for public integrations and
// is a fallback for deployments that do not provide an internal service URL.
const api = process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";
const nextConfig: NextConfig = {
  async rewrites() { return [{ source: "/api/:path*", destination: `${api}/api/:path*` }, { source: "/health/:path*", destination: `${api}/health/:path*` }]; },
};
export default nextConfig;
