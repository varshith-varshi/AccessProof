import type {NextConfig} from "next";
const config: NextConfig = {
  output:"standalone",
  // Installer archives are scoped to verified customer sessions, never public
  // CDN artifacts. The server-side proxy revalidates the session for every
  // request; these headers prevent an intermediary from reusing a ZIP response.
  async headers() {
    return [{
      source: "/downloads/:path*",
      headers: [
        { key: "Cache-Control", value: "private, no-store, max-age=0" },
        { key: "X-Content-Type-Options", value: "nosniff" },
      ],
    }];
  },
};
export default config;
