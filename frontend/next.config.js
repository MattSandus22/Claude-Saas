/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output for a minimal production Docker image.
  output: "standalone",
  // Security headers applied by Next for the app shell. The FastAPI backend sets
  // its own headers for API responses.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};
module.exports = nextConfig;
