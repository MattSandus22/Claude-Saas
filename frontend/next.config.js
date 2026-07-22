/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Standalone output is only for the self-contained Docker image (the Dockerfile
  // sets DOCKER_BUILD=1). Managed hosts like Vercel manage their own build output
  // and fail with a "no entry point" error if standalone is forced on, so it stays
  // off unless we're explicitly building the container.
  output: process.env.DOCKER_BUILD ? "standalone" : undefined,
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
