# MCPGuard frontend image (Next.js 15 standalone output).
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

FROM node:22-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# API base is baked at build time for the browser bundle.
ARG NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV NEXT_TELEMETRY_DISABLED=1
# Enables `output: "standalone"` in next.config.js for this container build.
ENV DOCKER_BUILD=1
RUN npm run build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Standalone output ships only what's needed to run.
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
RUN useradd --create-home --uid 10001 nextjs && chown -R nextjs:nextjs /app
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
