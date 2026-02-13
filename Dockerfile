# Multi-stage Dockerfile for Vif (Remix + Cloudflare Pages)

# Stage 1: Dependencies
FROM node:18-alpine AS deps
WORKDIR /app

# Install pnpm
RUN corepack enable && corepack prepare pnpm@9.14.4 --activate

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Stage 2: Builder
FROM node:18-alpine AS builder
WORKDIR /app

# Install pnpm
RUN corepack enable && corepack prepare pnpm@9.14.4 --activate

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build the application
RUN pnpm run build

# Stage 3: Production
FROM node:18-alpine AS vif-ai-production
WORKDIR /app

# Install pnpm and required tools
RUN corepack enable && corepack prepare pnpm@9.14.4 --activate && \
    apk add --no-cache bash

# Copy built application
COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/bindings.sh ./bindings.sh
COPY --from=builder /app/worker-configuration.d.ts ./worker-configuration.d.ts

# Make bindings.sh executable
RUN chmod +x ./bindings.sh

# Expose port
EXPOSE 5173

# Set NODE_ENV
ENV NODE_ENV=production

# Start the application using the dockerstart script
CMD ["pnpm", "run", "dockerstart"]

# Stage 4: Development (for local development)
FROM node:18-alpine AS development
WORKDIR /app

# Install pnpm and bash
RUN corepack enable && corepack prepare pnpm@9.14.4 --activate && \
    apk add --no-cache bash git

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install all dependencies (including dev)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Make bindings.sh executable
RUN chmod +x ./bindings.sh

# Expose port
EXPOSE 5173

# Build and start
CMD ["sh", "-c", "pnpm run build && pnpm run dockerstart"]
