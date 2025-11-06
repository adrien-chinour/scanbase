# Multi-stage build for production
FROM node:24-alpine AS builder

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM node:24-alpine

# Install runtime dependencies for better-sqlite3
RUN apk add --no-cache \
    sqlite \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application files
COPY package.json package-lock.json ./
COPY server.js ./
COPY routes.js ./
COPY lib ./lib
COPY public ./public

# Create data directory for SQLite database (mounted as volume)
# Database will be created at /app/data/sbom.db (can be persisted via volume)
RUN mkdir -p /app/data

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/me', (r) => {process.exit(r.statusCode === 200 || r.statusCode === 401 ? 0 : 1)})"

# Set production environment
ENV NODE_ENV=production

# Start the application
CMD ["node", "server.js"]

