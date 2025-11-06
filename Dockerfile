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

# Create app user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules

# Copy application files
COPY --chown=nodejs:nodejs package.json package-lock.json ./
COPY --chown=nodejs:nodejs server.js ./
COPY --chown=nodejs:nodejs routes.js ./
COPY --chown=nodejs:nodejs lib ./lib
COPY --chown=nodejs:nodejs public ./public

# Create data directory for SQLite database (mounted as volume)
# Database will be created at /app/data/sbom.db (can be persisted via volume)
RUN mkdir -p /app/data && chown -R nodejs:nodejs /app/data

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/me', (r) => {process.exit(r.statusCode === 200 || r.statusCode === 401 ? 0 : 1)})"

# Set production environment
ENV NODE_ENV=production

# Start the application
CMD ["node", "server.js"]

