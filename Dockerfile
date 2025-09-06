# Use Node.js 20 LTS Alpine for better compatibility
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for Puppeteer
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# Tell Puppeteer to skip installing Chromium (we use system package)
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership of app directory
RUN chown -R nodejs:nodejs /app
USER nodejs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "const http = require('http'); \
                 const options = { \
                   host: 'localhost', \
                   port: 3001, \
                   path: '/api/health', \
                   timeout: 2000 \
                 }; \
                 const req = http.request(options, (res) => { \
                   process.exit(res.statusCode === 200 ? 0 : 1); \
                 }); \
                 req.on('error', () => process.exit(1)); \
                 req.end();"

# Start the application
CMD ["node", "server.js"]

