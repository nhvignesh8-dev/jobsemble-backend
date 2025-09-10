# Use Alpine Linux with Node.js for smaller image and better container compatibility  
FROM node:20-alpine

# Set npm configuration for better reliability and fix aliases issue
RUN npm config set registry https://registry.npmjs.org/ && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm config delete aliases

# Install Chromium and dependencies with container optimizations
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    dbus \
    && rm -rf /var/cache/apk/* \
    && mkdir -p /tmp \
    && chmod 1777 /tmp \
    && addgroup -g 1001 -S pptruser \
    && adduser -S -D -H -u 1001 -s /sbin/nologin -G pptruser pptruser

# Create app directory
WORKDIR /workspace

# Copy package files
COPY package*.json ./

# Install dependencies with explicit npm configuration
RUN npm config delete aliases && \
    npm ci --only=production --no-audit --no-fund --prefer-offline

# Copy application code
COPY . .

# Set Chromium path for Puppeteer
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# Expose port
EXPOSE 3001

# Start the application  
CMD ["node", "server.js"]