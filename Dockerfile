# Use Alpine Linux with Node.js for smaller image and better container compatibility  
FROM node:18-alpine

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

# Install dependencies
RUN npm install --only=production

# Copy application code
COPY . .

# Set Chromium path for Puppeteer
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# Expose port
EXPOSE 3001

# Start the application  
CMD ["node", "server.js"]