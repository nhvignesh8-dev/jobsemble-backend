# Use an image that already has Chrome installed
FROM ghcr.io/puppeteer/puppeteer:21.5.2

# Set working directory
WORKDIR /workspace

# Copy package files first for better caching
COPY package*.json ./

# Install Node.js dependencies
# Skip Puppeteer download since it's already included in the image
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable
RUN npm ci --only=production

# Copy application code
COPY . .

# Expose port
EXPOSE 3001

# Start the application  
CMD ["node", "server.js"]