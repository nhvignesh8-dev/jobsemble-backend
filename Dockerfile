# Use an image that already has Chrome installed
FROM ghcr.io/puppeteer/puppeteer:21.5.2

# Create and set ownership of workspace directory as root
USER root
RUN mkdir -p /workspace && chown -R pptruser:pptruser /workspace

# Set working directory and switch to pptruser
WORKDIR /workspace
USER pptruser

# Copy package files first for better caching
COPY --chown=pptruser:pptruser package*.json ./

# Install Node.js dependencies
# Skip Puppeteer download since it's already included in the image
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
# Let Puppeteer auto-detect Chrome in the Docker image
# ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome
RUN npm install --only=production

# Copy application code
COPY --chown=pptruser:pptruser . .

# Expose port
EXPOSE 3001

# Start the application  
CMD ["node", "server.js"]