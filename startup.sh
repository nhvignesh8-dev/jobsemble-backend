#!/bin/bash

echo "🔧 Installing Chrome dependencies for DigitalOcean..."

# Update package list
apt-get update -y

# Install Chrome dependencies
apt-get install -y \
  libnspr4 \
  libnss3 \
  libxss1 \
  libatk-bridge2.0-0 \
  libdrm2 \
  libxcomposite1 \
  libxdamage1 \
  libxrandr2 \
  libgbm1 \
  libxkbcommon0 \
  libgtk-3-0 \
  libasound2 \
  libxshmfence1 \
  fonts-liberation \
  libappindicator3-1 \
  libatspi2.0-0 \
  libgconf-2-4

echo "✅ Chrome dependencies installed"

# Install Chrome browser
echo "🔧 Installing Chrome browser..."
npx puppeteer browsers install chrome --path /workspace/.cache/puppeteer

echo "✅ Chrome browser installed"

# Start the Node.js server
echo "🚀 Starting Node.js server..."
node server.js
