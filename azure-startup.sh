#!/bin/bash
# Azure Container Startup Script

echo "🚀 Starting Azure Container Setup..."

# Install required packages
apt-get update -y
apt-get install -y curl git

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Verify Node.js installation
echo "Node.js version: $(node --version)"
echo "NPM version: $(npm --version)"

# Create app directory
mkdir -p /app
cd /app

# Clone the repository
echo "📥 Cloning repository..."
git clone https://github.com/nhvignesh8-dev/jobsemble-backend.git .

# Create environment file
echo "🔧 Setting up environment..."
cat > .env << EOF
CLOUD_PROVIDER=AZURE-CONTAINER
SEARCH_BACKEND=tavily
TAVILY_API_KEY=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
PORT=3001
NODE_ENV=production
EOF

# Install dependencies
echo "📦 Installing dependencies..."
npm install --production

# Start the application
echo "🌟 Starting job scraper server..."
exec node server.js
