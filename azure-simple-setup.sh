#!/bin/bash
set -e

echo "🚀 Azure Container Setup Started..."

# Update and install basic tools
apt-get update -y
apt-get install -y curl git

# Install Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

echo "✅ Node.js $(node --version) installed"
echo "✅ NPM $(npm --version) installed"

# Create app directory
mkdir -p /app
cd /app

# Clone repository
echo "📥 Cloning repository..."
git clone https://github.com/nhvignesh8-dev/jobsemble-backend.git .

# Create environment file
echo "🔧 Creating environment..."
cat > .env << 'EOF'
CLOUD_PROVIDER=AZURE-CONTAINER-FIXED
SEARCH_BACKEND=tavily
TAVILY_API_KEY=${TAVILY_API_KEY:-"your_tavily_api_key_here"}
PORT=3001
NODE_ENV=production
EOF

# Install dependencies
echo "📦 Installing dependencies..."
npm install --production

echo "🌟 Starting server..."
exec node server.js
