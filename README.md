# Jobsemble Multi-Cloud Backend

This is the minimal backend for Jobsemble's job scraping service, optimized for deployment across AWS, DigitalOcean, and Oracle Cloud.

## 🏗️ Architecture

- **AWS EC2 t2.micro**: Primary server (Free tier)
- **DigitalOcean Professional**: Secondary server ($12/month)
- **Oracle ARM Ampere**: Tertiary server (Always free)
- **Oracle Load Balancer**: Traffic distribution (Always free)

## 🚀 Deployment Instructions

### 1. AWS EC2 Deployment

```bash
# 1. Launch t2.micro Ubuntu instance
# 2. Connect via SSH
# 3. Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs git

# 4. Clone and setup
git clone <your-repo-url>
cd cloud-backend
npm install

# 5. Setup environment
cp env-aws.txt .env
# Edit .env with your actual TAVILY_API_KEY

# 6. Install PM2 and start
sudo npm install -g pm2
pm2 start server.js --name jobsemble-aws
pm2 startup
pm2 save

# 7. Configure security group to allow port 3001
```

### 2. DigitalOcean App Platform Deployment

```bash
# 1. Create new App in DO dashboard
# 2. Connect this repository
# 3. Set build/run commands:
#    Build: npm install
#    Run: npm start
# 4. Set environment variables from env-digitalocean.txt
# 5. Deploy
```

### 3. Oracle ARM Ampere Deployment

```bash
# 1. Create ARM Ampere instance (1 OCPU, 6GB RAM)
# 2. Connect via SSH
# 3. Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs git

# 4. Clone and setup
git clone <your-repo-url>
cd cloud-backend
npm install

# 5. Setup environment
cp env-oracle.txt .env
# Edit .env with your actual TAVILY_API_KEY

# 6. Install PM2 and start
sudo npm install -g pm2
pm2 start server.js --name jobsemble-oracle
pm2 startup
pm2 save

# 7. Configure security list to allow port 3001
```

## 🔧 Environment Variables

Each deployment needs these environment variables:

- `CLOUD_PROVIDER`: Identifier for the cloud provider
- `SEARCH_BACKEND`: tavily (default)
- `TAVILY_API_KEY`: Your Tavily API key
- `PORT`: Server port
- `NODE_ENV`: production

## 📊 Health Checks

Each server exposes these endpoints:

- `GET /api/health` - Health check with provider info
- `POST /api/scrape-jobs` - Main job scraping endpoint
- `GET /api/test-tavily` - Tavily API test

## 🌍 Oracle Load Balancer Setup

After deploying all three backends, configure Oracle Load Balancer:

1. Create Flexible Load Balancer
2. Add backend sets for each server
3. Configure health checks pointing to `/api/health`
4. Set up SSL termination
5. Configure custom domain

## 🎯 Frontend Integration

Update your frontend to use the Oracle Load Balancer URL:

```javascript
const BACKEND_URL = 'https://api.jobsemble.com'; // Your Oracle LB URL
```

## 📈 Monitoring

Each server logs with provider identification:
- `[AWS-EC2]` for AWS logs
- `[DigitalOcean-Professional]` for DO logs  
- `[Oracle-ARM-Ampere]` for Oracle logs

## 🔄 Load Distribution

Expected load distribution:
- AWS EC2: 40-50% (Primary)
- DigitalOcean: 30-40% (Secondary)
- Oracle ARM: 10-20% (Tertiary)

Total capacity: 16-22 concurrent searches

# Updated Sun Sep  7 18:16:12 EDT 2025
