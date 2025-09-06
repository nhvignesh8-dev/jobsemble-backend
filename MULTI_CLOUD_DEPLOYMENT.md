# 🌍 Multi-Cloud Deployment Guide

## Overview
Deploy job scraper backend across 4 major cloud providers for maximum reliability and global coverage.

## Cloud Providers Setup

### 1. ✅ DigitalOcean Professional (Primary)
**Status**: Active and working
- **URL**: `https://jobsemble-lf37e.ondigitalocean.app`
- **Plan**: Professional ($24/month)
- **Features**: Auto-scaling, GitHub integration, 99.99% uptime SLA

### 2. 🔧 Azure Container Instances (Secondary)
**Status**: Needs Node.js setup fix

#### Fix Azure Deployment:
```bash
# Create new container with proper startup script
az container create \
  --resource-group jobsemble-rg \
  --name jobsemble-backend-fixed \
  --image mcr.microsoft.com/azure-functions/node:4-node20-appservice \
  --cpu 1 \
  --memory 1.5 \
  --restart-policy Always \
  --ports 3001 \
  --location "West US 2" \
  --environment-variables \
    CLOUD_PROVIDER=AZURE-CONTAINER \
    SEARCH_BACKEND=tavily \
    PORT=3001 \
    NODE_ENV=production \
  --secure-environment-variables \
    TAVILY_API_KEY=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 \
  --command-line "/bin/bash -c 'apt-get update && apt-get install -y git curl && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs && mkdir -p /app && cd /app && git clone https://github.com/nhvignesh8-dev/jobsemble-backend.git . && npm install --production && exec node server.js'"
```

### 3. 🆕 Google Cloud Platform Cloud Run (Tertiary)
**Status**: Ready to deploy

#### GCP Setup Steps:
```bash
# 1. Enable required APIs
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com

# 2. Create secret for Tavily API key
echo "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" | gcloud secrets create tavily-api-key --data-file=-

# 3. Deploy using Cloud Build
gcloud builds submit --config cloudbuild.yaml

# 4. Get service URL
gcloud run services describe jobsemble-backend --region=us-central1 --format="value(status.url)"
```

**Expected URL format**: `https://jobsemble-backend-xyz-uc.a.run.app`

### 4. 🔄 AWS EC2 (Quaternary)
**Status**: IP verification needed

#### AWS Health Check:
```bash
# Get current public IP
aws ec2 describe-instances --instance-ids i-YOUR-INSTANCE-ID --query 'Reservations[0].Instances[0].PublicIpAddress'

# Test health endpoint
curl http://NEW-IP:3001/api/health
```

## Load Balancer Configuration

Update `/src/services/loadBalancer.ts`:
```typescript
private endpoints: string[] = [
  'https://jobsemble-lf37e.ondigitalocean.app',           // DigitalOcean Pro
  'https://jobsemble-backend-xyz-uc.a.run.app',          // GCP Cloud Run
  'http://jobsemble-backend-fixed.westus2.azurecontainer.io:3001', // Azure Fixed
  'http://AWS-PUBLIC-IP:3001',                           // AWS EC2
];
```

## Benefits of 4-Cloud Setup

### 🌍 **Global Coverage**
- **DigitalOcean**: North America (primary)
- **GCP**: Global auto-scaling
- **Azure**: Europe/Asia proximity
- **AWS**: Worldwide edge locations

### 🛡️ **Redundancy Levels**
- **99.99%+ uptime**: Multiple provider failover
- **Geographic distribution**: Natural disaster resilience
- **Provider diversity**: No single point of failure
- **Auto-scaling**: Handle traffic spikes seamlessly

### 💰 **Cost Optimization**
- **DigitalOcean Pro**: $24/month (primary load)
- **GCP Cloud Run**: Pay-per-request (traffic bursts)
- **Azure Container**: Free tier (backup)
- **AWS EC2**: Free tier (emergency backup)

## Monitoring & Health Checks

The load balancer automatically:
- Health checks every 30 seconds
- Routes traffic to healthy endpoints
- Fails over in <5 seconds
- Removes unhealthy endpoints temporarily
- Auto-recovers when endpoints come back online

## Deployment Commands Summary

```bash
# Push updates to all clouds
git push origin main                    # Triggers DigitalOcean auto-deploy
gcloud builds submit --config cloudbuild.yaml  # Updates GCP Cloud Run
# Azure & AWS need manual deployment

# Test all endpoints
curl https://jobsemble-lf37e.ondigitalocean.app/api/health
curl https://jobsemble-backend-xyz-uc.a.run.app/api/health
curl http://azure-url:3001/api/health
curl http://aws-ip:3001/api/health
```

## Next Steps
1. Fix Azure container startup
2. Deploy to GCP Cloud Run
3. Verify AWS EC2 IP
4. Update load balancer with all 4 endpoints
5. Test complete failover scenarios
