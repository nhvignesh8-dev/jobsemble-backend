# Secure Backend Environment Setup

## Required Environment Variables

The secure backend requires the following environment variables to be set:

### 🔐 **System API Keys** (Required for Production)

```bash
# System Tavily API Key - Used for freemium users' free searches
TAVILY_API_KEY=tvly-your-system-api-key-here
```

### 🛡️ **Security Configuration** (Optional - defaults provided)

```bash
# JWT Secret for token signing (auto-generated if not provided)
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Encryption key for API key storage (auto-generated if not provided)
ENCRYPTION_KEY=your-32-character-encryption-key-here
```

### 🗄️ **Database Configuration** (Optional - defaults provided)

```bash
# Appwrite Configuration
VITE_APPWRITE_ENDPOINT=https://nyc.cloud.appwrite.io/v1
VITE_APPWRITE_PROJECT_ID=68bb20f90028125703bb
VITE_APPWRITE_DATABASE_ID=job-scout-db
VITE_APPWRITE_COLLECTION_ID=users
```

## Development Setup

### Local Development
```bash
cd secure-backend
export TAVILY_API_KEY="your-system-tavily-api-key"
node server.js
```

### Using .env file (Not recommended for production)
Create `secure-backend/.env`:
```bash
TAVILY_API_KEY=your-system-tavily-api-key
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-encryption-key
```

## Production Deployment

### DigitalOcean App Platform
Set environment variables in the App Platform dashboard:
- Go to your app → Settings → Environment Variables
- Add `TAVILY_API_KEY` with your system API key

### AWS/GCP/Azure
Set environment variables in your cloud platform's configuration:
- AWS: Lambda Environment Variables / ECS Task Definition
- GCP: Cloud Functions Environment Variables / Cloud Run
- Azure: App Service Application Settings

## Security Best Practices

1. **Never commit API keys to version control**
2. **Use different keys for development and production**
3. **Rotate API keys regularly**
4. **Monitor API key usage and rate limits**
5. **Use cloud platform secret management when available**

## Troubleshooting

### Error: "System Tavily API key not configured"
- Ensure `TAVILY_API_KEY` environment variable is set
- Verify the API key is valid and has sufficient credits
- Check cloud platform environment variable configuration

### Error: "Invalid signature" for JWT tokens
- Check if `JWT_SECRET` is consistent across restarts
- In production, set a fixed `JWT_SECRET` environment variable

## API Key Management

- **System API Key**: Used for freemium users (first 3 searches)
- **User API Keys**: Encrypted and stored in database
- **Environment Variables**: Never logged or exposed in responses
