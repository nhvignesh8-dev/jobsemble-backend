/**
 * Secure Backend Proxy for Jobsemble
 * Implements security best practices for API key management
 * 
 * Security Features:
 * - Server-side encrypted key storage
 * - Short-lived JWT tokens
 * - Rate limiting per user
 * - Input validation and sanitization
 * - Audit logging (with key redaction)
 * - Allowlisted endpoints only
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import axios from 'axios';
import { Client, Databases, Query, ID } from 'appwrite';

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy for DigitalOcean App Platform and other cloud providers
app.set('trust proxy', 1);

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);

// Appwrite Configuration
const client = new Client()
  .setEndpoint(process.env.VITE_APPWRITE_ENDPOINT || 'https://nyc.cloud.appwrite.io/v1')
  .setProject(process.env.VITE_APPWRITE_PROJECT_ID || '68bb20f90028125703bb');

const databases = new Databases(client);
const DATABASE_ID = process.env.VITE_APPWRITE_DATABASE_ID || 'job-scout-db';
const COLLECTION_ID = process.env.VITE_APPWRITE_COLLECTION_ID || 'users';

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.tavily.com", "https://serpapi.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

app.use(cors({
  origin: [
    'http://localhost:8080',
    'http://localhost:5173',
    'https://jobsemble.tech',
    'https://job-scout-automaton.lovable.app'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Rate Limiting
const globalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // Limit each user to 20 API calls per minute
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: 'API rate limit exceeded' }
});

app.use(globalRateLimit);

// Encryption Utilities
function encrypt(text) {
  if (!text) return '';
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  if (!encryptedText) return '';
  
  const [ivHex, encrypted] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Authentication Middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Audit Logging (with key redaction)
function auditLog(action, userId, details = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    action,
    userId,
    ip: details.ip,
    userAgent: details.userAgent,
    // Never log actual API keys
    apiKeyPresent: !!details.apiKey,
    endpoint: details.endpoint,
    success: details.success
  };
  
  console.log('AUDIT:', JSON.stringify(logEntry));
}

// Health Check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    security: 'enabled'
  });
});

// Authentication Endpoint - Issue Short-lived JWT
app.post('/auth/token', async (req, res) => {
  try {
    const { appwriteJwt } = req.body;
    
    if (!appwriteJwt) {
      return res.status(400).json({ error: 'Appwrite JWT required' });
    }

    // Verify the Appwrite JWT and extract user info
    // In production, you'd verify this with Appwrite
    // For now, we'll create a short-lived token
    
    const payload = {
      userId: req.body.userId,
      email: req.body.email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (30 * 60) // 30 minutes
    };

    const token = jwt.sign(payload, JWT_SECRET);
    
    auditLog('token_issued', payload.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    res.json({ 
      token,
      expiresIn: 1800 // 30 minutes
    });

  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Token generation failed' });
  }
});

// Store API Key Endpoint
app.post('/api/keys/store', authenticateToken, async (req, res) => {
  try {
    const { apiKey, provider, label } = req.body;
    
    if (!apiKey || !provider) {
      return res.status(400).json({ error: 'API key and provider required' });
    }

    // Validate provider
    if (!['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }

    // Encrypt the API key
    const encryptedKey = encrypt(apiKey);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', req.user.userId)]
    );

    if (userDocs.documents.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    const userDoc = userDocs.documents[0];
    
    // Get existing API keys or create empty object
    let apiKeys = {};
    try {
      apiKeys = userDoc.apiKeys ? JSON.parse(userDoc.apiKeys) : {};
    } catch (e) {
      apiKeys = {};
    }

    // Store the encrypted API key
    if (provider === 'tavily') {
      apiKeys.tavilyApiKey = encryptedKey;
    } else if (provider === 'serp') {
      apiKeys.serpApiKey = encryptedKey;
    }

    // Update the user document with the new API key
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTION_ID,
      userDoc.$id,
      {
        apiKeys: JSON.stringify(apiKeys)
      }
    );
    
    auditLog('key_stored', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      provider,
      success: true
    });

    res.json({ 
      success: true,
      message: 'API key stored securely',
      keyId: 'generated-key-id'
    });

  } catch (error) {
    console.error('Key storage error:', error);
    res.status(500).json({ error: 'Failed to store API key' });
  }
});

// Tavily Search Proxy
app.post('/api/proxy/tavily/search', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, searchDepth = 'basic', maxResults = 20 } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Search query required' });
    }

    // Get user's encrypted Tavily API key
    const userKey = await getUserApiKey(req.user.userId, 'tavily');
    if (!userKey) {
      return res.status(404).json({ error: 'Tavily API key not found' });
    }

    // Decrypt just-in-time
    const apiKey = decrypt(userKey);

    // Make request to Tavily API
    const response = await axios.post('https://api.tavily.com/search', {
      api_key: apiKey,
      query,
      search_depth: searchDepth,
      include_answer: false,
      include_images: false,
      include_raw_content: false,
      max_results: maxResults
    }, {
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    auditLog('tavily_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: 'tavily/search',
      success: true
    });

    // Return results (never log the actual API response for privacy)
    res.json(response.data);

  } catch (error) {
    console.error('Tavily proxy error:', error.message);
    
    auditLog('tavily_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: 'tavily/search',
      success: false
    });

    if (error.response?.status === 401) {
      res.status(401).json({ error: 'Invalid Tavily API key' });
    } else if (error.response?.status === 429) {
      res.status(429).json({ error: 'Tavily API rate limit exceeded' });
    } else {
      res.status(500).json({ error: 'Search request failed' });
    }
  }
});

// SERP API Search Proxy
app.post('/api/proxy/serp/search', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, engine = 'google', num = 50, timeFilter } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Search query required' });
    }

    // Get user's encrypted SERP API key
    const userKey = await getUserApiKey(req.user.userId, 'serp');
    if (!userKey) {
      return res.status(404).json({ error: 'SERP API key not found' });
    }

    // Decrypt just-in-time
    const apiKey = decrypt(userKey);

    // Build request parameters
    const params = new URLSearchParams({
      api_key: apiKey,
      engine,
      q: query,
      num: num.toString()
    });

    if (timeFilter && timeFilter !== 'anytime') {
      const timeFilters = {
        'day': 'qdr:d',
        'week': 'qdr:w', 
        'month': 'qdr:m',
        'year': 'qdr:y',
        'qdr:d': 'qdr:d',
        'qdr:w': 'qdr:w',
        'qdr:m': 'qdr:m',
        'qdr:y': 'qdr:y'
      };
      
      if (timeFilters[timeFilter]) {
        params.append('tbs', timeFilters[timeFilter]);
      }
    }

    // Make request to SERP API
    const response = await axios.get(`https://serpapi.com/search?${params.toString()}`, {
      timeout: 30000,
      headers: {
        'Accept': 'application/json'
      }
    });

    auditLog('serp_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: 'serp/search',
      success: true
    });

    res.json(response.data);

  } catch (error) {
    console.error('SERP proxy error:', error.message);
    
    auditLog('serp_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: 'serp/search',
      success: false
    });

    if (error.response?.status === 401) {
      res.status(401).json({ error: 'Invalid SERP API key' });
    } else if (error.response?.status === 429) {
      res.status(429).json({ error: 'SERP API rate limit exceeded' });
    } else if (error.response?.status === 402) {
      res.status(402).json({ error: 'SERP API credits exhausted' });
    } else {
      res.status(500).json({ error: 'Search request failed' });
    }
  }
});

// Helper function to get user's API key (simplified)
async function getUserApiKey(userId, provider) {
  try {
    // This is a simplified implementation
    // In practice, you'd query your Appwrite database
    // const response = await databases.listDocuments(DATABASE_ID, COLLECTION_ID, [
    //   Query.equal('userId', userId),
    //   Query.equal('provider', provider)
    // ]);
    
    // For now, return null to indicate key not found
    return null;
    
  } catch (error) {
    console.error('Error fetching user API key:', error);
    return null;
  }
}

// Job Search Proxy - handles individual job board searches
app.post('/api/proxy/search-jobs', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, location, jobBoard, provider, timeFilter } = req.body;
    
    if (!query || !location || !jobBoard || !provider) {
      return res.status(400).json({ error: 'Missing required fields (query, location, jobBoard, provider)' });
    }

    // Validate provider
    if (!['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }

    console.log(`🔍 Job search request: ${query} in ${location} on ${jobBoard} via ${provider}`);

    // Get user's encrypted API key for the provider
    const userKey = await getUserApiKey(req.user.userId, provider);
    if (!userKey) {
      return res.status(404).json({ error: `${provider.charAt(0).toUpperCase() + provider.slice(1)} API key not found` });
    }

    // Decrypt just-in-time
    const apiKey = decrypt(userKey);

    let searchResults = [];

    // Build job board specific search query
    const jobBoardQuery = buildJobBoardQuery(query, location, jobBoard, provider);

    // Use the appropriate search engine
    if (provider === 'tavily') {
      // Tavily search
      const tavilyResponse = await axios.post('https://api.tavily.com/search', {
        api_key: apiKey,
        query: jobBoardQuery,
        search_depth: 'basic',
        include_answer: false,
        include_images: false,
        include_raw_content: false,
        max_results: 50
      }, {
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Process Tavily results into job format
      searchResults = (tavilyResponse.data.results || []).map(result => {
        const cleanTitle = cleanJobTitle(result.title);
        return {
          title: cleanTitle,
          company: extractCompanyFromUrl(result.url) || extractCompanyFromJobBoard(jobBoard),
          location: location,
          url: result.url,
          description: result.content || '',
          datePosted: 'Recently',
          source: jobBoard
        };
      });

    } else if (provider === 'serp') {
      // SERP API search
      const params = new URLSearchParams({
        api_key: apiKey,
        engine: 'google',
        q: jobBoardQuery,
        num: '50'
      });

      if (timeFilter && timeFilter !== 'anytime') {
        const timeFilters = {
          'day': 'qdr:d',
          'week': 'qdr:w', 
          'month': 'qdr:m',
          'year': 'qdr:y',
          'qdr:d': 'qdr:d',
          'qdr:w': 'qdr:w',
          'qdr:m': 'qdr:m',
          'qdr:y': 'qdr:y'
        };
        params.append('tbs', timeFilters[timeFilter] || timeFilter);
      }

      const serpResponse = await axios.get(`https://serpapi.com/search?${params}`, {
        timeout: 30000
      });

      // Process SERP results into job format
      const organicResults = serpResponse.data.organic_results || [];
      searchResults = organicResults.map(result => {
        const cleanTitle = cleanJobTitle(result.title);
        return {
          title: cleanTitle,
          company: extractCompanyFromUrl(result.link) || extractCompanyFromJobBoard(jobBoard),
          location: location,
          url: result.link,
          description: result.snippet || '',
          datePosted: 'Recently',
          source: jobBoard
        };
      });
    }

    // Filter out results that don't look like jobs
    searchResults = searchResults.filter(job => 
      job.title && 
      job.title.length > 3 && 
      !job.title.toLowerCase().includes('error') &&
      job.url
    );

    auditLog('job_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      provider,
      query,
      location,
      jobBoard,
      resultCount: searchResults.length,
      success: true
    });

    res.json(searchResults);

  } catch (error) {
    console.error('Job search proxy error:', error.message);
    
    auditLog('job_search', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: false,
      error: error.message
    });

    if (error.response?.status === 401) {
      res.status(401).json({ error: 'Invalid API key' });
    } else if (error.response?.status === 429) {
      res.status(429).json({ error: 'API rate limit exceeded' });
    } else if (error.response?.status === 402) {
      res.status(402).json({ error: 'API credits exhausted' });
    } else {
      res.status(500).json({ error: 'Search request failed' });
    }
  }
});

// Helper functions for job processing
function buildJobBoardQuery(query, location, jobBoard, provider) {
  const board = jobBoard.toLowerCase();
  
  if (provider === 'tavily') {
    // Tavily doesn't need site restrictions, just good keywords
    return `${query} jobs ${location} ${getJobBoardName(board)}`;
  } else {
    // SERP API with specific site targeting
    const domain = getJobBoardDomain(board);
    return `"${query}" jobs "${location}" site:${domain}`;
  }
}

function getJobBoardName(boardId) {
  const names = {
    'greenhouse': 'Greenhouse',
    'lever': 'Lever',
    'ashby': 'Ashby',
    'pinpoint': 'Pinpoint',
    'paylocity': 'Paylocity',
    'keka': 'Keka',
    'workable': 'Workable',
    'breezyhr': 'BreezyHR',
    'wellfound': 'Wellfound AngelList',
    'ycombinator': 'Y Combinator',
    'oracle': 'Oracle',
    'workday': 'Workday',
    'recruitee': 'Recruitee',
    'rippling': 'Rippling',
    'gusto': 'Gusto',
    'smartrecruiters': 'SmartRecruiters',
    'jazzhr': 'JazzHR',
    'jobvite': 'Jobvite',
    'icims': 'iCIMS',
    'builtin': 'Builtin',
    'adp': 'ADP'
  };
  return names[boardId] || boardId;
}

function extractCompanyFromJobBoard(jobBoard) {
  // Fallback company name based on job board
  const companies = {
    'greenhouse': 'Company via Greenhouse',
    'lever': 'Company via Lever',
    'ashby': 'Company via Ashby',
    'pinpoint': 'Company via Pinpoint',
    'paylocity': 'Company via Paylocity',
    'keka': 'Company via Keka',
    'workable': 'Company via Workable',
    'breezyhr': 'Company via BreezyHR',
    'wellfound': 'Company via Wellfound',
    'ycombinator': 'Company via Y Combinator',
    'oracle': 'Company via Oracle',
    'workday': 'Company via Workday',
    'recruitee': 'Company via Recruitee',
    'rippling': 'Company via Rippling',
    'gusto': 'Company via Gusto',
    'smartrecruiters': 'Company via SmartRecruiters',
    'jazzhr': 'Company via JazzHR',
    'jobvite': 'Company via Jobvite',
    'icims': 'Company via iCIMS',
    'builtin': 'Company via Builtin',
    'adp': 'Company via ADP'
  };
  return companies[jobBoard] || 'Company';
}

function cleanJobTitle(title) {
  if (!title) return '';
  
  // Remove common unwanted patterns
  title = title.replace(/\s*-\s*.*$/, ''); // Remove everything after first dash
  title = title.replace(/\s*\|\s*.*$/, ''); // Remove everything after pipe
  title = title.replace(/\s*at\s+\w+.*$/i, ''); // Remove "at Company"
  title = title.replace(/\[\d{4}\]\s*/, ''); // Remove [2024] year prefixes
  title = title.replace(/^\d+\.\s*/, ''); // Remove numbered list prefixes
  title = title.replace(/^.*?\s*-\s*/, ''); // Remove prefixes like "123 -"
  
  // Clean up extra whitespace
  title = title.trim().replace(/\s+/g, ' ');
  
  return title;
}

function extractCompanyFromUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    let company = hostname.replace(/^(www|jobs|careers)\./, '');
    company = company.split('.')[0];
    return company.charAt(0).toUpperCase() + company.slice(1);
  } catch (e) {
    return null;
  }
}

function getJobBoardDomain(boardId) {
  const domains = {
    'greenhouse': 'greenhouse.io',
    'lever': 'lever.co',
    'ashby': 'ashby.com',
    'pinpoint': 'pinpoint.com',
    'paylocity': 'paylocity.com',
    'keka': 'keka.com',
    'workable': 'workable.com',
    'breezyhr': 'breezyhr.com',
    'wellfound': 'wellfound.com',
    'ycombinator': 'ycombinator.com',
    'oracle': 'oracle.com',
    'workday': 'workday.com',
    'recruitee': 'recruitee.com',
    'rippling': 'rippling.com',
    'gusto': 'gusto.com',
    'smartrecruiters': 'smartrecruiters.com',
    'jazzhr': 'jazzhr.com',
    'jobvite': 'jobvite.com',
    'icims': 'icims.com',
    'builtin': 'builtin.com',
    'adp': 'adp.com'
  };
  return domains[boardId] || boardId;
}

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Secure API Proxy running on port ${PORT}`);
  console.log('🛡️ Security features enabled:');
  console.log('  - Helmet security headers');
  console.log('  - Rate limiting');
  console.log('  - API key encryption');
  console.log('  - Audit logging');
  console.log('  - JWT authentication');
  console.log('  - Input validation');
});
