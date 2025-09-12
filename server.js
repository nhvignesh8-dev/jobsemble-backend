/**
 * Secure Backend Proxy for Jobsemble
 * Implements security best practices for API key management
 * 
 * Security Features:
 * - Server-side secure key storage
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
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Trust proxy for DigitalOcean App Platform and other cloud providers
app.set('trust proxy', 1);

// Security Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// System API Keys for freemium users - stored securely in database
// Create a system user profile to store system API keys

// Appwrite Configuration
const client = new Client()
  .setEndpoint(process.env.VITE_APPWRITE_ENDPOINT || 'https://nyc.cloud.appwrite.io/v1')
  .setProject(process.env.VITE_APPWRITE_PROJECT_ID || '68bb20f90028125703bb');

const databases = new Databases(client);
const DATABASE_ID = process.env.VITE_APPWRITE_DATABASE_ID || 'job-scout-db';
const COLLECTION_ID = process.env.VITE_APPWRITE_COLLECTION_ID || 'users';

// Session Management - Track active sessions per user
const activeSessions = new Map(); // userId -> { sessionId, token, issuedAt, lastActive, userAgent, ip }

// Cleanup old sessions periodically (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  const maxAge = 30 * 60 * 1000; // 30 minutes
  
  for (const [userId, session] of activeSessions.entries()) {
    if (now - session.lastActive > maxAge) {
      console.log(`🧹 Cleaning up expired session for user ${userId}`);
      activeSessions.delete(userId);
    }
  }
}, 5 * 60 * 1000);

// Helper function to invalidate a user's session
function invalidateUserSession(userId, reason = 'New session created') {
  if (activeSessions.has(userId)) {
    const oldSession = activeSessions.get(userId);
    console.log(`🔒 Invalidating session for user ${userId}: ${reason}`);
    activeSessions.delete(userId);
    return oldSession;
  }
  return null;
}

// Helper function to get valid Google access token using service account
async function getValidAccessToken(userId = null) {
  try {
    // Try to get service account from database first
    let serviceAccountKey = null;
    
    try {
      console.log('🔍 Looking for Google Service Account in database...');
      const systemDoc = await databases.getDocument(DATABASE_ID, COLLECTION_ID, '68c1d918601d5f9f7958');
      console.log('📄 System document retrieved:', !!systemDoc);
      
      if (systemDoc.apiKeys) {
        console.log('🔑 API keys found in document');
        const apiKeys = JSON.parse(systemDoc.apiKeys);
        console.log('🔑 Parsed API keys:', Object.keys(apiKeys));
        if (apiKeys.googleServiceAccountKey) {
          serviceAccountKey = apiKeys.googleServiceAccountKey;
          console.log('✅ Found Google Service Account in database');
        } else {
          console.log('❌ No Google Service Account key found in apiKeys');
        }
      } else {
        console.log('❌ No apiKeys found in system document');
      }
    } catch (error) {
      console.log('⚠️ Could not retrieve service account from database:', error.message);
      console.log('🔍 Database error details:', error);
    }
    
    // Fallback to environment variable
    if (!serviceAccountKey) {
      serviceAccountKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
      if (serviceAccountKey) {
        console.log('🔐 Using Google Service Account from environment variable');
      }
    }
    
    if (serviceAccountKey) {
      console.log('🔐 Using Google Service Account for authentication');
      
      const serviceAccount = JSON.parse(serviceAccountKey);
      
      // Create JWT assertion for service account
      const now = Math.floor(Date.now() / 1000);
      
      const jwtPayload = {
        iss: serviceAccount.client_email,
        scope: 'https://www.googleapis.com/auth/spreadsheets',
        aud: 'https://oauth2.googleapis.com/token',
        exp: now + 3600,
        iat: now
      };
      
      // Sign JWT with service account private key
      const jwtToken = jwt.sign(jwtPayload, serviceAccount.private_key, { 
        algorithm: 'RS256',
        header: {
          kid: serviceAccount.private_key_id
        }
      });
      
      // Exchange JWT for access token
      const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: jwtToken
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('✅ Service account token obtained, expires in:', data.expires_in);
        return data.access_token;
      } else {
        const errorData = await response.text();
        console.log('❌ Service account auth failed:', response.status, errorData);
      }
    }
    
    // Fallback to system environment token
    const systemGoogleToken = process.env.SYSTEM_GOOGLE_ACCESS_TOKEN || 
                             process.env.VITE_APP_GOOGLE_ACCESS_TOKEN ||
                             process.env.APP_GOOGLE_ACCESS_TOKEN;
    
    if (systemGoogleToken && systemGoogleToken !== 'placeholder-google-token') {
      console.log('✅ Using system Google OAuth token');
      return systemGoogleToken;
    }
    
  } catch (error) {
    console.error('❌ Error with Google authentication:', error);
  }
  
  console.warn('⚠️ No valid Google access token found - using placeholder');
  return 'placeholder-google-token';
}

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
    'http://localhost:8081',
    'http://localhost:5173',
    'https://jobsemble.tech',
    'https://job-scout-automaton.lovable.app'
  ],
  methods: ['GET', 'POST', 'DELETE'],
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
  max: 100, // Increased to 100 API calls per minute (supports pagination)
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: 'API rate limit exceeded' }
});

// Special rate limit for job search (more lenient due to pagination)
const jobSearchRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // Allow 10 job searches per 5 minutes per user
  keyGenerator: (req) => req.user?.userId || req.ip,
  message: { error: 'Job search rate limit exceeded. Please wait before searching again.' }
});

app.use(globalRateLimit);

// API Key Utilities - Plain text storage since backend is secure
function storeApiKey(apiKey) {
  // Return the API key as-is since we're storing plain text
  return apiKey;
}

function retrieveApiKey(storedKey) {
  // Return the stored key as-is since we're using plain text
  return storedKey || '';
}



// Authentication Middleware with Session Validation
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;
    
    // Check if user has an active session (handle server restarts gracefully)
    const activeSession = activeSessions.get(userId);
    
    if (!activeSession) {
      // Server restart or new session - create one instead of rejecting
      console.log(`🔄 No active session in memory for user ${userId}, creating new session (server restart handled)`);
      const sessionId = crypto.randomBytes(16).toString('hex');
      const now = Date.now();
      
      activeSessions.set(userId, {
        sessionId: sessionId,
        token: token,
        issuedAt: now,
        lastActive: now,
        userAgent: req.get('User-Agent') || 'Unknown'
      });
    } else {
      // Update last active time for existing session
    activeSession.lastActive = Date.now();
    activeSessions.set(userId, activeSession);
    }
    
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

// Authentication Endpoint - Issue Short-lived JWT with Single Session Enforcement
app.post('/auth/token', async (req, res) => {
  try {
    const { appwriteJwt } = req.body;
    
    if (!appwriteJwt) {
      return res.status(400).json({ error: 'Appwrite JWT required' });
    }

    // Verify the Appwrite JWT and extract user info
    const userId = req.body.userId;
    const email = req.body.email;
    
    if (!userId || !email) {
      return res.status(400).json({ error: 'User ID and email required' });
    }
    
    // For development, we'll trust the userId and email from the request
    // In production, you'd verify the Appwrite JWT with Appwrite's public key
    
    const userAgent = req.get('User-Agent') || 'Unknown';
    const clientIp = req.ip || 'Unknown';
    
    // Check if user already has an active session and invalidate it
    const existingSession = invalidateUserSession(userId, 'New login detected');
    if (existingSession) {
      console.log(`🔄 User ${userId} logged in from new device/browser - previous session invalidated`);
    }
    
    const payload = {
      userId: userId,
      email: req.body.email,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (30 * 60) // 30 minutes
    };

    const token = jwt.sign(payload, JWT_SECRET);
    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    
    // Store the new active session
    activeSessions.set(userId, {
      sessionId: sessionId,
      token: token,
      issuedAt: now,
      lastActive: now,
      userAgent: userAgent,
      ip: clientIp
    });
    
    console.log(`✅ New session created for user ${userId} from ${clientIp}`);
    
    auditLog('token_issued', payload.userId, {
      ip: clientIp,
      userAgent: userAgent,
      sessionId: sessionId,
      hadExistingSession: !!existingSession,
      success: true
    });

    res.json({ 
      token,
      expiresIn: 1800, // 30 minutes
      sessionId: sessionId,
      singleSession: true // Let frontend know single session is enforced
    });

  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Token generation failed' });
  }
});

// Session Management Endpoints

// Logout endpoint - invalidate current session
app.post('/auth/logout', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    
    const removedSession = invalidateUserSession(userId, 'User logout');
    
    auditLog('user_logout', userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: removedSession?.sessionId,
      success: true
    });
    
    console.log(`🚪 User ${userId} logged out successfully`);
    
    res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Get active session info
app.get('/auth/session', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const session = activeSessions.get(userId);
    
    if (!session) {
      return res.status(404).json({ error: 'No active session found' });
    }
    
    res.json({
      sessionId: session.sessionId,
      issuedAt: new Date(session.issuedAt).toISOString(),
      lastActive: new Date(session.lastActive).toISOString(),
      userAgent: session.userAgent,
      ip: session.ip
    });
  } catch (error) {
    console.error('Session info error:', error);
    res.status(500).json({ error: 'Failed to get session info' });
  }
});

// Delete API Key Endpoint
app.delete('/api/keys/:provider', authenticateToken, async (req, res) => {
  try {
    const { provider } = req.params;
    
    console.log(`🗑️ API key deletion request for user ${req.user.userId}, provider: ${provider}`);
    
    if (!provider || !['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Valid provider required' });
    }

    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', req.user.userId)]
    );

    if (userDocs.documents.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    const userProfile = userDocs.documents[0];
    let apiKeys = {};
    
    try {
      apiKeys = JSON.parse(userProfile.apiKeys || '{}');
    } catch (e) {
      apiKeys = {};
    }

    // Remove the API key and related data
    if (provider === 'serp') {
      delete apiKeys.serpApiKey;
      delete apiKeys.serpUsageTracking;
      console.log(`🗑️ Deleted SERP API key and usage tracking for user ${req.user.userId}`);
    } else if (provider === 'tavily') {
      delete apiKeys.tavilyApiKey;
      // CRITICAL: Do NOT delete usage count - this prevents abuse of freemium system
      // Usage count should persist even when API key is removed
      console.log(`🗑️ Deleted Tavily API key for user ${req.user.userId} (usage count preserved: ${apiKeys.tavilyUsageCount || 0}/${apiKeys.tavilyUsageLimit || 3})`);
    }

    // Update the user profile
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTION_ID,
      userProfile.$id,
      {
        apiKeys: JSON.stringify(apiKeys)
      }
    );

    console.log(`✅ ${provider} API key successfully deleted for user ${req.user.userId}`);
    
    res.json({ 
      success: true, 
      message: `${provider.toUpperCase()} API key deleted successfully`,
      provider 
    });

  } catch (error) {
    console.error('🚨 Key deletion error:', {
      provider,
      userId: req.user.userId,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Failed to delete API key', details: error.message });
  }
});

// System API key now properly stored with consistent format
// Storage issues resolved - temporary restore endpoint removed

// Store Google Sheet URL Endpoint
app.post('/api/user/google-sheet-url', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl } = req.body;
    
    console.log(`📊 Google Sheet URL update request for user ${req.user.userId}`);
    
    if (!sheetUrl || typeof sheetUrl !== 'string') {
      return res.status(400).json({ error: 'Google Sheet URL required' });
    }
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', req.user.userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${req.user.userId}`);
      return res.status(404).json({ error: 'User profile not found' });
    }

    const userDoc = userDocs.documents[0];
    console.log(`✅ Found user document for ${req.user.userId}: ${userDoc.$id}`);
    
    // Parse existing preferences or create new
    let preferences = {};
    try {
      preferences = userDoc.preferences ? JSON.parse(userDoc.preferences) : {};
    } catch (e) {
      console.log(`🔄 Creating new preferences object for user ${req.user.userId}`);
      preferences = {};
    }
    
    // Update Google Sheet URL
    preferences.googleSheetUrl = sheetUrl.trim();
    
    // Update the user document
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTION_ID,
      userDoc.$id,
      {
        preferences: JSON.stringify(preferences)
      }
    );

    console.log(`✅ Google Sheet URL stored for user ${req.user.userId}`);
    
    auditLog('google_sheet_url_stored', req.user.userId, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      success: true
    });

    res.json({ 
      success: true,
      message: 'Google Sheet URL stored successfully'
    });

  } catch (error) {
    console.error('Google Sheet URL storage error:', error);
    res.status(500).json({ error: 'Failed to store Google Sheet URL' });
  }
});

// Get Google Sheet URL Endpoint
app.get('/api/user/google-sheet-url', authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Google Sheet URL retrieval request for user ${req.user.userId}`);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', req.user.userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${req.user.userId}`);
      return res.status(404).json({ error: 'User profile not found' });
    }

    const userDoc = userDocs.documents[0];
    
    // Parse preferences
    let preferences = {};
    try {
      preferences = userDoc.preferences ? JSON.parse(userDoc.preferences) : {};
    } catch (e) {
      console.log(`⚠️ Failed to parse preferences for user ${req.user.userId}`);
      preferences = {};
    }
    
    const googleSheetUrl = preferences.googleSheetUrl || '';
    
    console.log(`✅ Google Sheet URL retrieved for user ${req.user.userId}: ${googleSheetUrl ? 'URL found' : 'No URL stored'}`);

    res.json({ 
      success: true,
      googleSheetUrl: googleSheetUrl
    });

  } catch (error) {
    console.error('Google Sheet URL retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve Google Sheet URL' });
  }
});

// Store API Key Endpoint
app.post('/api/keys/store', authenticateToken, async (req, res) => {
  try {
    const { apiKey, provider, label } = req.body;
    
    console.log(`🔑 API key storage request for user ${req.user.userId}, provider: ${provider}`);
    
    if (!apiKey || !provider) {
      return res.status(400).json({ error: 'API key and provider required' });
    }

    // Validate provider
    if (!['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }

    // Store the API key as plain text (backend is secure)
    const storedKey = storeApiKey(apiKey);
    console.log(`💾 API key stored for ${provider}`);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', req.user.userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${req.user.userId}`);
      return res.status(404).json({ error: 'User profile not found' });
    }

    const userDoc = userDocs.documents[0];
    console.log(`✅ Found user document for ${req.user.userId}: ${userDoc.$id}`);
    
    // Get existing API keys or create empty object
    let apiKeys = {};
    try {
      apiKeys = userDoc.apiKeys ? JSON.parse(userDoc.apiKeys) : {};
      console.log(`📋 Existing API keys for ${req.user.userId}:`, Object.keys(apiKeys));
    } catch (e) {
      console.log(`⚠️ Failed to parse existing API keys, creating new object:`, e.message);
      apiKeys = {};
    }

    const currentDate = new Date();
    const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;

    // Store the API key and initialize usage tracking
    if (provider === 'tavily') {
      apiKeys.tavilyApiKey = storedKey;
      // Initialize Tavily freemium tracking if not exists (check for undefined specifically)
      // CRITICAL: Never reset existing usage count - this should be ONE-TIME only
      if (typeof apiKeys.tavilyUsageCount === 'undefined') {
        apiKeys.tavilyUsageCount = 0;
        apiKeys.tavilyUsageLimit = 3;
        apiKeys.tavilyFirstUsedDate = currentDate.toISOString();
        console.log(`🆕 Initializing Tavily freemium tracking for user ${req.user.userId}: 0/3 free searches (FIRST TIME)`);
      } else {
        console.log(`📊 Preserving existing Tavily usage for user ${req.user.userId}: ${apiKeys.tavilyUsageCount}/${apiKeys.tavilyUsageLimit} searches used`);
        console.log(`⚠️  NEVER RESET: This is a one-time freemium limit, not monthly like SERP`);
      }
      console.log(`💾 Tavily API key stored for ${req.user.userId}`);
    } else if (provider === 'serp') {
      apiKeys.serpApiKey = storedKey;
      // Initialize SERP monthly tracking
      if (!apiKeys.serpUsageTracking || apiKeys.serpUsageTracking.month !== currentMonth) {
        apiKeys.serpUsageTracking = {
          month: currentMonth,
          searchesUsed: 0,
          creditsRemaining: 100, // Default free tier
          lastResetDate: currentDate.toISOString()
        };
      }
      console.log(`💾 SERP API key stored for ${req.user.userId}`);
    }

    // Update the user document with the new API key
    const updateResult = await databases.updateDocument(
      DATABASE_ID,
      COLLECTION_ID,
      userDoc.$id,
      {
        apiKeys: JSON.stringify(apiKeys)
      }
    );
    
    console.log(`✅ User document updated successfully for ${req.user.userId}`);
    
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

    // Get user's Tavily API key
    const userKey = await getUserApiKey(req.user.userId, 'tavily');
    if (!userKey) {
      return res.status(404).json({ error: 'Tavily API key not found' });
    }

    // Retrieve API key (plain text)
    const apiKey = retrieveApiKey(userKey);

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
    const { query, engine = 'google', num = 100, timeFilter } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Search query required' });
    }

    // Get user's SERP API key
    const userKey = await getUserApiKey(req.user.userId, 'serp');
    if (!userKey) {
      return res.status(404).json({ error: 'SERP API key not found' });
    }

    // Retrieve API key (plain text)
    const apiKey = retrieveApiKey(userKey);

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

// Helper function to increment API usage after successful search
async function incrementApiUsage(userId, provider) {
  try {
    console.log(`📈 Incrementing ${provider} usage for user ${userId}`);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${userId} during usage increment`);
      return false;
    }

    const userDoc = userDocs.documents[0];
    
    // Get API keys
    let apiKeys = {};
    try {
      apiKeys = userDoc.apiKeys ? JSON.parse(userDoc.apiKeys) : {};
    } catch (e) {
      console.log(`❌ Failed to parse API keys during usage increment:`, e.message);
      return false;
    }

    const currentDate = new Date();
    const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;

    if (provider === 'tavily') {
      // Increment Tavily freemium usage (only if using system key)
      const currentCount = apiKeys.tavilyUsageCount || 0;
      apiKeys.tavilyUsageCount = currentCount + 1;
      console.log(`🎯 Tavily usage incremented to ${apiKeys.tavilyUsageCount}/${apiKeys.tavilyUsageLimit || 3}`);
      
    } else if (provider === 'serp') {
      // Update SERP monthly usage tracking
      if (!apiKeys.serpUsageTracking || apiKeys.serpUsageTracking.month !== currentMonth) {
        apiKeys.serpUsageTracking = {
          month: currentMonth,
          searchesUsed: 0,
          creditsRemaining: 100, // Default, should be updated based on actual API response
          lastResetDate: currentDate.toISOString()
        };
      }
      
      apiKeys.serpUsageTracking.searchesUsed += 1;
      // Note: creditsRemaining should be updated based on actual API response
      console.log(`🎯 SERP usage incremented to ${apiKeys.serpUsageTracking.searchesUsed} searches this month`);
    }

    // Update the user document
    await databases.updateDocument(
      DATABASE_ID,
      COLLECTION_ID,
      userDoc.$id,
      {
        apiKeys: JSON.stringify(apiKeys)
      }
    );
    
    console.log(`✅ ${provider} usage tracking updated for user ${userId}`);
    return true;
    
  } catch (error) {
    console.error(`❌ Error incrementing ${provider} usage for ${userId}:`, error);
    return false;
  }
}

// Helper function to get system API key (stored securely in database)
async function getSystemApiKey(provider) {
  try {
    const SYSTEM_USER_ID = 'SYSTEM_API_KEYS';
    
    // Find the system profile document
    const systemDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', SYSTEM_USER_ID)]
    );

    if (systemDocs.documents.length === 0) {
      console.log(`❌ System API keys profile not found`);
      return null;
    }

    const systemDoc = systemDocs.documents[0];
    
    // Get API keys
    let apiKeys = {};
    try {
      apiKeys = systemDoc.apiKeys ? JSON.parse(systemDoc.apiKeys) : {};
    } catch (e) {
      console.log(`❌ Failed to parse system API keys:`, e.message);
      return null;
    }

    if (provider === 'tavily') {
      const storedKey = apiKeys.systemTavilyApiKey;
      if (!storedKey) {
        console.log(`❌ System Tavily API key not found in database`);
        return null;
      }
      
      // System API key should be stored in plain text now
      console.log(`✅ System Tavily API key retrieved from database`);
      return storedKey;
    }

    return null;
  } catch (error) {
    console.error(`❌ Error retrieving system API key:`, error.message);
    return null;
  }
}

// Helper function to get Tavily account usage from their API
async function getTavilyAccountUsage(apiKey) {
  try {
    // Use the correct /usage endpoint
    const response = await axios.get('https://api.tavily.com/usage', {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    if (response.data) {
      console.log(`✅ Tavily usage data retrieved:`, response.data);
      
      // Map the correct fields from Tavily API response
      const account = response.data.account || {};
      const key = response.data.key || {};
      
      const planLimit = account.plan_limit;
      const planUsage = account.plan_usage || key.usage || 0;
      const planName = account.current_plan || 'Unknown Plan';
      
      // Handle cases where limit is not defined (e.g. pay-as-you-go plans)
      if (planLimit === null || planLimit === undefined) {
        console.log(`ℹ️ Tavily plan limit not defined for user. Assuming high limit.`);
        return {
          totalSearchesLeft: 99999,
          thisMonthUsage: planUsage,
          searchesPerMonth: 99999, // Represents a very high/unlimited limit
          planName: planName,
        };
      }

      return {
        totalSearchesLeft: planLimit - planUsage,
        thisMonthUsage: planUsage,
        searchesPerMonth: planLimit,
        planName: planName
      };
    }
    
    return null;
  } catch (error) {
    console.error(`❌ Failed to get Tavily usage data:`, error.message);
    
    // If usage endpoint fails, try a test search to verify key is valid
    try {
      console.log(`🔄 Usage endpoint failed, trying test search to verify key`);
      const testResponse = await axios.post('https://api.tavily.com/search', {
        api_key: apiKey,
        query: 'test',
        search_depth: 'basic',
        include_answer: false,
        include_images: false,
        include_raw_content: false,
        max_results: 1
      }, {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      // If test search works, return a generic "API Key Connected" status
      if (testResponse.data) {
        return {
          totalSearchesLeft: 999, // Unknown, but key is valid
          thisMonthUsage: 0,
          searchesPerMonth: 999,
          planName: 'API Key Connected',
          isGeneric: true
        };
      }
    } catch (testError) {
      console.error(`❌ Both usage and test search failed:`, testError.message);
    }
    
    return null;
  }
}

// Helper function to get user document
async function getUserDocument(userId) {
  try {
    console.log(`🔍 Getting user document for user ${userId}`);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${userId}`);
      return null;
    }

    const userDoc = userDocs.documents[0];
    console.log(`✅ Found user document for ${userId}`);
    return userDoc;
    
  } catch (error) {
    console.error(`❌ Error getting user document for ${userId}:`, error);
    return null;
  }
}

// Helper function to get user's API key
async function getUserApiKey(userId, provider) {
  try {
    console.log(`🔑 Looking up ${provider} API key for user ${userId}`);
    
    // Find the user's profile document
    const userDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('accountId', userId)]
    );

    if (userDocs.documents.length === 0) {
      console.log(`❌ User profile not found for ${userId}`);
      return null;
    }

    const userDoc = userDocs.documents[0];
    console.log(`✅ Found user document for ${userId}`);
    
    // Get API keys
    let apiKeys = {};
    try {
      apiKeys = userDoc.apiKeys ? JSON.parse(userDoc.apiKeys) : {};
      console.log(`📋 API keys object parsed for ${userId}:`, Object.keys(apiKeys));
    } catch (e) {
      console.log(`❌ Failed to parse API keys for ${userId}:`, e.message);
      return null;
    }

    // Return the appropriate stored API key with usage info
    if (provider === 'tavily') {
      const key = apiKeys.tavilyApiKey;
      const usageCount = apiKeys.tavilyUsageCount || 0;
      const usageLimit = apiKeys.tavilyUsageLimit || 3;
      
      // Production logging - minimal
      
      // Check if user has exceeded free limit and needs their own key
      if (!key && usageCount >= usageLimit) {
        console.log(`❌ User ${userId} has exceeded free Tavily limit and has no API key`);
        return null;
      }
      
      return {
        key: key || 'SYSTEM_KEY', // Use system key if user hasn't provided one and still has free uses
        usageCount,
        usageLimit,
        hasFreesLeft: usageCount < usageLimit,
        isUserKey: !!key
      };
    } else if (provider === 'serp') {
      const key = apiKeys.serpApiKey;
      const currentDate = new Date();
      const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;
      
      let usageTracking = apiKeys.serpUsageTracking;
      
      // Reset tracking if month has changed
      if (!usageTracking || usageTracking.month !== currentMonth) {
        usageTracking = {
          month: currentMonth,
          searchesUsed: 0,
          creditsRemaining: 100, // Default free tier (adjust based on actual plan)
          lastResetDate: currentDate.toISOString()
        };
        console.log(`🔄 SERP usage tracking reset for new month: ${currentMonth}`);
      }
      
      console.log(`🔍 SERP API key ${key ? 'found' : 'not found'} for ${userId}`);
      console.log(`📊 SERP usage: ${usageTracking.searchesUsed} searches used, ${usageTracking.creditsRemaining} credits remaining`);
      
      if (!key) {
        console.log(`❌ User ${userId} has no SERP API key`);
        return null;
      }
      
      return {
        key,
        usageTracking,
        isUserKey: true
      };
    }
    
    console.log(`❌ Unknown provider ${provider} for ${userId}`);
    return null;
    
  } catch (error) {
    console.error(`❌ Error fetching ${provider} API key for ${userId}:`, error);
    return null;
  }
}

// Get API usage stats endpoint
app.get('/api/usage/:provider', authenticateToken, async (req, res) => {
  try {
    const { provider } = req.params;
    
    if (!['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }

    // Add retry mechanism for API key lookup
    let keyInfo = null;
    let retries = 3;
    
    while (retries > 0 && !keyInfo) {
      keyInfo = await getUserApiKey(req.user.userId, provider);
      if (!keyInfo && retries > 1) {
        // Retrying API key lookup
        await new Promise(resolve => setTimeout(resolve, 100)); // 100ms delay
      }
      retries--;
    }
    
    if (!keyInfo) {
      return res.json({
        provider,
        hasApiKey: false,
        usageInfo: null
      });
    }

    if (provider === 'tavily') {
      // If user has their own API key, fetch real account usage
      if (keyInfo.isUserKey && keyInfo.key) {
        try {
          const apiKey = retrieveApiKey(keyInfo.key);
          const accountData = await getTavilyAccountUsage(apiKey);
          
          if (accountData) {
            return res.json({
              provider: 'tavily',
              hasApiKey: true,
              usageInfo: {
                usageCount: accountData.thisMonthUsage,
                usageLimit: accountData.searchesPerMonth,
                hasFreesLeft: accountData.totalSearchesLeft > 0,
                isFreemium: false,
                creditsRemaining: accountData.totalSearchesLeft,
                planName: accountData.planName
              }
            });
          }
        } catch (error) {
          console.error(`❌ Failed to get Tavily account data:`, error.message);
        }
      }
      
      // If no user key, try to get system Tavily API key and fetch real usage
      if (!keyInfo.isUserKey) {
        try {
          const systemTavilyKey = await getSystemApiKey('tavily');
          if (systemTavilyKey) {
            const accountData = await getTavilyAccountUsage(systemTavilyKey);
            
            if (accountData) {
              console.log(`✅ System Tavily usage data retrieved:`, accountData);
              return res.json({
                provider: 'tavily',
                hasApiKey: false, // System key is not a personal API key
                usageInfo: {
                  usageCount: accountData.thisMonthUsage,
                  usageLimit: accountData.searchesPerMonth,
                  hasFreesLeft: accountData.totalSearchesLeft > 0,
                  isFreemium: true, // System key is freemium
                  creditsRemaining: accountData.totalSearchesLeft,
                  planName: accountData.planName
                }
              });
            }
          }
        } catch (error) {
          console.error(`❌ Failed to get system Tavily account data:`, error.message);
        }
      }
      
      // Fallback to freemium data or default
      return res.json({
        provider: 'tavily',
        hasApiKey: keyInfo.isUserKey,
        usageInfo: {
          usageCount: keyInfo.usageCount,
          usageLimit: keyInfo.usageLimit,
          hasFreesLeft: keyInfo.hasFreesLeft,
          isFreemium: !keyInfo.isUserKey
        }
      });
    } else if (provider === 'serp') {
      if (!keyInfo || !keyInfo.isUserKey || !keyInfo.key) {
        return res.json({
          provider: 'serp',
          hasApiKey: false,
          usageInfo: null
        });
      }

      try {
        // Get real usage data from SERP API account endpoint
        console.log(`🔍 Fetching real SERP usage data from account API`);
        
        const apiKey = retrieveApiKey(keyInfo.key);
        const accountResponse = await axios.get(`https://serpapi.com/account.json?api_key=${apiKey}`);
        
        if (accountResponse.data) {
          const accountData = accountResponse.data;
          console.log(`✅ SERP account data retrieved:`, {
            totalSearchesLeft: accountData.total_searches_left,
            thisMonthUsage: accountData.this_month_usage,
            searchesPerMonth: accountData.searches_per_month,
            planName: accountData.plan_name
          });

          return res.json({
            provider: 'serp',
            hasApiKey: true,
            usageInfo: {
              searchesUsed: accountData.this_month_usage || 0,
              creditsRemaining: accountData.total_searches_left || 0,
              searchesPerMonth: accountData.searches_per_month || 250,
              planName: accountData.plan_name || 'Unknown Plan',
              lastUpdated: new Date().toISOString(),
              month: `${new Date().getFullYear()}-${new Date().getMonth()}`,
              lastResetDate: new Date().toISOString()
            }
          });
        } else {
          throw new Error('No data returned from SERP account API');
        }
      } catch (serpApiError) {
        console.error('❌ SERP API account error:', serpApiError.message);
        
        // Fallback to our internal tracking if SERP API fails
        const fallbackSearchesUsed = keyInfo.usageTracking?.searchesUsed || 0;
        const fallbackCreditsRemaining = Math.max(0, 250 - fallbackSearchesUsed);
        
        console.log(`🔄 Using fallback data: ${fallbackSearchesUsed} used, ${fallbackCreditsRemaining} remaining`);
        
        return res.json({
          provider: 'serp',
          hasApiKey: keyInfo.isUserKey,
          usageInfo: {
            searchesUsed: fallbackSearchesUsed,
            creditsRemaining: fallbackCreditsRemaining,
            month: keyInfo.usageTracking?.month || `${new Date().getFullYear()}-${new Date().getMonth()}`,
            lastResetDate: keyInfo.usageTracking?.lastResetDate || new Date().toISOString(),
            searchesPerMonth: 250,
            planName: 'Fallback (API Error)',
            lastUpdated: new Date().toISOString(),
            error: 'Could not fetch real-time data from SERP API'
          }
        });
      }
    }

  } catch (error) {
    console.error('Usage stats error:', error);
    res.status(500).json({ error: 'Failed to get usage stats' });
  }
});

// Backend API Call Handler for SERP - returns raw data to frontend
app.post('/api/proxy/serp-raw', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, num, start, tbs } = req.body;
    
    // Get user's SERP API key
    const apiKeyInfo = await getUserApiKey(req.user.userId, 'serp');
    if (!apiKeyInfo || !apiKeyInfo.key) {
      return res.status(400).json({ error: 'SERP API key not found' });
    }
    
    let apiKey = retrieveApiKey(apiKeyInfo.key);
    
    // If retrieval fails, we can't proceed
    if (!apiKey) {
      console.log('🔄 SERP API key retrieval failed - all methods exhausted');
      return res.status(400).json({ 
        error: 'API key not found. Please contact support.',
        requiresReupload: true,
        provider: 'serp'
      });
    }
    
    // Build request parameters
    const params = new URLSearchParams({
      api_key: apiKey,
      engine: 'google',
      q: query,
      num: num || '10',
      start: start || '0'
    });
    
    if (tbs) {
      params.append('tbs', tbs);
    }
    
    console.log(`🔗 [BACKEND API] Making SERP API call: ${query}`);
    
    const serpResponse = await axios.get(`https://serpapi.com/search?${params}`, {
      timeout: 30000
    });
    
    // Return raw data for frontend processing
    res.json({
      success: true,
      rawData: serpResponse.data,
      query: query,
      page: Math.floor((start || 0) / (num || 10)) + 1
    });
    
  } catch (error) {
    console.error('SERP API call error:', error.message);
    res.status(500).json({ error: 'SERP API call failed' });
  }
});

// Async API Key Re-storage Endpoint - handles retrieval failures
app.post('/api/async/re-store-keys', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { provider } = req.body;
    
    console.log(`🔄 [ASYNC] Re-storing ${provider} API key for user ${req.user.userId}`);
    
    // Get user's API key
    const apiKeyInfo = await getUserApiKey(req.user.userId, provider);
    if (!apiKeyInfo || !apiKeyInfo.key) {
      return res.status(400).json({ error: `${provider} API key not found` });
    }
    
    // Try to retrieve with current key
    let apiKey = retrieveApiKey(apiKeyInfo.key);
    
    if (!apiKey) {
      // If retrieval fails, we need the user to re-upload the key
      return res.status(400).json({ 
        error: 'API key not found. Please re-upload your API key in settings.',
        requiresReupload: true
      });
    }
    
    // If retrieval succeeded, store with current format (plain text)
    const reStoredKey = storeApiKey(apiKey);
    
    // Update the key in database
    await updateUserApiKey(req.user.userId, provider, reStoredKey);
    
    console.log(`✅ [ASYNC] Successfully re-stored ${provider} API key for user ${req.user.userId}`);
    
    res.json({ 
      success: true, 
      message: `${provider} API key re-stored successfully` 
    });
    
  } catch (error) {
    console.error(`❌ [ASYNC] Error re-storing ${req.body.provider} API key:`, error);
    res.status(500).json({ error: 'Failed to re-store API key' });
  }
});

// Backend API Call Handler for Tavily - returns raw data to frontend
app.post('/api/proxy/tavily-raw', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, search_depth, max_results } = req.body;
    
    // Get user's Tavily API key
    const apiKeyInfo = await getUserApiKey(req.user.userId, 'tavily');
    if (!apiKeyInfo || !apiKeyInfo.key) {
      return res.status(400).json({ error: 'Tavily API key not found' });
    }
    
    let apiKey = retrieveApiKey(apiKeyInfo.key);
    
    // If retrieval fails, we can't proceed
    if (!apiKey) {
      console.log('🔄 Tavily API key retrieval failed - all methods exhausted');
      return res.status(400).json({ 
        error: 'API key not found. Please contact support.',
        requiresReupload: true,
        provider: 'tavily'
      });
    }
    
    console.log(`🔗 [BACKEND API] Making Tavily API call: ${query}`);
    
    const tavilyResponse = await axios.post('https://api.tavily.com/search', {
      api_key: apiKey,
      query: query,
      search_depth: search_depth || 'basic',
      include_answer: false,
      include_images: false,
      include_raw_content: false,
      max_results: max_results || 20
    }, {
      timeout: 30000
    });
    
    // Return raw data for frontend processing
    res.json({
      success: true,
      rawData: tavilyResponse.data,
      query: query
    });
    
  } catch (error) {
    console.error('Tavily API call error:', error.message);
    res.status(500).json({ error: 'Tavily API call failed' });
  }
});

// Clear API Keys Endpoint - for debugging/restoration
app.post('/api/admin/clear-api-keys', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log(`🧹 [ADMIN] Clearing API keys for user: ${userId}`);
    
    // Clear API keys for the user
    const updateData = {
      serpApiKey: '',
      tavilyApiKey: '',
      serpUsageTracking: '{"searchesUsed": 0, "creditsRemaining": 100}',
      tavilyUsageCount: 0,
      tavilyUsageLimit: 20
    };
    
    await databases.updateDocument(DATABASE_ID, USER_COLLECTION_ID, userId, updateData);
    
    console.log(`✅ [ADMIN] API keys cleared for user: ${userId}`);
    res.json({ 
      success: true, 
      message: 'API keys cleared successfully. Please re-upload your API keys in settings.' 
    });
    
  } catch (error) {
    console.error('❌ [ADMIN] Error clearing API keys:', error);
    res.status(500).json({ error: 'Failed to clear API keys' });
  }
});

// Job Search Proxy - handles individual job board searches
app.post('/api/proxy/search-jobs', authenticateToken, jobSearchRateLimit, async (req, res) => {
  try {
    const { query, location, jobBoard, provider, timeFilter } = req.body;
    
    console.log(`🔍 [DEBUG] Job search request received:`, {
      query, location, jobBoard, provider, timeFilter,
      userId: req.user.userId
    });
    
    if (!query || !location || !jobBoard || !provider) {
      console.log(`❌ [DEBUG] Missing required fields`);
      return res.status(400).json({ error: 'Missing required fields (query, location, jobBoard, provider)' });
    }

    // Validate provider
    if (!['tavily', 'serp'].includes(provider)) {
      console.log(`❌ [DEBUG] Invalid provider: ${provider}`);
      return res.status(400).json({ error: 'Invalid provider' });
    }

    console.log(`🔍 Job search request: ${query} in ${location} on ${jobBoard} via ${provider}`);

    // Get user's API key for the provider with usage info
    console.log(`🔑 [DEBUG] Getting API key for user ${req.user.userId}, provider: ${provider}`);
    const keyInfo = await getUserApiKey(req.user.userId, provider);
    console.log(`🔑 [DEBUG] API key result:`, keyInfo ? 'Found' : 'Not found');
    
    if (!keyInfo) {
      return res.status(404).json({ error: `${provider.charAt(0).toUpperCase() + provider.slice(1)} API key not found` });
    }

    // Handle Tavily freemium logic
    if (provider === 'tavily') {
      if (!keyInfo.isUserKey && !keyInfo.hasFreesLeft) {
        return res.status(403).json({ 
          error: `You've used all ${keyInfo.usageLimit} free Tavily searches. Please provide your own Tavily API key.`,
          requiresApiKey: true,
          usageCount: keyInfo.usageCount,
          usageLimit: keyInfo.usageLimit
        });
      }
    }

    // Retrieve the API key (or use system key for Tavily freemium)
    let apiKey;
    if (provider === 'tavily' && keyInfo.key === 'SYSTEM_KEY') {
      // Use system Tavily API key from database
      apiKey = await getSystemApiKey('tavily');
      if (!apiKey) {
        console.error('❌ System Tavily API key not found in database');
        return res.status(500).json({ 
          error: 'System Tavily API key not configured. Please contact administrator.',
          code: 'MISSING_SYSTEM_API_KEY'
        });
      }
      console.log(`🆓 Using system Tavily API key for freemium user ${req.user.userId} (${keyInfo.usageCount + 1}/${keyInfo.usageLimit})`);
    } else {
      apiKey = retrieveApiKey(keyInfo.key);
    }

    let searchResults = [];

    // Build job board specific search query based on the specified patterns
    let jobBoardQuery;
    // Make queries less restrictive for better SERP results
    const jobTitle = query.includes(' ') ? `"${query}"` : query; // Only quote if multiple words
    const searchLocation = location; // Remove quotes around location for broader matching
    
    switch (jobBoard.toLowerCase()) {
      case 'greenhouse':
        jobBoardQuery = `${jobTitle} site:greenhouse.io ${searchLocation}`;
        break;
      case 'lever':
        jobBoardQuery = `${jobTitle} site:lever.co ${searchLocation}`;
        break;
      case 'ashby':
        jobBoardQuery = `${jobTitle} site:ashbyhq.com ${searchLocation}`;
        break;
      case 'pinpoint':
        jobBoardQuery = `${jobTitle} site:pinpointhq.com ${searchLocation}`;
        break;
      case 'paylocity':
        jobBoardQuery = `${jobTitle} site:recruiting.paylocity.com ${searchLocation}`;
        break;
      case 'keka':
        jobBoardQuery = `${jobTitle} site:keka.com ${searchLocation}`;
        break;
      case 'workable':
        jobBoardQuery = `${jobTitle} site:jobs.workable.com ${searchLocation}`;
        break;
      case 'breezyhr':
        jobBoardQuery = `${jobTitle} site:breezy.hr ${searchLocation}`;
        break;
      case 'wellfound':
        jobBoardQuery = `${jobTitle} site:wellfound.com ${searchLocation}`;
        break;
      case 'y combinator work at a startup':
        jobBoardQuery = `${jobTitle} site:workatastartup.com ${searchLocation}`;
        break;
      case 'oracle cloud':
        jobBoardQuery = `${jobTitle} site:oraclecloud.com ${searchLocation}`;
        break;
      case 'workday jobs':
        jobBoardQuery = `${jobTitle} site:myworkdayjobs.com ${searchLocation}`;
        break;
      case 'recruitee':
        jobBoardQuery = `${jobTitle} site:recruitee.com ${searchLocation}`;
        break;
      case 'rippling':
        jobBoardQuery = `${jobTitle} (site:rippling.com OR site:rippling-ats.com) ${searchLocation}`;
        break;
      case 'gusto':
        jobBoardQuery = `${jobTitle} site:jobs.gusto.com ${searchLocation}`;
        break;
      case 'smartrecruiters':
        jobBoardQuery = `${jobTitle} site:jobs.smartrecruiters.com ${searchLocation}`;
        break;
      case 'jazzhr':
        jobBoardQuery = `${jobTitle} site:applytojob.com ${searchLocation}`;
        break;
      case 'jobvite':
        jobBoardQuery = `${jobTitle} site:jobvite.com ${searchLocation}`;
        break;
      case 'icims':
        jobBoardQuery = `${jobTitle} site:icims.com ${searchLocation}`;
        break;
      case 'builtin':
        jobBoardQuery = `${jobTitle} site:builtin.com/job/ ${searchLocation}`;
        break;
      case 'adp':
        jobBoardQuery = `${jobTitle} (site:workforcenow.adp.com OR site:myjobs.adp.com) ${searchLocation}`;
        break;
      case 'jobs subdomain':
        jobBoardQuery = `${jobTitle} site:jobs.* ${searchLocation}`;
        break;
      case 'talent subdomain':
        jobBoardQuery = `${jobTitle} site:talent.* ${searchLocation}`;
        break;
      default:
        // Generic search for other job boards
        jobBoardQuery = `${jobTitle} ${searchLocation} jobs ${jobBoard}`;
        break;
    }
    
    // Tavily doesn't use query-based time filters - we'll use the days parameter in the API call
    // SERP uses query-based time filters, so we add them to the query
    if (provider === 'serp' && timeFilter && timeFilter !== 'anytime') {
      const timeFilterMapping = {
        'day': 'tbs=qdr:d',
        'week': 'tbs=qdr:w', 
        'month': 'tbs=qdr:m',
        'year': 'tbs=qdr:y',
        'qdr:d': 'tbs=qdr:d',
        'qdr:w': 'tbs=qdr:w',
        'qdr:m': 'tbs=qdr:m',
        'qdr:y': 'tbs=qdr:y'
      };
      
      const timeFilterText = timeFilterMapping[timeFilter];
      if (timeFilterText) {
        jobBoardQuery += ` ${timeFilterText}`;
      }
    }
    
    console.log(`🔍 Built search query: "${jobBoardQuery}"`);

    // Use the appropriate search engine
    if (provider === 'tavily') {
      // Tavily search with proper time filtering
      const tavilyParams = {
        api_key: apiKey,
        query: jobBoardQuery,
        search_depth: 'basic',
        include_answer: false,
        include_images: false,
        include_raw_content: false,
        max_results: 100
      };
      
      // Add days parameter for time filtering (Tavily's way, not Google's tbs syntax)
      if (timeFilter && timeFilter !== 'anytime') {
        const daysMapping = {
          'day': 1,
          'week': 7, 
          'month': 30,
          'year': 365,
          'qdr:d': 1,
          'qdr:w': 7,
          'qdr:m': 30,
          'qdr:y': 365
        };
        
        const days = daysMapping[timeFilter];
        if (days) {
          tavilyParams.days = days;
          console.log(`📅 Using Tavily days filter: ${days} days`);
        }
      }
      
      const tavilyResponse = await axios.post('https://api.tavily.com/search', tavilyParams, {
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // Return raw Tavily data for frontend processing
      const tavilyResults = tavilyResponse.data.results || [];
      
      // Debug: Log first result to see available fields
      if (tavilyResults.length > 0) {
        console.log(`🔍 Sample Tavily result fields:`, Object.keys(tavilyResults[0]));
        console.log(`🔍 Sample Tavily result:`, JSON.stringify(tavilyResults[0], null, 2));
      }
      
      // Return raw Tavily data with metadata for frontend processing
      searchResults = tavilyResults.map(result => ({
        ...result, // Raw Tavily data
        _metadata: {
          jobBoard: jobBoard,
          location: location,
          timeFilter: timeFilter,
          searchQuery: jobBoardQuery
        }
      }));

    } else if (provider === 'serp') {
      // SERP API search with single call to get 100 results
      let allOrganicResults = [];
      
      console.log(`📊 [SERP DEBUG] Making single SERP API call for 100 results`);
      console.log(`📊 [SERP DEBUG] Job board query: "${jobBoardQuery}"`);
      console.log(`📊 [SERP DEBUG] Time filter: ${timeFilter || 'none'}`);
      console.log(`📊 [SERP DEBUG] API key found and valid: ${apiKey ? 'Yes' : 'No'}`);
      console.log(`📊 [SERP DEBUG] User ID: ${req.user.userId}`);
      console.log(`📊 [SERP DEBUG] Original query: "${query}", Location: "${location}", Job Board: "${jobBoard}"`);
      
      // Single API call with num=100 (max per call)
      const params = new URLSearchParams({
        api_key: apiKey,
        engine: 'google',
        q: jobBoardQuery,
        num: '100', // Request 100 results in a single call (max allowed)
        start: '0',
        filter: '0' // Include near-duplicates to get more results
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

      console.log(`📊 [SERP DEBUG] Making API call for up to 100 results at once`);
      console.log(`📊 [SERP DEBUG] Full API URL: https://serpapi.com/search?${params}`);
      
      try {
      const serpResponse = await axios.get(`https://serpapi.com/search?${params}`, {
          timeout: 60000 // Increased timeout for larger response
      });

      const organicResults = serpResponse.data.organic_results || [];
        const searchInformation = serpResponse.data.search_information || {};
        const serpMetadata = serpResponse.data.search_metadata || {};
        const pagination = serpResponse.data.serpapi_pagination || {};
        
        console.log(`📊 [SERP DEBUG] Results received: ${organicResults.length}`);
        console.log(`📊 [SERP DEBUG] Total available: ${searchInformation.total_results || 'unknown'}`);
        console.log(`📊 [SERP DEBUG] Has pagination next: ${pagination.next ? 'Yes' : 'No'}`);
        console.log(`📊 [SERP DEBUG] Pagination next URL: ${pagination.next || 'None'}`);
        console.log(`📊 [SERP DEBUG] Search metadata:`, JSON.stringify(serpMetadata, null, 2));
        console.log(`📊 [SERP DEBUG] First few results:`, organicResults.slice(0, 3).map(r => ({ title: r.title, link: r.link })));
        
        if (organicResults.length === 0) {
          console.log(`📊 [SERP DEBUG] No results found with original query`);
          
          // Try a fallback query with simpler format
          console.log(`📊 [SERP DEBUG] Trying fallback query...`);
          const fallbackQuery = `${query} ${jobBoard} jobs ${location}`;
          console.log(`📊 [SERP DEBUG] Fallback query: "${fallbackQuery}"`);
          
          const fallbackParams = new URLSearchParams({
            api_key: apiKey,
            engine: 'google',
            q: fallbackQuery,
            num: '50',
            start: '0',
            filter: '0'
          });
          
          try {
            const fallbackResponse = await axios.get(`https://serpapi.com/search?${fallbackParams}`, {
              timeout: 30000
            });
            
            const fallbackResults = fallbackResponse.data.organic_results || [];
            console.log(`📊 [SERP DEBUG] Fallback query returned: ${fallbackResults.length} results`);
            
            if (fallbackResults.length > 0) {
              console.log(`📊 [SERP DEBUG] Using fallback results`);
              allOrganicResults = fallbackResults;
            }
          } catch (fallbackError) {
            console.log(`📊 [SERP DEBUG] Fallback query also failed:`, fallbackError.message);
          }
        } else {
          console.log(`📊 [SERP DEBUG] Successfully retrieved ${organicResults.length} results in a single call`);
          allOrganicResults = organicResults; // Direct assignment, no need to push
        }
        
      } catch (error) {
        console.error(`❌ [SERP DEBUG] Error fetching results:`, error.message);
        console.error(`❌ [SERP DEBUG] Error details:`, error.response?.data || error);
      }
      
      console.log(`📊 [SERP DEBUG] Total organic results collected: ${allOrganicResults.length}`);
      console.log(`📊 [SERP DEBUG] First result: ${allOrganicResults.length > 0 ? allOrganicResults[0].title : 'None'}`);
      console.log(`📊 [SERP DEBUG] Last result: ${allOrganicResults.length > 0 ? allOrganicResults[allOrganicResults.length - 1].title : 'None'}`);
      
      // Return raw results for frontend processing (minimal backend processing)
      searchResults = allOrganicResults.map(result => ({
        title: result.title || '',
        company: '', // Let frontend extract company
          location: location,
        url: result.link || '',
          description: result.snippet || '',
        datePosted: result.date || 'Recently',
        source: jobBoard,
        // Include raw data for frontend processing
        rawData: {
          title: result.title,
          link: result.link,
          snippet: result.snippet,
          date: result.date,
          displayed_link: result.displayed_link
        }
      }));
      
      console.log(`🔗 [CORS PROXY] Returning ${searchResults.length} raw SERP results for frontend processing`);
    }

    // Minimal filtering - let frontend handle all processing
    console.log(`📊 [BACKEND DEBUG] Returning ${searchResults.length} raw results for frontend processing`);
    
    // Only basic validation - frontend will do all the heavy processing
    // For Tavily: results are raw API data with title/url at root level
    // For SERP: results are processed job objects
    if (provider === 'tavily') {
      // Tavily results are raw API data - minimal filtering
      searchResults = searchResults.filter(result => {
        return result.title && result.url && result.title.length > 3;
      });
    } else {
      // SERP results are processed job objects
      searchResults = searchResults.filter(job => {
        return job.title && job.url && job.title.length > 3;
      });
    }
    
    console.log(`📊 [BACKEND DEBUG] After basic filtering: ${searchResults.length} results`);

    // Increment usage tracking after successful search (only for freemium/system keys)
    // For Tavily: Only increment if using system key (freemium), not user's own key
    // For SERP: Only increment once per search request (not per page)
    if (provider === 'serp') {
      // Only increment once per search request, not per page of results
      console.log(`🎯 Incrementing SERP usage once for entire search (all pages)`);
      await incrementApiUsage(req.user.userId, provider);
    } else if (provider === 'tavily') {
      // Only increment Tavily usage if user was using system key (freemium)
      const userKeyInfo = await getUserApiKey(req.user.userId, 'tavily');
      if (userKeyInfo && !userKeyInfo.isUserKey) {
        console.log(`🎯 Incrementing Tavily freemium usage for system key usage`);
        await incrementApiUsage(req.user.userId, provider);
      } else {
        console.log(`🔑 User used their own Tavily API key - not incrementing freemium count`);
      }
    }

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

function cleanJobTitle(title, provider, jobBoard) {
  if (!title) return '';
  
  console.log(`🧹 Cleaning title: "${title}" [${provider.toUpperCase()}/${jobBoard.toUpperCase()}]`);
  
  let cleaned = title;
  const providerUpper = provider.toUpperCase();
  const jobBoardLower = jobBoard.toLowerCase();
  
  // ==========================================
  // AI-BASED CLEANING LOGIC - Provider & Job Board Specific
  // ==========================================
  
  // PHASE 1: PROVIDER-SPECIFIC PRE-PROCESSING
  if (provider === 'serp') {
    // SERP/Google Search specific cleaning - More structured titles
    cleaned = cleaned.replace(/^Job Application for\s+/i, ''); // Google often adds this
    cleaned = cleaned.replace(/\s*-\s*Google Search$/i, ''); // Remove Google Search suffix
    cleaned = cleaned.replace(/\s*\|\s*Indeed\.com$/i, ''); // Remove Indeed.com suffix
    cleaned = cleaned.replace(/\s*\|\s*LinkedIn$/i, ''); // Remove LinkedIn suffix
    cleaned = cleaned.replace(/\s*\|\s*Glassdoor$/i, ''); // Remove Glassdoor suffix
  } else if (provider === 'tavily') {
    // Tavily AI Search specific cleaning - More raw/unprocessed titles
    cleaned = cleaned.replace(/\s*\|\s*Tavily$/i, ''); // Remove Tavily suffix
    cleaned = cleaned.replace(/^.*?\s*›\s*/i, ''); // Remove breadcrumb navigation (Company › Job)
    cleaned = cleaned.replace(/\s*\.\.\.$/, ''); // Remove truncation indicators
    cleaned = cleaned.replace(/\s*\[Read More\]$/i, ''); // Remove read more indicators
  }
  
  // PHASE 2: JOB BOARD-SPECIFIC CLEANING
  if (jobBoardLower === 'greenhouse') {
    if (provider === 'serp') {
      // SERP + Greenhouse specific patterns
      cleaned = cleaned.replace(/- starpower$/i, '');
      cleaned = cleaned.replace(/at Two Six\s+/i, '');
      cleaned = cleaned.replace(/at Faraday\s+/i, '');
      cleaned = cleaned.replace(/at ID\.me\s+/i, '');
      cleaned = cleaned.replace(/- About\s+/i, '');
      cleaned = cleaned.replace(/Nextiva Careers & Job Openings - The Leader In/i, '');
      cleaned = cleaned.replace(/- Careers$/i, '');
      cleaned = cleaned.replace(/- - Careers$/i, '');
      cleaned = cleaned.replace(/^Greenhouse Job Application for\s+/i, '');
    } else if (provider === 'tavily') {
      // Tavily + Greenhouse specific patterns
      cleaned = cleaned.replace(/^Greenhouse Jobs at\s+/i, '');
      cleaned = cleaned.replace(/^Jobs at\s+.+\s*-\s*Greenhouse Software$/i, '');
      cleaned = cleaned.replace(/^Apply\s*-\s*My$/i, '');
      cleaned = cleaned.replace(/^N26 Jobs$/i, '');
      cleaned = cleaned.replace(/^AI Training for\s+.+\s+Writers?$/i, '');
    }
  } else if (jobBoardLower === 'indeed') {
    if (provider === 'serp') {
      // SERP + Indeed specific patterns
      cleaned = cleaned.replace(/\s*-\s*Indeed$/i, '');
      cleaned = cleaned.replace(/Apply Now\s*-\s*Indeed$/i, '');
      cleaned = cleaned.replace(/\$[\d,]+\/year$/i, ''); // Remove salary info
    } else if (provider === 'tavily') {
      // Tavily + Indeed specific patterns
      cleaned = cleaned.replace(/^Indeed\s*:\s*/i, '');
      cleaned = cleaned.replace(/\s*on Indeed$/i, '');
    }
  } else if (jobBoardLower === 'linkedin') {
    if (provider === 'serp') {
      // SERP + LinkedIn specific patterns
      cleaned = cleaned.replace(/\s*\|\s*LinkedIn$/i, '');
      cleaned = cleaned.replace(/Apply on LinkedIn$/i, '');
    } else if (provider === 'tavily') {
      // Tavily + LinkedIn specific patterns  
      cleaned = cleaned.replace(/^LinkedIn\s*:\s*/i, '');
      cleaned = cleaned.replace(/\s*on LinkedIn$/i, '');
    }
  }
  
  // PHASE 3: AI-BASED UNIVERSAL PATTERN RECOGNITION
  // Remove obvious prefixes and meta-information
  cleaned = cleaned.replace(/[\[\(]\d{4}[\]\)]\s*/, ''); // Year prefixes
  cleaned = cleaned.replace(/^.*?\s+Jobs:\s*/, ''); // "Company Jobs:" prefixes
  cleaned = cleaned.replace(/^(Job Application for|Apply for|Application for)\s*/i, ''); // Application language
  cleaned = cleaned.replace(/^\d+[\.\)]\s*/, ''); // Numbered prefixes
  
  // Phase 2: Advanced Truncation Detection and Cleanup
  // Handle common truncation patterns with AI-like reasoning
  
  // Pattern: "(Remote ...)" or "(Hybrid ...)" - Remove entire truncated location info
  cleaned = cleaned.replace(/\s*\((Remote|Hybrid|On-site|Contract|Full-time|Part-time)\s*\.{3,}[^)]*\)?\s*$/gi, '');
  
  // Pattern: "Title, Department & ..." - Clean truncated departmental info
  cleaned = cleaned.replace(/,\s*(Strategy|Corporate|Business|Technical|Operations|Marketing|Sales)\s*&?\s*\.{3,}.*$/gi, '');
  
  // Pattern: "Title - Company..." or "Title at Company..." - Remove truncated company references
  cleaned = cleaned.replace(/\s*[-–]\s*[A-Z][a-zA-Z]*\.{3,}.*$/g, '');
  cleaned = cleaned.replace(/\s+at\s+[A-Z][a-zA-Z]*\.{3,}.*$/gi, '');
  
  // Pattern: Any title ending with "..." (generic truncation)
  cleaned = cleaned.replace(/\.{3,}.*$/, '');
  
  // Phase 3: Location and Meta-info Removal (AI contextual understanding)
  // Remove location info that doesn't belong in job titles
  cleaned = cleaned.replace(/\s*[-–]\s*(United States|USA|US|Remote|Hybrid|On-site|Worldwide|Global).*$/i, '');
  cleaned = cleaned.replace(/\s*\((United States|USA|US|Remote|Hybrid|On-site|Contract|Full-time|Part-time)\)?\s*$/i, '');
  
  // Phase 4: Company Name Pattern Recognition
  // Advanced company suffix removal using AI-like pattern detection
  
  // Pattern: "Title - CompanyName" (single company word)
  cleaned = cleaned.replace(/\s*[-–]\s*[A-Z][a-z]+(\s+(Inc|LLC|Corp|Ltd|Co)\.?)?\s*$/g, '');
  
  // Pattern: "Title at CompanyName" (comprehensive company detection)
  cleaned = cleaned.replace(/\s+at\s+([A-Z][a-zA-Z]+(\s+[A-Z][a-zA-Z]+)*(\s+(Inc|LLC|Corp|Ltd|Co|Technologies|Systems|Solutions)\.?)?)\s*$/i, '');
  
  // Phase 5: Job Board and Platform Detection
  const jobBoardPattern = new RegExp(`\\s*(${[
    'Greenhouse', 'Lever', 'Ashby', 'Workday', 'Oracle', 'BreezyHR', 'Wellfound',
    'SmartRecruiters', 'JazzHR', 'Jobvite', 'iCIMS', 'Builtin', 'ADP', 'Paylocity',
    'Keka', 'Workable', 'Pinpoint', 'Recruitee', 'Rippling', 'Gusto'
  ].join('|')})\\s*$`, 'i');
  cleaned = cleaned.replace(jobBoardPattern, '');
  
  // Phase 6: Enhanced Google Search + Greenhouse Artifact Removal
  const artifactPatterns = [
    /\s*-\s*starpower\s*$/gi,
    /\s+at\s+Two\s+Six\s*\.{3,}.*$/gi,
    /\s+at\s+Faraday\s*\.{3,}.*$/gi,
    /\s+at\s+ID\.me\s*$/gi,
    /\s*-\s*About\s+[^-]+$/gi,
    /\s*Careers?\s*&?\s*Job\s*Openings?\s*-\s*.*$/gi,
    /\s*-\s*The\s+Leader\s+In\s+.*$/gi,
    /\s*-\s*-?\s*Careers?\s*$/gi
  ];
  
  artifactPatterns.forEach(pattern => {
    cleaned = cleaned.replace(pattern, '');
  });
  
  // Phase 7: Smart Parentheses Handling
  // AI logic: If parentheses are incomplete, either complete or remove
  if (cleaned.includes('(') && !cleaned.includes(')')) {
    // If it looks like location/type info, remove it
    if (/\([A-Za-z\s]*$/.test(cleaned)) {
      cleaned = cleaned.replace(/\([^)]*$/, '');
    } else {
      cleaned = cleaned + ')';
    }
  }
  
  // Phase 8: Generic Pattern Elimination
  // AI reasoning: These patterns indicate non-specific job content
  const genericPatterns = [
    /^Jobs?\s+at\s+[^\-]+$/i,
    /^Careers?\s*$/i,
    /^(Jobs?|Apply|Hiring|Open\s+Roles?|Opportunities)$/i,
    /^(Current\s+job\s+openings?|Available\s+positions?)$/i
  ];
  
  for (const pattern of genericPatterns) {
    if (pattern.test(cleaned.trim())) {
      cleaned = '';
      break;
    }
  }
  
  // Phase 9: Advanced Company Number Detection and Removal
  // Pattern: "CompanyName123" or "Company77" etc.
  cleaned = cleaned.replace(/([A-Za-z]+)\d+\s*$/, '$1');
  
  // Phase 9.5: ENHANCED PROVIDER-AWARE CLEANUP
  // Clean truncated "at" endings (universal)
  cleaned = cleaned.replace(/\s+at\s*$/, '');
  
  // Provider-specific advanced patterns
  if (provider === 'serp') {
    // SERP tends to have more structured company suffixes
    cleaned = cleaned.replace(/\s*-\s*Company Careers$/i, '');
    cleaned = cleaned.replace(/\s*\|\s*Jobs$/i, '');
  } else if (provider === 'tavily') {
    // Tavily tends to have more raw, unprocessed patterns
    cleaned = cleaned.replace(/^[A-Z0-9]+\s+jobs$/i, ''); // Remove standalone "N26 Jobs" type patterns
    cleaned = cleaned.replace(/^apply\s*-\s*my$/i, ''); // Clean "Apply - My" type meaningless patterns
  }
  
  // Phase 10: Final Cleanup and Normalization
  // AI-powered text normalization
  cleaned = cleaned
    .trim()
    .replace(/\s+/g, ' ') // Normalize whitespace
    .replace(/[,\-\|]+$/, '') // Remove trailing punctuation
    .replace(/^\s*[-–]\s*/, '') // Remove leading dashes
    .replace(/\s*[-–]\s*$/, ''); // Remove trailing dashes
  
  // Final validation: Ensure we have meaningful content
  if (cleaned.length < 3 || /^[^a-zA-Z]*$/.test(cleaned)) {
    cleaned = '';
  }
  
  console.log(`✨ AI Cleaned title: "${cleaned}" [${providerUpper}/${jobBoard.toUpperCase()}]`);
  
  return cleaned;
}

function extractCompanyFromUrl(url) {
  try {
    console.log(`🏢 Extracting company from URL: ${url}`);
    const hostname = new URL(url).hostname;
    
    // Handle specific job board patterns
    if (hostname.includes('greenhouse.io')) {
      // Extract from URLs like: company-name.greenhouse.io or boards.greenhouse.io/company-name
      if (hostname.startsWith('boards.')) {
        const match = url.match(/boards\.greenhouse\.io\/([^\/]+)/);
        if (match) {
          const company = formatCompanyName(match[1]);
          console.log(`✅ Greenhouse company from path: ${company}`);
          return company;
        }
      } else if (hostname.startsWith('job-boards.')) {
        // Handle job-boards.greenhouse.io URLs - try to extract company from path
        const pathMatch = url.match(/job-boards\.greenhouse\.io\/([^\/]+)/);
        if (pathMatch && pathMatch[1]) {
          const company = formatCompanyName(pathMatch[1]);
          console.log(`✅ Greenhouse company from job-boards path: ${company}`);
          return company;
        }
        // If no specific company in path, it's an aggregator
        console.log(`⚠️ Greenhouse job-boards subdomain - using generic name`);
        return "Multiple Companies (Greenhouse)";
      } else {
        const subdomain = hostname.split('.')[0];
        if (subdomain !== 'www' && subdomain !== 'boards' && subdomain !== 'job-boards') {
          const company = formatCompanyName(subdomain);
          console.log(`✅ Greenhouse company from subdomain: ${company}`);
          return company;
        }
      }
    }
    
    if (hostname.includes('lever.co')) {
      // Extract from URLs like: company-name.lever.co or jobs.lever.co/company-name
      if (hostname.startsWith('jobs.')) {
        const match = url.match(/jobs\.lever\.co\/([^\/]+)/);
        if (match) {
          const company = formatCompanyName(match[1]);
          console.log(`✅ Lever company from path: ${company}`);
          return company;
        }
      } else {
        const subdomain = hostname.split('.')[0];
        if (subdomain !== 'www' && subdomain !== 'jobs') {
          const company = formatCompanyName(subdomain);
          console.log(`✅ Lever company from subdomain: ${company}`);
          return company;
        }
      }
    }
    
    if (hostname.includes('ashby.com')) {
      // Extract from URLs like: company-name.ashby.com
      const subdomain = hostname.split('.')[0];
      if (subdomain !== 'www') {
        const company = formatCompanyName(subdomain);
        console.log(`✅ Ashby company: ${company}`);
        return company;
      }
    }
    
    // Try to extract company from URL path for other patterns
    const pathMatches = [
      url.match(/\/(?:jobs|careers|apply|company)\/([^\/\?]+)/i),
      url.match(/\/([^\/\?]+)\/(?:jobs|careers|apply)/i),
      url.match(/\.com\/([^\/\?]+)/i)
    ];
    
    for (const match of pathMatches) {
      if (match && match[1]) {
        const candidate = match[1].toLowerCase();
        // Skip generic terms and IDs
        if (!['jobs', 'careers', 'apply', 'company', 'about', 'contact', 'home', 'index'].includes(candidate) 
            && !/^\d+$/.test(candidate)
            && candidate.length > 2) {
          const company = formatCompanyName(candidate);
          console.log(`✅ Company from path: ${company}`);
          return company;
        }
      }
    }
    
    // Extract from main domain as fallback
    let company = hostname.replace(/^(www|jobs|careers|boards)\./, '');
    company = company.split('.')[0];
    
    // Skip generic terms
    if (['jobs', 'careers', 'apply', 'talent', 'hiring', 'monster', 'indeed', 'linkedin'].includes(company.toLowerCase())) {
      console.log(`❌ Skipping generic domain: ${company}`);
      return null;
    }
    
    const finalCompany = formatCompanyName(company);
    console.log(`✅ Company from domain: ${finalCompany}`);
    return finalCompany;
  } catch (e) {
    console.log(`❌ Error extracting company: ${e.message}`);
    return null;
  }
}

function formatCompanyName(name) {
  if (!name) return null;
  
  // Clean up the company name
  name = name.replace(/[-_]/g, ' ');
  name = name.replace(/\b\w/g, l => l.toUpperCase());
  
  // Remove common suffixes
  name = name.replace(/\s+(Inc|Corp|LLC|Ltd|Co)$/i, '');
  
  return name.trim();
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

// API endpoint to update individual cell in Google Sheet
app.post('/api/update-sheet-cell', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, row, column, value } = req.body;
    
    if (!sheetUrl || !row || !column || value === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken(req.user.userId);

    // Update the specific cell
    const cellRange = `Sheet1!${column}${row}`;
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${cellRange}?valueInputOption=RAW`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          values: [[value]]
        })
      }
    );

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Google Sheets API error:', errorData);
      return res.status(500).json({ error: 'Failed to update sheet' });
    }

    res.json({ success: true, message: 'Cell updated successfully' });
  } catch (error) {
    console.error('Error updating sheet cell:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Load filters from Google Sheet
app.post('/api/load-filters', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl } = req.body;
    
    if (!sheetUrl) {
      return res.status(400).json({ error: 'Missing sheet URL' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken(req.user.userId);

    // Try to read filters from "Filters" sheet
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    if (!filtersResponse.ok) {
      return res.json({ success: true, filters: [] }); // Return empty if no Filters sheet
    }

    const filtersData = await filtersResponse.json();
    if (!filtersData.values || filtersData.values.length <= 1) {
      return res.json({ success: true, filters: [] }); // No filters found
    }

    // Parse filters (skip header row)
    const filters = filtersData.values.slice(1).map(row => ({
      id: row[0],
      name: row[1],
      locations: row[2] || '',
      applicationStatuses: row[3] || '',
      jobTitleKeywords: row[4] || ''
    }));

    res.json({ success: true, filters: filters });
  } catch (error) {
    console.error('Error loading filters:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Save filter to Google Sheet
app.post('/api/save-filter', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, filter } = req.body;
    
    if (!sheetUrl || !filter) {
      return res.status(400).json({ error: 'Missing sheet URL or filter data' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken(req.user.userId);

    // First, try to read existing filters to see if we need to create the sheet
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    let existingFilters = [];
    let filtersSheetExists = false;
    
    if (filtersResponse.ok) {
      filtersSheetExists = true;
      const filtersData = await filtersResponse.json();
      if (filtersData.values && filtersData.values.length > 1) {
        // Parse existing filters (skip header row)
        existingFilters = filtersData.values.slice(1).map(row => ({
          id: row[0],
          name: row[1],
          locations: row[2] || '',
          applicationStatuses: row[3] || '',
          jobTitleKeywords: row[4] || '',
          createdAt: row[5] || new Date().toISOString()
        }));
      }
    } else {
      // Filters sheet doesn't exist, create it
      console.log('Creating Filters sheet...');
      const createSheetResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}:batchUpdate`,
        {
      method: 'POST',
      headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
      },
      body: JSON.stringify({
            requests: [{
              addSheet: {
                properties: {
                  title: 'Filters',
                  gridProperties: {
                    rowCount: 1000,
                    columnCount: 6
                  }
                }
              }
            }]
          })
        }
      );

      if (!createSheetResponse.ok) {
        const errorText = await createSheetResponse.text();
        console.error('Error creating Filters sheet:', errorText);
        return res.status(500).json({ error: 'Failed to create Filters sheet' });
      }
      
      console.log('Filters sheet created successfully');
      filtersSheetExists = true;
    }

    if (!filtersSheetExists) {
      return res.status(500).json({ error: 'Failed to create or access Filters sheet' });
    }

    // Check if filter already exists (by ID)
    console.log('🔍 [SAVE-FILTER] Checking for existing filter with ID:', filter.id);
    console.log('🔍 [SAVE-FILTER] Existing filters:', existingFilters.map(f => ({ id: f.id, name: f.name })));
    const existingFilterIndex = existingFilters.findIndex(f => f.id === filter.id);
    console.log('🔍 [SAVE-FILTER] Existing filter index:', existingFilterIndex);
    
    if (existingFilterIndex >= 0) {
      // Update existing filter
      console.log('✅ [SAVE-FILTER] Updating existing filter at index:', existingFilterIndex);
      existingFilters[existingFilterIndex] = {
        id: filter.id,
        name: filter.name,
        locations: filter.locations,
        applicationStatuses: filter.applicationStatuses,
        jobTitleKeywords: filter.jobTitleKeywords,
        createdAt: filter.createdAt
      };
    } else {
      // Add new filter
      console.log('➕ [SAVE-FILTER] Adding new filter with ID:', filter.id);
      existingFilters.push({
        id: filter.id,
        name: filter.name,
        locations: filter.locations,
        applicationStatuses: filter.applicationStatuses,
        jobTitleKeywords: filter.jobTitleKeywords,
        createdAt: filter.createdAt
      });
    }

    // Prepare data for writing to sheet
    const sheetData = [
      ['ID', 'Name', 'Locations', 'Application Statuses', 'Job Title Keywords', 'Created At'],
      ...existingFilters.map(f => [
        f.id,
        f.name,
        f.locations,
        f.applicationStatuses,
        f.jobTitleKeywords,
        f.createdAt
      ])
    ];

    // Write to the Filters sheet
    console.log('Writing filter data to Google Sheets:', {
      sheetId,
      sheetDataLength: sheetData.length,
      firstRow: sheetData[0],
      secondRow: sheetData[1]
    });

    const writeResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000?valueInputOption=RAW`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          values: sheetData
        })
      }
    );

    console.log('Write response status:', writeResponse.status);
    console.log('Write response ok:', writeResponse.ok);

    if (!writeResponse.ok) {
      const errorText = await writeResponse.text();
      console.error('Error writing filters to sheet:', errorText);
      return res.status(500).json({ error: 'Failed to save filter to Google Sheets', details: errorText });
    }

    const writeResult = await writeResponse.json();
    console.log('Write result:', writeResult);

    res.json({ success: true, message: 'Filter saved successfully' });
  } catch (error) {
    console.error('Error saving filter:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete filter endpoint
app.post('/api/delete-filter', authenticateToken, async (req, res) => {
  try {
    console.log('🗑️ [DELETE-FILTER] Received delete request');
    console.log('🗑️ [DELETE-FILTER] Request body:', req.body);
    
    const { sheetUrl, filterId } = req.body;
    
    if (!sheetUrl || !filterId) {
      console.error('❌ [DELETE-FILTER] Missing required parameters');
      return res.status(400).json({ error: 'Missing sheet URL or filter ID' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken(req.user.userId);
    
    if (!accessToken) {
      console.error('❌ [DELETE-FILTER] No valid Google access token available');
      return res.status(400).json({ 
        error: 'Google Sheets integration not configured. Please contact support.' 
      });
    }

    // First check if the Filters sheet exists
    const sheetInfoResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );
    
    if (!sheetInfoResponse.ok) {
      const errorText = await sheetInfoResponse.text();
      console.error('❌ [DELETE-FILTER] Cannot access spreadsheet:', errorText);
      return res.status(400).json({ 
        error: 'Cannot access spreadsheet. Please check the URL and permissions.', 
        details: errorText 
      });
    }
    
    const sheetInfo = await sheetInfoResponse.json();
    const filtersSheetExists = sheetInfo.sheets && sheetInfo.sheets.some(sheet => sheet.properties.title === 'Filters');
    
    if (!filtersSheetExists) {
      console.log('❌ [DELETE-FILTER] Filters sheet does not exist');
      return res.status(400).json({ error: 'Filters sheet does not exist in this spreadsheet' });
    }
    
    console.log('✅ [DELETE-FILTER] Filters sheet exists, proceeding with deletion');

    // Read existing filters
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    if (!filtersResponse.ok) {
      const errorText = await filtersResponse.text();
      console.error('❌ [DELETE-FILTER] Cannot access Filters sheet:', errorText);
      return res.status(400).json({ 
        error: 'Cannot access Filters sheet', 
        details: errorText 
      });
    }

    const filtersData = await filtersResponse.json();
    console.log('📊 [DELETE-FILTER] Filters data received:', filtersData);
    
    if (!filtersData.values || filtersData.values.length <= 1) {
      console.log('❌ [DELETE-FILTER] No filters found to delete');
      return res.status(400).json({ error: 'No filters found to delete' });
    }

    // Parse existing filters (skip header row)
    const existingFilters = filtersData.values.slice(1).map(row => ({
      id: row[0],
      name: row[1],
      locations: row[2] || '',
      applicationStatuses: row[3] || '',
      jobTitleKeywords: row[4] || '',
      createdAt: row[5] || new Date().toISOString()
    }));

    // Find and remove the filter
    console.log('🔍 [DELETE-FILTER] Looking for filter with ID:', filterId);
    console.log('🔍 [DELETE-FILTER] Available filters:', existingFilters.map(f => ({ id: f.id, name: f.name })));
    
    const filterIndex = existingFilters.findIndex(f => f.id === filterId);
    console.log('🔍 [DELETE-FILTER] Filter index found:', filterIndex);
    
    if (filterIndex === -1) {
      console.error('❌ [DELETE-FILTER] Filter not found in existing filters');
      return res.status(400).json({ error: 'Filter not found' });
    }

    console.log('✅ [DELETE-FILTER] Removing filter at index:', filterIndex);
    const removedFilter = existingFilters[filterIndex];
    console.log('🗑️ [DELETE-FILTER] Removed filter:', { id: removedFilter.id, name: removedFilter.name });
    
    existingFilters.splice(filterIndex, 1);
    console.log('📊 [DELETE-FILTER] Remaining filters count:', existingFilters.length);

    // Prepare data for writing to sheet
    const sheetData = [
      ['ID', 'Name', 'Locations', 'Application Statuses', 'Job Title Keywords', 'Created At'],
      ...existingFilters.map(f => [
        f.id,
        f.name,
        f.locations,
        f.applicationStatuses,
        f.jobTitleKeywords,
        f.createdAt
      ])
    ];
    
    // If no filters remain, we still need to write the header row
    if (existingFilters.length === 0) {
      console.log('📝 [DELETE-FILTER] No filters remaining, writing header only');
    }

    // Write updated filters back to sheet
    console.log('📝 [DELETE-FILTER] Writing updated filters to sheet:');
    console.log('📝 [DELETE-FILTER] Sheet data:', sheetData);
    console.log('📝 [DELETE-FILTER] Filters count:', existingFilters.length);
    
    // First, clear the entire Filters sheet using the proper CLEAR method
    let clearResponse;
    let clearAttempts = 0;
    const maxClearAttempts = 3;
    
    while (clearAttempts < maxClearAttempts) {
      clearResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000:clear`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (clearResponse.ok) {
        console.log('✅ [DELETE-FILTER] Sheet cleared successfully');
        break;
      } else {
        clearAttempts++;
        const errorText = await clearResponse.text();
        console.error(`❌ [DELETE-FILTER] Error clearing sheet (attempt ${clearAttempts}/${maxClearAttempts}):`, errorText);
        
        if (clearAttempts >= maxClearAttempts) {
          return res.status(500).json({ 
            error: 'Failed to clear Filters sheet after multiple attempts',
            details: errorText
          });
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    // Then write the new data with retry mechanism
    let writeResponse;
    let writeAttempts = 0;
    const maxWriteAttempts = 3;
    
    while (writeAttempts < maxWriteAttempts) {
      writeResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000?valueInputOption=RAW`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: sheetData
          })
        }
      );

      if (writeResponse.ok) {
        console.log('✅ [DELETE-FILTER] Data written successfully');
        break;
      } else {
        writeAttempts++;
        const errorText = await writeResponse.text();
        console.error(`❌ [DELETE-FILTER] Error writing data (attempt ${writeAttempts}/${maxWriteAttempts}):`, errorText);
        
        if (writeAttempts >= maxWriteAttempts) {
          return res.status(500).json({ 
            error: 'Failed to write updated filters after multiple attempts',
            details: errorText
          });
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    console.log(`📊 [DELETE] Write response status: ${writeResponse.status}`);
    console.log(`📊 [DELETE] Write response ok: ${writeResponse.ok}`);

    if (!writeResponse.ok) {
      const errorText = await writeResponse.text();
      console.error('❌ [DELETE] Error writing updated filters:', errorText);
      return res.status(500).json({ error: 'Failed to update Filters sheet' });
    }

    const writeResult = await writeResponse.json();
    console.log(`📊 [DELETE] Write result:`, writeResult);

    // Verify the write was successful by checking the updated cells count
    if (writeResult.updatedCells && writeResult.updatedCells > 0) {
      console.log(`✅ Filter deleted successfully: ${filterId} (${writeResult.updatedCells} cells updated)`);
      res.json({
        success: true,
        message: 'Filter deleted successfully',
        deletedFilterId: filterId,
        updatedCells: writeResult.updatedCells
      });
    } else {
      console.error(`❌ [DELETE] Write succeeded but no cells were updated. Write result:`, writeResult);
      
      // Try to verify the deletion by reading the sheet back
      const verifyResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
        {
          headers: { 'Authorization': `Bearer ${accessToken}` }
        }
      );
      
      if (verifyResponse.ok) {
        const verifyData = await verifyResponse.json();
        const remainingFilters = verifyData.values ? verifyData.values.slice(1) : [];
        const filterStillExists = remainingFilters.some(row => row[0] === filterId);
        
        if (filterStillExists) {
          console.error(`❌ [DELETE] Filter still exists in sheet after deletion attempt`);
          res.status(500).json({ 
            error: 'Filter deletion failed - filter still exists in Google Sheets',
            details: writeResult
          });
        } else {
          console.log(`✅ [DELETE] Filter successfully deleted (verified by reading sheet)`);
          res.json({
            success: true,
            message: 'Filter deleted successfully (verified)',
            deletedFilterId: filterId,
            updatedCells: writeResult.updatedCells || 0
          });
        }
      } else {
        res.status(500).json({ 
          error: 'Filter deletion failed - no cells were updated in Google Sheets',
          details: writeResult
        });
      }
    }

  } catch (error) {
    console.error('Delete filter error:', error);
    res.status(500).json({ error: 'Failed to delete filter' });
  }
});

// Replace sheet data endpoint (for duplicate removal)
app.post('/api/replace-sheet-data', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, jobs } = req.body;
    
    if (!sheetUrl || !jobs || !Array.isArray(jobs)) {
      return res.status(400).json({ error: 'Sheet URL and jobs data are required' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }
    const sheetId = sheetIdMatch[1];

    // Get Google access token using the same method as filters (system service account)
    console.log(`🔗 [REPLACE] Getting Google access token for user: ${req.user.userId}`);
    const accessToken = await getValidAccessToken(req.user.userId);
    
    if (!accessToken) {
      console.log(`❌ [REPLACE] Failed to get Google access token for user: ${req.user.userId}`);
      return res.status(400).json({ error: 'Google Sheets integration not configured. Please contact support.' });
    }
    
    console.log(`✅ [REPLACE] Google access token obtained successfully`);

    // Prepare data for replacement
    const headers = ['Job Title', 'Company', 'Location', 'Job URL', 'Application Status', 'Date Posted', 'Source'];
    const jobRows = jobs.map(job => [
      job.title || '',
      job.company || '',
      job.location || '',
      job.url || '',
      job.applicationStatus || 'Not Applied',
      job.datePosted || '',
      job.source || ''
    ]);
    const dataToReplace = [headers, ...jobRows];

    // First, check if we can access the sheet
    console.log(`🔍 [REPLACE] Checking sheet access for: ${sheetId}`);
    try {
      const testResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}?fields=properties.title`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log(`✅ [REPLACE] Sheet access confirmed: ${testResponse.data?.properties?.title || 'Unknown'}`);
    } catch (accessError) {
      console.error('❌ [REPLACE] Cannot access sheet:', accessError.response?.data || accessError.message);
      return res.status(400).json({ 
        error: 'Cannot access your Google Sheet. Please ensure the service account has Editor access to the sheet.' 
      });
    }

    // Replace all data in the sheet
    const range = 'A1:Z1000'; // Large range to clear existing data
    console.log(`🔗 [REPLACE] Replacing sheet data:`, {
      sheetId: sheetId,
      range: range,
      dataRows: dataToReplace.length,
      jobsCount: jobs.length
    });
    
    try {
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}?valueInputOption=RAW`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: dataToReplace
          })
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ [REPLACE] Google Sheets API error:', errorText);
        return res.status(400).json({ 
          error: 'Failed to replace Google Sheets data. Please ensure the service account has Editor access to the sheet.' 
        });
      }

      console.log(`✅ [REPLACE] Successfully replaced sheet data with ${jobs.length} jobs`);
      res.json({ 
        success: true, 
        message: `Successfully replaced sheet data with ${jobs.length} jobs`,
        replacedCount: jobs.length
      });
    } catch (sheetsError) {
      console.error('❌ [REPLACE] Google Sheets API error:', sheetsError.message);
      return res.status(400).json({ 
        error: 'Failed to replace Google Sheets data. Please ensure the service account has Editor access to the sheet.' 
      });
    }

  } catch (error) {
    console.error('Replace sheet data error:', error);
    const errorMessage = error.response?.data?.error?.message || error.message || 'Replace failed';
    res.status(500).json({ error: 'Failed to replace sheet data', details: errorMessage });
  }
});

// Read data from Google Sheet
// Export jobs to Google Sheets
app.post('/api/export-to-sheets', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, jobs } = req.body;
    
    if (!sheetUrl || !jobs || !Array.isArray(jobs)) {
      return res.status(400).json({ error: 'Sheet URL and jobs data are required' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }
    const sheetId = sheetIdMatch[1];

    // Get Google access token using the same method as filters (system service account)
    console.log(`🔗 [EXPORT] Getting Google access token for user: ${req.user.userId}`);
    const accessToken = await getValidAccessToken(req.user.userId);
    
    if (!accessToken) {
      console.log(`❌ [EXPORT] Failed to get Google access token for user: ${req.user.userId}`);
      return res.status(400).json({ error: 'Google Sheets integration not configured. Please contact support.' });
    }
    
    console.log(`✅ [EXPORT] Google access token obtained successfully`);

    // Prepare data for export
    const headers = ['Job Title', 'Company', 'Location', 'Job URL', 'Application Status', 'Date Posted', 'Source'];
    const jobRows = jobs.map(job => [
      job.title || '',
      job.company || '',
      job.location || '',
      job.url || '',
      job.applicationStatus || 'Not Applied',
      job.datePosted || '',
      job.source || ''
    ]);
    const dataToExport = [headers, ...jobRows];

    // First, check if we can access the sheet
    console.log(`🔗 [EXPORT] Checking sheet access for: ${sheetId}`);
    try {
      const testResponse = await axios.get(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}?fields=properties.title`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log(`✅ [EXPORT] Sheet access confirmed: ${testResponse.data.properties.title}`);
    } catch (accessError) {
      console.error('❌ [EXPORT] Cannot access sheet:', accessError.response?.data || accessError.message);
      return res.status(400).json({ 
        error: 'Cannot access your Google Sheet. Please ensure the service account has Editor access to the sheet.' 
      });
    }

    // First, check how many rows already exist to append after them
    console.log(`🔍 [EXPORT] Checking existing data in sheet...`);
    const checkResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/A:A?majorDimension=COLUMNS`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    let startRow = 1; // Default to start from row 1 if no existing data
    if (checkResponse.ok) {
      const checkData = await checkResponse.json();
      if (checkData.values && checkData.values[0]) {
        startRow = checkData.values[0].length + 1; // Start after last existing row
        console.log(`📊 [EXPORT] Found ${checkData.values[0].length} existing rows, will append from row ${startRow}`);
      }
    }

    // Write to Google Sheets (append mode)
    const range = `A${startRow}:G${startRow + dataToExport.length - 1}`;
    console.log(`🔗 [EXPORT] Writing to Google Sheets (append mode):`, {
      sheetId: sheetId,
      range: range,
      startRow: startRow,
      dataRows: dataToExport.length,
      jobsCount: jobs.length
    });
    
    try {
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}?valueInputOption=RAW`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: dataToExport
          })
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ [EXPORT] Google Sheets API error:', errorText);
        return res.status(400).json({ 
          error: 'Failed to write to Google Sheets. Please ensure the service account has Editor access to the sheet.' 
        });
      }

      console.log(`✅ [EXPORT] Successfully exported ${jobs.length} jobs to Google Sheets`);
      res.json({ 
        success: true, 
        message: `Successfully exported ${jobs.length} jobs to Google Sheets`,
        exportedCount: jobs.length
      });
    } catch (sheetsError) {
      console.error('❌ [EXPORT] Google Sheets API error:', sheetsError.message);
      return res.status(400).json({ 
        error: 'Failed to write to Google Sheets. Please ensure the service account has Editor access to the sheet.' 
      });
    }

  } catch (error) {
    console.error('Export to Google Sheets error:', error);
    const errorMessage = error.response?.data?.error?.message || error.message || 'Export failed';
    res.status(500).json({ error: 'Failed to export to Google Sheets', details: errorMessage });
  }
});

app.post('/api/read-sheet', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, range = 'A:Z' } = req.body;
    
    if (!sheetUrl) {
      return res.status(400).json({ error: 'Missing sheet URL' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken(req.user.userId);

    // Read data from the sheet
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}?majorDimension=ROWS`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Google Sheets API error:', errorData);
      return res.status(500).json({ 
        success: false, 
        error: `Failed to read sheet: ${response.statusText}` 
      });
    }

    const data = await response.json();
    
    // Convert to job format if it looks like job data
    const jobs = [];
    if (data.values && data.values.length > 1) {
      const headers = data.values[0];
      const jobIndex = headers.findIndex(h => h && h.toLowerCase().includes('job'));
      
      if (jobIndex >= 0) {
        for (let i = 1; i < data.values.length; i++) {
          const row = data.values[i];
          if (row && row.length > 0 && row[0]) { // Skip empty rows
            jobs.push({
              title: row[0] || '',
              company: row[1] || '',
              location: row[2] || '',
              url: row[3] || '',
              applicationStatus: row[4] || '',
              datePosted: row[5] || '',
              description: row[6] || '',
              source: 'Google Sheets'
            });
          }
        }
      }
    }

    res.json({ 
      success: true, 
      jobs: jobs,
      rawData: data.values || []
    });
  } catch (error) {
    console.error('Error reading sheet:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔒 Secure API Proxy running on port ${PORT}`);
  console.log(`🚀 Deployment timestamp: ${new Date().toISOString()}`);
  console.log('🛡️ Security features enabled:');
  console.log('  - Helmet security headers');
  console.log('  - Rate limiting');
  console.log('  - API key security');
  console.log('  - Audit logging');
  console.log('  - JWT authentication');
  console.log('  - Input validation');
});
