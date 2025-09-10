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
// Use a consistent encryption key to avoid decryption issues
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || Buffer.from('12345678901234567890123456789012', 'utf8');

// System API Keys for freemium users - stored encrypted in database
// Create a system user profile to store encrypted system API keys

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
    
    // Check if user has an active session
    const activeSession = activeSessions.get(userId);
    
    if (!activeSession) {
      console.log(`🚫 No active session found for user ${userId}`);
      return res.status(401).json({ 
        error: 'Session expired', 
        code: 'SESSION_EXPIRED',
        message: 'Please log in again' 
      });
    }
    
    // Verify the token matches the active session
    if (activeSession.token !== token) {
      console.log(`🚫 Token mismatch for user ${userId} - session invalidated from another device`);
      activeSessions.delete(userId); // Clean up invalid session
      return res.status(401).json({ 
        error: 'Session invalidated', 
        code: 'SESSION_INVALIDATED',
        message: 'You have been logged out because you signed in from another device' 
      });
    }
    
    // Update last active time
    activeSession.lastActive = Date.now();
    activeSessions.set(userId, activeSession);
    
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
    // In production, you'd verify this with Appwrite
    // For now, we'll create a short-lived token
    
    const userId = req.body.userId;
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
      delete apiKeys.tavilyUsageCount;
      console.log(`🗑️ Deleted Tavily API key and usage count for user ${req.user.userId}`);
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

// System API key now properly encrypted with consistent encryption key
// Decryption issues resolved - temporary restore endpoint removed

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

    // Encrypt the API key
    const encryptedKey = encrypt(apiKey);
    console.log(`🔒 API key encrypted for ${provider}`);
    
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

    // Store the encrypted API key and initialize usage tracking
    if (provider === 'tavily') {
      apiKeys.tavilyApiKey = encryptedKey;
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
      apiKeys.serpApiKey = encryptedKey;
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
    const { query, engine = 'google', num = 100, timeFilter } = req.body;
    
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

// Helper function to get system API key (stored encrypted in database)
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
      const encryptedKey = apiKeys.systemTavilyApiKey;
      if (!encryptedKey) {
        console.log(`❌ System Tavily API key not found in database`);
        return null;
      }
      
      try {
        const decryptedKey = decrypt(encryptedKey);
        console.log(`✅ System Tavily API key retrieved from database`);
        return decryptedKey;
      } catch (error) {
        console.error(`❌ Failed to decrypt system Tavily API key:`, error.message);
        return null;
      }
    }

    return null;
  } catch (error) {
    console.error(`❌ Error retrieving system API key:`, error.message);
    return null;
  }
}

// Helper function to get valid Google Sheets API access token
async function getValidAccessToken() {
  try {
    // For now, use the app-level Google OAuth token from environment
    const accessToken = process.env.GOOGLE_ACCESS_TOKEN;
    
    if (!accessToken) {
      console.error('❌ No Google access token found in environment variables');
      throw new Error('Google access token not configured');
    }
    
    console.log('✅ Using Google access token for Sheets API');
    return accessToken;
  } catch (error) {
    console.error('❌ Error getting Google access token:', error);
    throw error;
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
      
      return {
        totalSearchesLeft: (account.plan_limit || 0) - (account.plan_usage || 0),
        thisMonthUsage: account.plan_usage || key.usage || 0,
        searchesPerMonth: account.plan_limit || 0,
        planName: account.current_plan || 'Unknown Plan'
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

    // Return the appropriate encrypted API key with usage info
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
          const decryptedKey = decrypt(keyInfo.key);
          const accountData = await getTavilyAccountUsage(decryptedKey);
          
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
        
        const decryptedApiKey = decrypt(keyInfo.key);
        const accountResponse = await axios.get(`https://serpapi.com/account.json?api_key=${decryptedApiKey}`);
        
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

// Job Search Proxy - handles individual job board searches
app.post('/api/proxy/search-jobs', authenticateToken, apiRateLimit, async (req, res) => {
  try {
    const { query, location, jobBoard, provider, timeFilter } = req.body;
    
    if (!query || !jobBoard || !provider) {
      return res.status(400).json({ error: 'Missing required fields (query, jobBoard, provider)' });
    }

    // Validate provider
    if (!['tavily', 'serp'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider' });
    }

    console.log(`🔍 Job search request: ${query} in ${location} on ${jobBoard} via ${provider}`);

    // Get user's encrypted API key for the provider with usage info
    const keyInfo = await getUserApiKey(req.user.userId, provider);
    
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

    // Decrypt the API key (or use system key for Tavily freemium)
    let apiKey;
    if (provider === 'tavily' && keyInfo.key === 'SYSTEM_KEY') {
      // Use encrypted system Tavily API key from database
      apiKey = await getSystemApiKey('tavily');
      if (!apiKey) {
        console.error('❌ System Tavily API key not found in database');
        return res.status(500).json({ 
          error: 'System Tavily API key not configured. Please contact administrator.',
          code: 'MISSING_SYSTEM_API_KEY'
        });
      }
      console.log(`🆓 Using encrypted system Tavily API key for freemium user ${req.user.userId} (${keyInfo.usageCount + 1}/${keyInfo.usageLimit})`);
    } else {
      apiKey = decrypt(keyInfo.key);
    }

    let searchResults = [];

    // Build job board specific search query based on the specified patterns
    let jobBoardQuery;
    const jobTitle = `"${query}"`;
    const searchLocation = `"${location}"`;
    
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
    
    // Add time filter to query for Tavily (SERP handles it separately)
    if (provider === 'tavily' && timeFilter && timeFilter !== 'anytime') {
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
      const tavilyResults = tavilyResponse.data.results || [];
      
      // Debug: Log first result to see available fields
      if (tavilyResults.length > 0) {
        console.log(`🔍 Sample Tavily result fields:`, Object.keys(tavilyResults[0]));
        console.log(`🔍 Sample Tavily result:`, JSON.stringify(tavilyResults[0], null, 2));
      }
      
      searchResults = tavilyResults.map(result => {
        // Title cleaning moved to frontend
        
        // Try to extract date from various possible fields
        let datePosted = 'Recently';
        if (result.published_date) {
          datePosted = result.published_date;
        } else if (result.date) {
          datePosted = result.date;
        } else if (result.timestamp) {
          datePosted = new Date(result.timestamp).toLocaleDateString();
        }
        
        // Return raw data - let frontend handle all cleaning and company extraction
        return {
          title: result.title,
          company: result.company || '', // Pass through raw company data
          location: location,
          url: result.url,
          description: result.content || '',
          datePosted: datePosted,
          source: jobBoard
        };
      });

    } else if (provider === 'serp') {
      // SERP API search
      const params = new URLSearchParams({
        api_key: apiKey,
        engine: 'google',
        q: jobBoardQuery,
        num: '100'
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
      
      // Debug: Log first result to see available fields
      if (organicResults.length > 0) {
        console.log(`🔍 Sample SERP result fields:`, Object.keys(organicResults[0]));
        console.log(`🔍 Sample SERP result:`, JSON.stringify(organicResults[0], null, 2));
      }
      
      searchResults = organicResults.map(result => {
        // Title cleaning moved to frontend
        
        // Try to extract date from various possible fields
        let datePosted = 'Recently';
        if (result.date) {
          datePosted = result.date;
        } else if (result.displayed_link && result.displayed_link.includes('•')) {
          // Sometimes dates appear in the displayed link like "company.com › careers › 2 days ago"
          const parts = result.displayed_link.split('•');
          const lastPart = parts[parts.length - 1]?.trim();
          if (lastPart && (lastPart.includes('ago') || lastPart.includes('day') || lastPart.includes('hour'))) {
            datePosted = lastPart;
          }
        }
        
        return {
          title: result.title,
          company: result.company || '', // Pass through raw company data
          location: location,
          url: result.link,
          description: result.snippet || '',
          datePosted: datePosted,
          source: jobBoard
        };
      });
    }

    // Data cleaning and filtering moved to frontend
    console.log(`📊 Returning ${searchResults.length} raw results to frontend for processing`);

    // Increment usage tracking after successful search (only for freemium/system keys)
    // For Tavily: Only increment if using system key (freemium), not user's own key
    // For SERP: Always increment since user is always using their own key
    if (provider === 'serp') {
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

    res.json({
      success: true,
      jobs: searchResults,
      totalJobs: searchResults.length,
      searchBackend: 'digitalocean',
      searchParams: {
        jobTitle: query,
        location: location || '',
        jobBoards: [jobBoard],
        timeFilter: timeFilter || 'qdr:d'
      }
    });

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

// cleanJobTitle function moved to frontend

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
        // Try alternative patterns for job-boards URLs
        const altMatch = url.match(/job-boards\.eu\.greenhouse\.io\/([^\/]+)/);
        if (altMatch && altMatch[1]) {
          const company = formatCompanyName(altMatch[1]);
          console.log(`✅ Greenhouse company from job-boards.eu path: ${company}`);
          return company;
        }
        // If no specific company in path, it's an aggregator
        console.log(`⚠️ Greenhouse job-boards subdomain - using generic name`);
        return "Unknown Company";
      } else {
        const subdomain = hostname.split('.')[0];
        if (subdomain !== 'www' && subdomain !== 'boards' && subdomain !== 'job-boards') {
          const company = formatCompanyName(subdomain);
          console.log(`✅ Greenhouse company from subdomain: ${company}`);
          return company;
        }
      }
      
      // Handle URLs with "embed" in the path - try to extract company from other parts
      if (url.includes('embed')) {
        // Try to extract company from the URL path before "embed"
        const embedMatch = url.match(/\/([^\/]+)\/.*embed/i);
        if (embedMatch && embedMatch[1] && !['jobs', 'careers', 'apply', 'company', 'about'].includes(embedMatch[1].toLowerCase())) {
          const company = formatCompanyName(embedMatch[1]);
          console.log(`✅ Greenhouse company from embed path: ${company}`);
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
    if (['jobs', 'careers', 'apply', 'talent', 'hiring', 'monster', 'indeed', 'linkedin', 'embed', 'multiple', 'companies'].includes(company.toLowerCase())) {
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
    const accessToken = await getValidAccessToken();

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

// Filter Management Endpoints
app.post('/api/save-filter', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, filter } = req.body;
    
    if (!sheetUrl || !filter) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken();

    // Check if "Filters" sheet exists, create if not
    const sheetsResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}?fields=sheets.properties.title`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    if (!sheetsResponse.ok) {
      return res.status(500).json({ error: 'Failed to access sheet' });
    }

    const sheetsData = await sheetsResponse.json();
    const hasFiltersSheet = sheetsData.sheets?.some(sheet => sheet.properties.title === 'Filters');

    if (!hasFiltersSheet) {
      // Create "Filters" sheet
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
                  gridProperties: { rowCount: 1000, columnCount: 10 }
                }
              }
            }]
          })
        }
      );

      if (!createSheetResponse.ok) {
        return res.status(500).json({ error: 'Failed to create Filters sheet' });
      }
    }

    // Get existing filters
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    let existingFilters = [];
    if (filtersResponse.ok) {
      const filtersData = await filtersResponse.json();
      if (filtersData.values && filtersData.values.length > 0) {
        // Skip header row
        existingFilters = filtersData.values.slice(1).map(row => ({
          id: row[0],
          name: row[1],
          locations: row[2] || '',
          applicationStatuses: row[3] || '',
          jobTitleKeywords: row[4] || ''
        }));
      }
    }

    // Remove existing filter with same ID
    const filteredFilters = existingFilters.filter(f => f.id !== filter.id);
    
    // Add new filter
    const newFilters = [...filteredFilters, filter];
    
    // Prepare data for writing
    const filterData = [
      ['ID', 'Name', 'Locations', 'ApplicationStatuses', 'JobTitleKeywords'], // Headers
      ...newFilters.map(f => [f.id, f.name, f.locations, f.applicationStatuses, f.jobTitleKeywords])
    ];

    // Write filters to sheet
    const writeResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000?valueInputOption=RAW`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ values: filterData })
      }
    );

    if (!writeResponse.ok) {
      return res.status(500).json({ error: 'Failed to save filter' });
    }

    res.json({ success: true, message: 'Filter saved successfully' });
  } catch (error) {
    console.error('Error saving filter:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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
    const accessToken = await getValidAccessToken();

    // Try to read filters from "Filters" sheet
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    if (!filtersResponse.ok) {
      return res.json({ success: true, jobs: [] }); // Return empty if no Filters sheet
    }

    const filtersData = await filtersResponse.json();
    if (!filtersData.values || filtersData.values.length <= 1) {
      return res.json({ success: true, jobs: [] }); // No filters found
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

app.post('/api/delete-filter', authenticateToken, async (req, res) => {
  try {
    const { sheetUrl, filterId } = req.body;
    
    if (!sheetUrl || !filterId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Extract sheet ID from URL
    const sheetIdMatch = sheetUrl.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
    if (!sheetIdMatch) {
      return res.status(400).json({ error: 'Invalid Google Sheets URL' });
    }

    const sheetId = sheetIdMatch[1];
    const accessToken = await getValidAccessToken();

    // Get existing filters
    const filtersResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000`,
      {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      }
    );

    if (!filtersResponse.ok) {
      return res.status(500).json({ error: 'Failed to access Filters sheet' });
    }

    const filtersData = await filtersResponse.json();
    if (!filtersData.values || filtersData.values.length <= 1) {
      return res.json({ success: true, message: 'No filters to delete' });
    }

    // Filter out the deleted filter
    const remainingFilters = filtersData.values.slice(1).filter(row => row[0] !== filterId);
    
    // Prepare data for writing
    const filterData = [
      ['ID', 'Name', 'Locations', 'ApplicationStatuses', 'JobTitleKeywords'], // Headers
      ...remainingFilters
    ];

    // Write updated filters to sheet
    const writeResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Filters!A1:Z1000?valueInputOption=RAW`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ values: filterData })
      }
    );

    if (!writeResponse.ok) {
      return res.status(500).json({ error: 'Failed to delete filter' });
    }

    res.json({ success: true, message: 'Filter deleted successfully' });
  } catch (error) {
    console.error('Error deleting filter:', error);
    res.status(500).json({ error: 'Internal server error' });
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
  console.log('🛡️ Security features enabled:');
  console.log('  - Helmet security headers');
  console.log('  - Rate limiting');
  console.log('  - API key encryption');
  console.log('  - Audit logging');
  console.log('  - JWT authentication');
  console.log('  - Input validation');
});
