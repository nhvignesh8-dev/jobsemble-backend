const serverless = require('serverless-http');
const express = require('express');
const cors = require('cors');

// Import our existing server logic
const app = express();

// Enable CORS for all origins
app.use(cors({
  origin: [
    'https://jobsemble.tech',
    'https://job-scout-automaton.lovable.app',
    'http://localhost:8080',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Import the route handlers from server.js
// We'll need to refactor server.js to export the routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    cloudProvider: 'AWS-LAMBDA',
    searchBackend: 'tavily',
    tavilyConfigured: !!process.env.TAVILY_API_KEY,
    timestamp: new Date().toISOString()
  });
});

// For now, let's create a simple test endpoint
app.post('/api/scrape-jobs', async (req, res) => {
  try {
    // Import and use the scraping logic from server.js
    const result = {
      success: true,
      jobs: [],
      totalJobs: 0,
      searchBackend: 'google',
      cloudProvider: 'AWS-LAMBDA',
      searchParams: req.body,
      message: 'Lambda deployment in progress - Chrome setup needed'
    };
    
    res.json(result);
  } catch (error) {
    console.error('Lambda scraping error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      cloudProvider: 'AWS-LAMBDA'
    });
  }
});

// Export the serverless handler
module.exports.handler = serverless(app);
