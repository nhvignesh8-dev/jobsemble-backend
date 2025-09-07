import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import puppeteer from 'puppeteer';
import { searchJobListings } from './tavily.js';

const app = express();
const PORT = process.env.PORT || 3001;

// Environment Configuration
const SEARCH_BACKEND = process.env.SEARCH_BACKEND || 'tavily';
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;
const CLOUD_PROVIDER = process.env.CLOUD_PROVIDER || 'unknown';

console.log('🔧 Server Configuration:', {
  backend: SEARCH_BACKEND,
  tavilyConfigured: !!TAVILY_API_KEY,
  cloudProvider: CLOUD_PROVIDER,
  port: PORT
});

// CORS configuration
app.use(cors({
  origin: '*', // Allow all origins for load balancer
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// Job Board Configurations
const JOB_BOARD_CONFIGS = {
  'greenhouse': { name: 'Greenhouse', description: 'Popular ATS used by many companies' },
  'lever': { name: 'Lever', description: 'Modern recruiting platform' },
  'ashby': { name: 'Ashby', description: 'All-in-one recruiting solution' },
  'pinpoint': { name: 'Pinpoint HQ', description: 'Talent acquisition platform' },
  'paylocity': { name: 'Paylocity', description: 'HR and payroll platform with careers' },
  'keka': { name: 'Keka', description: 'HR platform with job postings' },
  'workable': { name: 'Workable', description: 'Recruiting software platform' },
  'breezyhr': { name: 'BreezyHR', description: 'Recruiting and applicant tracking' },
  'wellfound': { name: 'Wellfound', description: 'Startup job platform (formerly AngelList)' },
  'ycombinator': { name: 'Y Combinator', description: 'Work at a Startup job board' },
  'oracle': { name: 'Oracle', description: 'Enterprise software company careers' },
  'workday': { name: 'Workday', description: 'Enterprise cloud applications for HR' },
  'recruitee': { name: 'Recruitee', description: 'Collaborative hiring platform' },
  'rippling': { name: 'Rippling', description: 'Employee management platform' },
  'gusto': { name: 'Gusto', description: 'Payroll and benefits platform' },
  'smartrecruiters': { name: 'SmartRecruiters', description: 'Talent acquisition suite' },
  'jazzhr': { name: 'JazzHR', description: 'Recruiting software for SMBs' },
  'jobvite': { name: 'Jobvite', description: 'Talent acquisition platform' },
  'icims': { name: 'iCIMS', description: 'Talent cloud platform' },
  'builtin': { name: 'Built In', description: 'Tech startup job platform' },
  'adp': { name: 'ADP', description: 'Human capital management solutions' },
  'jobs-subdomain': { name: 'Jobs Subdomain', description: 'Jobs subdomain pattern (jobs.company.com)' },
  'talent-subdomain': { name: 'Talent Subdomain', description: 'Talent subdomain pattern (talent.company.com)' }
};

// Multi-Platform Job Scraping Function
async function scrapeMultipleJobBoards(jobTitle, selectedBoards, location = 'United States', retryCount = 0, timeFilter = 'qdr:d', searchEngine = 'tavily') {
  console.log(`🚀 [${CLOUD_PROVIDER}] Starting multi-platform job scraping with ${searchEngine.toUpperCase()}...`);
  console.log('📋 Selected boards:', selectedBoards);
  console.log('⏰ Time filter:', timeFilter);
  
  const allResults = [];
  const validBoards = selectedBoards.filter(board => JOB_BOARD_CONFIGS[board]);
  
  if (validBoards.length === 0) {
    throw new Error('No valid job boards selected');
  }

  try {
    // Process each job board
    for (const board of validBoards) {
      try {
        console.log(`🔍 [${CLOUD_PROVIDER}] Searching ${JOB_BOARD_CONFIGS[board].name}...`);
        
        let result;
        if (searchEngine === 'tavily') {
          result = await scrapeViaSearch(board, jobTitle, location, retryCount, timeFilter, effectiveTavilyKey);
        } else if (searchEngine === 'google') {
          result = await scrapeViaGoogleSearch(board, jobTitle, location, retryCount, timeFilter);
        } else {
          throw new Error(`Unsupported search engine: ${searchEngine}`);
        }
        
        if (result && result.length > 0) {
          allResults.push(...result);
          console.log(`✅ [${CLOUD_PROVIDER}] Found ${result.length} jobs from ${JOB_BOARD_CONFIGS[board].name}`);
        } else {
          console.log(`⚠️ [${CLOUD_PROVIDER}] No jobs found from ${JOB_BOARD_CONFIGS[board].name}`);
        }
        
      } catch (error) {
        console.error(`❌ [${CLOUD_PROVIDER}] Error searching ${board}:`, error.message);
      }
    }

    // Remove duplicates and return results
    const uniqueJobs = allResults.filter((job, index, self) => 
      index === self.findIndex(j => j.url === job.url)
    );

    console.log(`✅ [${CLOUD_PROVIDER}] Total unique jobs found: ${uniqueJobs.length}`);
    return uniqueJobs;

  } catch (error) {
    console.error(`❌ [${CLOUD_PROVIDER}] Multi-platform scraping failed:`, error.message);
    throw error;
  }
}

// Search via Tavily API
async function scrapeViaSearch(boardId, jobTitle, location = 'United States', retryCount = 0, timeFilter = 'qdr:d', tavilyApiKey = null) {
  const config = JOB_BOARD_CONFIGS[boardId];
  if (!config) {
    throw new Error(`Unknown job board: ${boardId}`);
  }

  try {
    console.log(`🔍 [${CLOUD_PROVIDER}] Using Tavily API for ${config.name}`);
    console.log(`🔑 [${CLOUD_PROVIDER}] Using API key: ${tavilyApiKey ? 'User-provided' : 'System'}`);
    
    const jobs = await searchJobListings(jobTitle, [boardId], location, timeFilter, tavilyApiKey);
    
    return jobs
      .map(result => ({
        title: cleanJobTitle(result.title),
        url: result.url,
        company: extractCompanyFromUrl(result.url) || extractCompanyFromTitle(result.title),
        location: location,
        datePosted: formatDatePosted(result.publishedDate),
        source: 'tavily',
        score: result.score
      }))
      .filter(job => job.title && job.title !== 'Unknown Position');
    
  } catch (error) {
    console.error(`❌ [${CLOUD_PROVIDER}] Tavily search failed for ${config.name}:`, error);
    
    if (error.message?.includes('API key') || error.message?.includes('401')) {
      throw new Error(`Tavily API key not configured. Please set TAVILY_API_KEY environment variable.`);
    }
    
    throw error;
  }
}

// Google Search implementation using Puppeteer  
async function scrapeViaGoogleSearch(boardId, jobTitle, location, retryCount = 0, timeFilter = 'qdr:d') {
  const config = JOB_BOARD_CONFIGS[boardId];
  if (!config) {
    throw new Error(`Unknown job board: ${boardId}`);
  }

  let browser;
  
  try {
    console.log(`🔍 [${CLOUD_PROVIDER}] Using Google Search with Puppeteer for ${config.name}`);
    
    // Launch browser with cloud-optimized settings
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ]
    });

    const page = await browser.newPage();
    
    // Set user agent and viewport
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
    await page.setViewport({ width: 1366, height: 768 });

    // Construct search query
    const searchQuery = `"${jobTitle}" site:${getBoardDomain(boardId)} ${location}`;
    let searchUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}&num=50`;
    
    // Add time filter
    if (timeFilter && timeFilter !== 'all') {
      searchUrl += `&tbs=${timeFilter}`;
    }

    console.log(`🔗 [${CLOUD_PROVIDER}] Search URL:`, searchUrl);
    
    // Navigate and extract results
    await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 30000 });
    
    // Extract job results
    const jobs = await page.evaluate(() => {
      const results = [];
      const searchResults = document.querySelectorAll('div.g');
      
      searchResults.forEach(result => {
        const titleElement = result.querySelector('h3');
        const linkElement = result.querySelector('a');
        const snippetElement = result.querySelector('.VwiC3b, .s3v9rd, .hgKElc');
        
        if (titleElement && linkElement) {
          results.push({
            title: titleElement.textContent?.trim() || '',
            url: linkElement.href || '',
            snippet: snippetElement?.textContent?.trim() || ''
          });
        }
      });
      
      return results;
    });

    await browser.close();

    return jobs
      .map(job => ({
        title: cleanJobTitle(job.title),
        url: job.url,
        company: extractCompanyFromUrl(job.url) || extractCompanyFromTitle(job.title),
        location: location,
        datePosted: 'Recent',
        source: 'google',
        score: 0.5
      }))
      .filter(job => job.title && job.title !== 'Unknown Position');

  } catch (error) {
    if (browser) {
      await browser.close();
    }
    console.error(`❌ [${CLOUD_PROVIDER}] Google search failed for ${config.name}:`, error);
    throw error;
  }
}

// Utility functions
function getBoardDomain(boardId) {
  const domainMap = {
    'greenhouse': 'greenhouse.io',
    'lever': 'lever.co',
    'ashby': 'ashbyhq.com',
    'pinpoint': 'pinpointhq.com',
    'paylocity': 'recruiting.paylocity.com',
    'keka': 'keka.com',
    'workable': 'jobs.workable.com',
    'breezyhr': 'breezy.hr',
    'wellfound': 'wellfound.com',
    'ycombinator': 'workatastartup.com',
    'oracle': 'oraclecloud.com',
    'workday': 'myworkdayjobs.com',
    'recruitee': 'recruitee.com',
    'rippling': 'rippling.com',
    'gusto': 'jobs.gusto.com',
    'smartrecruiters': 'jobs.smartrecruiters.com',
    'jazzhr': 'applytojob.com',
    'jobvite': 'jobvite.com',
    'icims': 'icims.com',
    'builtin': 'builtin.com',
    'adp': 'workforcenow.adp.com'
  };
  
  return domainMap[boardId] || `${boardId}.com`;
}

function cleanJobTitle(title) {
  if (!title) return '';
  
  return title
    .replace(/\s*-\s*.*$/, '')
    .replace(/\s*\|\s*.*$/, '')
    .replace(/\s*at\s+.*$/i, '')
    .replace(/Jobs?$/, '')
    .replace(/Career(s)?$/, '')
    .trim();
}

function extractCompanyFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    if (hostname.includes('greenhouse.io')) {
      const parts = urlObj.pathname.split('/');
      const companyIndex = parts.findIndex(part => part === 'boards');
      if (companyIndex > 0) {
        return parts[companyIndex - 1];
      }
    } else if (hostname.includes('lever.co')) {
      const subdomain = hostname.split('.')[0];
      return subdomain !== 'jobs' ? subdomain : null;
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

function extractCompanyFromTitle(title) {
  if (!title) return '';
  
  const atMatch = title.match(/\s+at\s+(.+?)(?:\s*[-|]|$)/i);
  if (atMatch) {
    return atMatch[1].trim();
  }
  
  const dashMatch = title.match(/\s*-\s*(.+?)(?:\s*[-|]|$)/);
  if (dashMatch) {
    return dashMatch[1].trim();
  }
  
  return '';
}

function formatDatePosted(dateString) {
  if (!dateString) return 'Recent';
  
  try {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return '1 day ago';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.ceil(diffDays / 7)} weeks ago`;
    
    return 'Recent';
  } catch (error) {
    return 'Recent';
  }
}

// API Routes
app.post('/api/scrape-jobs', async (req, res) => {
  try {
    console.log(`📨 [${CLOUD_PROVIDER}] Raw request body:`, JSON.stringify(req.body, null, 2));
    const { 
      jobTitle, 
      jobBoards = ['greenhouse'], 
      location = 'United States', 
      timeFilter = 'qdr:d', 
      searchEngine = 'tavily',
      userApiKey = null,  // User's specific API key
      isUserKey = false   // Whether using user's key or system key
    } = req.body;
    
    if (!jobTitle) {
      return res.status(400).json({ 
        success: false, 
        error: 'Job title is required',
        cloudProvider: CLOUD_PROVIDER
      });
    }
    
    // Determine which Tavily API key to use
    let effectiveTavilyKey = null;
    
    if (searchEngine === 'tavily') {
      if (isUserKey && userApiKey) {
        // Use user's API key
        effectiveTavilyKey = userApiKey;
        console.log(`🔑 [${CLOUD_PROVIDER}] Using user-provided Tavily API key`);
      } else if (!isUserKey && TAVILY_API_KEY) {
        // Use system key only for free searches
        effectiveTavilyKey = TAVILY_API_KEY;
        console.log(`🔑 [${CLOUD_PROVIDER}] Using system Tavily API key (free search)`);
      } else {
        // User has no key and no free searches left
        return res.status(403).json({
          success: false,
          error: 'Usage exceeded. Please provide your Tavily API key to continue using this feature.',
          code: 'API_KEY_REQUIRED',
          cloudProvider: CLOUD_PROVIDER
        });
      }
    }
    
    console.log(`📥 [${CLOUD_PROVIDER}] Received multi-platform search request:`, jobTitle);
    console.log(`🎯 [${CLOUD_PROVIDER}] Selected job boards:`, jobBoards);
    console.log(`📍 [${CLOUD_PROVIDER}] Location:`, location);
    console.log(`⏰ [${CLOUD_PROVIDER}] Time filter received:`, timeFilter);
    console.log(`🔍 [${CLOUD_PROVIDER}] Search engine selected:`, searchEngine);
    
    // Perform multi-platform scraping
    const jobResults = await scrapeMultipleJobBoards(
      jobTitle, 
      jobBoards, 
      location, 
      0, 
      timeFilter, 
      searchEngine
    );
    
    console.log(`✅ [${CLOUD_PROVIDER}] Search completed successfully. Found ${jobResults.length} jobs`);
    
    return res.json({
      success: true,
      jobs: jobResults,
      totalJobs: jobResults.length,
      searchBackend: searchEngine,
      cloudProvider: CLOUD_PROVIDER,
      searchParams: {
        jobTitle,
        location,
        jobBoards,
        timeFilter,
        searchEngine
      }
    });

  } catch (error) {
    console.error(`❌ [${CLOUD_PROVIDER}] Search failed:`, error);
    
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error during job search',
      cloudProvider: CLOUD_PROVIDER,
      searchBackend: req.body.searchEngine || 'unknown'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    cloudProvider: CLOUD_PROVIDER,
    searchBackend: SEARCH_BACKEND,
    tavilyConfigured: !!TAVILY_API_KEY,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Test endpoint for Tavily API
app.get('/api/test-tavily', async (req, res) => {
  try {
    if (!TAVILY_API_KEY) {
      return res.status(500).json({
        success: false,
        error: 'Tavily API key not configured',
        cloudProvider: CLOUD_PROVIDER
      });
    }

    // Test with a simple search
    console.log(`🧪 [${CLOUD_PROVIDER}] Testing Tavily API...`);
    const testResults = await searchJobListings('Software Engineer', ['greenhouse'], 'San Francisco', 'qdr:d');
    
    return res.json({
      success: true,
      message: 'Tavily API working',
      cloudProvider: CLOUD_PROVIDER,
      testResults: testResults.slice(0, 3), // Return first 3 for testing
      totalResults: testResults.length
    });
    
  } catch (error) {
    console.error(`❌ [${CLOUD_PROVIDER}] Tavily test failed:`, error);
    return res.status(500).json({
      success: false,
      error: error.message,
      cloudProvider: CLOUD_PROVIDER
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 [${CLOUD_PROVIDER}] Job Scraping Server running on port ${PORT}`);
  console.log(`📋 [${CLOUD_PROVIDER}] Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔍 [${CLOUD_PROVIDER}] Scrape jobs: POST http://localhost:${PORT}/api/scrape-jobs`);
  console.log(`🧪 [${CLOUD_PROVIDER}] Test Tavily: GET http://localhost:${PORT}/api/test-tavily`);
  
  if (SEARCH_BACKEND === 'tavily') {
    if (TAVILY_API_KEY) {
      console.log(`✅ [${CLOUD_PROVIDER}] Tavily API configured and ready`);
    } else {
      console.log(`⚠️ [${CLOUD_PROVIDER}] WARNING: TAVILY_API_KEY not set! Please configure your API key.`);
      console.log('📝 Get your API key from: https://app.tavily.com');
    }
  }
});

