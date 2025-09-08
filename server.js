import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import puppeteer from 'puppeteer';
import { searchJobListings } from './src/tavily.js';

// Check Chrome installation (using pre-built Docker image)
async function ensureChromeInstalled() {
  try {
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome-stable';
    console.log('🔍 Chrome path:', executablePath);
    console.log('✅ Using pre-installed Chrome from Docker image');
  } catch (error) {
    console.log('⚠️ Chrome check failed:', error.message);
  }
}

const app = express();
const PORT = process.env.PORT || 3001;

// Environment Configuration
const SEARCH_BACKEND = process.env.SEARCH_BACKEND || 'tavily';
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;

console.log('🔧 Search Configuration:', {
  backend: SEARCH_BACKEND,
  tavilyConfigured: !!TAVILY_API_KEY
});

// CORS configuration - Enhanced for production
app.use(cors({
  origin: [
    'http://localhost:8080',
    'http://localhost:5173',
    'http://localhost:3000',
    'https://job-scout-automaton.vercel.app',
    'https://jobsemble.tech',
    'https://job-scout-automaton.lovable.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200 // For legacy browser support
}));
app.use(express.json());

// Multi-Platform Job Board Configuration
const JOB_BOARD_CONFIGS = {
  greenhouse: { name: 'Greenhouse', description: 'Greenhouse.io job board' },
  lever: { name: 'Lever', description: 'Lever job board' },
  ashby: { name: 'Ashby', description: 'Ashby job board' },
  pinpoint: { name: 'Pinpoint', description: 'Pinpoint job board' },
  paylocity: { name: 'Paylocity', description: 'Paylocity job board' },
  keka: { name: 'Keka', description: 'Keka job board' },
  workable: { name: 'Workable', description: 'Workable job board' },
  breezyhr: { name: 'BreezyHR', description: 'BreezyHR job board' },
  wellfound: { name: 'Wellfound', description: 'Wellfound job board (formerly AngelList)' },
  ycombinator: { name: 'Y Combinator Work at a Startup', description: 'Y Combinator job board' },
  oracle: { name: 'Oracle Cloud', description: 'Oracle Cloud job board' },
  workday: { name: 'Workday Jobs', description: 'Workday job board' },
  recruitee: { name: 'Recruitee', description: 'Recruitee job board' },
  rippling: { name: 'Rippling', description: 'Rippling job board' },
  gusto: { name: 'Gusto', description: 'Gusto job board' },
  smartrecruiters: { name: 'SmartRecruiters', description: 'SmartRecruiters job board' },
  jazzhr: { name: 'JazzHR', description: 'JazzHR job board' },
  jobvite: { name: 'Jobvite', description: 'Jobvite job board' },
  icims: { name: 'iCIMS', description: 'iCIMS job board' },
  builtin: { name: 'Builtin', description: 'Builtin job board' },
  adp: { name: 'ADP', description: 'ADP job board' },
  'jobs-subdomain': { name: 'Jobs Subdomain', description: 'Jobs subdomain pattern (jobs.company.com)' },
  'talent-subdomain': { name: 'Talent Subdomain', description: 'Talent subdomain pattern (talent.company.com)' }
};

// Multi-Platform Job Scraping Function using Tavily
async function scrapeMultipleJobBoards(jobTitle, selectedBoards, location = 'United States', retryCount = 0, timeFilter = 'qdr:d', searchEngine = 'tavily', apiKey = null) {
  console.log(`🚀 Starting multi-platform job scraping with ${searchEngine.toUpperCase()}...`);
  console.log('📋 Selected boards:', selectedBoards);
  console.log('⏰ Time filter:', timeFilter);
  
  const allResults = [];
  
  try {
    // Filter valid job boards
    const validBoards = selectedBoards.filter(board => 
      Object.keys(JOB_BOARD_CONFIGS).includes(board)
    );
    
    if (validBoards.length > 0) {
      console.log(`🔍 Scraping via ${searchEngine.toUpperCase()} Search API:`, validBoards);
      
      // Process each board sequentially to avoid overwhelming the API
      for (const board of validBoards) {
        try {
          console.log(`🔍 Searching ${JOB_BOARD_CONFIGS[board].name}...`);
          
        let result;
        if (searchEngine === 'tavily') {
          result = await scrapeViaSearch(board, jobTitle, location, retryCount, timeFilter, apiKey);
        } else if (searchEngine === 'google') {
          result = await scrapeViaGoogleSearch(board, jobTitle, location, retryCount, timeFilter);
  } else {
            throw new Error(`Unsupported search engine: ${searchEngine}`);
          }
          
          allResults.push(...result);
          
          console.log(`✅ Found ${result.length} jobs from ${JOB_BOARD_CONFIGS[board].name}`);
          
        } catch (err) {
          console.log(`⚠️ Failed to scrape ${board}:`, err.message);
        }
        
        // Small delay between boards to be respectful to the API
        if (validBoards.length > 1) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    }
    
    // Aggregate and deduplicate results
    const uniqueJobs = aggregateAndDeduplicateResults(allResults);
    console.log(`✅ Multi-platform scraping completed. Total unique jobs: ${uniqueJobs.length}`);
    
    return uniqueJobs;
    
  } catch (error) {
    console.error('💥 Multi-platform scraping error:', error);
    throw error;
  }
}

// Search via Tavily API
async function scrapeViaSearch(boardId, jobTitle, location = 'United States', retryCount = 0, timeFilter = 'qdr:d', tavilyApiKey = null) {
  const config = JOB_BOARD_CONFIGS[boardId];
  if (!config) {
    throw new Error(`Unknown job board: ${boardId}`);
  }
  
  console.log(`🔍 Searching ${config.name} via Tavily API...`);
  console.log(`⏰ Time filter: ${timeFilter}`);
  console.log(`🔑 Using API key: ${tavilyApiKey ? 'User-provided' : 'System'}`);
  
  try {
    // Use our Tavily service to search for jobs with dynamic API key
    const searchResults = await searchJobListings(jobTitle, location, [boardId], timeFilter, tavilyApiKey);
    
    if (searchResults.length === 0) {
      console.log(`❌ No jobs found for ${config.name}`);
      return [];
    }
    
    // Transform Tavily results to our job format and filter out invalid titles
    const jobs = searchResults
      .map(result => ({
        title: cleanJobTitle(result.title),
        url: result.url,
        company: extractCompanyFromUrl(result.url) || extractCompanyFromTitle(result.title),
        location: location,
        datePosted: formatDatePosted(result.publishedDate),
        source: 'tavily',
        score: result.score
      }))
      .filter(job => job.title && job.title !== 'Unknown Position'); // Filter out jobs with null/invalid titles
    
    console.log(`✅ Successfully processed ${jobs.length} jobs from ${config.name}`);
    return jobs;

  } catch (error) {
    console.error(`❌ Tavily search failed for ${config.name}:`, error);
    
    // If it's an API key error, provide helpful message
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

  try {
    console.log(`🔍 Searching ${config.name} via Google Search...`);
    console.log('⏰ Time filter:', timeFilter);
    
    // Construct Google search query for the specific job board
    let query;
    if (boardId === 'greenhouse') {
      query = `"${jobTitle}" site:greenhouse.io "${location}"`;
    } else if (boardId === 'lever') {
      query = `"${jobTitle}" site:lever.co "${location}"`;
    } else if (boardId === 'ashby') {
      query = `"${jobTitle}" site:ashbyhq.com "${location}"`;
    } else if (boardId === 'pinpoint') {
      query = `"${jobTitle}" site:pinpointhq.com "${location}"`;
    } else if (boardId === 'paylocity') {
      query = `"${jobTitle}" site:recruiting.paylocity.com "${location}"`;
    } else if (boardId === 'keka') {
      query = `"${jobTitle}" site:keka.com "${location}"`;
    } else if (boardId === 'workable') {
      query = `"${jobTitle}" site:jobs.workable.com "${location}"`;
    } else if (boardId === 'breezyhr') {
      query = `"${jobTitle}" site:breezy.hr "${location}"`;
    } else if (boardId === 'wellfound') {
      query = `"${jobTitle}" site:wellfound.com "${location}"`;
    } else if (boardId === 'ycombinator') {
      query = `"${jobTitle}" site:workatastartup.com "${location}"`;
    } else if (boardId === 'oracle') {
      query = `"${jobTitle}" site:oraclecloud.com "${location}"`;
    } else if (boardId === 'workday') {
      query = `"${jobTitle}" site:myworkdayjobs.com "${location}"`;
    } else if (boardId === 'recruitee') {
      query = `"${jobTitle}" site:recruitee.com "${location}"`;
    } else if (boardId === 'rippling') {
      query = `"${jobTitle}" (site:rippling.com OR site:rippling-ats.com) "${location}"`;
    } else if (boardId === 'gusto') {
      query = `"${jobTitle}" site:jobs.gusto.com "${location}"`;
    } else if (boardId === 'smartrecruiters') {
      query = `"${jobTitle}" site:jobs.smartrecruiters.com "${location}"`;
    } else if (boardId === 'jazzhr') {
      query = `"${jobTitle}" site:applytojob.com "${location}"`;
    } else if (boardId === 'jobvite') {
      query = `"${jobTitle}" site:jobvite.com "${location}"`;
    } else if (boardId === 'icims') {
      query = `"${jobTitle}" site:icims.com "${location}"`;
    } else if (boardId === 'builtin') {
      query = `"${jobTitle}" site:builtin.com/job/ "${location}"`;
    } else if (boardId === 'adp') {
      query = `"${jobTitle}" (site:workforcenow.adp.com OR site:myjobs.adp.com) "${location}"`;
    } else if (boardId === 'jobs-subdomain') {
      query = `"${jobTitle}" site:jobs.* "${location}"`;
    } else if (boardId === 'talent-subdomain') {
      query = `"${jobTitle}" site:talent.* "${location}"`;
    } else {
      query = `"${jobTitle}" "${location}" jobs site:${boardId}.com`;
    }

    console.log(`🔍 Google search query: ${query}`);

    // Generate random user agent
    const userAgents = [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0'
    ];
    const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];

    // Launch browser with maximum stealth and cloud compatibility
    let browser = await puppeteer.launch({
      headless: "new", // Use new headless mode
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome-stable',
      ignoreDefaultArgs: ['--disable-extensions'],
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--single-process', // This might help with missing libraries
        '--disable-blink-features=AutomationControlled',
        '--disable-extensions',
        '--no-first-run',
        '--disable-default-apps',
        '--disable-sync',
        '--disable-translate',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-ipc-flooding-protection',
        '--window-size=1366,768'
      ]
    });

    let page = await browser.newPage();

    // Advanced stealth configuration
    await page.setUserAgent(randomUserAgent);
    
    // Set viewport to common resolution
    await page.setViewport({ width: 1366, height: 768 });
    
    // Remove webdriver property
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
      });
    });
    
    // Override the plugins property to use a real value
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5],
      });
    });
    
    // Override the languages property to use a real value
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
      });
    });
    
    // Override permissions and hide automation traces
    await page.evaluateOnNewDocument(() => {
      const originalQuery = window.navigator.permissions.query;
      window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
          Promise.resolve({ state: 'granted' }) :
          originalQuery(parameters)
      );
      
      // Hide chrome automation
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
      });
      
      // Override chrome detection
      if (window.chrome) {
        Object.defineProperty(window.chrome, 'runtime', {
          get: () => ({
            onConnect: undefined,
            onMessage: undefined,
          }),
        });
      }
      
      // Mock screen properties to avoid fingerprinting
      Object.defineProperty(screen, 'colorDepth', {
        get: () => 24,
      });
      
      Object.defineProperty(screen, 'pixelDepth', {
        get: () => 24,
      });
      
      // Override console to hide automation logs
      const originalConsole = window.console;
      window.console = {
        ...originalConsole,
        debug: () => {},
        log: () => {},
        warn: () => {},
      };
    });
    
    // Advanced request interception for stealth
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const headers = {
        ...request.headers(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"macOS"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Dnt': '1' // Do not track
      };
      
      // Remove automation-specific headers
      delete headers['sec-ch-ua-full-version'];
      delete headers['sec-ch-ua-full-version-list'];
      
      request.continue({ headers });
    });

    try {
      // Build Google search URL with pagination and time filter
      let searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}&num=50`; // Show 50 results per page
      
      // Add time filter to URL if specified
      if (timeFilter && timeFilter !== 'all') {
        if (timeFilter === 'qdr:h') {
          searchUrl += '&tbs=qdr:h'; // Past hour
        } else if (timeFilter === 'qdr:d') {
          searchUrl += '&tbs=qdr:d'; // Past 24 hours
        } else if (timeFilter === 'qdr:w') {
          searchUrl += '&tbs=qdr:w'; // Past week
        } else if (timeFilter === 'qdr:m') {
          searchUrl += '&tbs=qdr:m'; // Past month
        }
      }

      // Pagination support - collect results from multiple pages
      const allSearchResults = [];
      const maxPages = 3; // Limit to 3 pages (150 results total)
      
      console.log(`🔍 Starting paginated search for up to ${maxPages} pages (${maxPages * 50} results)...`);

      // Human-like behavior: First visit google.com like a real user
      console.log('🤖 Acting like human: visiting google.com first...');
      await page.goto('https://www.google.com', { waitUntil: 'networkidle2' });
      
      // Random delay like a human reading the page
      const initialDelay = Math.random() * 2000 + 1000; // 1-3 seconds
      console.log(`⏱️ Human-like delay: ${Math.round(initialDelay)}ms`);
      await new Promise(resolve => setTimeout(resolve, initialDelay));
      
      // Simulate human mouse movement
      await page.mouse.move(Math.random() * 1366, Math.random() * 768);
      await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 200));

      // Loop through pages
      for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
        console.log(`📄 Processing page ${pageNum}/${maxPages}...`);
        
        // Build URL for current page
        let currentPageUrl = searchUrl;
        if (pageNum > 1) {
          const startIndex = (pageNum - 1) * 50; // Google uses 'start' parameter for pagination
          currentPageUrl += `&start=${startIndex}`;
        }
        
        console.log(`🌐 Navigating to page ${pageNum}: ${currentPageUrl}`);
        
        // Navigate to search URL
        await page.goto(currentPageUrl, { 
          waitUntil: 'networkidle2',
          timeout: 30000 
        });
        
        // Human-like delay after page load
        const afterLoadDelay = Math.random() * 1500 + 500; // 0.5-2 seconds
        await new Promise(resolve => setTimeout(resolve, afterLoadDelay));

        // Check if we got blocked by CAPTCHA or other Google blocks (only on first page)
        if (pageNum === 1) {
          const pageTitle = await page.title();
          const pageContent = await page.content();
          
          console.log(`📄 Page title: ${pageTitle}`);
          
          if (pageTitle.includes('CAPTCHA') || pageContent.includes('CAPTCHA') || 
              pageContent.includes('unusual traffic') || pageContent.includes('robots')) {
            console.log('🚫 Google blocked request with CAPTCHA or bot detection');
            console.log('🖥️ Opening browser window for CAPTCHA solving...');
        
        // Open a visible browser window for the user to solve CAPTCHA
        await browser.close(); // Close headless browser
        
        const visibleBrowser = await puppeteer.launch({
          headless: false, // Make browser visible
          defaultViewport: null,
          args: [
            '--start-maximized',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-web-security',
            '--disable-blink-features=AutomationControlled',
            '--disable-extensions',
            '--no-first-run',
            '--disable-default-apps'
          ]
        });
        
        const visiblePage = await visibleBrowser.newPage();
        
        // Apply same stealth techniques to visible browser
        await visiblePage.setUserAgent(randomUserAgent);
        
        // Remove webdriver property for visible browser too
        await visiblePage.evaluateOnNewDocument(() => {
          Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
          });
        });
        
        await visiblePage.setExtraHTTPHeaders({
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
          'Accept-Encoding': 'gzip, deflate, br',
          'Accept-Language': 'en-US,en;q=0.9',
          'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
          'Sec-Ch-Ua-Mobile': '?0',
          'Sec-Ch-Ua-Platform': '"macOS"',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          'Upgrade-Insecure-Requests': '1'
        });
        
        console.log('🌐 Navigating to CAPTCHA page in visible browser...');
        await visiblePage.goto(searchUrl, { waitUntil: 'networkidle2' });
        
        console.log('⏳ Waiting for CAPTCHA to be solved...');
        console.log('👆 Please solve the CAPTCHA in the browser window that opened');
        
        // Wait for CAPTCHA to be solved - check for successful navigation
        let captchaSolved = false;
        let attempts = 0;
        const maxAttempts = 60; // Wait up to 5 minutes (60 * 5 seconds)
        
        while (!captchaSolved && attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
          attempts++;
          
          try {
            const currentTitle = await visiblePage.title();
            const currentContent = await visiblePage.content();
            
            // Check if we're no longer on CAPTCHA page
            if (!currentTitle.includes('CAPTCHA') && 
                !currentContent.includes('CAPTCHA') && 
                !currentContent.includes('unusual traffic') && 
                !currentContent.includes('robots')) {
              captchaSolved = true;
              console.log('✅ CAPTCHA appears to be solved! Continuing with scraping...');
            } else {
              console.log(`⏳ Still waiting for CAPTCHA (attempt ${attempts}/${maxAttempts})...`);
            }
          } catch (error) {
            console.log(`⚠️ Error checking CAPTCHA status: ${error.message}`);
          }
        }
        
        if (!captchaSolved) {
          await visibleBrowser.close();
          throw new Error('CAPTCHA solving timeout. Please try again.');
        }
        
        // Replace the original page with the visible page that has solved CAPTCHA
        // Note: original browser was already closed above, now use the visible browser
        browser = visibleBrowser;
        page = visiblePage;
        
            console.log('🎯 CAPTCHA solved successfully, continuing with job search...');
          }
        }

        // Human-like behavior: scroll and look around the page
        console.log('🤖 Acting like human: scrolling page...');
        await page.evaluate(() => {
          // Simulate reading behavior with natural scrolling
          window.scrollTo(0, Math.random() * 300);
        });
        
        // Human reading time
        const readingDelay = Math.random() * 2000 + 1000; // 1-3 seconds
        await new Promise(resolve => setTimeout(resolve, readingDelay));
        
        // Scroll back to top like looking for results
        await page.evaluate(() => window.scrollTo(0, 0));
        await new Promise(resolve => setTimeout(resolve, 500));

        // Debug: Take a screenshot and log page info after potential CAPTCHA solving
        try {
          const currentUrl = page.url();
          const currentTitle = await page.title();
          console.log(`🔍 Debug - Current URL: ${currentUrl}`);
          console.log(`🔍 Debug - Current Title: ${currentTitle}`);
          
          // Take a screenshot for debugging
          await page.screenshot({ path: 'debug-screenshot.png', fullPage: false });
          console.log(`📸 Debug screenshot saved as debug-screenshot.png`);
          
          // Log page content length
          const pageContent = await page.content();
          console.log(`📄 Debug - Page content length: ${pageContent.length} characters`);
          
          // Check if we're still on a blocked page
          if (currentTitle.includes('CAPTCHA') || pageContent.includes('CAPTCHA') || 
              pageContent.includes('unusual traffic') || pageContent.includes('robots')) {
            console.log('⚠️ Still on blocked page after CAPTCHA attempt');
          } else {
            console.log('✅ Page appears to be unblocked, proceeding with extraction');
          }
        } catch (debugError) {
          console.log(`⚠️ Debug logging failed: ${debugError.message}`);
        }

        // Extract search results using multiple selector strategies
        const pageResults = await page.evaluate(() => {
        const results = [];
        
        // Debug: Log what we find on the page
        console.log('🔍 Starting search results extraction...');
        
        // Get the domain for the specific job board based on search query
        let boardDomain = '';
        if (window.location.href.includes('greenhouse.io')) boardDomain = 'greenhouse.io';
        else if (window.location.href.includes('lever.co')) boardDomain = 'lever.co';
        else if (window.location.href.includes('ashbyhq.com')) boardDomain = 'ashbyhq.com';
        else if (window.location.href.includes('site:')) {
          const siteMatch = window.location.href.match(/site%3A([^&%]+)/);
          if (siteMatch) boardDomain = siteMatch[1];
        }
        console.log('🎯 Targeting domain:', boardDomain);
        
        // Multiple Google search result selectors to try (more specific to avoid navigation links)
        const selectorStrategies = [
          // Target specific job board domain first (if we found one)
          boardDomain ? '.g .yuRUbf a[href*="' + boardDomain + '"]' : null,
          boardDomain ? '.g a[href*="' + boardDomain + '"]' : null,
          boardDomain ? '#search .g a[href*="' + boardDomain + '"]' : null,
          // Target actual search results containers and exclude navigation
          '#search .g .yuRUbf a[href^="http"]',
          '#rso .g .yuRUbf a[href^="http"]',
          '.srg .g .yuRUbf a[href^="http"]',
          // Fallback but filter by content
          '.g a[href*="jobs"][href^="http"]',
          '.g a[href*="career"][href^="http"]'
        ].filter(Boolean);
        
        let foundResults = false;
        
        for (let i = 0; i < selectorStrategies.length; i++) {
          const selector = selectorStrategies[i];
          if (foundResults) break;
          
          console.log(`🔍 Trying selector ${i + 1}/${selectorStrategies.length}: ${selector}`);
          
          try {
            const linkElements = document.querySelectorAll(selector);
            console.log(`🔍 Found ${linkElements.length} elements with selector: ${selector}`);
            
            for (const linkElement of linkElements) {
              if (!linkElement.href || !linkElement.href.startsWith('http')) continue;
              
              // Skip Google's internal navigation links
              if (linkElement.href.includes('google.com/search') || 
                  linkElement.href.includes('accounts.google.com') ||
                  linkElement.href.includes('support.google.com') ||
                  linkElement.href.includes('policies.google.com')) {
                continue;
              }
              
              // Find the title (h3 element)
              let titleElement = linkElement.querySelector('h3');
              if (!titleElement) {
                titleElement = linkElement.closest('.g')?.querySelector('h3');
              }
              if (!titleElement) {
                titleElement = linkElement.parentElement?.querySelector('h3');
              }
              
              if (titleElement && titleElement.textContent.trim()) {
                const title = titleElement.textContent.trim();
                
                // Skip Google navigation elements
                const navigationTexts = ['Sign in', 'AI Mode', 'Images', 'Videos', 'Shopping', 'Forums', 
                                        'Any time', 'Past hour', 'Past 24 hours', 'Past week', 'Past month', 
                                        'Past year', 'All results', 'Verbatim', 'Send feedback', 'Previous',
                                        'Next', 'Reset search tools', 'Short videos'];
                                        
                if (navigationTexts.includes(title) || title.includes('From your IP address')) {
                  console.log(`🔍 Skipping navigation element: "${title}"`);
                  continue;
                }
                
                results.push({
                  title: title,
                  url: linkElement.href,
                  snippet: ''
                });
                foundResults = true;
                console.log(`✅ Found result: ${title}`);
              }
            }
          } catch (e) {
            console.log(`⚠️ Selector failed: ${selector} - ${e.message}`);
            continue;
          }
        }
        
        console.log(`🔍 Total results found: ${results.length}`);
        
        // If no results found with standard selectors, try extracting any links
        if (results.length === 0) {
          const allLinks = document.querySelectorAll('a[href]');
          for (const link of allLinks) {
            if (link.href && link.href.startsWith('http') && 
                (link.href.includes('greenhouse.io') || 
                 link.href.includes('lever.co') || 
                 link.href.includes('ashbyhq.com'))) {
              const text = link.textContent.trim();
              if (text && text.length > 5) {
                results.push({
                  title: text,
                  url: link.href,
                  snippet: ''
                });
              }
            }
          }
        }
        
        return results;
        });

        console.log(`📄 Page ${pageNum}: Found ${pageResults.length} results`);
        
        // Add page results to overall collection
        allSearchResults.push(...pageResults);
        
        // Check if we should continue to next page
        if (pageResults.length === 0) {
          console.log(`📄 No more results found on page ${pageNum}, stopping pagination`);
          break;
        }
        
        // Human-like delay between pages
        if (pageNum < maxPages) {
          const betweenPagesDelay = Math.random() * 2000 + 1000; // 1-3 seconds
          console.log(`⏳ Waiting ${Math.round(betweenPagesDelay)}ms before next page...`);
          await new Promise(resolve => setTimeout(resolve, betweenPagesDelay));
        }
      }

      await browser.close();

      console.log(`✅ Google found ${allSearchResults.length} total results from ${maxPages} pages for ${boardId}`);

      // Process the search results
      const jobs = allSearchResults
        .filter(result => {
          // Filter to only include job board URLs
          const url = result.url.toLowerCase();
          
          // Exclude sign-in, login, and non-job pages
          if (url.includes('/users/sign_in') || 
              url.includes('/sign_in') || 
              url.includes('/login') ||
              url.includes('/embed/job_app') ||
              url.includes('my.greenhouse.io') ||
              url.includes('app.greenhouse.io')) {
            return false;
          }
          
          return (
            url.includes('greenhouse.io') ||
            url.includes('lever.co') ||
            url.includes('ashbyhq.com') ||
            url.includes('pinpointhq.com') ||
            url.includes('recruiting.paylocity.com') ||
            url.includes('keka.com') ||
            url.includes('jobs.workable.com') ||
            url.includes('breezy.hr') ||
            url.includes('wellfound.com') ||
            url.includes('workatastartup.com') ||
            url.includes('oraclecloud.com') ||
            url.includes('myworkdayjobs.com') ||
            url.includes('recruitee.com') ||
            url.includes('rippling.com') ||
            url.includes('rippling-ats.com') ||
            url.includes('jobs.gusto.com') ||
            url.includes('jobs.smartrecruiters.com') ||
            url.includes('applytojob.com') ||
            url.includes('jobvite.com') ||
            url.includes('icims.com') ||
            url.includes('builtin.com') ||
            url.includes('workforcenow.adp.com') ||
            url.includes('myjobs.adp.com') ||
            url.includes(boardId.toLowerCase())
          );
        })
        .filter(result => {
          // Filter by job title relevance
          return isJobTitleRelevant(result.title, jobTitle);
        })
        .map(result => ({
          title: cleanJobTitle(result.title),
          url: result.url,
          company: extractCompanyFromUrl(result.url) || extractCompanyFromTitle(result.title),
          location: location,
          datePosted: 'Recent', // Google search doesn't provide publication dates
          source: 'google',
          score: 0 // Google search doesn't provide relevance scores
        }))
        .filter(job => job.title && job.title !== 'Unknown Position'); // Filter out jobs with null/invalid titles
      
      console.log(`✅ Successfully processed ${jobs.length} jobs from ${config.name}`);
      return jobs;
      
    } catch (error) {
      await browser.close();
      throw error;
    }
    
  } catch (error) {
    console.error(`❌ Google search failed for ${config.name}:`, error);
    throw error;
  }
}

// Helper function to check job title relevance (duplicated from Tavily service)
function isJobTitleRelevant(resultTitle, searchJobTitle) {
  if (!resultTitle || !searchJobTitle) return false;
  
  // Clean both titles for comparison
  const cleanResult = resultTitle.toLowerCase().trim();
  const cleanSearch = searchJobTitle.toLowerCase().trim();
  
  // Extract key words from search title (remove common words)
  const commonWords = ['the', 'and', 'or', 'of', 'in', 'at', 'to', 'for', 'with', 'by', 'a', 'an'];
  const searchWords = cleanSearch.split(/\s+/).filter(word => 
    word.length > 2 && !commonWords.includes(word)
  );
  
  // Check if at least 60% of search words appear in the result title
  const matchingWords = searchWords.filter(word => 
    cleanResult.includes(word)
  );
  
  const relevanceScore = matchingWords.length / searchWords.length;
  
  // Require at least 30% word match for relevance (temporarily relaxed for debugging)
  console.log(`🔍 Title relevance: "${resultTitle}" vs "${searchJobTitle}" = ${relevanceScore} (${matchingWords.length}/${searchWords.length})`);
  return relevanceScore >= 0.3;
}

// Result Aggregation and Deduplication
function aggregateAndDeduplicateResults(allResults) {
  console.log('🔄 Aggregating and deduplicating results...');
  
  const seen = new Set();
  const uniqueJobs = [];
  
  for (const job of allResults) {
    // Create unique key based on URL and title
    const key = `${job.url}-${job.title}`.toLowerCase();
    
    if (!seen.has(key)) {
      seen.add(key);
      uniqueJobs.push(job);
    }
  }
  
  // Sort by score if available, otherwise by title
  uniqueJobs.sort((a, b) => {
    if (a.score && b.score) {
      return b.score - a.score; // Higher score first
    }
    return a.title.localeCompare(b.title);
  });
  
  console.log(`📊 Deduplicated ${allResults.length} results to ${uniqueJobs.length} unique jobs`);
  return uniqueJobs;
}

// Helper Functions
function cleanJobTitle(title) {
  if (!title) return 'Unknown Position';
  
  // Filter out generic/junk titles (exact matches only, not partial)
  const genericTitles = [
    'open positions',
    'current openings', 
    'apply now',
    'view all jobs',
    'see all positions',
    'job opportunities',
    'careers'
  ];
  
  // Exact matches for job board names (not partial matches)
  const exactGenericTitles = [
    'greenhouse',
    'lever', 
    'ashby',
    'workable'
  ];
  
  const cleanedTitle = title
    .replace(/^(Greenhouse Job Application for|DevRev Job Application for|Job Application for|Job:|Position:|Career:|Opportunity:)\s*/i, '')
    .replace(/\s*-\s*(Apply Now|Job Details|View Job|Greenhouse).*$/i, '')
    .replace(/\s*\|\s*.*$/, '')
    .replace(/\s*at\s+.+$/, '')
    .replace(/,\s*(New Graduate|Entry Level|Senior|Junior).*$/i, '')
    .replace(/\s*\([^)]*\)\s*$/g, '') // Remove location text in parentheses at the end
    // Clean up URLs and site names that get concatenated
    .replace(/greenhouse\.io.*$/i, '')
    .replace(/lever\.co.*$/i, '')
    .replace(/ashby\.com.*$/i, '')
    .replace(/workable\.com.*$/i, '')
    .replace(/https?:\/\/.*$/i, '')
    .replace(/boards\..*$/i, '')
    .replace(/jobs\..*$/i, '')
    .replace(/\s*›\s*.*$/i, '')
    .replace(/\s*-\s*.*\.(io|com|co).*$/i, '')
    .trim();

  // Return null for generic titles (will be filtered out later)
  if (genericTitles.some(generic => cleanedTitle.toLowerCase().includes(generic))) {
    console.log(`🔍 Filtered out generic title: "${title}" -> "${cleanedTitle}" (contains: ${genericTitles.find(g => cleanedTitle.toLowerCase().includes(g))})`);
    return null;
  }
  
  // Return null for exact matches of job board names only
  if (exactGenericTitles.some(exact => cleanedTitle.toLowerCase() === exact)) {
    console.log(`🔍 Filtered out exact generic title: "${title}" -> "${cleanedTitle}" (exact match: ${exactGenericTitles.find(g => cleanedTitle.toLowerCase() === g)})`);
    return null;
  }
  
  // Filter out very short titles (likely junk)
  if (cleanedTitle.length <= 2) {
    console.log(`🔍 Filtered out short title: "${title}" -> "${cleanedTitle}" (length: ${cleanedTitle.length})`);
    return null;
  }
  
  console.log(`✅ Clean title: "${title}" -> "${cleanedTitle}"`);
  return cleanedTitle;
}

function formatDatePosted(publishedDate) {
  if (!publishedDate) return 'Recent';
  
  try {
    const date = new Date(publishedDate);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
      return '1 day ago';
    } else if (diffDays < 7) {
      return `${diffDays} days ago`;
    } else if (diffDays < 30) {
      const weeks = Math.floor(diffDays / 7);
      return weeks === 1 ? '1 week ago' : `${weeks} weeks ago`;
      } else {
      const months = Math.floor(diffDays / 30);
      return months === 1 ? '1 month ago' : `${months} months ago`;
    }
  } catch (error) {
    return 'Recent';
  }
}

function extractCompanyFromUrl(url) {
  if (!url) return null;
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const pathParts = urlObj.pathname.split('/').filter(part => part);
    
    if (hostname.includes('greenhouse.io')) {
      // Handle different greenhouse.io URL patterns:
      // https://boards.greenhouse.io/stripe/jobs/123
      // https://job-boards.greenhouse.io/masterclass/jobs/123
      if (pathParts.length > 0) {
        const companyName = pathParts[0];
        if (companyName && companyName !== 'jobs' && companyName !== 'careers') {
          return formatCompanyName(companyName);
        }
      }
    }
    
    if (hostname.includes('lever.co')) {
      // Handle lever URLs: https://jobs.lever.co/company/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('ashbyhq.com')) {
      // Handle ashby URLs: https://jobs.ashbyhq.com/company/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('pinpointhq.com')) {
      // Handle pinpoint URLs: https://company.pinpointhq.com/jobs/job-id
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('workable.com')) {
      // Handle workable URLs: https://company.workable.com/jobs/job-id
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('breezy.hr')) {
      // Handle breezy URLs: https://company.breezy.hr/p/job-id
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('smartrecruiters.com')) {
      // Handle SmartRecruiters URLs: https://jobs.smartrecruiters.com/company/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('builtin.com')) {
      // Handle Builtin URLs: https://builtin.com/jobs/company/job-title
      if (pathParts.length > 1 && pathParts[0] === 'jobs') {
        return formatCompanyName(pathParts[1]);
      }
    }
    
    // Handle updated domain patterns
    if (hostname.includes('recruiting.paylocity.com')) {
      // Handle Paylocity URLs: https://recruiting.paylocity.com/recruiting/find/company/jobs
      if (pathParts.length > 2 && pathParts[1] === 'find') {
        return formatCompanyName(pathParts[2]);
      }
    }
    
    if (hostname.includes('jobs.workable.com')) {
      // Handle updated Workable URLs: https://jobs.workable.com/company/j/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('oraclecloud.com')) {
      // Handle Oracle Cloud URLs: https://oraclecloud.com/careers/company/job-id
      if (pathParts.length > 1 && pathParts[0] === 'careers') {
        return formatCompanyName(pathParts[1]);
      }
    }
    
    if (hostname.includes('myworkdayjobs.com')) {
      // Handle Workday URLs: https://company.myworkdayjobs.com/job-site/job/job-id
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('rippling-ats.com')) {
      // Handle Rippling ATS URLs: https://company.rippling-ats.com
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('jobs.gusto.com')) {
      // Handle Gusto URLs: https://jobs.gusto.com/company/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('jobs.smartrecruiters.com')) {
      // Handle updated SmartRecruiters URLs: https://jobs.smartrecruiters.com/company/job-id
      if (pathParts.length > 0) {
        return formatCompanyName(pathParts[0]);
      }
    }
    
    if (hostname.includes('applytojob.com')) {
      // Handle JazzHR URLs: https://company.applytojob.com/apply/job-id
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('workforcenow.adp.com') || hostname.includes('myjobs.adp.com')) {
      // Handle ADP URLs: https://company.workforcenow.adp.com or https://company.myjobs.adp.com
      const subdomain = hostname.split('.')[0];
      if (subdomain && subdomain !== 'www') {
        return formatCompanyName(subdomain);
      }
    }
    
    if (hostname.includes('builtin.com') && pathParts.includes('job')) {
      // Handle updated Builtin URLs: https://builtin.com/job/company/job-title
      const jobIndex = pathParts.indexOf('job');
      if (jobIndex >= 0 && pathParts.length > jobIndex + 1) {
        return formatCompanyName(pathParts[jobIndex + 1]);
      }
    }
    
    // Fallback: try subdomain extraction
    const subdomain = hostname.split('.')[0];
    if (subdomain && subdomain !== 'www' && subdomain !== 'jobs' && subdomain !== 'careers' && subdomain !== 'job-boards' && subdomain !== 'boards') {
      return formatCompanyName(subdomain);
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

function formatCompanyName(companySlug) {
  if (!companySlug) return 'Unknown Company';
  
  // Handle common company name patterns
  return companySlug
    .split(/[-_]/)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ')
    .replace(/\b(io|co|inc|llc|ltd|com)\b/gi, match => match.toUpperCase())
    .trim();
}

function extractCompanyFromTitle(title) {
  if (!title) return 'Unknown Company';
  
  const patterns = [
    /at\s+([^-|,]+)(?:\s*[-|,]|$)/i,
    /-\s*([^-|,]+?)(?:\s*[-|,]|$)/i,
    /\|\s*([^-|,]+?)(?:\s*[-|,]|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = title.match(pattern);
    if (match && match[1]) {
      const company = match[1].trim();
      if (company.length > 2 && company.length < 50) {
        return formatCompanyName(company);
      }
    }
  }
  
  return 'Unknown Company';
}

// API Routes
app.post('/api/scrape-jobs', async (req, res) => {
  try {
    console.log('📨 Raw request body:', JSON.stringify(req.body, null, 2));
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
        error: 'Job title is required' 
      });
    }
    
    // Determine which Tavily API key to use
    let effectiveTavilyKey = null;
    
    if (searchEngine === 'tavily') {
      if (isUserKey && userApiKey) {
        // Use user's API key
        effectiveTavilyKey = userApiKey;
        console.log('🔑 Using user-provided Tavily API key');
      } else if (!isUserKey && TAVILY_API_KEY) {
        // Use system key only for free searches
        effectiveTavilyKey = TAVILY_API_KEY;
        console.log('🔑 Using system Tavily API key (free search)');
      } else {
        // User has no key and no free searches left
        return res.status(403).json({
          success: false,
          error: 'Usage exceeded. Please provide your Tavily API key to continue using this feature.',
          code: 'API_KEY_REQUIRED'
        });
      }
    }
    
    console.log('📥 Received multi-platform search request:', jobTitle);
    console.log('🎯 Selected job boards:', jobBoards);
    console.log('📍 Location:', location);
    console.log('⏰ Time filter received:', timeFilter);
    console.log('🔍 Search engine selected:', searchEngine);
    
    // Perform multi-platform scraping with retries
    let jobResults;
    let lastError;
    
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        jobResults = await scrapeMultipleJobBoards(jobTitle, jobBoards, location, attempt, timeFilter, searchEngine, effectiveTavilyKey);
        console.log(`📊 Multi-platform scraping completed on attempt ${attempt + 1}. Found jobs:`, jobResults.length);
        break;
          } catch (error) {
          lastError = error;
        console.log(`⚠️ Attempt ${attempt + 1} failed:`, error.message);
        
        if (attempt < 2) {
          const delay = Math.pow(2, attempt) * 2000;
          console.log(`⏱️ Waiting ${delay}ms before retry...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    if (!jobResults || jobResults.length === 0) {
      const errorMessage = lastError?.message || 'No jobs found';
      console.log('❌ No jobs found or scraping failed:', errorMessage);
      
      return res.json({
        success: true,
        jobs: [],
        message: `No jobs found. ${errorMessage}`,
        searchBackend: searchEngine,
        searchParams: { jobTitle, location, jobBoards, timeFilter, searchEngine }
      });
    }
    
    console.log(`✅ Successfully found ${jobResults.length} jobs`);
    
    res.json({
      success: true,
      jobs: jobResults,
      totalJobs: jobResults.length,
      searchBackend: searchEngine,
      searchParams: { jobTitle, location, jobBoards, timeFilter, searchEngine }
    });
    
  } catch (error) {
    console.error('💥 API Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      searchBackend: searchEngine
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    searchBackend: SEARCH_BACKEND,
    tavilyConfigured: !!TAVILY_API_KEY,
    timestamp: new Date().toISOString()
  });
});

// Test endpoint for Tavily API
app.get('/api/test-tavily', async (req, res) => {
  try {
    if (!TAVILY_API_KEY) {
      return res.status(500).json({
        success: false,
        error: 'Tavily API key not configured'
      });
    }
    
    console.log('🧪 Testing Tavily API...');
    const testResults = await searchJobListings('Software Engineer', 'San Francisco', ['greenhouse']);
    
    res.json({
      success: true,
      message: 'Tavily API working',
      testResults: testResults.slice(0, 3),
      totalResults: testResults.length
    });
    
  } catch (error) {
    console.error('❌ Tavily test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Initialize Chrome and start server
async function startServer() {
  // Ensure Chrome is installed for Puppeteer
  await ensureChromeInstalled();
  
  // Start server
  app.listen(PORT, () => {
    console.log('🚀 Job Scraping Server running on http://localhost:' + PORT);
    console.log('📋 Health check: http://localhost:' + PORT + '/api/health');
    console.log('🔍 Scrape jobs: POST http://localhost:' + PORT + '/api/scrape-jobs');
    console.log('🧪 Test Tavily: GET http://localhost:' + PORT + '/api/test-tavily');
    
    if (SEARCH_BACKEND === 'tavily') {
      if (TAVILY_API_KEY) {
        console.log('✅ Tavily API configured and ready');
      } else {
        console.log('⚠️ WARNING: TAVILY_API_KEY not set! Please configure your API key.');
        console.log('📝 Get your API key from: https://app.tavily.com');
      }
    }
  });
}

// Start the server
startServer().catch(error => {
  console.error('❌ Failed to start server:', error);
  process.exit(1);
});
