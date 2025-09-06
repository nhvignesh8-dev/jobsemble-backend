// src/services/tavily.js
import axios from 'axios';

const TAVILY_API_URL = 'https://api.tavily.com/search';

// Simple Tavily client implementation
const client = {
  search: async (query, options = {}) => {
    try {
      const response = await axios.post(TAVILY_API_URL, {
        api_key: process.env.TAVILY_API_KEY,
        query: query,
        max_results: options.maxResults || 10,
        search_depth: options.searchDepth || 'basic',
        include_answer: options.includeAnswer || false,
        include_raw_content: options.includeRawContent || false
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 30000
      });
      
      return response.data;
    } catch (error) {
      console.error('Tavily API Error:', error.message);
      throw new Error(`Tavily search failed: ${error.message}`);
    }
  }
};

/**
 * Search for job listings using Tavily
 * @param {string} jobTitle - The job title to search for
 * @param {string} location - The location to search in
 * @param {Array<string>} jobBoards - Array of job board names to search
 * @param {string} timeFilter - Time filter (e.g., 'qdr:d' for past day)
 * @returns {Promise<Array>} Array of job results
 */
export async function searchJobListings(jobTitle, location, jobBoards, timeFilter) {
  console.log('🔍 Tavily Job Search:', { jobTitle, location, jobBoards, timeFilter });
  
  if (!process.env.TAVILY_API_KEY) {
    throw new Error('TAVILY_API_KEY environment variable is not set');
  }

  const allJobs = [];

  for (const board of jobBoards) {
    try {
      console.log(`🎯 Searching ${board} for "${jobTitle}" in ${location}`);
      
      // Construct search query for each job board with correct domain patterns
      // Handle broad locations that don't work well with Tavily
      const locationFilter = (location === 'United States' || location === 'USA') ? '' : location;
      
      let query;
      if (board === 'greenhouse') {
        query = `"${jobTitle}" site:greenhouse.io${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'lever') {
        query = `"${jobTitle}" site:lever.co${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'ashby') {
        query = `"${jobTitle}" site:ashbyhq.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'pinpoint') {
        query = `"${jobTitle}" site:pinpointhq.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'paylocity') {
        query = `"${jobTitle}" site:recruiting.paylocity.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'keka') {
        query = `"${jobTitle}" site:keka.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'workable') {
        query = `"${jobTitle}" site:jobs.workable.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'breezyhr') {
        query = `"${jobTitle}" site:breezy.hr${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'wellfound') {
        query = `"${jobTitle}" site:wellfound.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'ycombinator') {
        query = `"${jobTitle}" site:workatastartup.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'oracle') {
        query = `"${jobTitle}" site:oraclecloud.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'workday') {
        query = `"${jobTitle}" site:myworkdayjobs.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'recruitee') {
        query = `"${jobTitle}" site:recruitee.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'rippling') {
        query = `"${jobTitle}" (site:rippling.com OR site:rippling-ats.com)${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'gusto') {
        query = `"${jobTitle}" site:jobs.gusto.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'smartrecruiters') {
        query = `"${jobTitle}" site:jobs.smartrecruiters.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'jazzhr') {
        query = `"${jobTitle}" site:applytojob.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'jobvite') {
        query = `"${jobTitle}" site:jobvite.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'icims') {
        query = `"${jobTitle}" site:icims.com${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'builtin') {
        query = `"${jobTitle}" site:builtin.com/job/${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'adp') {
        query = `"${jobTitle}" (site:workforcenow.adp.com OR site:myjobs.adp.com)${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'jobs-subdomain') {
        query = `"${jobTitle}" site:jobs.*${locationFilter ? ` ${locationFilter}` : ''}`;
      } else if (board === 'talent-subdomain') {
        query = `"${jobTitle}" site:talent.*${locationFilter ? ` ${locationFilter}` : ''}`;
      } else {
        query = `"${jobTitle}"${locationFilter ? ` ${locationFilter}` : ''} jobs site:${board}.com`;
      }

      // Add time filter if specified
      if (timeFilter && timeFilter !== 'all') {
        query += ` "${timeFilter}"`;
      }

      console.log(`🔍 Tavily search query: ${query}`);

      const searchOptions = {
        maxResults: 75,
        searchDepth: "basic",
        includeAnswer: false,
        includeRawContent: false,
      };

      const results = await webSearch(query, searchOptions);
      console.log(`✅ Tavily found ${results.length} results for ${board}`);

      // Process and clean the results
      const jobsForBoard = results
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
            url.includes(board.toLowerCase())
          );
        })
        .filter(result => {
          // Filter by job title relevance
          return isJobTitleRelevant(result.title, jobTitle);
        })
        .map(result => ({
          title: cleanJobTitle(result.title),
          company: extractCompanyFromUrl(result.url) || extractCompanyFromTitle(result.title),
          location: location,
          url: result.url,
          jobBoard: board,
          snippet: result.snippet || '',
          score: result.score || 0,
        }));

      console.log(`🧹 Processed ${jobsForBoard.length} jobs from ${board}`);
      allJobs.push(...jobsForBoard);

    } catch (error) {
      console.error(`❌ Error searching ${board}:`, error.message);
    }
  }

  // Remove duplicates based on URL
  const uniqueJobs = allJobs.filter((job, index, self) => 
    index === self.findIndex(j => j.url === job.url)
  );

  console.log(`✅ Total unique jobs found: ${uniqueJobs.length}`);
  return uniqueJobs;
}

/**
 * General web search using Tavily
 * @param {string} query - Search query
 * @param {Object} opts - Search options
 * @returns {Promise<Array>} Search results
 */
export async function webSearch(query, opts = {}) {
  const options = {
    maxResults: opts.maxResults || 10,
    searchDepth: opts.searchDepth || "advanced",
    includeAnswer: opts.includeAnswer || false,
    includeRawContent: opts.includeRawContent || false,
  };

  try {
    const res = await client.search(query, options);
    
    return (res.results || []).map(r => ({
      title: r.title,
      url: r.url,
      snippet: r.content || r.snippet,
      score: r.score,
      rawContent: r.raw_content,
      publishedDate: r.publishedDate || r.published_date || null, // Extract date if available
    }));
  } catch (error) {
    console.error('❌ Tavily search error:', error);
    throw error;
  }
}

/**
 * Extract content from URLs using Tavily
 * @param {Array<string>} urls - URLs to extract content from
 * @returns {Promise<Object>} URL to content mapping
 */
export async function extractContent(urls) {
  try {
    const res = await client.extract(urls);
    const out = {};
    
    for (const item of Array.isArray(res) ? res : Object.values(res)) {
      const url = item.url || item.source || "";
      const raw = item.raw_content || item.content || "";
      if (url && raw) {
        out[url] = raw;
      }
    }
    
    return out;
  } catch (error) {
    console.error('❌ Tavily extract error:', error);
    throw error;
  }
}

// Helper functions
function cleanJobTitle(title) {
  if (!title) return '';
  
  // Remove common suffixes and prefixes
  return title
    .replace(/\s*-\s*.*$/, '') // Remove everything after dash
    .replace(/\s*\|\s*.*$/, '') // Remove everything after pipe
    .replace(/\s*at\s+.*$/i, '') // Remove "at Company"
    .replace(/Jobs?$/, '') // Remove trailing "Job" or "Jobs"
    .replace(/Career(s)?$/, '') // Remove trailing "Career" or "Careers"
    .trim();
}

function extractCompanyFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    if (hostname.includes('greenhouse.io')) {
      // Extract company from greenhouse URLs
      const parts = urlObj.pathname.split('/');
      const companyIndex = parts.findIndex(part => part === 'boards');
      if (companyIndex > 0) {
        return parts[companyIndex - 1];
      }
    } else if (hostname.includes('lever.co')) {
      // Extract company from lever URLs
      const subdomain = hostname.split('.')[0];
      return subdomain !== 'jobs' ? subdomain : null;
    } else if (hostname.includes('ashbyhq.com')) {
      // Extract company from ashby URLs
      const parts = urlObj.pathname.split('/');
      if (parts.length > 1) {
        return parts[1];
      }
    }
    
    return null;
  } catch (error) {
    return null;
  }
}

function extractCompanyFromTitle(title) {
  if (!title) return '';
  
  // Try to extract company name from patterns like "Job Title at Company"
  const atMatch = title.match(/\s+at\s+(.+?)(?:\s*[-|]|$)/i);
  if (atMatch) {
    return atMatch[1].trim();
  }
  
  // Try to extract from patterns like "Job Title - Company"
  const dashMatch = title.match(/\s*-\s*(.+?)(?:\s*[-|]|$)/);
  if (dashMatch) {
    return dashMatch[1].trim();
  }
  
  return '';
}

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
  
  // Require at least 60% word match forly relevance
  return relevanceScore >= 0.6;
}
