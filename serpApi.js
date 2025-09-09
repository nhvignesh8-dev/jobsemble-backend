/**
 * SERP API Integration for Google Search
 * Replaces Chrome/Puppeteer with reliable API-based Google search
 */

import axios from 'axios';

class SerpApiService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://serpapi.com/search';
  }

  /**
   * Search Google for job listings using SERP API
   */
  async searchGoogle(query, options = {}) {
    try {
      const params = {
        api_key: this.apiKey,
        engine: 'google',
        q: query,
        num: options.num || 50, // Number of results
        ...options
      };

      // Add time filter if specified
      if (options.timeFilter && options.timeFilter !== 'anytime') {
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
        
        if (timeFilters[options.timeFilter]) {
          params.tbs = timeFilters[options.timeFilter];
        }
      }

      console.log(`🔍 SERP API search query: "${query}"`);
      console.log(`📊 SERP API params:`, { ...params, api_key: '[HIDDEN]' });

      const response = await axios.get(this.baseUrl, { 
        params,
        timeout: 30000 // 30 second timeout
      });

      const results = response.data;
      
      if (results.error) {
        throw new Error(`SERP API Error: ${results.error}`);
      }

      console.log(`✅ SERP API returned ${results.organic_results?.length || 0} organic results`);
      
      return this.parseGoogleResults(results);
      
    } catch (error) {
      console.error('❌ SERP API search failed:', error.message);
      
      if (error.response?.status === 401) {
        throw new Error('Invalid SERP API key. Please check your API key.');
      } else if (error.response?.status === 429) {
        throw new Error('SERP API rate limit exceeded. Try again later.');
      } else if (error.response?.status === 402) {
        throw new Error('SERP API credits exhausted. Please upgrade your plan.');
      }
      
      throw error;
    }
  }

  /**
   * Parse Google search results from SERP API response
   */
  parseGoogleResults(serpResults) {
    const jobs = [];
    
    if (!serpResults.organic_results) {
      console.log('⚠️ No organic results from SERP API');
      return jobs;
    }

    serpResults.organic_results.forEach((result, index) => {
      try {
        const title = result.title || 'Unknown Position';
        const link = result.link;
        const snippet = result.snippet || '';
        
        // Basic filtering for job-related results
        if (link && title && !link.includes('youtube.com') && !link.includes('google.com')) {
          
          // Extract company name from title or snippet
          let company = 'Company';
          
          // Try to extract company from title patterns
          if (title.includes(' at ')) {
            const parts = title.split(' at ');
            if (parts.length > 1) {
              company = parts[parts.length - 1].split(' - ')[0].trim();
            }
          } else if (title.includes(' | ')) {
            const parts = title.split(' | ');
            if (parts.length > 1) {
              company = parts[parts.length - 1].trim();
            }
          }

          // Clean title (remove company suffix, job board names, etc.)
          let cleanTitle = this.cleanJobTitle(title);
          
          jobs.push({
            title: cleanTitle,
            company: company,
            location: this.extractLocation(snippet) || 'Remote',
            url: link,
            datePosted: this.extractDate(snippet) || new Date().toISOString().split('T')[0],
            description: snippet.slice(0, 200) + '...', // Truncate description
            source: 'SERP API Google Search',
            foundOn: new Date().toISOString().split('T')[0]
          });
        }
      } catch (e) {
        console.error('Error processing SERP result:', e);
      }
    });

    console.log(`🔄 Processed ${jobs.length} job listings from SERP API`);
    return jobs;
  }

  /**
   * Clean job title by removing common suffixes and job board names
   */
  cleanJobTitle(title) {
    if (!title) return 'Unknown Position';
    
    let cleaned = title
      // Remove job board names
      .replace(/\s*-?\s*(Greenhouse|Lever|Ashby|Workable|BambooHR|JazzHR|SmartRecruiters).*$/i, '')
      .replace(/\s*\|\s*(Greenhouse|Lever|Ashby|Workable|BambooHR|JazzHR|SmartRecruiters).*$/i, '')
      // Remove company suffixes
      .replace(/\s*-\s*[A-Z][a-zA-Z\s&.,]+$/, '') // Remove "- Company Name"
      .replace(/\s*\|\s*[A-Z][a-zA-Z\s&.,]+$/, '') // Remove "| Company Name"
      .replace(/\s*at\s+[A-Z][a-zA-Z\s&.,]+$/, '') // Remove "at Company Name"
      // Remove location patterns
      .replace(/\s*-?\s*\(.*?\)$/, '') // Remove "(Location)"
      .replace(/\s*-?\s*\d{4,}.*$/, '') // Remove year references
      // Remove URL fragments
      .replace(/https?:\/\/[^\s]+/g, '')
      .replace(/www\.[^\s]+/g, '')
      .replace(/[a-zA-Z0-9-]+\.com[^\s]*/g, '')
      // Clean up whitespace
      .replace(/\s+/g, ' ')
      .trim();

    return cleaned || 'Unknown Position';
  }

  /**
   * Extract location from snippet text
   */
  extractLocation(snippet) {
    if (!snippet) return null;
    
    // Common location patterns
    const locationPatterns = [
      /(?:in|at)\s+([A-Z][a-zA-Z\s]+(?:,\s*[A-Z]{2})?)/,
      /([A-Z][a-zA-Z\s]+,\s*[A-Z]{2}(?:\s+\d{5})?)/,
      /(San Francisco|New York|Los Angeles|Chicago|Boston|Seattle|Austin|Denver|Remote)/i
    ];
    
    for (const pattern of locationPatterns) {
      const match = snippet.match(pattern);
      if (match) {
        return match[1] || match[0];
      }
    }
    
    return null;
  }

  /**
   * Extract date from snippet text
   */
  extractDate(snippet) {
    if (!snippet) return null;
    
    const datePatterns = [
      /(\d{1,2}\/\d{1,2}\/\d{4})/,
      /(\d{1,2}-\d{1,2}-\d{4})/,
      /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}/i
    ];
    
    for (const pattern of datePatterns) {
      const match = snippet.match(pattern);
      if (match) {
        return new Date(match[0]).toISOString().split('T')[0];
      }
    }
    
    return null;
  }
}

export { SerpApiService };
