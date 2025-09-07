/**
 * Google Sheets Service using App-Level OAuth
 * Users provide sheet URLs, app writes using its own verified credentials
 */

import { extractSheetId, validateSheetPermissions, type SheetUrlInfo } from './sheetUtils';

// Types for our job data
export interface JobResult {
  title: string;
  company: string;
  location: string;
  url: string;
  datePosted: string;
  description: string;
}

export interface ExportResult {
  success: boolean;
  message: string;
  exportedCount?: number;
  error?: string;
  sheetUrl?: string;
}

// App-level Google OAuth configuration
const APP_GOOGLE_CONFIG = {
  // These will be your verified app credentials (not user credentials)
  clientId: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
  clientSecret: import.meta.env.VITE_GOOGLE_CLIENT_SECRET || '',
  // App access token (your verified OAuth token)
  accessToken: import.meta.env.VITE_APP_GOOGLE_ACCESS_TOKEN || '',
  refreshToken: import.meta.env.VITE_APP_GOOGLE_REFRESH_TOKEN || ''
};

export class GoogleSheetsAppService {
  private static appAccessToken: string | null = null;
  private static tokenExpiry: number = 0;

  /**
   * Initialize the service with app-level credentials
   */
  static initialize(): void {
    this.appAccessToken = APP_GOOGLE_CONFIG.accessToken;
    console.log('🔧 GoogleSheetsAppService initialized with app credentials');
  }

  /**
   * Check if app has valid credentials
   */
  static isConfigured(): boolean {
    return !!(APP_GOOGLE_CONFIG.accessToken && APP_GOOGLE_CONFIG.clientId);
  }

  /**
   * Get current app access token (refresh if needed)
   */
  private static async getValidAccessToken(): Promise<string> {
    // If we have a valid token that's not expired, use it
    if (this.appAccessToken && Date.now() < this.tokenExpiry) {
      return this.appAccessToken;
    }

    // If we have a refresh token, refresh the access token
    if (APP_GOOGLE_CONFIG.refreshToken) {
      try {
        const response = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            client_id: APP_GOOGLE_CONFIG.clientId,
            client_secret: APP_GOOGLE_CONFIG.clientSecret,
            refresh_token: APP_GOOGLE_CONFIG.refreshToken,
            grant_type: 'refresh_token',
          }),
        });

        if (response.ok) {
          const data = await response.json();
          this.appAccessToken = data.access_token;
          this.tokenExpiry = Date.now() + (data.expires_in * 1000) - 60000; // 1 minute buffer
          console.log('🔄 App access token refreshed');
          return this.appAccessToken;
        }
      } catch (error) {
        console.error('❌ Failed to refresh app access token:', error);
      }
    }

    // Fall back to the configured token
    if (APP_GOOGLE_CONFIG.accessToken) {
      this.appAccessToken = APP_GOOGLE_CONFIG.accessToken;
      return this.appAccessToken;
    }

    throw new Error('No valid app access token available');
  }

  /**
   * Write jobs to a user's public Google Sheet
   */
  static async writeToPublicSheet(userSheetUrl: string, jobs: JobResult[]): Promise<ExportResult> {
    try {
      if (!this.isConfigured()) {
        return {
          success: false,
          message: 'Google Sheets integration is not configured.',
          error: 'App credentials not found'
        };
      }

      if (!jobs || jobs.length === 0) {
        return {
          success: false,
          message: 'No jobs provided for export.',
          error: 'No data to export'
        };
      }

      // Extract and validate sheet ID
      const sheetInfo = extractSheetId(userSheetUrl);
      if (!sheetInfo.isValid || !sheetInfo.sheetId) {
        return {
          success: false,
          message: 'Invalid Google Sheets URL.',
          error: sheetInfo.error || 'Invalid URL format'
        };
      }

      const sheetId = sheetInfo.sheetId;
      const accessToken = await this.getValidAccessToken();

      console.log('📊 Writing jobs to public sheet:', sheetId);
      console.log('🔢 Number of jobs:', jobs.length);

      // Validate sheet permissions
      const permissionCheck = await validateSheetPermissions(sheetId, accessToken);
      if (!permissionCheck.isAccessible) {
        return {
          success: false,
          message: 'Unable to access the Google Sheet.',
          error: permissionCheck.error || 'Sheet is not publicly accessible'
        };
      }

      // Check if sheet has the correct structure / add headers if needed
      await this.ensureSheetHeaders(sheetId, accessToken);

      // Prepare job data for insertion
      const values = jobs.map(job => [
        job.title,
        job.company,
        job.location,
        job.url,
        job.datePosted,
        job.description.substring(0, 1000), // Limit description length
        new Date().toISOString() // Export timestamp
      ]);

      // Append the job data to the sheet
      const appendResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1!A:G:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: values
          })
        }
      );

      if (!appendResponse.ok) {
        const errorText = await appendResponse.text();
        console.error('❌ Failed to append data:', appendResponse.status, errorText);
        
        let errorMessage = `Failed to write to sheet (${appendResponse.status})`;
        if (appendResponse.status === 403) {
          errorMessage = 'Access denied. Please ensure your sheet is set to "Anyone with the link can edit".';
        } else if (appendResponse.status === 404) {
          errorMessage = 'Sheet not found. Please check the URL is correct.';
        }

        return {
          success: false,
          message: errorMessage,
          error: errorText
        };
      }

      const appendData = await appendResponse.json();
      console.log('✅ Successfully exported to Google Sheets:', appendData);

      return {
        success: true,
        message: `Successfully added ${jobs.length} jobs to your Google Sheet!`,
        exportedCount: jobs.length,
        sheetUrl: userSheetUrl
      };

    } catch (error) {
      console.error('💥 Google Sheets export error:', error);
      return {
        success: false,
        message: 'An error occurred while exporting to Google Sheets.',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Ensure the sheet has proper headers
   */
  private static async ensureSheetHeaders(sheetId: string, accessToken: string): Promise<void> {
    try {
      // Check if headers exist
      const headerResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1!A1:G1`,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const headerData = await headerResponse.json();
      const existingHeaders = headerData.values?.[0] || [];

      // Define expected headers
      const expectedHeaders = [
        'Job Title',
        'Company', 
        'Location',
        'URL',
        'Date Posted',
        'Description',
        'Exported At'
      ];

      // If no headers or incomplete headers, write them
      if (existingHeaders.length === 0 || existingHeaders[0] !== expectedHeaders[0]) {
        console.log('📝 Adding headers to sheet...');
        
        await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1!A1:G1?valueInputOption=RAW`,
          {
            method: 'PUT',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              values: [expectedHeaders]
            })
          }
        );

        console.log('✅ Headers added successfully');
      }
    } catch (error) {
      console.warn('⚠️ Could not ensure headers (continuing anyway):', error);
      // Continue even if header setup fails
    }
  }

  /**
   * Test connection to a public sheet
   */
  static async testSheetConnection(userSheetUrl: string): Promise<{
    success: boolean;
    message: string;
    sheetTitle?: string;
    error?: string;
  }> {
    try {
      const sheetInfo = extractSheetId(userSheetUrl);
      if (!sheetInfo.isValid || !sheetInfo.sheetId) {
        return {
          success: false,
          message: 'Invalid Google Sheets URL',
          error: sheetInfo.error
        };
      }

      const accessToken = await this.getValidAccessToken();
      const permissionCheck = await validateSheetPermissions(sheetInfo.sheetId, accessToken);

      if (permissionCheck.isAccessible) {
        // Try to get sheet title
        try {
          const response = await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${sheetInfo.sheetId}?fields=properties.title`,
            {
              headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
              }
            }
          );

          if (response.ok) {
            const data = await response.json();
            return {
              success: true,
              message: 'Sheet connection successful!',
              sheetTitle: data.properties?.title || 'Unknown Sheet'
            };
          }
        } catch (error) {
          // Continue with basic success if title fetch fails
        }

        return {
          success: true,
          message: 'Sheet is accessible and ready for export!'
        };
      } else {
        return {
          success: false,
          message: permissionCheck.error || 'Sheet is not accessible',
          error: permissionCheck.error
        };
      }
    } catch (error) {
      return {
        success: false,
        message: 'Error testing sheet connection',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Read jobs from a public Google Sheet
   * @param sheetUrl The URL of the Google Sheet to read from
   * @returns Promise with jobs data or error
   */
  static async readFromPublicSheet(sheetUrl: string): Promise<{
    success: boolean;
    jobs?: any[];
    headers?: string[];
    error?: string;
  }> {
    try {
      const sheetResult = extractSheetId(sheetUrl);
      if (!sheetResult.isValid || !sheetResult.sheetId) {
        return {
          success: false,
          error: sheetResult.error || 'Invalid Google Sheet URL'
        };
      }
      
      const sheetId = sheetResult.sheetId;

      // Ensure we have a valid access token
      const accessToken = await this.getValidAccessToken();
      if (!accessToken) {
        return {
          success: false,
          error: 'Unable to access Google Sheets - app authentication failed'
        };
      }

      // Read data from the sheet
      const range = 'A:Z'; // Read all columns, Google Sheets will return only used range
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
        if (response.status === 403) {
          return {
            success: false,
            error: 'Access denied. Make sure your Google Sheet is set to "Anyone with the link can view"'
          };
        } else if (response.status === 404) {
          return {
            success: false,
            error: 'Sheet not found. Please check the URL and try again'
          };
        } else {
          return {
            success: false,
            error: `Failed to read sheet: ${response.statusText}`
          };
        }
      }

      const data = await response.json();
      const rows = data.values || [];

      if (rows.length === 0) {
        return {
          success: true,
          jobs: [],
          headers: [],
        };
      }

      // First row is headers
      const headers = rows[0] || [];
      const jobRows = rows.slice(1);

      // Convert rows to job objects with proper property mapping
      const jobs = jobRows.map((row: any[]) => {
        const job: any = {};
        headers.forEach((header: string, index: number) => {
          const value = row[index] || '';
          
          // Map sheet column headers to expected job object properties
          switch (header.toLowerCase().trim()) {
            case 'job title':
              job.title = value;
              break;
            case 'company':
              job.company = value;
              break;
            case 'location':
              job.location = value;
              break;
            case 'url':
              job.url = value;
              break;
            case 'date posted':
              job.datePosted = value;
              break;
            case 'description':
              job.description = value;
              break;
            case 'exported at':
              job.exportedAt = value;
              break;
            default:
              // For any other columns, use the header as-is (camelCase)
              const propertyName = header.toLowerCase().replace(/\s+/g, '');
              job[propertyName] = value;
              break;
          }
        });
        return job;
      });

      return {
        success: true,
        jobs,
        headers,
      };

    } catch (error) {
      console.error('Error reading from sheet:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  /**
   * Get setup instructions for users
   */
  static getSetupInstructions(): string[] {
    return [
      "Create or open your Google Sheet",
      "Click the 'Share' button (top right)",
      "Change 'Restricted' to 'Anyone with the link'",
      "Set permission to 'Editor' (can edit)",
      "Click 'Copy link' and paste it in the field below",
      "Click 'Test Connection' to verify setup"
    ];
  }
}

// Initialize on import
GoogleSheetsAppService.initialize();
