// Types for our job data
export interface JobResult {
  title: string;
  company: string;
  location: string;
  url: string;
  datePosted: string;
  description: string;
}

// Extended type for saved jobs with additional metadata
export interface SavedJobResult extends JobResult {
  exportedAt: string;
  companyWebsite?: string;
  directCompanyLink?: string;
}

export interface ExportResult {
  success: boolean;
  message: string;
  exportedCount?: number;
  error?: string;
}

// Google Sheets API configuration
const SPREADSHEET_ID = '1GzaIdG3niZVRXxZranodN_nXraMBShQS84Btv-HHii8';
const SHEET_NAME = 'JobListings';

// Google API credentials from environment variables
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';

export class GoogleSheetsService {
  private static isAuthenticated = false;
  private static accessToken: string | null = null;

  /**
   * Initialize Google Identity Services
   */
  static async initializeGoogleAuth(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Load Google Identity Services script
      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      
      script.onload = () => {
        // Initialize Google Identity Services
        if (window.google) {
          window.google.accounts.id.initialize({
            client_id: GOOGLE_CLIENT_ID,
            scope: 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive',
            callback: this.handleCredentialResponse.bind(this)
          });
          resolve();
        } else {
          reject(new Error('Google Identity Services failed to load'));
        }
      };
      
      script.onerror = () => reject(new Error('Failed to load Google Identity Services'));
      document.head.appendChild(script);
    });
  }

  /**
   * Handle OAuth credential response
   */
  private static handleCredentialResponse(response: { credential?: string }): void {
    if (response.credential) {
      this.accessToken = response.credential;
      this.isAuthenticated = true;
      
      // Store token in localStorage for persistence
      localStorage.setItem('google_access_token', this.accessToken);
      
      // Notify parent window of successful authentication
      if (window.opener) {
        window.opener.postMessage({
          type: 'GOOGLE_OAUTH_SUCCESS',
          token: this.accessToken
        }, window.location.origin);
      }
    }
  }

  /**
   * Check if user is authenticated
   */
  static isUserAuthenticated(): boolean {
    const storedToken = localStorage.getItem('google_access_token');
    console.log('🔍 isUserAuthenticated - Stored token exists:', !!storedToken);
    console.log('🔍 isUserAuthenticated - Current accessToken:', !!this.accessToken);
    console.log('🔍 isUserAuthenticated - Current isAuthenticated flag:', this.isAuthenticated);
    
    if (storedToken) {
      this.accessToken = storedToken;
      this.isAuthenticated = true;
      console.log('🔍 isUserAuthenticated - Set accessToken and isAuthenticated to true');
    } else {
      console.log('🔍 isUserAuthenticated - No stored token, setting isAuthenticated to false');
      this.isAuthenticated = false;
      this.accessToken = null;
    }
    return this.isAuthenticated;
  }

  /**
   * Clear authentication state
   */
  static clearAuth(): void {
    console.log('🧹 Clearing GoogleSheetsService authentication state...');
    this.accessToken = null;
    this.isAuthenticated = false;
    console.log('🧹 Authentication state cleared');
  }

  /**
   * Create a new sheet in the spreadsheet
   */
  private static async createSheet(): Promise<void> {
    try {
      console.log('🔨 Creating new sheet:', SHEET_NAME);
      
      const batchUpdateResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}:batchUpdate`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            requests: [
              {
                addSheet: {
                  properties: {
                    title: SHEET_NAME
                  }
                }
              }
            ]
          })
        }
      );

      if (batchUpdateResponse.ok) {
        console.log('✅ Successfully created new sheet:', SHEET_NAME);
      } else {
        const errorText = await batchUpdateResponse.text();
        console.error('❌ Failed to create sheet:', batchUpdateResponse.status, errorText);
        throw new Error(`Failed to create sheet: ${batchUpdateResponse.status}`);
      }
    } catch (error) {
      console.error('💥 Error creating sheet:', error);
      throw error;
    }
  }

  /**
   * Get OAuth2 authorization URL for popup
   */
  static getAuthUrl(): string {
    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: `${window.location.origin}/google-oauth-callback.html`,
      scope: 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive',
      response_type: 'code',
      access_type: 'offline',
      prompt: 'consent'
    });
    
    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  /**
   * Handle OAuth callback and exchange code for token
   */
  static async handleAuthCallback(code: string): Promise<{success: boolean, error?: string}> {
    try {
      console.log('🔄 Exchanging OAuth code for token...');
      console.log('🔑 Client ID:', GOOGLE_CLIENT_ID);
      console.log('🌐 Redirect URI:', `${window.location.origin}/google-oauth-callback.html`);
      
      // Exchange authorization code for access token
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: GOOGLE_CLIENT_ID,
          client_secret: import.meta.env.VITE_GOOGLE_CLIENT_SECRET || '',
          code: code,
          grant_type: 'authorization_code',
          redirect_uri: `${window.location.origin}/google-oauth-callback.html`
        })
      });

      console.log('📥 Token response status:', tokenResponse.status);
      
      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        console.error('❌ Token exchange failed:', errorText);
        throw new Error(`Failed to exchange code for token: ${tokenResponse.status} - ${errorText}`);
      }

      const tokenData = await tokenResponse.json();
      console.log('✅ Token exchange successful');
      
      this.accessToken = tokenData.access_token;
      this.isAuthenticated = true;

      // Store tokens in localStorage
      localStorage.setItem('google_access_token', this.accessToken);
      if (tokenData.refresh_token) {
        localStorage.setItem('google_refresh_token', tokenData.refresh_token);
      }

      return { success: true };
    } catch (error) {
      console.error('💥 OAuth callback error:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Write jobs to Google Sheets using the API
   */
  static async writeToGoogleSheets(jobs: JobResult[]): Promise<ExportResult> {
    try {
      if (!this.isUserAuthenticated()) {
        return {
          success: false,
          message: 'Not authenticated. Please authenticate with Google first.',
          error: 'Authentication required'
        };
      }

      if (jobs.length === 0) {
        return {
          success: false,
          message: 'No jobs to export'
        };
      }

      console.log('🚀 Starting Google Sheets API export...');
      console.log('📊 Jobs to export:', jobs);

      // Prepare data for Google Sheets
      const values = jobs.map(job => [
        job.title || '',
        job.company || '',
        job.location || '',
        job.url || '',
        job.datePosted || '',
        job.description || '',
        new Date().toISOString() // timestamp
      ]);

      // Add headers if sheet is empty
      const headers = [
        'Job Title',
        'Company',
        'Location',
        'Job URL',
        'Date Posted',
        'Description',
        'Exported At'
      ];

      // First, check if the sheet exists
      try {
        console.log('🔍 Checking if sheet exists:', SHEET_NAME);
        
        const checkResponse = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}`,
          {
            headers: {
              'Authorization': `Bearer ${this.accessToken}`,
              'Content-Type': 'application/json'
            }
          }
        );

        if (checkResponse.ok) {
          const spreadsheetData = await checkResponse.json();
          const sheetExists = spreadsheetData.sheets?.some((sheet: { properties: { title: string } }) => sheet.properties.title === SHEET_NAME);
          
          if (sheetExists) {
            console.log('✅ Sheet already exists:', SHEET_NAME);
          } else {
            console.log('❌ Sheet does not exist, creating it...');
            // Create the sheet
            await this.createSheet();
          }
        } else {
          console.log('⚠️ Could not check spreadsheet:', checkResponse.status);
          // Try to create the sheet anyway
          await this.createSheet();
        }
      } catch (error) {
        console.log('⚠️ Error checking sheet, trying to create:', error);
        await this.createSheet();
      }

      // Check if headers already exist (only write headers once)
      try {
        console.log('📋 Checking if headers already exist in sheet:', SHEET_NAME);
        
        const headerCheckResponse = await fetch(
          `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A1:D1`,
          {
            headers: {
              'Authorization': `Bearer ${this.accessToken}`,
              'Content-Type': 'application/json'
            }
          }
        );

        if (headerCheckResponse.ok) {
          const existingHeaders = await headerCheckResponse.json();
          const hasHeaders = existingHeaders.values && existingHeaders.values.length > 0;
          
          if (!hasHeaders) {
            console.log('📋 No headers found, writing headers to sheet:', SHEET_NAME);
            
            // Write headers only if they don't exist
            const headerResponse = await fetch(
              `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A1`,
              {
                method: 'PUT',
                headers: {
                  'Authorization': `Bearer ${this.accessToken}`,
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  values: [headers]
                })
              }
            );

            if (headerResponse.ok) {
              console.log('✅ Successfully wrote headers to sheet');
            } else {
              const errorText = await headerResponse.text();
              console.log('⚠️ Could not write headers:', headerResponse.status, errorText);
            }
          } else {
            console.log('✅ Headers already exist, skipping header write');
          }
        } else {
          console.log('⚠️ Could not check headers, writing them anyway');
          // Fallback: write headers
          const headerResponse = await fetch(
            `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A1`,
            {
              method: 'PUT',
              headers: {
                'Authorization': `Bearer ${this.accessToken}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                values: [headers]
              })
            }
          );

          if (headerResponse.ok) {
            console.log('✅ Successfully wrote headers to sheet (fallback)');
          } else {
            const errorText = await headerResponse.text();
            console.log('⚠️ Could not write headers (fallback):', headerResponse.status, errorText);
          }
        }
      } catch (error) {
        console.log('⚠️ Error checking/writing headers:', error);
      }

      // Append the job data
      console.log('📊 Appending job data to sheet:', SHEET_NAME);
      console.log('🔗 Append URL:', `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A1:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`);
      
      const appendResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A1:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            values: values
          })
        }
      );

      if (!appendResponse.ok) {
        const errorText = await appendResponse.text();
        console.error('❌ Append failed:', appendResponse.status, errorText);
        throw new Error(`Google Sheets API error: ${appendResponse.status} - ${errorText}`);
      }

      const appendData = await appendResponse.json();
      console.log('✅ Successfully exported to Google Sheets:', appendData);

      return {
        success: true,
        message: `Successfully added ${jobs.length} jobs to Google Sheets!`,
        exportedCount: jobs.length
      };

    } catch (error) {
      console.error('💥 Google Sheets API error:', error);
      return {
        success: false,
        message: 'Failed to write to Google Sheets',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }


  /**
   * Get the sheet ID for the JobListings sheet
   */
  private static async getSheetId(): Promise<number> {
    try {
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}`,
        {
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        const sheet = data.sheets?.find((s: { properties: { title: string } }) => s.properties.title === SHEET_NAME);
        return sheet?.properties?.sheetId || 0;
      }
      return 0;
    } catch (error) {
      console.log('⚠️ Error getting sheet ID:', error);
      return 0;
    }
  }

  /**
   * Open Google Sheets in new tab
   */
  static openSheets(): void {
    const url = `https://docs.google.com/spreadsheets/d/${SPREADSHEET_ID}`;
    window.open(url, '_blank');
  }

  /**
   * Clear all jobs from the sheet (for testing)
   */
  static async clearSheet(): Promise<ExportResult> {
    try {
      if (!this.isUserAuthenticated()) {
        return {
          success: false,
          message: 'Not authenticated',
          error: 'Authentication required'
        };
      }

      const clearResponse = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}!A2:Z`,
        {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!clearResponse.ok) {
        throw new Error('Failed to clear sheet');
      }

      return {
        success: true,
        message: 'Sheet cleared successfully'
      };
    } catch (error) {
      return {
        success: false,
        message: 'Failed to clear sheet',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get authentication status and user info
   */
  static getAuthStatus(): { isAuthenticated: boolean; authUrl?: string } {
    if (this.isUserAuthenticated()) {
      return { isAuthenticated: true };
    } else {
      return { 
        isAuthenticated: false, 
        authUrl: this.getAuthUrl() 
      };
    }
  }

  /**
   * Fetch jobs from Google Sheets
   */
  static async fetchJobsFromSheets(): Promise<{ success: boolean; jobs?: SavedJobResult[]; headers?: string[]; error?: string }> {
    try {
      if (!this.isUserAuthenticated()) {
        return {
          success: false,
          error: 'Not authenticated. Please authenticate with Google first.'
        };
      }

      console.log('📥 Fetching jobs from Google Sheets...');
      
      // Fetch all data from the sheet
      const response = await fetch(
        `https://sheets.googleapis.com/v4/spreadsheets/${SPREADSHEET_ID}/values/${SHEET_NAME}`,
        {
          headers: {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ Failed to fetch data from sheets:', response.status, errorText);
        
        let errorMessage = `Failed to fetch data: ${response.status}`;
        
        if (response.status === 401) {
          errorMessage = "Google Sheets authentication expired. Please reconnect to Google Sheets in the search configuration.";
        } else if (response.status === 403) {
          errorMessage = "Access denied. Please ensure your Google Sheet is public and set to 'Anyone with the link can edit'.";
        } else if (response.status === 404) {
          errorMessage = "Google Sheet not found. Please check your sheet URL and ensure it's accessible.";
        }
        
        return {
          success: false,
          error: errorMessage
        };
      }

      const data = await response.json();
      
      if (!data.values || data.values.length === 0) {
        console.log('📋 No data found in sheet');
        return {
          success: true,
          jobs: [],
          headers: []
        };
      }

      // Get headers from the first row
      const headers = data.values[0] || [];
      console.log('📋 Sheet headers:', headers);

      if (data.values.length <= 1) {
        console.log('📋 No job data found in sheet (only headers)');
        return {
          success: true,
          jobs: [],
          headers: headers
        };
      }

      // Skip the header row and convert data to job objects
      const jobRows = data.values.slice(1);
      const jobs: SavedJobResult[] = jobRows.map((row: string[]) => ({
        title: row[0] || '',
        company: row[1] || '',
        location: row[2] || '',
        url: row[3] || '',
        datePosted: row[4] || '',
        description: row[5] || '',
        exportedAt: row[6] || '',
        companyWebsite: '', // We'll need to derive this
        directCompanyLink: '' // We'll need to derive this
      })).filter(job => job.title && job.company); // Filter out empty rows

      console.log(`✅ Successfully fetched ${jobs.length} jobs from Google Sheets`);
      
      return {
        success: true,
        jobs: jobs,
        headers: headers
      };

    } catch (error) {
      console.error('💥 Error fetching jobs from Google Sheets:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Sign out user
   */
  static signOut(): void {
    this.accessToken = null;
    this.isAuthenticated = false;
    localStorage.removeItem('google_access_token');
    localStorage.removeItem('google_refresh_token');
  }
}

// Add Google types to window object
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: { client_id: string; scope: string; callback: (response: { credential?: string }) => void }) => void;
          renderButton: (element: HTMLElement, config: { theme: string; size: string }) => void;
        };
      };
    };
  }
}
