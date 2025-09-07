/**
 * Google Sheets URL utilities for extracting sheet IDs and validating URLs
 */

export interface SheetUrlInfo {
  isValid: boolean;
  sheetId: string | null;
  error?: string;
}

/**
 * Extract Google Sheets ID from various URL formats
 */
export function extractSheetId(url: string): SheetUrlInfo {
  if (!url || typeof url !== 'string') {
    return {
      isValid: false,
      sheetId: null,
      error: 'Please provide a valid URL'
    };
  }

  // Clean the URL (remove extra spaces, etc.)
  const cleanUrl = url.trim();

  // Google Sheets URL patterns
  const patterns = [
    // Standard sharing URL: https://docs.google.com/spreadsheets/d/SHEET_ID/edit
    /(?:https?:\/\/)?(?:www\.)?docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/,
    // Alternative format: https://docs.google.com/spreadsheets/d/SHEET_ID/edit#gid=0
    /(?:https?:\/\/)?(?:www\.)?docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9-_]+)(?:\/edit)?(?:#gid=\d+)?/,
    // Mobile format: https://docs.google.com/spreadsheets/u/0/d/SHEET_ID/edit
    /(?:https?:\/\/)?(?:www\.)?docs\.google\.com\/spreadsheets\/u\/\d+\/d\/([a-zA-Z0-9-_]+)/
  ];

  for (const pattern of patterns) {
    const match = cleanUrl.match(pattern);
    if (match && match[1]) {
      const sheetId = match[1];
      
      // Validate sheet ID format (Google Sheets IDs are typically 44+ characters)
      if (sheetId.length >= 20) {
        return {
          isValid: true,
          sheetId: sheetId
        };
      }
    }
  }

  return {
    isValid: false,
    sheetId: null,
    error: 'Please provide a valid Google Sheets URL (e.g., https://docs.google.com/spreadsheets/d/...)'
  };
}

/**
 * Validate if URL is a Google Sheets URL
 */
export function isGoogleSheetsUrl(url: string): boolean {
  const result = extractSheetId(url);
  return result.isValid;
}

/**
 * Get formatted instructions for users
 */
export function getSheetSetupInstructions(): string[] {
  return [
    "Open your Google Sheet",
    "Click 'Share' button in the top right",
    "Change access to 'Anyone with the link'",
    "Set permission to 'Editor' (can edit)",
    "Click 'Copy link' and paste it below"
  ];
}

/**
 * Generate a sample Google Sheets URL for UI examples
 */
export function getSampleSheetUrl(): string {
  return "https://docs.google.com/spreadsheets/d/1GzaIdG3niZVRXxZranodN_nXraMBShQS84Btv-HHii8/edit";
}

/**
 * Validate sheet permissions by attempting to read metadata
 */
export async function validateSheetPermissions(sheetId: string, accessToken: string): Promise<{
  isAccessible: boolean;
  isPublic: boolean;
  error?: string;
}> {
  try {
    const response = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}?fields=properties.title`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (response.ok) {
      return {
        isAccessible: true,
        isPublic: true
      };
    } else if (response.status === 403) {
      return {
        isAccessible: false,
        isPublic: false,
        error: 'Sheet is not publicly accessible. Please set it to "Anyone with the link can edit"'
      };
    } else {
      return {
        isAccessible: false,
        isPublic: false,
        error: `Unable to access sheet (${response.status}). Please check the URL and permissions.`
      };
    }
  } catch (error) {
    return {
      isAccessible: false,
      isPublic: false,
      error: 'Network error while validating sheet access'
    };
  }
}
