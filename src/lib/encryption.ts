import CryptoJS from 'crypto-js';

// This should be stored as an environment variable, NOT in code
const ENCRYPTION_KEY = import.meta.env.VITE_ENCRYPTION_KEY || 'your-256-bit-secret-key-here-change-this-in-production';

/**
 * Encrypts sensitive data like API keys before storing in database
 * @param text - Plain text to encrypt
 * @returns Encrypted string
 */
export function encryptSensitiveData(text: string): string {
  if (!text || text.trim() === '') {
    return '';
  }
  
  try {
    const encrypted = CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
    return encrypted;
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Failed to encrypt sensitive data');
  }
}

/**
 * Decrypts sensitive data like API keys when retrieving from database
 * @param encryptedText - Encrypted string from database
 * @returns Decrypted plain text
 */
export function decryptSensitiveData(encryptedText: string): string {
  if (!encryptedText || encryptedText.trim() === '') {
    return '';
  }
  
  try {
    const decrypted = CryptoJS.AES.decrypt(encryptedText, ENCRYPTION_KEY);
    const plainText = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!plainText) {
      throw new Error('Decryption resulted in empty string');
    }
    
    return plainText;
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt sensitive data');
  }
}

/**
 * Encrypts API keys object before storing
 * @param apiKeys - API keys object
 * @returns Object with encrypted API keys
 */
export function encryptApiKeys(apiKeys: any): any {
  if (!apiKeys) return apiKeys;
  
  const encrypted = { ...apiKeys };
  
  // Encrypt only sensitive fields
  if (apiKeys.tavilyApiKey && apiKeys.tavilyApiKey.trim() !== '') {
    encrypted.tavilyApiKey = encryptSensitiveData(apiKeys.tavilyApiKey);
  }
  
  // Keep non-sensitive fields as-is
  // tavilyUsageCount, tavilyUsageLimit, googleSheetsConnected remain unencrypted
  
  return encrypted;
}

/**
 * Decrypts API keys object after retrieving from database
 * @param encryptedApiKeys - Encrypted API keys object
 * @returns Object with decrypted API keys
 */
export function decryptApiKeys(encryptedApiKeys: any): any {
  if (!encryptedApiKeys) return encryptedApiKeys;
  
  const decrypted = { ...encryptedApiKeys };
  
  // Decrypt only sensitive fields
  if (encryptedApiKeys.tavilyApiKey && encryptedApiKeys.tavilyApiKey.trim() !== '') {
    try {
      decrypted.tavilyApiKey = decryptSensitiveData(encryptedApiKeys.tavilyApiKey);
    } catch (error) {
      console.warn('Failed to decrypt Tavily API key, using empty string');
      decrypted.tavilyApiKey = '';
    }
  }
  
  return decrypted;
}

/**
 * Validates that encryption/decryption is working properly
 * @param testString - Test string to encrypt and decrypt
 * @returns true if encryption is working
 */
export function validateEncryption(testString: string = 'test-api-key-123'): boolean {
  try {
    const encrypted = encryptSensitiveData(testString);
    const decrypted = decryptSensitiveData(encrypted);
    return decrypted === testString;
  } catch (error) {
    console.error('Encryption validation failed:', error);
    return false;
  }
}
