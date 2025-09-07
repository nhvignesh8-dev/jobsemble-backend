/**
 * Temporary Email Detection Service
 * Uses open-source library to prevent fake account creation using disposable email services
 */

import MailChecker from 'mailchecker';

/**
 * Extract domain from email address
 */
export function extractEmailDomain(email: string): string {
  const atIndex = email.lastIndexOf('@');
  if (atIndex === -1) {
    throw new Error('Invalid email format');
  }
  return email.substring(atIndex + 1).toLowerCase().trim();
}

/**
 * Check if an email address is from a temporary/disposable email service
 * Uses open-source library with automatically updated domain list
 */
export function isTempEmail(email: string): boolean {
  try {
    // MailChecker returns true for valid emails, false for disposable ones
    // So we need to negate the result (we want true for temp emails)
    return !MailChecker.isValid(email);
  } catch {
    // Invalid email format
    return false;
  }
}

/**
 * Validate email and check for temp services
 * Returns validation result with specific error messages
 */
export function validateEmailForSignup(email: string): {
  isValid: boolean;
  error?: string;
  suggestion?: string;
} {
  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return {
      isValid: false,
      error: 'Please enter a valid email address.'
    };
  }

  // Check for temp email using open-source library
  if (isTempEmail(email)) {
    const domain = extractEmailDomain(email);
    return {
      isValid: false,
      error: `Temporary email addresses are not allowed. Please use a permanent email address.`,
      suggestion: 'Try using Gmail, Outlook, Yahoo, or your work/school email instead.'
    };
  }

  return { isValid: true };
}

/**
 * Get user-friendly error message for blocked temp emails
 */
export function getTempEmailErrorMessage(email: string): string {
  const domain = extractEmailDomain(email);
  
  return `We don't allow temporary email addresses like ${domain}. Please use a permanent email address such as Gmail, Outlook, Yahoo, or your work/school email to ensure you receive important notifications and can recover your account.`;
}

/**
 * Check if domain is a legitimate email provider
 */
export function isLegitimateEmailProvider(domain: string): boolean {
  const legitimateProviders = new Set([
    'gmail.com',
    'outlook.com',
    'hotmail.com',
    'yahoo.com',
    'aol.com',
    'icloud.com',
    'protonmail.com',
    'zoho.com',
    'fastmail.com',
    'hey.com',
    'mail.com',
    'gmx.com',
    'yandex.com',
    'live.com',
    'msn.com',
    'mail.ru',
    'qq.com',
    '163.com',
    '126.com',
    'sina.com',
    'rediffmail.com',
    'edu', // Educational domains
    'ac.uk', // UK academic
    'edu.au', // Australian educational
    'edu.ca', // Canadian educational
  ]);

  const normalizedDomain = domain.toLowerCase();
  
  // Check direct matches
  if (legitimateProviders.has(normalizedDomain)) {
    return true;
  }
  
  // Check educational domains
  if (normalizedDomain.endsWith('.edu') || 
      normalizedDomain.endsWith('.ac.uk') ||
      normalizedDomain.endsWith('.edu.au') ||
      normalizedDomain.endsWith('.edu.ca')) {
    return true;
  }
  
  // Check company domains (basic heuristic - real companies usually have simple domains)
  const parts = normalizedDomain.split('.');
  if (parts.length === 2 && parts[1].length <= 4 && MailChecker.isValid('test@' + normalizedDomain)) {
    return true; // Likely a company domain like company.com
  }
  
  return false;
}
