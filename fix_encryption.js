/**
 * Fix ENCRYPTION_KEY format in server.js
 * This makes the code more resilient to different key formats
 */

import fs from 'fs';

const serverFile = 'server.js';
const serverContent = fs.readFileSync(serverFile, 'utf8');

// Find the ENCRYPTION_KEY_BUFFER line
const bufferLineRegex = /const ENCRYPTION_KEY_BUFFER = Buffer\.from\(ENCRYPTION_KEY, 'hex'\);/;

// Replace with more robust key handling
const robustKeyHandling = `
// Normalize encryption key (strip spaces, ensure proper hex format)
let normalizedKey = ENCRYPTION_KEY.replace(/\\s+/g, '');
if (normalizedKey.length !== 64) {
  console.error(\`❌ ENCRYPTION_KEY must be 64 hex characters (32 bytes). Current length: \${normalizedKey.length}\`);
  process.exit(1);
}

// Convert hex string to buffer for encryption operations
const ENCRYPTION_KEY_BUFFER = Buffer.from(normalizedKey, 'hex');
console.log(\`✅ ENCRYPTION_KEY validated: \${normalizedKey.length} chars, \${ENCRYPTION_KEY_BUFFER.length} bytes\`);
`;

// Replace the line
const updatedContent = serverContent.replace(bufferLineRegex, robustKeyHandling);

// Write back to file
fs.writeFileSync(serverFile, updatedContent);

console.log('✅ Updated server.js with robust ENCRYPTION_KEY handling');
