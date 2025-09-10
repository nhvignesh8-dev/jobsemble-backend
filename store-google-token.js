#!/usr/bin/env node

import { Client, Databases, Query, ID } from 'appwrite';
import crypto from 'crypto';

// Appwrite configuration
const APPWRITE_ENDPOINT = 'https://nyc.cloud.appwrite.io/v1';
const APPWRITE_PROJECT_ID = '68c0dafb0032ed52a334';
const DATABASE_ID = '68c0dafb0032ed52a334';
const COLLECTION_ID = '68c0dafb0032ed52a334';

// Initialize Appwrite client
const client = new Client();
client
  .setEndpoint(APPWRITE_ENDPOINT)
  .setProject(APPWRITE_PROJECT_ID)
  .setKey('a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6'); // Replace with your API key

const databases = new Databases(client);

// Encryption function (same as in server.js)
function encrypt(text) {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_KEY not found');
  }
  
  // Normalize key
  let normalizedKey = key.trim().replace(/\s+/g, '');
  
  let keyBuffer;
  if (/^[0-9a-fA-F]+$/.test(normalizedKey)) {
    if (normalizedKey.length === 64) {
      keyBuffer = Buffer.from(normalizedKey, 'hex');
    } else if (normalizedKey.length === 128) {
      keyBuffer = crypto.createHash('sha256').update(Buffer.from(normalizedKey, 'hex')).digest();
    } else {
      throw new Error(`Invalid hex key length: ${normalizedKey.length}`);
    }
  } else {
    keyBuffer = crypto.createHash('sha256').update(normalizedKey, 'utf8').digest();
  }
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher('aes-256-cbc', keyBuffer);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

async function storeGoogleToken() {
  try {
    const GOOGLE_ACCESS_TOKEN = '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';
    const SYSTEM_USER_ID = 'SYSTEM_API_KEYS';
    
    console.log('🔒 Encrypting Google OAuth token...');
    const encryptedToken = encrypt(GOOGLE_ACCESS_TOKEN);
    console.log('✅ Token encrypted');
    
    // Check if system document exists
    console.log('🔍 Looking for existing system document...');
    const systemDocs = await databases.listDocuments(
      DATABASE_ID,
      COLLECTION_ID,
      [Query.equal('userId', SYSTEM_USER_ID)]
    );
    
    if (systemDocs.documents.length > 0) {
      console.log('📝 Updating existing system document...');
      const systemDoc = systemDocs.documents[0];
      const existingApiKeys = JSON.parse(systemDoc.apiKeys || '{}');
      existingApiKeys.systemGoogleAccessToken = encryptedToken;
      
      await databases.updateDocument(
        DATABASE_ID,
        COLLECTION_ID,
        systemDoc.$id,
        {
          apiKeys: JSON.stringify(existingApiKeys)
        }
      );
      console.log('✅ Updated existing system document');
    } else {
      console.log('📝 Creating new system document...');
      await databases.createDocument(
        DATABASE_ID,
        COLLECTION_ID,
        ID.unique(),
        {
          userId: SYSTEM_USER_ID,
          accountId: SYSTEM_USER_ID,
          apiKeys: JSON.stringify({
            systemSerpApiKey: '',
            systemTavilyApiKey: '',
            systemGoogleAccessToken: encryptedToken
          })
        }
      );
      console.log('✅ Created new system document');
    }
    
    console.log('🎉 Google OAuth token stored successfully!');
    
  } catch (error) {
    console.error('❌ Error storing Google OAuth token:', error);
    process.exit(1);
  }
}

// Run the script
storeGoogleToken();
