#!/usr/bin/env node

/**
 * Setup Google OAuth Token in Database
 * 
 * This script stores the Google OAuth token encrypted in the database
 * using the same security pattern as SERP and Tavily API keys.
 */

import { Client, Databases, Query, ID } from 'appwrite';
import crypto from 'crypto';

// Appwrite Configuration
const client = new Client()
  .setEndpoint(process.env.VITE_APPWRITE_ENDPOINT || 'https://nyc.cloud.appwrite.io/v1')
  .setProject(process.env.VITE_APPWRITE_PROJECT_ID || '68bb20f90028125703bb');

const databases = new Databases(client);

const DATABASE_ID = process.env.VITE_APPWRITE_DATABASE_ID || 'job-scout-db';
const COLLECTION_ID = process.env.VITE_APPWRITE_COLLECTION_ID || 'users';

// Use the same encryption key as the main server
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || Buffer.from('12345678901234567890123456789012', 'utf8');

// Encryption function (same as server.js)
function encrypt(text) {
  if (!text) return '';
  
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return iv.toString('hex') + ':' + encrypted;
}

async function setupGoogleOAuthToken() {
  try {
    const googleAccessToken = process.env.GOOGLE_ACCESS_TOKEN;
    
    if (!googleAccessToken) {
      console.error('❌ GOOGLE_ACCESS_TOKEN environment variable not set');
      console.error('Please set GOOGLE_ACCESS_TOKEN=your_token_here');
      process.exit(1);
    }

    console.log('🔒 Encrypting Google OAuth token...');
    const encryptedToken = encrypt(googleAccessToken);
    
    const SYSTEM_USER_ID = 'SYSTEM_API_KEYS';
    
    // Check if system document exists
    let systemDoc;
    try {
      const systemDocs = await databases.listDocuments(
        DATABASE_ID,
        COLLECTION_ID,
        [Query.equal('accountId', SYSTEM_USER_ID)]
      );
      
      if (systemDocs.documents.length > 0) {
        systemDoc = systemDocs.documents[0];
        console.log('📄 Found existing system document');
      } else {
        console.log('📄 Creating new system document...');
        systemDoc = await databases.createDocument(
          DATABASE_ID,
          COLLECTION_ID,
          ID.unique(),
          {
            accountId: SYSTEM_USER_ID,
            apiKeys: JSON.stringify({
              systemTavilyApiKey: '',
              systemGoogleAccessToken: encryptedToken
            })
          }
        );
        console.log('✅ Created new system document');
      }
    } catch (error) {
      console.error('❌ Error accessing system document:', error);
      process.exit(1);
    }

    // Update the system document with encrypted Google OAuth token
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

    console.log('✅ Google OAuth token stored securely in database');
    console.log('🔐 Token is encrypted and stored in system storage');
    console.log('🚀 Backend can now use Google Sheets API for filter operations');
    
  } catch (error) {
    console.error('❌ Error setting up Google OAuth token:', error);
    process.exit(1);
  }
}

// Run the setup
setupGoogleOAuthToken();
