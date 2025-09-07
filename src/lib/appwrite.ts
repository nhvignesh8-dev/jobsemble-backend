import { Client, Account, Databases, Storage } from 'appwrite';

// Debug environment variables
console.log('Environment variables check:', {
  VITE_APPWRITE_ENDPOINT: import.meta.env.VITE_APPWRITE_ENDPOINT,
  VITE_APPWRITE_PROJECT_ID: import.meta.env.VITE_APPWRITE_PROJECT_ID,
  VITE_APPWRITE_DATABASE_ID: import.meta.env.VITE_APPWRITE_DATABASE_ID,
});

// Appwrite configuration - using hardcoded values for now
const appwriteConfig = {
  endpoint: import.meta.env.VITE_APPWRITE_ENDPOINT || 'https://nyc.cloud.appwrite.io/v1',
  projectId: import.meta.env.VITE_APPWRITE_PROJECT_ID || '68bb20f90028125703bb',
  databaseId: import.meta.env.VITE_APPWRITE_DATABASE_ID || 'job-scout-db',
  userCollectionId: import.meta.env.VITE_APPWRITE_USER_COLLECTION_ID || 'users',
  jobCollectionId: import.meta.env.VITE_APPWRITE_JOB_COLLECTION_ID || 'jobs',
  storageId: import.meta.env.VITE_APPWRITE_STORAGE_ID || 'files',
};

// Initialize Appwrite client - only if we have a valid project ID
let client: Client | null = null;
let account: Account | null = null;
let databases: Databases | null = null;
let storage: Storage | null = null;

// Check if Appwrite is properly configured
const isAppwriteConfigured = appwriteConfig.projectId && 
  appwriteConfig.projectId !== 'demo-project-id' && 
  appwriteConfig.projectId !== 'your-project-id' &&
  appwriteConfig.projectId !== 'job-scout-automaton';

console.log('Appwrite configuration:', {
  ...appwriteConfig,
  isConfigured: isAppwriteConfigured
});

if (isAppwriteConfigured) {
  try {
    client = new Client()
      .setEndpoint(appwriteConfig.endpoint)
      .setProject(appwriteConfig.projectId);
    
    account = new Account(client);
    databases = new Databases(client);
    storage = new Storage(client);
  } catch (error) {
    console.warn('Appwrite initialization failed:', error);
  }
}

// Export services (will be null if not configured)
export { account, databases, storage };
export { isAppwriteConfigured };
export default appwriteConfig;
