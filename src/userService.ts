import { account, databases, isAppwriteConfigured } from '@/lib/appwrite';
import appwriteConfig from '@/lib/appwrite';
import { ID, Query } from 'appwrite';
import { encryptApiKeys, decryptApiKeys } from '@/lib/encryption';

export interface UserProfile {
  accountId: string;
  name: string;
  email: string;
  avatar?: string; // Avatar identifier for preset options
  preferences?: {
    defaultJobTitle?: string;
    defaultLocation?: string;
    experienceLevel?: string;
    jobType?: string;
    salaryMin?: number;
    salaryMax?: number;
    remote?: boolean;
  };
  apiKeys?: {
    tavilyApiKey?: string;
    tavilyUsageCount?: number;  // Track free usage (max 3, never resets)
    tavilyUsageLimit?: number;  // Free limit (default 3)
    googleSheetsConnected?: boolean;
  };
  createdAt?: string;
  updatedAt?: string;
}

export class UserService {
  // Get current user profile from Appwrite
  static async getCurrentUserProfile(): Promise<UserProfile | null> {
    if (!isAppwriteConfigured || !account || !databases) {
      console.warn('Appwrite not configured');
      return null;
    }

    try {
      // Get current user from account
      const currentUser = await account.get();
      
      // Try to get user profile from database
      try {
        const userDocs = await databases.listDocuments(
          appwriteConfig.databaseId,
          appwriteConfig.userCollectionId,
          [Query.equal('accountId', currentUser.$id)]
        );

        if (userDocs.documents.length > 0) {
          const profile = userDocs.documents[0];
          return {
            accountId: profile.accountId,
            name: profile.name || currentUser.name,
            email: profile.email || currentUser.email,
            avatar: profile.avatar || 'avatar-1',
            preferences: profile.preferences ? JSON.parse(profile.preferences) : {},
            apiKeys: profile.apiKeys ? decryptApiKeys(JSON.parse(profile.apiKeys)) : {
              tavilyApiKey: '',
              tavilyUsageCount: 0,
              tavilyUsageLimit: 3,
              googleSheetsConnected: false
            },
            createdAt: profile.$createdAt,
            updatedAt: profile.$updatedAt
          };
        } else {
          // Create new profile document if doesn't exist
          return await this.createUserProfile(currentUser.$id, currentUser.name, currentUser.email);
        }
      } catch (dbError) {
        console.error('Database error, creating new profile:', dbError);
        return await this.createUserProfile(currentUser.$id, currentUser.name, currentUser.email);
      }
    } catch (error) {
      console.error('Error getting user profile:', error);
      return null;
    }
  }

  // Create new user profile in database
  static async createUserProfile(userId: string, name: string, email: string): Promise<UserProfile | null> {
    if (!isAppwriteConfigured || !databases) {
      return null;
    }

    try {
      const newProfile = {
        accountId: userId, // Use accountId as expected by database schema
        name,
        email,
        avatar: 'avatar-1',
        preferences: JSON.stringify({
          defaultJobTitle: '',
          defaultLocation: '',
          experienceLevel: 'Mid Level',
          jobType: 'Full-time',
          salaryMin: 0,
          salaryMax: 0,
          remote: false
        }),
        apiKeys: JSON.stringify(encryptApiKeys({
          tavilyApiKey: '',
          tavilyUsageCount: 0,
          tavilyUsageLimit: 3,
          googleSheetsConnected: false
        }))
      };

      const document = await databases.createDocument(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        ID.unique(),
        newProfile
      );

      return {
        accountId: document.accountId,
        name: document.name,
        email: document.email,
        avatar: document.avatar,
        preferences: JSON.parse(document.preferences),
        apiKeys: decryptApiKeys(JSON.parse(document.apiKeys)),
        createdAt: document.$createdAt,
        updatedAt: document.$updatedAt
      };
    } catch (error) {
      console.error('Error creating user profile:', error);
      return null;
    }
  }

  // Update user profile
  static async updateUserProfile(updates: Partial<UserProfile>): Promise<boolean> {
    if (!isAppwriteConfigured || !account || !databases) {
      console.warn('Appwrite not configured');
      return false;
    }

    try {
      const currentUser = await account.get();
      
      // Find user document
      const userDocs = await databases.listDocuments(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        [Query.equal('userId', currentUser.$id)]
      );

      if (userDocs.documents.length === 0) {
        console.error('User profile not found');
        return false;
      }

      const documentId = userDocs.documents[0].$id;
      
      // Prepare update data - stringify objects
      const updateData: any = {};
      
      if (updates.name !== undefined) updateData.name = updates.name;
      if (updates.email !== undefined) updateData.email = updates.email;
      if (updates.avatar !== undefined) updateData.avatar = updates.avatar;
      if (updates.preferences !== undefined) updateData.preferences = JSON.stringify(updates.preferences);
      if (updates.notifications !== undefined) updateData.notifications = JSON.stringify(updates.notifications);
      if (updates.privacy !== undefined) updateData.privacy = JSON.stringify(updates.privacy);
      if (updates.security !== undefined) updateData.security = JSON.stringify(updates.security);
      if (updates.apiKeys !== undefined) updateData.apiKeys = JSON.stringify(encryptApiKeys(updates.apiKeys));

      await databases.updateDocument(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        documentId,
        updateData
      );

      return true;
    } catch (error) {
      console.error('Error updating user profile:', error);
      return false;
    }
  }

  // Update password
  static async updatePassword(currentPassword: string, newPassword: string): Promise<boolean> {
    if (!isAppwriteConfigured || !account) {
      console.warn('Appwrite not configured');
      return false;
    }

    try {
      await account.updatePassword(newPassword, currentPassword);
      
      // Profile updated successfully without additional security fields

      return true;
    } catch (error) {
      console.error('Error updating password:', error);
      return false;
    }
  }

  // Delete user account
  static async deleteUserAccount(): Promise<boolean> {
    if (!isAppwriteConfigured || !account || !databases) {
      console.warn('Appwrite not configured');
      return false;
    }

    try {
      const currentUser = await account.get();
      
      // Delete user profile from database
      const userDocs = await databases.listDocuments(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        [Query.equal('userId', currentUser.$id)]
      );

      if (userDocs.documents.length > 0) {
        await databases.deleteDocument(
          appwriteConfig.databaseId,
          appwriteConfig.userCollectionId,
          userDocs.documents[0].$id
        );
      }

      // Delete account
      await account.deleteAccount();

      return true;
    } catch (error) {
      console.error('Error deleting user account:', error);
      return false;
    }
  }

  // Get active sessions
  static async getActiveSessions(): Promise<number> {
    if (!isAppwriteConfigured || !account) {
      return 0;
    }

    try {
      const sessions = await account.listSessions();
      return sessions.sessions.length;
    } catch (error) {
      console.error('Error getting sessions:', error);
      return 0;
    }
  }

  // Logout from all other sessions
  static async logoutFromOtherSessions(): Promise<boolean> {
    if (!isAppwriteConfigured || !account) {
      return false;
    }

    try {
      const sessions = await account.listSessions();
      const currentSession = await account.getSession('current');
      
      // Delete all sessions except current
      for (const session of sessions.sessions) {
        if (session.$id !== currentSession.$id) {
          await account.deleteSession(session.$id);
        }
      }

      return true;
    } catch (error) {
      console.error('Error logging out from other sessions:', error);
      return false;
    }
  }

  // Check if user has free Tavily searches remaining
  static async checkTavilyUsage(): Promise<{ hasFreesLeft: boolean; count: number; limit: number }> {
    const profile = await this.getCurrentUserProfile();
    if (!profile || !profile.apiKeys) {
      return { hasFreesLeft: true, count: 0, limit: 3 };
    }

    const apiKeys = profile.apiKeys;
    const count = apiKeys.tavilyUsageCount || 0;
    const limit = apiKeys.tavilyUsageLimit || 3;
    
    return { 
      hasFreesLeft: count < limit, 
      count, 
      limit 
    };
  }

  // Increment Tavily usage count
  static async incrementTavilyUsage(): Promise<boolean> {
    const profile = await this.getCurrentUserProfile();
    if (!profile || !profile.apiKeys) {
      return false;
    }

    const apiKeys = profile.apiKeys;
    const currentCount = apiKeys.tavilyUsageCount || 0;
    
    return await this.updateUserProfile({
      apiKeys: {
        ...apiKeys,
        tavilyUsageCount: currentCount + 1
      }
    });
  }

  // Get effective Tavily API key (system or user's)
  static async getTavilyApiKey(): Promise<{ apiKey: string; isUserKey: boolean; usage: any }> {
    const usage = await this.checkTavilyUsage();
    const profile = await this.getCurrentUserProfile();
    
    // If user has free searches left, use system key (backend will handle this)
    if (usage.hasFreesLeft) {
      // Increment usage when using system key
      await this.incrementTavilyUsage();
      return {
        apiKey: '', // Frontend should not have access to system API key
        isUserKey: false,
        usage: {
          ...usage,
          count: usage.count + 1 // Updated count
        }
      };
    }
    
    // User exhausted free searches, check for user's API key
    const userApiKey = profile?.apiKeys?.tavilyApiKey;
    if (userApiKey) {
      return {
        apiKey: userApiKey,
        isUserKey: true,
        usage
      };
    }
    
    // No API key available
    throw new Error('API_KEY_REQUIRED');
  }

  // Save user's Tavily API key
  static async saveTavilyApiKey(apiKey: string): Promise<boolean> {
    const profile = await this.getCurrentUserProfile();
    if (!profile) {
      return false;
    }

    return await this.updateUserProfile({
      apiKeys: {
        ...profile.apiKeys,
        tavilyApiKey: apiKey
      }
    });
  }
}
