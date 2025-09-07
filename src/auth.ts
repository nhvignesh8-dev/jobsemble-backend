import { account, databases, isAppwriteConfigured } from '@/lib/appwrite';
import { ID, Models, Query, Permission, Role } from 'appwrite';
import appwriteConfig from '@/lib/appwrite';
import { rateLimitRecovery } from '@/lib/rateLimitRecovery';

export interface User extends Models.Document {
  accountId: string;
  email: string;
  name: string;
}

export interface SignUpData {
  email: string;
  password: string;
  name: string;
}

export interface SignInData {
  email: string;
  password: string;
}

class AuthService {
  private lastRequestTime = 0;
  private retryCount = 0;
  private readonly MIN_REQUEST_INTERVAL = 1000; // Reduced to 1 second between requests
  private readonly MAX_RETRY_ATTEMPTS = 3;
  
  // Check if Appwrite is configured
  private checkAppwriteConfiguration() {
    if (!isAppwriteConfigured || !account) {
      throw new Error('Authentication service is not available. Please try again later.');
    }
  }

  // Improve error messages for production
  private getProductionErrorMessage(error: any): string {
    const errorMessage = error.message || error.toString();
    
    // CORS error - common in production deployments
    if (errorMessage.includes('CORS') || errorMessage.includes('Access-Control-Allow-Origin')) {
      return 'Authentication service temporarily unavailable. Please refresh the page and try again.';
    }
    
    // Network errors
    if (errorMessage.includes('Failed to fetch') || errorMessage.includes('NetworkError')) {
      return 'Connection error. Please check your internet connection and try again.';
    }
    
    // Rate limiting
    if (errorMessage.includes('rate') || errorMessage.includes('limit') || errorMessage.includes('429')) {
      return 'Too many attempts. Please wait a moment and try again.';
    }
    
    // Authentication errors
    if (errorMessage.includes('Invalid credentials') || errorMessage.includes('401')) {
      return 'Invalid email or password. Please check your credentials and try again.';
    }
    
    // User exists
    if (errorMessage.includes('already exists') || errorMessage.includes('409')) {
      return 'An account with this email already exists. Please try signing in instead.';
    }
    
    // Validation errors
    if (errorMessage.includes('validation') || errorMessage.includes('400')) {
      return 'Please check your input and try again.';
    }
    
    // Default user-friendly message
    return 'Something went wrong. Please try again in a moment.';
  }

  // Enhanced rate limiting with exponential backoff
  private async rateLimit(attempt: number = 0) {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    // Only apply rate limiting if the previous request was very recent (less than 1 second)
    // This allows normal user behavior while preventing rapid-fire requests
    if (timeSinceLastRequest < this.MIN_REQUEST_INTERVAL) {
      const waitTime = this.MIN_REQUEST_INTERVAL - timeSinceLastRequest;
      console.log(`Rate limiting: waiting ${Math.round(waitTime)}ms before request`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequestTime = Date.now();
  }

  // Enhanced error handling for rate limits with retry logic
  private async handleRateLimit(error: any, operation: string, retryFunction?: () => Promise<any>): Promise<any> {
    const isRateLimit = error.code === 429 || 
        (error.message && (
          error.message.includes('rate limit') || 
          error.message.includes('Too Many Requests') ||
          error.message.includes('429') ||
          error.message.includes('temporarily unavailable') ||
          error.message.includes('exceeded')
        ));

    if (isRateLimit && retryFunction && this.retryCount < this.MAX_RETRY_ATTEMPTS) {
      this.retryCount++;
      const retryDelay = 3000 * this.retryCount; // 3s, 6s, 9s
      console.log(`Rate limit hit. Retrying in ${retryDelay}ms (attempt ${this.retryCount}/${this.MAX_RETRY_ATTEMPTS})`);
      
      await new Promise(resolve => setTimeout(resolve, retryDelay));
      await this.rateLimit(this.retryCount);
      
      try {
        const result = await retryFunction();
        this.retryCount = 0; // Reset on success
        return result;
      } catch (retryError) {
        return this.handleRateLimit(retryError, operation, retryFunction);
      }
    }

    if (isRateLimit) {
      this.retryCount = 0; // Reset counter
      throw new Error(`Account creation is temporarily busy. Please wait a moment and try again.`);
    }
    
    this.retryCount = 0; // Reset counter for non-rate-limit errors
    throw error;
  }

  // Sign up new user
  async signUp({ email, password, name }: SignUpData) {
    return await this.signUpWithRetry({ email, password, name }, 0);
  }

  // Internal method for signup with retry logic
  private async signUpWithRetry({ email, password, name }: SignUpData, attemptCount: number = 0) {
    console.log('Starting signup process for:', email, `(attempt ${attemptCount + 1})`);
    this.checkAppwriteConfiguration();
    console.log('Appwrite configuration check passed');
    await this.rateLimit(attemptCount);
    
    try {
      console.log('Attempting to create account with Appwrite...');
      // Create account
      const newAccount = await account!.create(
        ID.unique(),
        email,
        password,
        name
      );
      console.log('Account created successfully:', newAccount);

      if (!newAccount) throw new Error('Failed to create account');

      // Send email verification immediately after account creation
      // Create temporary session for verification email, then delete it
      try {
        // Create temporary session for verification permissions
        console.log('Creating temporary session for verification email...');
        await account!.createEmailPasswordSession(email, password);
        
        const verificationUrl = `${window.location.origin}/auth/verify`;
        await account!.createVerification(verificationUrl);
        console.log('Email verification sent successfully');
        
        // Delete the temporary session - user must verify email first
        console.log('Deleting temporary session...');
        await account!.deleteSession('current');
        console.log('Temporary session deleted - user must verify email to log in');
      } catch (verificationError) {
        console.error('Failed to send verification email:', verificationError);
        // Try to clean up session if it was created
        try {
          await account!.deleteSession('current');
        } catch (cleanupError) {
          // Session might not exist, ignore cleanup error
        }
        // Don't fail the entire signup if verification email fails
      }

      // Note: We don't create the user profile document yet
      // Profile will be created after email verification when user logs in
      
      // Reset retry count on success
      this.retryCount = 0;
      
      // Return basic account info for the toast
      return {
        accountId: newAccount.$id,
        name: newAccount.name,
        email: newAccount.email,
        needsVerification: true
      };
    } catch (error: any) {
      console.error('Sign up error details:', {
        error,
        message: error.message,
        code: error.code,
        type: error.type,
        response: error.response
      });
      
      // Log the full error for debugging
      console.error('Full Appwrite error object:', JSON.stringify(error, null, 2));
      
      // Check if this is a rate limit error
      const isRateLimit = error.code === 429 || 
          (error.message && (
            error.message.includes('rate limit') || 
            error.message.includes('Too Many Requests') ||
            error.message.includes('429') ||
            error.message.includes('temporarily unavailable') ||
            error.message.includes('exceeded')
          ));
      
      // For rate limits, fail fast and give immediate user feedback
      if (isRateLimit) {
        // Only try one quick retry for rate limits
        if (attemptCount === 0) {
          console.log('Rate limit hit. Trying once more after short delay...');
          await new Promise(resolve => setTimeout(resolve, 1500)); // Short 1.5s delay
          return this.signUpWithRetry({ email, password, name }, 1);
        } else {
          // After one retry, give user clear feedback immediately
          throw new Error('Our servers are currently busy. Please wait 30 seconds and try again.');
        }
      }
      
      // Handle existing user
      if (error.message && error.message.includes('already exists')) {
        throw new Error('An account with this email already exists. Please use a different email or try logging in.');
      }
      
      // Handle authorization errors with more specific information
      if (error.message && error.message.includes('not authorized')) {
        console.error('🚫 Authorization error detected. Full error details:', error);
        throw new Error('Account creation temporarily unavailable. Please try again in a few minutes.');
      }
      
      // Handle network errors
      if (error.message && (error.message.includes('fetch') || error.message.includes('NetworkError') || error.message.includes('Failed to fetch'))) {
        throw new Error('Network connection error. Please check your internet connection and try again.');
      }
      
      // In development, show the actual error for debugging
      if (import.meta.env.DEV) {
        console.error('🐛 Unhandled signup error in development mode:', error);
        throw new Error(`Signup failed: ${error.message || 'Unknown error'} (Code: ${error.code || 'unknown'})`);
      }
      
      throw error;
    }
  }

  // Sign in user
  async signIn({ email, password }: SignInData) {
    this.checkAppwriteConfiguration();
    
    // Check if we're in recovery mode
    if (rateLimitRecovery.isInRecoveryMode()) {
      throw new Error(rateLimitRecovery.getRecoveryMessage());
    }
    
    // Check and exit recovery if time has passed
    rateLimitRecovery.checkAndExitRecovery();
    
    const attemptLogin = async (): Promise<any> => {
      await this.rateLimit(this.retryCount);
      return await account!.createEmailPasswordSession(email, password);
    };
    
    try {
      const session = await attemptLogin();
      this.retryCount = 0; // Reset on success
      
      // Check if email is verified after successful login
      const currentAccount = await account!.get();
      if (!currentAccount.emailVerification) {
        // Email not verified - delete the session and throw error
        await account!.deleteSession('current');
        throw new Error('Please verify your email before logging in. Check your inbox for the verification link.');
      }
      
      // Create user profile if it doesn't exist (for users who verified email)
      try {
        console.log('Checking/creating user profile after successful login...');
        await this.ensureUserProfile(currentAccount);
      } catch (profileError) {
        console.error('Failed to create user profile:', profileError);
        // Don't fail login if profile creation fails, but log it
      }
      
      return session;
    } catch (error: any) {
      console.error('Sign in error:', error);
      
      // Handle rate limiting with retry
      if (error.code === 429 || error.message?.includes('rate limit')) {
        rateLimitRecovery.enterRecoveryMode();
        try {
          return await this.handleRateLimit(error, 'login', attemptLogin);
        } catch (rateLimitError) {
          throw new Error(rateLimitRecovery.getRecoveryMessage());
        }
      }
      
      // Handle active session error
      if (error.message && error.message.includes('session is active')) {
        try {
          await account!.deleteSession('current');
          await new Promise(resolve => setTimeout(resolve, 2000)); // Increased delay
          const session = await attemptLogin();
          return session;
        } catch (retryError: any) {
          console.error('Retry after session deletion failed:', retryError);
          if (retryError.code === 429 || retryError.message?.includes('rate limit')) {
            rateLimitRecovery.enterRecoveryMode();
            throw new Error(rateLimitRecovery.getRecoveryMessage());
          }
          throw new Error('Authentication error. Please refresh the page and try again.');
        }
      }
      
      // Handle invalid credentials
      if (error.message && (error.message.includes('Invalid credentials') || error.message.includes('invalid'))) {
        throw new Error('Invalid email or password. Please check your credentials and try again.');
      }
      
      throw error;
    }
  }

  // Get current user
  async getCurrentUser() {
    if (!isAppwriteConfigured || !account) {
      return null; // Return null instead of throwing error for this method
    }
    
    try {
      // First check if we have an active session
      const currentAccount = await account.get();
      if (!currentAccount) {
        return null; // No active session
      }

      // Add rate limiting for database queries
      await this.rateLimit();

      const currentUser = await databases!.listDocuments(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        [Query.equal('accountId', currentAccount.$id)]
      );

      if (!currentUser.documents.length) {
        console.warn('User account exists but no user document found in database');
        
        // Check if user's email is verified before creating profile
        if (currentAccount.emailVerification) {
          console.log('Creating missing profile for verified user:', currentAccount.email);
          try {
            await this.saveUserToDB({
              accountId: currentAccount.$id,
              name: currentAccount.name,
              email: currentAccount.email,
            });
            
            // Retry getting the user document
            const retryUser = await databases!.listDocuments(
              appwriteConfig.databaseId,
              appwriteConfig.userCollectionId,
              [Query.equal('accountId', currentAccount.$id)]
            );
            
            if (retryUser.documents.length > 0) {
              console.log('User profile created successfully');
              return retryUser.documents[0] as unknown as User;
            }
          } catch (profileError) {
            console.error('Failed to create user profile in getCurrentUser:', profileError);
          }
        }
        
        return null;
      }

      return currentUser.documents[0] as unknown as User;
    } catch (error: any) {
      // Handle specific error types
      if (error.code === 401 || error.message?.includes('missing scopes') || error.message?.includes('guests')) {
        // User is not authenticated - this is normal, just return null
        return null;
      }
      
      if (error.code === 429 || error.message?.includes('rate limit')) {
        console.warn('Rate limit hit while getting current user, returning null');
        return null;
      }
      
      console.error('Get current user error:', error);
      return null;
    }
  }

  // Sign out user
  async signOut() {
    this.checkAppwriteConfiguration();
    
    try {
      const session = await account!.deleteSession('current');
      return session;
    } catch (error) {
      console.error('Sign out error:', error);
      throw error;
    }
  }

  // Save user to database
  async saveUserToDB({
    accountId,
    email,
    name,
  }: {
    accountId: string;
    email: string;
    name: string;
  }) {
    this.checkAppwriteConfiguration();
    
    try {
      const newUser = await databases!.createDocument(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        ID.unique(),
        {
          accountId,
          email,
          name,
        },
        [
          Permission.read(Role.any()),
          Permission.update(Role.user(accountId)),
          Permission.delete(Role.user(accountId)),
        ]
      );

      return newUser;
    } catch (error) {
      console.error('Save user to DB error:', error);
      throw error;
    }
  }

  // Update user profile
  async updateProfile({ name }: { name?: string }) {
    try {
      const currentUser = await this.getCurrentUser();
      if (!currentUser) throw new Error('No user found');

      const updateData: any = {};
      if (name) updateData.name = name;

      const updatedUser = await databases!.updateDocument(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        currentUser.$id,
        updateData
      );

      return updatedUser;
    } catch (error) {
      console.error('Update profile error:', error);
      throw error;
    }
  }

  // Google OAuth Sign In
  async signInWithGoogle() {
    this.checkAppwriteConfiguration();
    
    try {
      // Create OAuth2 session with Google
      await account!.createOAuth2Session(
        'google' as any, 
        `${window.location.origin}/auth/success`, // Success redirect
        `${window.location.origin}/auth/failure`  // Failure redirect
      );
    } catch (error) {
      console.error('Google sign in error:', error);
      throw error;
    }
  }

  // Handle OAuth callback and create user document
  async handleOAuthCallback() {
    this.checkAppwriteConfiguration();
    
    try {
      // Get the current account after OAuth
      const currentAccount = await account!.get();
      if (!currentAccount) throw new Error('No account found after OAuth');

      // Check if user document already exists
      const existingUser = await databases!.listDocuments(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        [Query.equal('accountId', currentAccount.$id)]
      );

      // If user doesn't exist, create user document
      if (!existingUser.documents.length) {
        const newUser = await this.saveUserToDB({
          accountId: currentAccount.$id,
          email: currentAccount.email,
          name: currentAccount.name,
        });
        return newUser;
      }

      return existingUser.documents[0] as unknown as User;
    } catch (error) {
      console.error('OAuth callback error:', error);
      throw error;
    }
  }

  // Check if user is authenticated
  async isAuthenticated() {
    if (!isAppwriteConfigured || !account) {
      return false;
    }
    
    try {
      await account.get();
      return true;
    } catch {
      return false;
    }
  }

  // Ensure user profile exists, create if missing
  private async ensureUserProfile(userAccount: any) {
    if (!databases) return;
    
    try {
      // Check if profile already exists
      const userDocs = await databases.listDocuments(
        appwriteConfig.databaseId,
        appwriteConfig.userCollectionId,
        [Query.equal('accountId', userAccount.$id)]
      );
      
      if (userDocs.documents.length === 0) {
        // Profile doesn't exist, create it
        console.log('Creating user profile for verified user:', userAccount.email);
        await this.saveUserToDB({
          accountId: userAccount.$id,
          name: userAccount.name,
          email: userAccount.email,
        });
        console.log('User profile created successfully');
      } else {
        console.log('User profile already exists');
      }
    } catch (error) {
      console.error('Error ensuring user profile:', error);
      throw error;
    }
  }

  // Verify email with magic link
  async verifyEmail(userId: string, secret: string) {
    this.checkAppwriteConfiguration();
    
    try {
      await account!.updateVerification(userId, secret);
      return { success: true, message: 'Email verified successfully! You can now log in.' };
    } catch (error: any) {
      console.error('Email verification error:', error);
      
      if (error.message?.includes('invalid') || error.message?.includes('expired')) {
        throw new Error('Invalid or expired verification link. Please request a new verification email.');
      }
      
      throw new Error('Email verification failed. Please try again or contact support.');
    }
  }

  // Resend email verification
  async resendVerificationEmail() {
    this.checkAppwriteConfiguration();
    
    try {
      const verificationUrl = `${window.location.origin}/auth/verify`;
      await account!.createVerification(verificationUrl);
      return { success: true, message: 'Verification email sent! Please check your inbox.' };
    } catch (error: any) {
      console.error('Resend verification error:', error);
      
      if (error.message?.includes('rate limit') || error.code === 429) {
        throw new Error('Please wait before requesting another verification email.');
      }
      
      throw new Error('Failed to send verification email. Please try again later.');
    }
  }

  // Check if current user's email is verified
  async isEmailVerified() {
    if (!isAppwriteConfigured || !account) {
      return false;
    }
    
    try {
      const currentAccount = await account.get();
      return currentAccount.emailVerification;
    } catch {
      return false;
    }
  }
}

export const authService = new AuthService();
export default authService;
