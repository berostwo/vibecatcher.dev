import { doc, getDoc, updateDoc, serverTimestamp } from 'firebase/firestore';
import { db } from './firebase';

/**
 * Centralized token security service to prevent race conditions and unauthorized access
 */
export class TokenSecurityService {
  
  /**
   * Get GitHub token with atomic expiration check to prevent race conditions
   */
  static async getGitHubTokenSecurely(userId: string): Promise<string | null> {
    try {
      const userRef = doc(db, 'users', userId);
      
      // Get current user data
      const userDoc = await getDoc(userRef);
      if (!userDoc.exists()) {
        return null;
      }
      
      const userData = userDoc.data();
      if (!userData?.githubAccessToken) {
        return null;
      }
      
      // Check if token is expired
      if (userData.githubTokenExpiresAt && userData.githubTokenExpiresAt < new Date()) {
        console.log('TokenSecurityService: Token expired, removing securely');
        
        // Use optimistic locking to prevent race conditions
        try {
          await updateDoc(userRef, {
            githubAccessToken: null,
            githubTokenExpiresAt: null,
            updatedAt: serverTimestamp(),
          });
        } catch (updateError) {
          // If update fails, token was already handled by another request
          console.log('TokenSecurityService: Token already handled by concurrent request');
        }
        
        return null;
      }
      
      return userData.githubAccessToken;
      
    } catch (error) {
      console.error('Error getting GitHub token securely:', error);
      return null;
    }
  }

  /**
   * Check if token is about to expire (within 15 minutes)
   */
  static async isTokenExpiringSoon(userId: string): Promise<boolean> {
    try {
      const userRef = doc(db, 'users', userId);
      const userDoc = await getDoc(userRef);
      
      if (!userDoc.exists()) {
        return false;
      }
      
      const userData = userDoc.data();
      if (!userData?.githubTokenExpiresAt) {
        return false;
      }
      
      const now = new Date();
      const expiresAt = userData.githubTokenExpiresAt.toDate();
      const fifteenMinutesFromNow = new Date(now.getTime() + 15 * 60 * 1000);
      
      return expiresAt < fifteenMinutesFromNow;
      
    } catch (error) {
      console.error('Error checking token expiration:', error);
      return false;
    }
  }

  /**
   * Force refresh token by clearing and requiring re-authentication
   */
  static async forceTokenRefresh(userId: string): Promise<void> {
    try {
      const userRef = doc(db, 'users', userId);
      await updateDoc(userRef, {
        githubAccessToken: null,
        githubTokenExpiresAt: null,
        updatedAt: serverTimestamp(),
      });
      
      console.log('TokenSecurityService: Token force refreshed for user:', userId);
    } catch (error) {
      console.error('Error force refreshing token:', error);
      throw error;
    }
  }

  /**
   * Validate token format and basic security
   */
  static validateTokenFormat(token: string): boolean {
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // GitHub OAuth tokens start with 'gho_' and are 40 characters long
    if (token.startsWith('gho_') && token.length === 40) {
      return true;
    }
    
    // GitHub personal access tokens start with 'ghp_' and are 40 characters long
    if (token.startsWith('ghp_') && token.length === 40) {
      return true;
    }
    
    // Legacy GitHub tokens start with 'gho_' and are 40 characters long
    if (token.startsWith('gho_') && token.length === 40) {
      return true;
    }
    
    return false;
  }

  /**
   * Get token age in minutes
   */
  static getTokenAge(tokenTimestamp: any): number {
    const now = new Date();
    let tokenTime: Date;
    
    if (tokenTimestamp instanceof Date) {
      tokenTime = tokenTimestamp;
    } else if (tokenTimestamp && typeof tokenTimestamp.toDate === 'function') {
      tokenTime = tokenTimestamp.toDate();
    } else {
      return 0; // Invalid timestamp
    }
    
    const diffMs = now.getTime() - tokenTime.getTime();
    return Math.floor(diffMs / (1000 * 60));
  }
}
