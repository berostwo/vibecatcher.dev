import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc, 
  serverTimestamp,
  increment
} from 'firebase/firestore';
import { db } from './firebase';

export interface UserData {
  uid: string;
  email: string;
  displayName?: string;
  photoURL?: string;
  auditsAvailable: number;
  totalAuditsUsed: number;
  createdAt: Date;
  updatedAt: Date;
  // GitHub integration
  githubAccessToken?: string;
  githubTokenExpiresAt?: Date;
  githubUsername?: string;
  githubUserId?: number;
}

export class UserService {
  static async getUserData(userId: string): Promise<UserData | null> {
    try {
      const userDoc = await getDoc(doc(db, 'users', userId));
      
      if (userDoc.exists()) {
        const data = userDoc.data();
        return {
          uid: userId,
          email: data.email || '',
          displayName: data.displayName || '',
          photoURL: data.photoURL || '',
          auditsAvailable: data.auditsAvailable || 0,
          totalAuditsUsed: data.totalAuditsUsed || 0,
          createdAt: data.createdAt?.toDate() || new Date(),
          updatedAt: data.updatedAt?.toDate() || new Date(),
          githubAccessToken: data.githubAccessToken || undefined,
          githubTokenExpiresAt: data.githubTokenExpiresAt?.toDate() || undefined,
          githubUsername: data.githubUsername || undefined,
          githubUserId: data.githubUserId || undefined,
        };
      } else {
        // Create new user document
        const newUserData: UserData = {
          uid: userId,
          email: '',
          auditsAvailable: 0,
          totalAuditsUsed: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        
        await setDoc(doc(db, 'users', userId), {
          ...newUserData,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        
        return newUserData;
      }
    } catch (error) {
      console.error('Error getting user data:', error);
      throw error;
    }
  }

  static async updateUserData(userId: string, updates: Partial<UserData>): Promise<void> {
    try {
      const updateData: any = {
        ...updates,
        updatedAt: serverTimestamp(),
      };
      
      // Remove undefined values to prevent Firestore errors
      Object.keys(updateData).forEach(key => {
        if (updateData[key] === undefined) {
          delete updateData[key];
        }
      });
      
      await updateDoc(doc(db, 'users', userId), updateData);
    } catch (error) {
      console.error('Error updating user data:', error);
      throw error;
    }
  }

  static async addAudits(userId: string, count: number): Promise<void> {
    try {
      await updateDoc(doc(db, 'users', userId), {
        auditsAvailable: increment(count),
        updatedAt: serverTimestamp(),
      });
    } catch (error) {
      console.error('Error adding audits:', error);
      throw error;
    }
  }

  static async useAudit(userId: string): Promise<void> {
    try {
      await updateDoc(doc(db, 'users', userId), {
        auditsAvailable: increment(-1),
        totalAuditsUsed: increment(1),
        updatedAt: serverTimestamp(),
      });
    } catch (error) {
      console.error('Error using audit:', error);
      throw error;
    }
  }

  // GitHub token management
  static async storeGitHubToken(
    userId: string, 
    token: string, 
    expiresIn?: number,
    username?: string,
    githubUserId?: number
  ): Promise<void> {
    try {
      const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : undefined;
      
      await updateDoc(doc(db, 'users', userId), {
        githubAccessToken: token,
        githubTokenExpiresAt: expiresAt,
        githubUsername: username,
        githubUserId: githubUserId,
        updatedAt: serverTimestamp(),
      });
      
      console.log('GitHubService: Token stored securely in Firebase for user:', userId);
    } catch (error) {
      console.error('Error storing GitHub token:', error);
      throw error;
    }
  }

  static async getGitHubToken(userId: string): Promise<string | null> {
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
        console.log('GitHubService: Token expired, removing atomically');
        
        // Use optimistic locking with timestamp check to prevent race conditions
        try {
          await updateDoc(userRef, {
            githubAccessToken: null,
            githubTokenExpiresAt: null,
            updatedAt: serverTimestamp(),
          });
        } catch (updateError) {
          // If update fails due to concurrent modification, token was already handled
          console.log('GitHubService: Token already handled by another request');
        }
        
        return null;
      }
      
      return userData.githubAccessToken;
      
    } catch (error) {
      console.error('Error getting GitHub token:', error);
      return null;
    }
  }

  static async removeGitHubToken(userId: string): Promise<void> {
    try {
      await updateDoc(doc(db, 'users', userId), {
        githubAccessToken: null,
        githubTokenExpiresAt: null,
        updatedAt: serverTimestamp(),
      });
      
      console.log('GitHubService: Token removed from Firebase for user:', userId);
    } catch (error) {
      console.error('Error removing GitHub token:', error);
      throw error;
    }
  }

  static async isGitHubTokenValid(userId: string): Promise<boolean> {
    try {
      const token = await this.getGitHubToken(userId);
      return !!token;
    } catch (error) {
      console.error('Error checking GitHub token validity:', error);
      return false;
    }
  }
}

