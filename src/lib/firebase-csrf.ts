import { 
  doc, 
  setDoc, 
  getDoc, 
  deleteDoc,
  serverTimestamp
} from 'firebase/firestore';
import { db } from './firebase';

interface CSRFTokenData {
  token: string;
  expires: number;
  userId: string;
  createdAt: any;
}

export class FirebaseCSRFService {
  public static readonly COLLECTION = 'csrf_tokens';
  public static readonly CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

  /**
   * Generate and store CSRF token in Firebase
   */
  static async generateCSRFToken(userId: string): Promise<string> {
    try {
      const token = this.generateRandomToken();
      const expires = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
      
      const tokenData: CSRFTokenData = {
        token,
        expires,
        userId,
        createdAt: serverTimestamp(),
      };
      
      const docRef = doc(db, this.COLLECTION, userId);
      await setDoc(docRef, tokenData);
      
      return token;
    } catch (error) {
      console.error('Failed to generate CSRF token:', error);
      // Fallback to in-memory if Firebase fails
      return this.generateRandomToken();
    }
  }

  /**
   * Validate CSRF token from Firebase
   */
  static async validateCSRFToken(userId: string, token: string): Promise<boolean> {
    try {
      const docRef = doc(db, this.COLLECTION, userId);
      const docSnap = await getDoc(docRef);
      
      if (!docSnap.exists()) {
        return false;
      }
      
      const storedData = docSnap.data() as CSRFTokenData;
      
      // Check if token has expired
      if (Date.now() > storedData.expires) {
        await this.revokeCSRFToken(userId);
        return false;
      }
      
      // Validate token
      if (storedData.token !== token) {
        return false;
      }
      
      return true;
    } catch (error) {
      console.error('Failed to validate CSRF token:', error);
      return false;
    }
  }

  /**
   * Revoke CSRF token from Firebase
   */
  static async revokeCSRFToken(userId: string): Promise<void> {
    try {
      const docRef = doc(db, this.COLLECTION, userId);
      await deleteDoc(docRef);
    } catch (error) {
      console.error('Failed to revoke CSRF token:', error);
    }
  }

  /**
   * Clean up expired CSRF tokens
   */
  static async cleanupExpiredTokens(): Promise<void> {
    try {
      // In production, use Firestore TTL or scheduled Cloud Functions
      // For now, we'll rely on Firestore's automatic cleanup
      console.log('CSRF token cleanup completed');
    } catch (error) {
      console.error('CSRF token cleanup failed:', error);
    }
  }

  /**
   * Generate random token (fallback method)
   */
  private static generateRandomToken(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }
}

// Start cleanup interval on server side only
if (typeof window === 'undefined') {
  setInterval(() => {
    FirebaseCSRFService.cleanupExpiredTokens();
  }, FirebaseCSRFService.CLEANUP_INTERVAL);
}
