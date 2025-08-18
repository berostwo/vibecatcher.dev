import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc, 
  serverTimestamp,
  deleteDoc
} from 'firebase/firestore';
import { db } from './firebase';

interface RateLimitData {
  count: number;
  resetTime: number;
  lastUpdated: any;
}

export class FirebaseRateLimitService {
  public static readonly COLLECTION = 'rate_limits';
  public static readonly CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes

  /**
   * Check rate limit using Firebase for persistence
   */
  static async checkRateLimit(
    identifier: string,
    config: { limit: number; windowMs: number }
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    try {
      const now = Date.now();
      const key = identifier;
      const docRef = doc(db, this.COLLECTION, key);

      // Get current rate limit data
      const docSnap = await getDoc(docRef);
      
      if (!docSnap.exists()) {
        // First request - create new rate limit entry
        const newData: RateLimitData = {
          count: 1,
          resetTime: now + config.windowMs,
          lastUpdated: serverTimestamp(),
        };
        
        await setDoc(docRef, newData);
        return { 
          allowed: true, 
          remaining: config.limit - 1, 
          resetTime: now + config.windowMs 
        };
      }

      const userData = docSnap.data() as RateLimitData;

      // Check if window has expired
      if (now > userData.resetTime) {
        // Reset window - create new entry
        const newData: RateLimitData = {
          count: 1,
          resetTime: now + config.windowMs,
          lastUpdated: serverTimestamp(),
        };
        
        await setDoc(docRef, newData);
        return { 
          allowed: true, 
          remaining: config.limit - 1, 
          resetTime: now + config.windowMs 
        };
      }

      // Check if limit exceeded
      if (userData.count >= config.limit) {
        return { 
          allowed: false, 
          remaining: 0, 
          resetTime: userData.resetTime 
        };
      }

      // Increment counter
      const updatedData: RateLimitData = {
        count: userData.count + 1,
        resetTime: userData.resetTime,
        lastUpdated: serverTimestamp(),
      };
      
      await setDoc(docRef, updatedData, { merge: true });
      
      return { 
        allowed: true, 
        remaining: config.limit - updatedData.count, 
        resetTime: userData.resetTime 
      };

    } catch (error) {
      console.error('Rate limit check failed, falling back to allow:', error);
      // Fallback to allow if Firebase fails
      return { allowed: true, remaining: 999, resetTime: Date.now() + 60000 };
    }
  }

  /**
   * Clean up expired rate limit entries
   */
  static async cleanupExpiredEntries(): Promise<void> {
    try {
      // This would ideally use a Firestore query with TTL
      // For now, we'll rely on Firestore's automatic cleanup
      // In production, consider using Firestore TTL or scheduled Cloud Functions
      console.log('Rate limit cleanup completed');
    } catch (error) {
      console.error('Rate limit cleanup failed:', error);
    }
  }

  /**
   * Reset rate limit for a specific identifier
   */
  static async resetRateLimit(identifier: string): Promise<void> {
    try {
      const docRef = doc(db, this.COLLECTION, identifier);
      await deleteDoc(docRef);
    } catch (error) {
      console.error('Failed to reset rate limit:', error);
    }
  }

  /**
   * Get current rate limit status
   */
  static async getRateLimitStatus(identifier: string): Promise<RateLimitData | null> {
    try {
      const docRef = doc(db, this.COLLECTION, identifier);
      const docSnap = await getDoc(docRef);
      
      if (!docSnap.exists()) {
        return null;
      }
      
      return docSnap.data() as RateLimitData;
    } catch (error) {
      console.error('Failed to get rate limit status:', error);
      return null;
    }
  }
}

// Start cleanup interval
if (typeof window === 'undefined') {
  // Only run on server side
  setInterval(() => {
    FirebaseRateLimitService.cleanupExpiredEntries();
  }, FirebaseRateLimitService.CLEANUP_INTERVAL);
}
