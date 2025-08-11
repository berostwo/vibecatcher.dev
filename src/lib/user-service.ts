import { db } from './firebase';
import { 
  doc, 
  getDoc, 
  setDoc, 
  updateDoc, 
  increment,
  serverTimestamp 
} from 'firebase/firestore';

export interface UserData {
  uid: string;
  email: string;
  displayName?: string;
  photoURL?: string;
  auditsAvailable: number;
  totalAuditsUsed: number;
  createdAt: any;
  updatedAt: any;
}

export class UserService {
  private static COLLECTION = 'users';

  // Get or create user data (with free audit for new users)
  static async getUserData(uid: string, email: string, displayName?: string, photoURL?: string): Promise<UserData> {
    const userRef = doc(db, this.COLLECTION, uid);
    const userSnap = await getDoc(userRef);

    if (userSnap.exists()) {
      // User exists, return their data
      return userSnap.data() as UserData;
    } else {
      // New user - create with 1 free audit
      const newUserData: UserData = {
        uid,
        email,
        displayName,
        photoURL,
        auditsAvailable: 1, // Free audit for new users
        totalAuditsUsed: 0,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };

      await setDoc(userRef, newUserData);
      return newUserData;
    }
  }

  // Update user data
  static async updateUserData(uid: string, updates: Partial<UserData>): Promise<void> {
    const userRef = doc(db, this.COLLECTION, uid);
    await updateDoc(userRef, {
      ...updates,
      updatedAt: serverTimestamp(),
    });
  }

  // Add audits to user account
  static async addAudits(uid: string, count: number): Promise<void> {
    const userRef = doc(db, this.COLLECTION, uid);
    await updateDoc(userRef, {
      auditsAvailable: increment(count),
      updatedAt: serverTimestamp(),
    });
  }

  // Use an audit
  static async useAudit(uid: string): Promise<boolean> {
    const userRef = doc(db, this.COLLECTION, uid);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      throw new Error('User not found');
    }

    const userData = userSnap.data() as UserData;
    
    if (userData.auditsAvailable <= 0) {
      return false; // No audits available
    }

    await updateDoc(userRef, {
      auditsAvailable: increment(-1),
      totalAuditsUsed: increment(1),
      updatedAt: serverTimestamp(),
    });

    return true;
  }

  // Get user's current audit count
  static async getAuditsAvailable(uid: string): Promise<number> {
    const userRef = doc(db, this.COLLECTION, uid);
    const userSnap = await getDoc(userRef);
    
    if (!userSnap.exists()) {
      return 0;
    }

    const userData = userSnap.data() as UserData;
    return userData.auditsAvailable;
  }
}

