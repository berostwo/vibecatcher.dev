import { 
  doc, 
  setDoc, 
  getDoc, 
  updateDoc, 
  serverTimestamp,
  collection,
  query,
  where,
  getDocs
} from 'firebase/firestore';
import { 
  signInWithCredential,
  GithubAuthProvider,
  UserCredential,
  User
} from 'firebase/auth';
import { db, auth } from './firebase';

export interface FirebaseUser {
  uid: string;
  email: string;
  displayName: string;
  photoURL: string;
  githubId: number;
  githubUsername: string;
  githubAccessToken: string;
  createdAt: any;
  updatedAt: any;
}

export class FirebaseUserService {
  /**
   * Create a new Firebase user after successful GitHub OAuth
   */
  static async createUserFromGitHub(
    githubUser: {
      id: number;
      login: string;
      name: string;
      email: string;
      avatar_url: string;
    },
    accessToken: string
  ): Promise<FirebaseUser> {
    try {
      console.log('=== Creating Firebase User ===');
      console.log('GitHub user:', githubUser);
      console.log('Current Firebase auth state:', auth.currentUser ? 'Authenticated' : 'Not authenticated');
      
      // Check if user already exists by GitHub ID
      const existingUser = await this.getUserByGitHubId(githubUser.id);
      if (existingUser) {
        console.log('User already exists, updating token:', existingUser.uid);
        // Update existing user's token and info
        await this.updateUserToken(existingUser.uid, accessToken);
        return existingUser;
      }

      // Use Firebase's GitHub OAuth provider to authenticate
      console.log('Authenticating with Firebase using GitHub OAuth...');
      
      // Create GitHub credential
      const credential = GithubAuthProvider.credential(accessToken);
      
      // Sign in with the credential
      const userCredential = await signInWithCredential(auth, credential);
      const firebaseUser = userCredential.user;
      const uid = firebaseUser.uid;
      
      console.log('Firebase Auth user authenticated via GitHub:', uid);
      console.log('Current auth state after authentication:', auth.currentUser ? 'Authenticated' : 'Not authenticated');
      
      // Create new user document in Firestore
      const userData: FirebaseUser = {
        uid,
        email: githubUser.email || firebaseUser.email || `${githubUser.login}@github.user`,
        displayName: githubUser.name || githubUser.login,
        photoURL: githubUser.avatar_url,
        githubId: githubUser.id,
        githubUsername: githubUser.login,
        githubAccessToken: accessToken,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      };

      console.log('Storing user data in Firestore:', uid);
      console.log('User data to store:', userData);
      
      // Store user in Firestore
      await setDoc(doc(db, 'users', uid), userData);
      
      console.log('Firebase user created successfully in Firestore:', uid);
      console.log('=== Firebase User Creation Complete ===');
      return userData;
      
    } catch (error) {
      console.error('=== Firebase User Creation Failed ===');
      console.error('Error creating Firebase user:', error);
      console.error('Error details:', {
        code: (error as any)?.code,
        message: (error as any)?.message,
        stack: (error as any)?.stack
      });
      throw error;
    }
  }

  /**
   * Get user by GitHub ID
   */
  static async getUserByGitHubId(githubId: number): Promise<FirebaseUser | null> {
    try {
      console.log('=== Getting User by GitHub ID ===');
      console.log('GitHub ID:', githubId);
      console.log('Current Firebase auth state:', auth.currentUser ? 'Authenticated' : 'Not authenticated');
      
      // Check if we're authenticated
      if (!auth.currentUser) {
        console.log('Not authenticated with Firebase, cannot query Firestore');
        return null;
      }
      
      const usersRef = collection(db, 'users');
      const q = query(usersRef, where('githubId', '==', githubId));
      
      console.log('Executing Firestore query for GitHub ID:', githubId);
      const querySnapshot = await getDocs(q);
      
      if (querySnapshot.empty) {
        console.log('No user found with GitHub ID:', githubId);
        return null;
      }
      
      const userDoc = querySnapshot.docs[0];
      const userData = userDoc.data() as FirebaseUser;
      console.log('User found:', userData.uid);
      return userData;
      
    } catch (error) {
      console.error('=== Error Getting User by GitHub ID ===');
      console.error('GitHub ID:', githubId);
      console.error('Error details:', {
        code: (error as any)?.code,
        message: (error as any)?.message,
        stack: (error as any)?.stack
      });
      return null;
    }
  }

  /**
   * Get user by UID
   */
  static async getUserByUid(uid: string): Promise<FirebaseUser | null> {
    try {
      const userDoc = await getDoc(doc(db, 'users', uid));
      
      if (!userDoc.exists()) {
        return null;
      }
      
      return userDoc.data() as FirebaseUser;
      
    } catch (error) {
      console.error('Error getting user by UID:', error);
      return null;
    }
  }

  /**
   * Update user's GitHub access token
   */
  static async updateUserToken(uid: string, accessToken: string): Promise<void> {
    try {
      await updateDoc(doc(db, 'users', uid), {
        githubAccessToken: accessToken,
        updatedAt: serverTimestamp(),
      });
      
      console.log('User token updated successfully:', uid);
      
    } catch (error) {
      console.error('Error updating user token:', error);
      throw error;
    }
  }

  /**
   * Get user's GitHub access token
   */
  static async getGitHubToken(uid: string): Promise<string | null> {
    try {
      const user = await this.getUserByUid(uid);
      return user?.githubAccessToken || null;
      
    } catch (error) {
      console.error('Error getting GitHub token:', error);
      return null;
    }
  }

  /**
   * Remove user's GitHub access token
   */
  static async removeGitHubToken(uid: string): Promise<void> {
    try {
      await updateDoc(doc(db, 'users', uid), {
        githubAccessToken: null,
        updatedAt: serverTimestamp(),
      });
      
      console.log('GitHub token removed successfully:', uid);
      
    } catch (error) {
      console.error('Error removing GitHub token:', error);
      throw error;
    }
  }

  /**
   * Check if user exists in Firebase
   */
  static async userExists(uid: string): Promise<boolean> {
    try {
      const userDoc = await getDoc(doc(db, 'users', uid));
      return userDoc.exists();
      
    } catch (error) {
      console.error('Error checking if user exists:', error);
      return false;
    }
  }
}
