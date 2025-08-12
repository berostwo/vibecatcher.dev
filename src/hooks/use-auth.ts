import { useState, useEffect } from 'react';
import { 
  User, 
  signInWithPopup, 
  signOut as firebaseSignOut,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile
} from 'firebase/auth';
import { auth, githubProvider } from '@/lib/firebase';
import { UserService, UserData } from '@/lib/user-service';

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [userData, setUserData] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      console.log('Auth state changed:', { user: !!user, uid: user?.uid, email: user?.email });
      
      if (user) {
        setUser(user);
        try {
          console.log('Getting user data for:', user.uid);
          // Get or create user data (with free audit for new users)
          const data = await UserService.getUserData(
            user.uid, 
            user.email || '', 
            user.displayName || undefined,
            user.photoURL || undefined
          );
          console.log('User data retrieved successfully:', data);
          setUserData(data);
        } catch (error) {
          console.error('Error getting user data:', error);
          // Don't clear the user - they're still authenticated
          // Just log the error for debugging
        }
      } else {
        console.log('No user authenticated');
        setUser(null);
        setUserData(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGithub = async () => {
    try {
      console.log('useAuth: Starting GitHub sign-in...');
      const result = await signInWithPopup(auth, githubProvider);
      
      // Extract GitHub username and photo from the OAuth result
      const githubUsername = (result as any).user?.reloadUserInfo?.screenName || 
                            (result as any).user?.providerData?.[0]?.displayName ||
                            result.user.displayName;
      
      const githubPhoto = (result as any).user?.reloadUserInfo?.photoURL ||
                         (result as any).user?.providerData?.[0]?.photoURL ||
                         result.user.photoURL;
      
      console.log('useAuth: GitHub sign-in successful:', result.user.uid, 'Username:', githubUsername, 'Photo:', githubPhoto);
      
      // Update the user's profile with GitHub info if available
      if ((githubUsername && !result.user.displayName) || (githubPhoto && !result.user.photoURL)) {
        try {
          const updates: { displayName?: string; photoURL?: string } = {};
          
          if (githubUsername && !result.user.displayName) {
            updates.displayName = githubUsername;
          }
          if (githubPhoto && !result.user.photoURL) {
            updates.photoURL = githubPhoto;
          }
          
          await updateProfile(result.user, updates);
          console.log('useAuth: Updated profile with GitHub info:', updates);
        } catch (profileError) {
          console.warn('useAuth: Could not update profile:', profileError);
        }
      }
      
      return result.user;
    } catch (error) {
      console.error('useAuth: GitHub sign-in failed:', error);
      throw error;
    }
  };

  const signInWithEmail = async (email: string, password: string) => {
    try {
      const result = await signInWithEmailAndPassword(auth, email, password);
      return result.user;
    } catch (error) {
      console.error('Error signing in with email:', error);
      throw error;
    }
  };

  const signUpWithEmail = async (email: string, password: string) => {
    try {
      const result = await createUserWithEmailAndPassword(auth, email, password);
      return result.user;
    } catch (error) {
      console.error('Error signing up with email:', error);
      throw error;
    }
  };

  const signOut = async () => {
    try {
      await firebaseSignOut(auth);
    } catch (error) {
      console.error('Error signing out:', error);
      throw error;
    }
  };

  return {
    user,
    userData,
    loading,
    signInWithGithub,
    signInWithEmail,
    signUpWithEmail,
    signOut,
  };
}
