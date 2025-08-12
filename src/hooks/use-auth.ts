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
      
      console.log('useAuth: Full OAuth result:', result);
      console.log('useAuth: Credential object:', (result as any).credential);
      console.log('useAuth: User object:', result.user);
      console.log('useAuth: Provider data:', result.user.providerData);
      
      // Extract GitHub username and photo from the OAuth result
      const githubUsername = (result as any).user?.reloadUserInfo?.screenName || 
                            (result as any).user?.providerData?.[0]?.displayName ||
                            result.user.displayName;
      
      const githubPhoto = (result as any).user?.reloadUserInfo?.photoURL ||
                         (result as any).user?.providerData?.[0]?.photoURL ||
                         result.user.photoURL;
      
      // Extract GitHub access token - try multiple possible locations
      let githubToken = null;
      
      // Method 1: Try credential.accessToken (most common)
      if ((result as any).credential?.accessToken) {
        githubToken = (result as any).credential.accessToken;
        console.log('useAuth: Found token in credential.accessToken');
      }
      // Method 2: Try credential.access_token (alternative format)
      else if ((result as any).credential?.access_token) {
        githubToken = (result as any).credential.access_token;
        console.log('useAuth: Found token in credential.access_token');
      }
      // Method 3: Try user.accessToken
      else if ((result as any).user?.accessToken) {
        githubToken = (result as any).user.accessToken;
        console.log('useAuth: Found token in user.accessToken');
      }
      // Method 4: Try providerData
      else if ((result.user.providerData?.[0] as any)?.accessToken) {
        githubToken = (result.user.providerData[0] as any).accessToken;
        console.log('useAuth: Found token in providerData[0].accessToken');
      }
      // Method 5: Try to get token from Firebase auth state
      else if ((result as any).user?.providerData?.[0]?.accessToken) {
        githubToken = (result as any).user.providerData[0].accessToken;
        console.log('useAuth: Found token in user.providerData[0].accessToken');
      }
      // Method 6: Try to get from the credential object directly
      else if ((result as any).credential) {
        const credential = (result as any).credential;
        console.log('useAuth: Credential object keys:', Object.keys(credential));
        // Log all credential properties to see what's available
        for (const [key, value] of Object.entries(credential)) {
          console.log(`useAuth: Credential.${key}:`, value);
        }
      }
      
      console.log('useAuth: GitHub sign-in successful:', result.user.uid, 'Username:', githubUsername, 'Photo:', githubPhoto, 'Token found:', !!githubToken);
      
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
      
      // Store GitHub token in localStorage for API calls
      if (githubToken) {
        localStorage.setItem('github_access_token', githubToken);
        console.log('useAuth: Stored GitHub access token in localStorage, length:', githubToken.length);
      } else {
        console.warn('useAuth: No GitHub access token found in OAuth result');
        console.warn('useAuth: This may prevent repository access');
        console.warn('useAuth: Please check Firebase OAuth configuration and scopes');
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
      console.log('useAuth: Starting sign out...');
      
      // Clear GitHub token from localStorage
      localStorage.removeItem('github_access_token');
      console.log('useAuth: Cleared GitHub access token from localStorage');
      
      // Clear user data state
      setUserData(null);
      
      // Sign out from Firebase
      await firebaseSignOut(auth);
      console.log('useAuth: Firebase sign out successful');
      
      // Clear user state (this will be handled by onAuthStateChanged)
      setUser(null);
      
    } catch (error) {
      console.error('useAuth: Error signing out:', error);
      throw error;
    }
  };

  const forceGitHubReauth = async () => {
    try {
      console.log('useAuth: Forcing GitHub re-authentication...');
      
      // Clear current GitHub token
      localStorage.removeItem('github_access_token');
      
      // Sign out from Firebase to clear OAuth state
      await firebaseSignOut(auth);
      
      // Force a new GitHub sign-in
      return await signInWithGithub();
    } catch (error) {
      console.error('useAuth: Force GitHub re-auth failed:', error);
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
    forceGitHubReauth,
  };
}
