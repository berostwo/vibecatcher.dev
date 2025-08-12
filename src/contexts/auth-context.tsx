'use client';

import { 
  createContext, 
  useContext, 
  useEffect, 
  useState, 
  ReactNode 
} from 'react';
import { 
  User, 
  signInWithPopup, 
  signOut as firebaseSignOut, 
  onAuthStateChanged,
  GithubAuthProvider,
  updateProfile
} from 'firebase/auth';
import { auth, githubProvider } from '@/lib/firebase';
import { UserService } from '@/lib/user-service';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signInWithGithub: () => Promise<User>;
  signOut: () => Promise<void>;
  forceGitHubReauth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuthContext() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  // VERSION CHECK - Force cache clear if needed
  const VERSION = '2.0.0';
  console.log('🔥 AuthProvider VERSION:', VERSION, '🔥');
  
  // Force clear any cached data
  if (typeof window !== 'undefined') {
    // Clear localStorage
    localStorage.removeItem('github_access_token');
    localStorage.removeItem('github_token');
    
    // Clear sessionStorage
    sessionStorage.clear();
    
    // Force reload if version mismatch detected
    const cachedVersion = localStorage.getItem('auth_provider_version');
    if (cachedVersion !== VERSION) {
      console.log('🔄 Version mismatch detected, clearing cache...');
      localStorage.setItem('auth_provider_version', VERSION);
      // Don't force reload here, just clear cache
    }
  }

  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      console.log('useAuth: Auth state changed:', user?.uid || 'no user');
      
      if (user) {
        setUser(user);
        
        // Get or create user data in Firestore
        try {
          const userData = await UserService.getUserData(user.uid);
          if (userData) {
            console.log('useAuth: User data loaded from Firestore:', userData);
            
            // BULLETPROOF: Check if user has a valid GitHub token
            if (!userData.githubAccessToken) {
              console.log('useAuth: User has no GitHub token - this is a returning user who needs re-authentication');
              console.log('useAuth: Clearing user state to force re-authentication');
              
              // Clear the user state to force re-authentication
              setUser(null);
              
              return;
            }
            
            // Verify the token is still valid
            try {
              const token = await UserService.getGitHubToken(user.uid);
              if (token) {
                console.log('useAuth: GitHub token verified and valid');
              } else {
                console.log('useAuth: GitHub token is invalid or expired - forcing re-authentication');
                setUser(null);
                return;
              }
            } catch (tokenError) {
              console.error('useAuth: Error verifying GitHub token:', tokenError);
              setUser(null);
              return;
            }
          }
        } catch (error) {
          console.error('useAuth: Error loading user data:', error);
        }
      } else {
        setUser(null);
      }
      
      setLoading(false);
    });
    
    return unsubscribe;
  }, []);

  const signInWithGithub = async (): Promise<User> => {
    try {
      console.log('useAuth: Starting GitHub sign-in...');
      
      // Add a small delay to show the loading state
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const result = await signInWithPopup(auth, githubProvider);
      
      console.log('useAuth: GitHub sign-in successful:', result.user.uid);
      
      // Extract GitHub username and photo from the OAuth result
      const githubUsername = (result as any).user?.reloadUserInfo?.screenName || 
                            (result as any).user?.providerData?.[0]?.displayName ||
                            result.user.displayName;
      
      const githubPhoto = (result as any).user?.reloadUserInfo?.photoURL ||
                         (result as any).user?.providerData?.[0]?.photoURL ||
                         result.user.photoURL;
      
      // Extract GitHub access token from OAuth result
      let githubToken: string | null = null;
      
      // COMPREHENSIVE LOGGING - Let's see exactly what we get
      console.log('🔥 FULL OAUTH RESULT STRUCTURE 🔥');
      console.log('Result type:', typeof result);
      console.log('Result keys:', Object.keys(result));
      console.log('Result.user type:', typeof result.user);
      console.log('Result.user keys:', Object.keys(result.user));
      
      if ((result as any).credential) {
        const credential = (result as any).credential;
        console.log('🔥 CREDENTIAL OBJECT FOUND 🔥');
        console.log('Credential type:', typeof credential);
        console.log('Credential keys:', Object.keys(credential));
        console.log('Full credential object:', JSON.stringify(credential, null, 2));
        
        // Try different possible locations for the GitHub access token
        if (credential.accessToken) {
          githubToken = credential.accessToken;
          console.log('✅ Found token in credential.accessToken');
        } else if (credential.access_token) {
          githubToken = credential.access_token;
          console.log('✅ Found token in credential.access_token');
        } else if (credential.token) {
          githubToken = credential.token;
          console.log('✅ Found token in credential.token');
        } else if (credential.oauthAccessToken) {
          githubToken = credential.oauthAccessToken;
          console.log('✅ Found token in credential.oauthAccessToken');
        } else {
          console.log('❌ No token found in credential object');
          console.log('Credential structure:', JSON.stringify(credential, null, 2));
        }
      } else {
        console.log('❌ No credential object in OAuth result');
        console.log('Full result structure:', JSON.stringify(result, null, 2));
      }
      
      // If we still don't have a token, try the provider data
      if (!githubToken && result.user?.providerData) {
        console.log('🔥 CHECKING PROVIDER DATA 🔥');
        const providerData = result.user.providerData[0] as any;
        console.log('Provider data type:', typeof providerData);
        console.log('Provider data keys:', Object.keys(providerData));
        console.log('Full provider data:', JSON.stringify(providerData, null, 2));
        
        if (providerData.accessToken) {
          githubToken = providerData.accessToken;
          console.log('✅ Found token in providerData.accessToken');
        } else if (providerData.oauthAccessToken) {
          githubToken = providerData.oauthAccessToken;
          console.log('✅ Found token in providerData.oauthAccessToken');
        } else {
          console.log('❌ No token found in provider data');
        }
      }
      
      // Also check if the token is in the user object itself
      if (!githubToken && (result.user as any).accessToken) {
        githubToken = (result.user as any).accessToken;
        console.log('✅ Found token in user.accessToken (direct)');
      }
      
      // Check if token is in the result object itself
      if (!githubToken && (result as any).accessToken) {
        githubToken = (result as any).accessToken;
        console.log('✅ Found token in result.accessToken (direct)');
      }
      
      // FALLBACK: Try to get token from the auth state directly
      if (!githubToken) {
        console.log('🔥 FALLBACK: Checking auth state for token 🔥');
        try {
          const currentUser = auth.currentUser;
          if (currentUser) {
            console.log('Current user found, checking for token...');
            
            // Try to get the token from the current user's provider data
            const currentProviderData = currentUser.providerData[0] as any;
            if (currentProviderData && currentProviderData.accessToken) {
              githubToken = currentProviderData.accessToken;
              console.log('✅ Found token in current user provider data');
            }
            
            // Also try to get the token from the user's credential
            const credential = (result as any).credential;
            if (credential && credential.accessToken) {
              githubToken = credential.accessToken;
              console.log('✅ Found token in credential (fallback)');
            }
          }
        } catch (fallbackError) {
          console.log('Fallback token check failed:', fallbackError);
        }
      }
      
      // Validate the token format
      if (githubToken) {
        console.log('useAuth: Token found, validating format...');
        console.log('useAuth: Token preview (first 20 chars):', githubToken.substring(0, 20) + '...');
        console.log('useAuth: Token length:', githubToken.length);
        
        // GitHub OAuth tokens should start with specific prefixes
        if (githubToken.startsWith('ghp_') || githubToken.startsWith('gho_') || 
            githubToken.startsWith('ghu_') || githubToken.startsWith('ghs_') || 
            githubToken.startsWith('ghr_')) {
          console.log('useAuth: Token format appears to be valid GitHub OAuth token');
        } else if (githubToken.startsWith('eyJhbGciOi')) {
          console.error('useAuth: ERROR - This is a JWT token, not a GitHub OAuth token!');
          console.error('useAuth: We need the actual GitHub access token, not Firebase JWT');
          githubToken = null; // Don't use JWT tokens
        } else {
          console.warn('useAuth: Token format is unknown - may not be a valid GitHub token');
        }
      }
      
      console.log('useAuth: GitHub sign-in successful:', result.user.uid, 'Username:', githubUsername, 'Photo:', githubPhoto, 'Token found:', !!githubToken);
      
      if (githubToken) {
        console.log('useAuth: Token details:', {
          length: githubToken.length,
          startsWith: githubToken.substring(0, 10),
          endsWith: githubToken.substring(githubToken.length - 10)
        });
      }
      
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
      
      // Store GitHub token securely in Firebase
      if (githubToken) {
        try {
          // Extract GitHub user ID if available
          const githubUserId = (result as any).user?.providerData?.[0]?.uid;
          
          console.log('useAuth: Storing GitHub token in Firebase...');
          
          // Store token in Firebase with expiration (GitHub OAuth tokens typically don't expire, but we'll set a long expiration)
          await UserService.storeGitHubToken(
            result.user.uid,
            githubToken,
            31536000, // 1 year in seconds (GitHub OAuth tokens are long-lived)
            githubUsername,
            githubUserId
          );
          
          console.log('useAuth: GitHub access token stored securely in Firebase, length:', githubToken.length);
          
          // CRITICAL: Verify the token was stored by retrieving it
          const storedToken = await UserService.getGitHubToken(result.user.uid);
          if (storedToken) {
            console.log('useAuth: Token verification successful - token is now available in Firebase');
            
            // Test the token with GitHub API to ensure it's valid
            try {
              const response = await fetch('https://api.github.com/user', {
                headers: {
                  'Authorization': `Bearer ${storedToken}`,
                  'Accept': 'application/vnd.github.v3+json',
                  'User-Agent': 'VibeCatcher-Dev'
                }
              });
              
              if (response.ok) {
                const userData = await response.json();
                console.log('useAuth: GitHub API test successful - token is valid for user:', userData.login);
              } else {
                console.error('useAuth: GitHub API test failed - token may be invalid');
                // Don't fail the sign-in, but log the issue
              }
            } catch (apiError) {
              console.error('useAuth: Error testing GitHub API:', apiError);
            }
            
          } else {
            console.error('useAuth: Token verification failed - token was not stored properly');
            throw new Error('Failed to store GitHub token in Firebase');
          }
          
        } catch (storageError) {
          console.error('useAuth: Failed to store GitHub token in Firebase:', storageError);
          // Don't fail the sign-in if token storage fails
        }
      } else {
        console.warn('useAuth: No valid GitHub access token found in OAuth result');
        console.warn('useAuth: This may prevent repository access');
        console.warn('useAuth: Please check Firebase OAuth configuration and scopes');
      }
      
      // Add a small delay to show the success state
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      return result.user;
    } catch (error) {
      console.error('useAuth: GitHub sign-in failed:', error);
      throw error;
    }
  };

  const signOut = async (): Promise<void> => {
    try {
      if (user) {
        // Clear GitHub token from Firebase
        await UserService.removeGitHubToken(user.uid);
        console.log('useAuth: GitHub token cleared from Firebase');
      }
      
      // Clear any remaining localStorage tokens (cleanup)
      if (typeof window !== 'undefined') {
        localStorage.removeItem('github_access_token');
      }
      
      // Sign out from Firebase
      await firebaseSignOut(auth);
      
      // Clear local user state
      setUser(null);
      
      console.log('useAuth: Sign out completed successfully');
    } catch (error) {
      console.error('useAuth: Sign out failed:', error);
      // Even if Firebase sign out fails, clear local state
      setUser(null);
      throw error;
    }
  };

  const forceGitHubReauth = async (): Promise<void> => {
    try {
      if (user) {
        // Clear GitHub token from Firebase
        await UserService.removeGitHubToken(user.uid);
        console.log('useAuth: GitHub token cleared from Firebase for re-auth');
      }
      
      // Clear any remaining localStorage tokens
      if (typeof window !== 'undefined') {
        localStorage.removeItem('github_access_token');
      }
      
      // Sign out from Firebase
      await firebaseSignOut(auth);
      
      // Clear local user state
      setUser(null);
      
      console.log('useAuth: Force re-auth completed, user needs to sign in again');
    } catch (error) {
      console.error('useAuth: Force re-auth failed:', error);
      // Clear local state even if Firebase operations fail
      setUser(null);
      throw error;
    }
  };

  const value = {
    user,
    loading,
    signInWithGithub,
    signOut,
    forceGitHubReauth,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
