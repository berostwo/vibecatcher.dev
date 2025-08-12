'use client';

import { 
  createContext, 
  useContext, 
  useEffect, 
  useState, 
  ReactNode 
} from 'react';
import { GitHubOAuthService } from '@/lib/github-oauth';
import { FirebaseUserService, FirebaseUser } from '@/lib/firebase-user-service';

interface GitHubUser {
  id: number;
  login: string;
  name: string;
  email: string;
  avatar_url: string;
  html_url: string;
}

interface AuthUser {
  githubUser: GitHubUser;
  firebaseUser: FirebaseUser;
}

interface GitHubAuthContextType {
  user: AuthUser | null;
  loading: boolean;
  isAuthenticated: boolean;
  signInWithGithub: () => void;
  signOut: () => void;
  refreshUser: () => Promise<void>;
  forceGitHubReauth: () => void;
}

const GitHubAuthContext = createContext<GitHubAuthContextType | undefined>(undefined);

export function useGitHubAuth() {
  const context = useContext(GitHubAuthContext);
  if (context === undefined) {
    throw new Error('useGitHubAuth must be used within a GitHubAuthProvider');
  }
  return context;
}

export const GitHubAuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isSigningIn, setIsSigningIn] = useState(false);

  // Check authentication status on mount
  useEffect(() => {
    // Clean up any stale OAuth state first
    GitHubOAuthService.cleanupStaleState();
    checkAuthenticationStatus();
  }, []);

  // Check for redirect return from OAuth
  useEffect(() => {
    const checkRedirectReturn = async () => {
      // Don't handle redirect returns if we're on the OAuth callback page
      // The callback page will handle the OAuth flow directly
      if (typeof window !== 'undefined' && window.location.pathname === '/auth/github/callback') {
        console.log('On OAuth callback page, skipping redirect return handling in auth context');
        return;
      }

      if (GitHubOAuthService.checkRedirectReturn()) {
        try {
          setLoading(true);
          const accessToken = await GitHubOAuthService.handleRedirectReturn();
          
          if (accessToken) {
            // Complete the authentication flow
            await completeAuthentication(accessToken);
          }
        } catch (error) {
          console.error('Failed to handle redirect return:', error);
          // Clear any stale OAuth data on error
          if (user?.firebaseUser?.uid) {
            await GitHubOAuthService.clearAllOAuthData(user.firebaseUser.uid);
          } else {
            GitHubOAuthService.clearAllOAuthData();
          }
        } finally {
          setLoading(false);
        }
      }
    };

    checkRedirectReturn();
  }, []);

  const completeAuthentication = async (accessToken: string) => {
    try {
      // Get GitHub user info
      const userInfo = await GitHubOAuthService.getUserInfo(accessToken);
      const emails = await GitHubOAuthService.getUserEmails(accessToken);
      
      // Find primary email
      const primaryEmail = emails.find((email: any) => email.primary)?.email || emails[0]?.email;
      
      const githubUser: GitHubUser = {
        id: userInfo.id,
        login: userInfo.login,
        name: userInfo.name || userInfo.login,
        email: primaryEmail || '',
        avatar_url: userInfo.avatar_url,
        html_url: userInfo.html_url
      };
      
      // Get or create Firebase user
      const firebaseUser = await FirebaseUserService.createUserFromGitHub(githubUser, accessToken);
      
      // Store token on server for enhanced security
      await GitHubOAuthService.storeTokenOnServer(firebaseUser.uid, accessToken);
      
      const authUser: AuthUser = {
        githubUser,
        firebaseUser
      };
      
      setUser(authUser);
      setIsAuthenticated(true);
    } catch (error) {
      console.error('Failed to complete authentication:', error);
      throw error;
    }
  };

  const checkAuthenticationStatus = async () => {
    try {
      setLoading(true);
      
      // Check if we have a stored access token
      const accessToken = GitHubOAuthService.getAccessToken();
      
      if (accessToken) {
        // Verify token is still valid by fetching user info
        try {
          const userInfo = await GitHubOAuthService.getUserInfo(accessToken);
          const emails = await GitHubOAuthService.getUserEmails(accessToken);
          
          // Find primary email
          const primaryEmail = emails.find((email: any) => email.primary)?.email || emails[0]?.email;
          
          const githubUser: GitHubUser = {
            id: userInfo.id,
            login: userInfo.login,
            name: userInfo.name || userInfo.login,
            email: primaryEmail || '',
            avatar_url: userInfo.avatar_url,
            html_url: userInfo.html_url
          };
          
          // Get or create Firebase user
          const firebaseUser = await FirebaseUserService.createUserFromGitHub(githubUser, accessToken);
          
          const authUser: AuthUser = {
            githubUser,
            firebaseUser
          };
          
          setUser(authUser);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Token validation failed:', error);
          // Token is invalid, clear it
          GitHubOAuthService.clearAccessToken();
          setUser(null);
          setIsAuthenticated(false);
        }
      } else {
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Error checking authentication status:', error);
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  const signInWithGithub = async () => {
    // Prevent multiple sign-in attempts
    if (isSigningIn) {
      console.log('Sign-in already in progress, ignoring request');
      return;
    }

    try {
      setIsSigningIn(true);
      setLoading(true);
      
      // Debug current OAuth state
      GitHubOAuthService.debugOAuthState();
      
      // Don't clean up state here - it might clear the state we just created
      // The cleanup on mount should handle stale states
      
      // Try popup-based OAuth first
      try {
        const accessToken = await GitHubOAuthService.initiateOAuth();
        
        // Store the access token
        GitHubOAuthService.storeAccessToken(accessToken);
        
        // Complete authentication
        await completeAuthentication(accessToken);
        
      } catch (popupError) {
        console.log('Popup OAuth failed, error:', popupError);
        
        // If popup failed but it's not a redirect fallback, show the error
        if (popupError instanceof Error && !popupError.message.includes('redirect method')) {
          // Clear OAuth data on error
          if (user?.firebaseUser?.uid) {
            await GitHubOAuthService.clearAllOAuthData(user.firebaseUser.uid);
          } else {
            GitHubOAuthService.clearAllOAuthData();
          }
          throw popupError;
        }
        
        // For redirect method, the authentication will be completed when the user returns
        // Just show a message that they're being redirected
        console.log('Using redirect-based OAuth flow');
      }
      
    } catch (error) {
      console.error('Failed to initiate GitHub OAuth:', error);
      // Clear any OAuth data on error
      if (user?.firebaseUser?.uid) {
        await GitHubOAuthService.clearAllOAuthData(user.firebaseUser.uid);
      } else {
        GitHubOAuthService.clearAllOAuthData();
      }
      // Show error to user (you can add toast notification here)
      throw error;
    } finally {
      setLoading(false);
      setIsSigningIn(false);
    }
  };

  const signOut = async () => {
    if (user?.firebaseUser?.uid) {
      await FirebaseUserService.removeGitHubToken(user.firebaseUser.uid);
      // Clear server-side token
      await GitHubOAuthService.clearTokenFromServer(user.firebaseUser.uid);
    }
    GitHubOAuthService.clearAccessToken();
    setUser(null);
    setIsAuthenticated(false);
  };

  const refreshUser = async () => {
    await checkAuthenticationStatus();
  };

  const forceGitHubReauth = () => {
    GitHubOAuthService.clearAccessToken();
    setUser(null);
    setIsAuthenticated(false);
    // Redirect to home page to re-authenticate
    if (typeof window !== 'undefined') {
      window.location.href = '/';
    }
  };

  const value = {
    user,
    loading,
    isAuthenticated,
    signInWithGithub,
    signOut,
    refreshUser,
    forceGitHubReauth,
  };

  return (
    <GitHubAuthContext.Provider value={value}>
      {children}
    </GitHubAuthContext.Provider>
  );
};
