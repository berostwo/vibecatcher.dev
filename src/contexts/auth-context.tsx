'use client';

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, onAuthStateChanged } from 'firebase/auth';
import { auth } from '@/lib/firebase';
import { GitHubOAuthService } from '@/lib/github-oauth';

interface AuthContextType {
  user: User | null;
  githubToken: string | null;
  isLoading: boolean;
  signOut: () => Promise<void>;
  refreshGitHubToken: () => Promise<void>;
  setGitHubToken: (token: string) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [githubToken, setGitHubToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    console.log('🔐 Auth context: Setting up Firebase auth listener...');
    
    // Check if Firebase auth is available
    if (!auth) {
      console.error('❌ Firebase auth is not available!');
      setIsLoading(false);
      return;
    }
    
    console.log('🔐 Firebase auth object:', auth);
    
    // Add timeout to prevent infinite loading
    const timeoutId = setTimeout(() => {
      console.warn('🔐 Auth loading timeout - forcing isLoading to false');
      setIsLoading(false);
    }, 10000); // 10 second timeout
    
    try {
      const unsubscribe = onAuthStateChanged(auth, async (user) => {
        console.log('🔐 Auth state changed:', user ? `User: ${user.email}` : 'No user');
        clearTimeout(timeoutId); // Clear timeout on success
        setUser(user);
        
        if (user) {
          // Check server for GitHub token instead of local storage
          try {
            console.log('🔐 Fetching GitHub token for user:', user.uid);
            const token = await GitHubOAuthService.getTokenFromServer(user.uid);
            if (token) {
              console.log('🔐 GitHub token retrieved successfully');
              setGitHubToken(token);
            } else {
              console.log('🔐 No GitHub token found for user');
            }
          } catch (error) {
            console.warn('Could not retrieve GitHub token from server:', error);
          }
        } else {
          console.log('🔐 No user, clearing GitHub token');
          setGitHubToken(null);
        }
        
        console.log('🔐 Auth loading complete, setting isLoading to false');
        setIsLoading(false);
      }, (error) => {
        console.error('🔐 Firebase auth error:', error);
        clearTimeout(timeoutId); // Clear timeout on error
        setIsLoading(false);
      });

      return () => {
        clearTimeout(timeoutId);
        unsubscribe();
      };
    } catch (error) {
      console.error('❌ Error setting up Firebase auth listener:', error);
      clearTimeout(timeoutId);
      setIsLoading(false);
    }
  }, []);

  const signOut = async () => {
    try {
      if (githubToken) {
        // Clear GitHub token
        GitHubOAuthService.clearAccessToken();
        setGitHubToken(null);
      }
      
      // Sign out from Firebase
      await auth.signOut();
    } catch (error) {
      console.error('Error signing out:', error);
    }
  };

  const refreshGitHubToken = async () => {
    if (user) {
      try {
        const token = await GitHubOAuthService.getTokenFromServer(user.uid);
        setGitHubToken(token);
      } catch (error) {
        console.warn('Could not refresh GitHub token from server:', error);
        setGitHubToken(null);
      }
    }
  };

  // Method to set GitHub token after successful OAuth
  const setGitHubTokenValue = (token: string) => {
    setGitHubToken(token);
  };

  const value = {
    user,
    githubToken,
    isLoading,
    signOut,
    refreshGitHubToken,
    setGitHubToken: setGitHubTokenValue,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
