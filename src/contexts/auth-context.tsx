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
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setUser(user);
      
      if (user) {
        // Check server for GitHub token instead of local storage
        try {
          const token = await GitHubOAuthService.getTokenFromServer(user.uid);
          if (token) {
            setGitHubToken(token);
          }
        } catch (error) {
          console.warn('Could not retrieve GitHub token from server:', error);
        }
      } else {
        setGitHubToken(null);
      }
      
      setIsLoading(false);
    });

    return () => unsubscribe();
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
