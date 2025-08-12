'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { GitHubOAuthService } from '@/lib/github-oauth';
import { FirebaseUserService } from '@/lib/firebase-user-service';
import { CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

function GitHubCallbackContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string>('');
  const [hasHandledCallback, setHasHandledCallback] = useState(false);

  useEffect(() => {
    if (!hasHandledCallback) {
      handleCallback();
      setHasHandledCallback(true);
    }
  }, [hasHandledCallback]);

  const handleCallback = async () => {
    // Prevent duplicate callback handling
    if (hasHandledCallback) {
      console.log('Callback already handled, skipping...');
      return;
    }

    try {
      const code = searchParams.get('code');
      const state = searchParams.get('state');

      if (!code || !state) {
        setError('Missing OAuth parameters');
        setStatus('error');
        return;
      }

      console.log('=== OAuth Callback Page Debug ===');
      console.log('OAuth callback received - code:', code.substring(0, 10) + '...', 'state:', state);
      console.log('Current URL:', window.location.href);
      console.log('Has handled callback flag:', hasHandledCallback);
      console.log('================================');

      // Check if we're in a popup context
      const isPopup = window.opener && !window.opener.closed;
      
      if (isPopup) {
        console.log('Detected popup context - sending message to parent window');
        
        // In popup context, just send the OAuth parameters back to parent
        // Don't complete the full authentication flow here
        window.opener.postMessage({
          type: 'GITHUB_OAUTH_CALLBACK',
          code,
          state
        }, window.location.origin);
        
        setStatus('success');
        
        // Close popup after a short delay
        setTimeout(() => {
          window.close();
        }, 1000);
        
        return;
      }

      // Only complete full authentication flow if NOT in popup context
      console.log('Not in popup context - completing full authentication flow');
      
      // Validate state without exchanging token (to avoid duplication)
      await GitHubOAuthService.handleCallbackWithoutTokenExchange(code, state);
      
      // Exchange code for access token using the API endpoint
      const response = await fetch('/api/github/oauth/callback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code, state }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Token exchange failed:', response.status, errorText);
        throw new Error(`Failed to exchange code for token: ${response.status} ${errorText}`);
      }

      const { access_token } = await response.json();
      
      if (!access_token) {
        throw new Error('No access token received');
      }

      console.log('Access token received successfully');
      
      // Store the access token
      GitHubOAuthService.storeAccessToken(access_token);
      
      // Get GitHub user info
      const userInfo = await GitHubOAuthService.getUserInfo(access_token);
      const emails = await GitHubOAuthService.getUserEmails(access_token);
      
      // Find primary email
      const primaryEmail = emails.find((email: any) => email.primary)?.email || emails[0]?.email;
      
      const githubUser = {
        id: userInfo.id,
        login: userInfo.login,
        name: userInfo.name || userInfo.login,
        email: primaryEmail || '',
        avatar_url: userInfo.avatar_url,
      };
      
      // Create or update Firebase user
      await FirebaseUserService.createUserFromGitHub(githubUser, access_token);
      
      setStatus('success');
      
    } catch (error) {
      console.error('OAuth callback error:', error);
      
      // More specific error handling
      let errorMessage = 'Authentication failed';
      if (error instanceof Error) {
        if (error.message.includes('Failed to exchange code for token')) {
          errorMessage = 'Failed to complete authentication. Please check your GitHub OAuth App configuration.';
        } else if (error.message.includes('Missing or insufficient permissions')) {
          errorMessage = 'GitHub OAuth App permissions are insufficient. Please check your app configuration.';
        } else {
          errorMessage = error.message;
        }
      }
      
      setError(errorMessage);
      setStatus('error');
      
      // Send error message to parent window if in popup context
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage({
          type: 'GITHUB_OAUTH_ERROR',
          error: errorMessage
        }, window.location.origin);
      }
    }
  };

  if (status === 'loading') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
          <h1 className="text-2xl font-bold">Completing GitHub Authentication</h1>
          <p className="text-muted-foreground">Please wait while we complete your sign-in...</p>
        </div>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="w-16 h-16 bg-green-500 rounded-full flex items-center justify-center">
            <CheckCircle className="h-10 w-10 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-green-500">Authentication Successful!</h1>
          <p className="text-muted-foreground">
            You have successfully signed in with GitHub.
          </p>
          <p className="text-sm text-muted-foreground">
            Redirecting to dashboard...
          </p>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="w-16 h-16 bg-red-500 rounded-full flex items-center justify-center">
            <AlertCircle className="h-10 w-10 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-red-500">Authentication Failed</h1>
          <p className="text-muted-foreground">
            {error || 'An error occurred during authentication.'}
          </p>
          <button
            onClick={() => router.push('/')}
            className="mt-4 px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
          >
            Return to Home
          </button>
        </div>
      </div>
    );
  }

  return null;
}

export default function GitHubCallbackPage() {
  return (
    <Suspense fallback={
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-primary" />
          <h1 className="text-2xl font-bold">Loading...</h1>
        </div>
      </div>
    }>
      <GitHubCallbackContent />
    </Suspense>
  );
}
