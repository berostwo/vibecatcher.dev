'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { GitHubOAuthService } from '@/lib/github-oauth';

export default function GitHubCallback() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const code = searchParams.get('code');
        const state = searchParams.get('state');

        if (!code || !state) {
          setError('Missing OAuth parameters');
          setStatus('error');
          return;
        }

        console.log('OAuth callback received - code:', code.substring(0, 10) + '...', 'state:', state);

        // Handle the OAuth callback
        const accessToken = await GitHubOAuthService.handleCallback(code, state);
        
        if (accessToken) {
          console.log('Access token received, getting user info...');
          
          // Get user info from GitHub
          const userInfo = await GitHubOAuthService.getUserInfo(accessToken);
          console.log('GitHub user info:', userInfo);
          
          // Create/update Firebase user
          const { FirebaseUserService } = await import('@/lib/firebase-user-service');
          const firebaseUser = await FirebaseUserService.createUserFromGitHub(
            {
              id: userInfo.id,
              login: userInfo.login,
              name: userInfo.name || userInfo.login,
              email: userInfo.email,
              avatar_url: userInfo.avatar_url
            },
            accessToken
          );
          
          console.log('Firebase user created/updated:', firebaseUser);
          
          // Store token on server (secure)
          await GitHubOAuthService.storeTokenOnServer(firebaseUser.uid, accessToken);
          
          // Store token temporarily in memory for this session only
          GitHubOAuthService.storeAccessToken(accessToken);

          // Check if this is a popup window and send message to parent
          if (window.opener && !window.opener.closed) {
            console.log('Sending success message to parent window');
            window.opener.postMessage({
              type: 'GITHUB_OAUTH_CALLBACK',
              code,
              state,
              accessToken
            }, window.location.origin);
            
            // Close the popup
            window.close();
            return;
          }

          setStatus('success');
          
          // Redirect to dashboard after a short delay (for direct access)
          setTimeout(() => {
            router.push('/dashboard');
          }, 2000);
        } else {
          setError('Failed to complete authentication');
          setStatus('error');
        }
      } catch (error) {
        console.error('OAuth callback error:', error);
        
        // Handle specific error types
        let errorMessage = 'Authentication failed';
        if (error instanceof Error) {
          if (error.message.includes('network')) {
            errorMessage = 'Network connection issue. Please check your internet connection and try again.';
          } else if (error.message.includes('Firebase')) {
            errorMessage = 'Firebase service issue. Please try again in a few moments.';
          } else if (error.message.includes('OAuth')) {
            errorMessage = 'GitHub authentication issue. Please try signing in again.';
          } else {
            errorMessage = error.message;
          }
        }
        
        setError(errorMessage);
        setStatus('error');
        
        // Log detailed error for debugging
        console.error('Detailed error info:', {
          error: error,
          errorType: typeof error,
          errorMessage: error instanceof Error ? error.message : 'Unknown error type',
          errorStack: error instanceof Error ? error.stack : 'No stack trace',
          timestamp: new Date().toISOString()
        });
      }
    };

    handleCallback();
  }, [searchParams, router]);

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <h2 className="text-2xl font-semibold mb-2">Completing GitHub Authentication</h2>
          <p className="text-gray-600">Please wait while we complete your sign-in...</p>
        </div>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-green-500 text-6xl mb-4">✓</div>
          <h2 className="text-2xl font-semibold mb-2">Authentication Successful!</h2>
          <p className="text-gray-600 mb-4">You have been successfully signed in with GitHub.</p>
          <p className="text-sm text-gray-500">Redirecting to dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="text-red-500 text-6xl mb-4">✗</div>
        <h2 className="text-2xl font-semibold mb-2">Authentication Failed</h2>
        <p className="text-gray-600 mb-4">{error}</p>
        <button
          onClick={() => router.push('/')}
          className="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-lg transition-colors"
        >
          Return to Home
        </button>
      </div>
    </div>
  );
}
