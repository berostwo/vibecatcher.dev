// GitHub OAuth Configuration
// SECURITY: GitHub tokens are NEVER stored in localStorage or sessionStorage
// They are only stored on the server and temporarily in memory for the current session
// 
// OAuth Parameters:
// - prompt: 'login' - Forces GitHub to always show login form (prevents auto-login)
// - allow_signup: 'false' - Prevents new account creation during OAuth flow
// - force_login: 'true' - Forces fresh login every time (no cached credentials)
// - timestamp: Date.now() - Makes each request unique to prevent caching
// - random: Math.random() - Additional randomness to ensure fresh authentication
const GITHUB_CLIENT_ID = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID;

// Helper function to get redirect URI safely
const getRedirectUri = () => {
  if (typeof window !== 'undefined') {
    return process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI || `${window.location.origin}/auth/github/callback`;
  }
  return process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI || '/auth/github/callback';
};

// GitHub OAuth scopes - updated to include repository access
const GITHUB_SCOPES = ['read:user', 'user:email', 'repo'];

export class GitHubOAuthService {
  // Flag to prevent multiple OAuth flows
  private static isOAuthInProgress = false;

  /**
   * Clear all OAuth state and force fresh authentication
   */
  static clearOAuthState(): void {
    try {
      // Clear all OAuth-related storage
      sessionStorage.removeItem('github_oauth_state');
      sessionStorage.removeItem('github_oauth_return_url');
      localStorage.removeItem('github_oauth_cache');
      
      // Reset OAuth progress flag
      this.isOAuthInProgress = false;
      
      console.log('🧹 Cleared all OAuth state - fresh authentication will be required');
    } catch (error) {
      console.error('Error clearing OAuth state:', error);
    }
  }

  /**
   * Initiate GitHub OAuth flow with popup
   */
  static initiateOAuth(): Promise<string> {
    return new Promise((resolve, reject) => {
      console.log('=== OAuth Initiation Debug ===');
      console.log('GITHUB_CLIENT_ID:', GITHUB_CLIENT_ID);
      console.log('NEXT_PUBLIC_GITHUB_CLIENT_ID env:', process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID);
      console.log('Redirect URI function result:', getRedirectUri());
      console.log('=============================');
      
      if (!GITHUB_CLIENT_ID) {
        reject(new Error('GitHub Client ID not configured'));
        return;
      }

      // Prevent multiple OAuth flows
      if (this.isOAuthInProgress) {
        reject(new Error('OAuth flow already in progress. Please wait for the current flow to complete.'));
        return;
      }

      this.isOAuthInProgress = true;
      console.log('Starting OAuth flow...');

      // Generate random state parameter for security
      const state = this.generateRandomState();
      
      // Store state in sessionStorage with timestamp to prevent conflicts
      const stateData = {
        state: state,
        timestamp: Date.now(),
        clientId: GITHUB_CLIENT_ID
      };
      
      sessionStorage.setItem('github_oauth_state', JSON.stringify(stateData));
      console.log('Stored OAuth state:', stateData);
      
      // Build GitHub OAuth URL with aggressive parameters to force fresh login
      const params = new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        redirect_uri: getRedirectUri(),
        scope: GITHUB_SCOPES.join(' '),
        state: state,
        response_type: 'code',
        prompt: 'login',  // Force GitHub to always show login form
        allow_signup: 'false',  // Prevent new account creation during OAuth
        force_login: 'true',  // Force fresh login every time
        timestamp: Date.now().toString(),  // Make each request unique
        random: Math.random().toString(36).substring(7)  // Additional randomness
      });

      const githubOAuthUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
      
      console.log('GitHub OAuth URL:', githubOAuthUrl);
      console.log('Requested scopes:', GITHUB_SCOPES.join(' '));
      console.log('Redirect URI being sent to GitHub:', getRedirectUri());
      console.log('Current origin:', window.location.origin);
      
      // Try popup first, fallback to redirect if popup fails
      try {
        // Open popup window
        const popup = window.open(
          githubOAuthUrl,
          'github-oauth',
          'width=600,height=700,scrollbars=yes,resizable=yes'
        );

        if (!popup) {
          // Popup blocked, fallback to redirect
          console.log('Popup blocked, falling back to redirect method');
          this.isOAuthInProgress = false; // Reset flag
          this.initiateOAuthRedirect();
          reject(new Error('Popup blocked - using redirect method instead'));
          return;
        }

        // Listen for messages from the popup
        const messageListener = (event: MessageEvent) => {
          if (event.origin !== window.location.origin) return;
          
          console.log('Received message from popup:', event.data);
          
          if (event.data.type === 'GITHUB_OAUTH_CALLBACK') {
            const { code, state, accessToken } = event.data;
            console.log('Received OAuth callback from popup - code:', code.substring(0, 10) + '...', 'state:', state);
            
            if (accessToken) {
              // Popup already handled the OAuth flow, just return the token
              console.log('OAuth success, received access token from popup:', accessToken ? 'Present' : 'Not present');
              popup.close();
              window.removeEventListener('message', messageListener);
              this.isOAuthInProgress = false; // Reset flag
              resolve(accessToken);
            } else {
              // Fallback: complete the authentication flow in the parent window
              this.handleCallback(code, state, true) // Skip state validation for popup context
                .then((accessToken) => {
                  console.log('OAuth success, received access token:', accessToken ? 'Present' : 'Not present');
                  popup.close();
                  window.removeEventListener('message', messageListener);
                  this.isOAuthInProgress = false; // Reset flag
                  resolve(accessToken);
                })
                .catch((error) => {
                  console.error('OAuth callback failed:', error);
                  popup.close();
                  window.removeEventListener('message', messageListener);
                  this.isOAuthInProgress = false; // Reset flag
                  reject(error);
                });
            }
          } else if (event.data.type === 'GITHUB_OAUTH_SUCCESS') {
            // Legacy success message - should not be used anymore
            console.log('Received legacy success message, ignoring');
          } else if (event.data.type === 'GITHUB_OAUTH_ERROR') {
            const { error } = event.data;
            console.error('OAuth error from popup:', error);
            popup.close();
            window.removeEventListener('message', messageListener);
            this.isOAuthInProgress = false; // Reset flag
            reject(new Error(error));
          }
        };

        window.addEventListener('message', messageListener);

        // Set a timeout for the OAuth flow instead of checking window.closed
        const timeout = setTimeout(() => {
          window.removeEventListener('message', messageListener);
          popup.close();
          this.isOAuthInProgress = false; // Reset flag
          reject(new Error('OAuth timeout - please try again'));
        }, 300000); // 5 minutes timeout

        // Clean up timeout when message is received
        const originalMessageListener = messageListener;
        const wrappedMessageListener = (event: MessageEvent) => {
          clearTimeout(timeout);
          originalMessageListener(event);
        };

        window.removeEventListener('message', messageListener);
        window.addEventListener('message', wrappedMessageListener);
      } catch (error) {
        console.error('Popup OAuth failed, using redirect method:', error);
        this.isOAuthInProgress = false; // Reset flag
        this.initiateOAuthRedirect();
        reject(new Error('Popup OAuth failed - using redirect method instead'));
      }
    });
  }

  /**
   * Simple OAuth initiation that always uses redirect (fallback method)
   */
  static initiateOAuthRedirect(): void {
    if (!GITHUB_CLIENT_ID) {
      throw new Error('GitHub Client ID not configured');
    }

    // Generate random state parameter for security
    const state = this.generateRandomState();
    
    // Store state in sessionStorage with timestamp to prevent conflicts
    const stateData = {
      state: state,
      timestamp: Date.now(),
      clientId: GITHUB_CLIENT_ID
    };
    
    sessionStorage.setItem('github_oauth_state', JSON.stringify(stateData));
    console.log('Stored OAuth state for redirect:', stateData);
    
    // Build GitHub OAuth URL with aggressive parameters to force fresh login
    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      redirect_uri: getRedirectUri(),
      scope: GITHUB_SCOPES.join(' '),
      state: state,
      response_type: 'code',
      prompt: 'login',  // Force GitHub to always show login form
      allow_signup: 'false',  // Prevent new account creation during OAuth
      force_login: 'true',  // Force fresh login every time
      timestamp: Date.now().toString(),  // Make each request unique
      random: Math.random().toString(36).substring(7)  // Additional randomness
    });

    const githubOAuthUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
    
    console.log('Redirecting to GitHub OAuth:', githubOAuthUrl);
    
    // Store the current page URL to return to after OAuth
    if (typeof window !== 'undefined') {
      sessionStorage.setItem('github_oauth_return_url', window.location.href);
    }
    
    // Redirect to GitHub OAuth
    window.location.href = githubOAuthUrl;
  }

  /**
   * Check if we're returning from a redirect-based OAuth flow
   */
  static checkRedirectReturn(): boolean {
    if (typeof window === 'undefined') return false;
    
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    
    return !!(code && state);
  }

  /**
   * Handle redirect return and complete OAuth flow
   */
  static async handleRedirectReturn(): Promise<string | null> {
    if (!this.checkRedirectReturn()) return null;
    
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code')!;
    const state = urlParams.get('state')!;
    
    try {
      // Clear URL parameters
      const newUrl = new URL(window.location.href);
      newUrl.searchParams.delete('code');
      newUrl.searchParams.delete('state');
      window.history.replaceState({}, '', newUrl.toString());
      
      // Exchange code for token
      const accessToken = await this.handleCallback(code, state);
      
      // Return to the original page if we have one stored
      const returnUrl = sessionStorage.getItem('github_oauth_return_url');
      if (returnUrl) {
        sessionStorage.removeItem('github_oauth_return_url');
        window.location.href = returnUrl;
      }
      
      return accessToken;
    } catch (error) {
      console.error('Failed to handle redirect return:', error);
      return null;
    }
  }

  /**
   * Handle OAuth callback without exchanging code for token (for frontend use)
   * This method only validates state and returns the validated parameters
   */
  static async handleCallbackWithoutTokenExchange(code: string, state: string): Promise<{ code: string; state: string }> {
    console.log('handleCallbackWithoutTokenExchange called with code:', code.substring(0, 10) + '...', 'state:', state);
    
    // Verify state parameter
    const storedStateData = sessionStorage.getItem('github_oauth_state');
    console.log('Stored state data from sessionStorage:', storedStateData);
    
    if (!storedStateData) {
      throw new Error('No OAuth state found in sessionStorage. Please try signing in again.');
    }
    
    let stateData;
    try {
      stateData = JSON.parse(storedStateData);
    } catch (error) {
      console.error('Failed to parse stored state data:', error);
      sessionStorage.removeItem('github_oauth_state');
      throw new Error('Invalid OAuth state data. Please try signing in again.');
    }
    
    const receivedState = state;
    const receivedTimestamp = Date.now();
    
    // Check if state matches
    if (stateData.state !== receivedState) {
      console.error('State mismatch - stored:', stateData.state, 'received:', receivedState);
      sessionStorage.removeItem('github_oauth_state');
      throw new Error('OAuth state parameter mismatch. Please try signing in again.');
    }
    
    // Check if state is expired (5 minutes)
    if (receivedTimestamp - stateData.timestamp > 300000) {
      console.error('State expired - stored timestamp:', stateData.timestamp, 'current:', receivedTimestamp);
      sessionStorage.removeItem('github_oauth_state');
      throw new Error('OAuth state expired. Please try signing in again.');
    }

    // Clear stored state AFTER successful validation
    sessionStorage.removeItem('github_oauth_state');
    console.log('State validation successful, returning validated parameters');
    
    return { code, state };
  }

  /**
   * Handle OAuth callback and exchange code for access token
   */
  static async handleCallback(code: string, state: string, skipStateValidation: boolean = false): Promise<string> {
    console.log('handleCallback called with code:', code.substring(0, 10) + '...', 'state:', state);
    
    // Verify state parameter (unless skipping validation for popup context)
    if (!skipStateValidation) {
      const storedStateData = sessionStorage.getItem('github_oauth_state');
      console.log('Stored state data from sessionStorage:', storedStateData);
      
      if (!storedStateData) {
        throw new Error('No OAuth state found in sessionStorage. Please try signing in again.');
      }
      
      let stateData;
      try {
        stateData = JSON.parse(storedStateData);
      } catch (error) {
        console.error('Failed to parse stored state data:', error);
        sessionStorage.removeItem('github_oauth_state');
        throw new Error('Invalid OAuth state data. Please try signing in again.');
      }
      
      const receivedState = state;
      const receivedTimestamp = Date.now();
      
      // Check if state matches
      if (stateData.state !== receivedState) {
        console.error('State mismatch - stored:', stateData.state, 'received:', receivedState);
        sessionStorage.removeItem('github_oauth_state');
        throw new Error('OAuth state parameter mismatch. Please try signing in again.');
      }
      
      // Check if state is expired (5 minutes)
      if (receivedTimestamp - stateData.timestamp > 300000) {
        console.error('State expired - stored timestamp:', stateData.timestamp, 'current:', receivedTimestamp);
        sessionStorage.removeItem('github_oauth_state');
        throw new Error('OAuth state expired. Please try signing in again.');
      }

      // Clear stored state AFTER successful validation
      sessionStorage.removeItem('github_oauth_state');
      console.log('State validation successful, proceeding with token exchange');
    } else {
      console.log('Skipping state validation for popup context');
    }

    try {
      // Exchange authorization code for access token
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

      // Clean the token - remove any whitespace or formatting issues
      const cleanToken = access_token.trim();
      console.log('Access token received successfully');
      console.log('Original token length:', access_token.length);
      console.log('Cleaned token length:', cleanToken.length);
      console.log('Token preview:', `${cleanToken.substring(0, 10)}...`);
      console.log('Token type:', typeof cleanToken);
      
      // Verify token format (GitHub tokens are typically 40 characters)
      if (cleanToken.length !== 40) {
        console.warn('Warning: Token length is not 40 characters, this might indicate an issue');
      }
      
      return cleanToken;
    } catch (error) {
      console.error('OAuth callback error:', error);
      throw error;
    }
  }

  /**
   * Get GitHub user info using access token
   */
  static async getUserInfo(accessToken: string): Promise<any> {
    try {
      console.log('Making GitHub API call with token:');
      console.log('Token length:', accessToken.length);
      console.log('Token preview:', `${accessToken.substring(0, 10)}...`);
      console.log('Authorization header:', `Bearer ${accessToken.substring(0, 10)}...`);
      
      // Test the token with multiple endpoints to diagnose the issue
      await this.testToken(accessToken);
      
      const response = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        },
      });

      console.log('GitHub API response status:', response.status);
      console.log('GitHub API response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        const errorText = await response.text();
        console.error('GitHub API error response:', errorText);
        throw new Error('Failed to fetch GitHub user info');
      }

      return await response.json();
    } catch (error) {
      console.error('Error fetching GitHub user info:', error);
      throw error;
    }
  }

  /**
   * Get GitHub user emails using access token
   */
  static async getUserEmails(accessToken: string): Promise<any[]> {
    try {
      const response = await fetch('https://api.github.com/user/emails', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch GitHub user emails');
      }

      return await response.json();
    } catch (error) {
      console.error('Error fetching GitHub user emails:', error);
      throw error;
    }
  }

  /**
   * Test token validity with different GitHub API endpoints
   */
  static async testToken(accessToken: string): Promise<void> {
    console.log('=== Testing GitHub Token ===');
    
    const endpoints = [
      'https://api.github.com/rate_limit',
      'https://api.github.com/user',
      'https://api.github.com/user/emails'
    ];
    
    for (const endpoint of endpoints) {
      try {
        console.log(`Testing endpoint: ${endpoint}`);
        const response = await fetch(endpoint, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          },
        });
        
        console.log(`  Status: ${response.status}`);
        console.log(`  Headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
          const errorText = await response.text();
          console.log(`  Error: ${errorText}`);
        } else {
          console.log(`  Success: ${response.statusText}`);
        }
      } catch (error) {
        console.error(`  Exception:`, error);
      }
    }
    
    console.log('=== Token Test Complete ===');
  }

  /**
   * Generate random state parameter for OAuth security
   */
  private static generateRandomState(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Store GitHub access token securely
   * NOTE: Tokens are only stored on the server, not locally for security
   */
  static storeAccessToken(token: string): void {
    // Store token in memory temporarily for the current session only
    // This is cleared when the page refreshes or tab is closed
    this._accessToken = token;
    
    console.log('Access token stored in memory only (server-side storage is secure)');
  }

  /**
   * Store token on server for enhanced security
   */
  static async storeTokenOnServer(userId: string, token: string): Promise<void> {
    try {
      const response = await fetch('/api/github/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, accessToken: token }),
      });

      if (!response.ok) {
        console.error('Failed to store token on server');
      } else {
        console.log('Token stored securely on server');
      }
    } catch (error) {
      console.error('Error storing token on server:', error);
    }
  }

  /**
   * Get token from server if available
   */
  static async getTokenFromServer(userId: string): Promise<string | null> {
    try {
      const response = await fetch(`/api/github/token?userId=${userId}`);
      
      if (!response.ok) {
        return null;
      }

      const { token } = await response.json();
      return token;
    } catch (error) {
      console.error('Error retrieving token from server:', error);
      return null;
    }
  }

  /**
   * Clear token from server
   */
  static async clearTokenFromServer(userId: string): Promise<void> {
    try {
      await fetch('/api/github/token', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId }),
      });
      console.log('Token cleared from server');
    } catch (error) {
      console.error('Error clearing token from server:', error);
    }
  }

  /**
   * Get stored GitHub access token
   */
  static getAccessToken(): string | null {
    // Only check memory storage - no local storage for security
    return this._accessToken || null;
  }

  /**
   * Clear GitHub access token
   */
  static clearAccessToken(): void {
    this._accessToken = null;
    console.log('Access token cleared from memory');
  }

  /**
   * Clear all OAuth-related data
   */
  static async clearAllOAuthData(userId?: string): Promise<void> {
    // Only clear OAuth state and return URL - tokens are server-side only
    sessionStorage.removeItem('github_oauth_state');
    sessionStorage.removeItem('github_oauth_return_url');
    this._accessToken = null;
    
    // Clear server-side token if userId is provided
    if (userId) {
      await this.clearTokenFromServer(userId);
    }
    
    console.log('Cleared all OAuth data (tokens remain secure on server)');
  }

  /**
   * Check if user is currently authenticated with GitHub
   * Note: This only checks memory storage. For persistent auth, check server-side.
   */
  static isAuthenticated(): boolean {
    return !!this.getAccessToken();
  }

  // Private memory storage for immediate access
  private static _accessToken: string | null = null;

  /**
   * Clean up stale OAuth state (older than 5 minutes)
   */
  static cleanupStaleState(): void {
    try {
      const storedStateData = sessionStorage.getItem('github_oauth_state');
      if (storedStateData) {
        const stateData = JSON.parse(storedStateData);
        const currentTime = Date.now();
        
        // Only clean up if state is older than 10 minutes (more conservative)
        if (currentTime - stateData.timestamp > 600000) { // 10 minutes
          console.log('Cleaning up stale OAuth state (older than 10 minutes)');
          sessionStorage.removeItem('github_oauth_state');
        } else {
          console.log('OAuth state is still valid, not cleaning up');
        }
      }
    } catch (error) {
      console.error('Error cleaning up stale state:', error);
      // Don't clear the state on parsing errors - it might be valid
    }
  }

  /**
   * Debug function to show current OAuth state
   */
  static debugOAuthState(): void {
    console.log('=== OAuth State Debug ===');
    console.log('OAuth in progress:', this.isOAuthInProgress);
    console.log('Access Token:', sessionStorage.getItem('github_access_token') ? 'Present' : 'Not present');
    console.log('OAuth State:', sessionStorage.getItem('github_oauth_state'));
    console.log('Return URL:', sessionStorage.getItem('github_oauth_return_url'));
    console.log('Client ID:', GITHUB_CLIENT_ID);
    console.log('Redirect URI:', getRedirectUri());
    console.log('========================');
  }

  /**
   * Manually reset OAuth state (useful for debugging)
   */
  static resetOAuthState(): void {
    this.isOAuthInProgress = false;
    this.clearAllOAuthData();
    console.log('OAuth state manually reset');
  }
}
