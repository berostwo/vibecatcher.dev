export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  description: string | null;
  private: boolean;
  fork: boolean;
  language: string | null;
  updated_at: string;
  html_url: string;
  clone_url: string;
}

export class GitHubService {
  private static async getAuthToken(): Promise<string | null> {
    try {
      // Get the GitHub access token from localStorage (stored during OAuth sign-in)
      const token = localStorage.getItem('github_access_token');
      
      if (token) {
        console.log('GitHubService: Found token in localStorage, length:', token.length);
        // Check if token looks valid (should be a long string)
        if (token.length > 20) {
          console.log('GitHubService: Token appears valid');
          return token;
        } else {
          console.warn('GitHubService: Token seems too short, may be invalid');
          return null;
        }
      } else {
        console.warn('GitHubService: No token found in localStorage');
        return null;
      }
    } catch (error) {
      console.error('GitHubService: Failed to get GitHub auth token:', error);
      return null;
    }
  }

  static async getUserRepositories(): Promise<GitHubRepository[]> {
    try {
      const token = await this.getAuthToken();
      
      if (!token) {
        throw new Error('No GitHub access token available. Please sign in with GitHub again.');
      }

      console.log('GitHubService: Fetching repositories with token...');
      console.log('GitHubService: Token preview (first 10 chars):', token.substring(0, 10) + '...');
      
      // Try both authorization header formats
      const headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'VibeCatcher-Dev'
      };
      
      // Method 1: Try Bearer token format (OAuth app)
      let response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
        headers: {
          ...headers,
          'Authorization': `Bearer ${token}`
        }
      });

      // Method 2: If Bearer fails, try token format (Personal Access Token)
      if (!response.ok && response.status === 401) {
        console.log('GitHubService: Bearer token failed, trying token format...');
        response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
          headers: {
            ...headers,
            'Authorization': `token ${token}`
          }
        });
      }

      console.log('GitHubService: API response status:', response.status);
      console.log('GitHubService: API response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('GitHub token is invalid or expired. Please sign in again.');
        } else if (response.status === 403) {
          throw new Error('GitHub API rate limit exceeded or insufficient permissions.');
        } else {
          throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
        }
      }

      const repos: GitHubRepository[] = await response.json();
      console.log('GitHubService: Successfully fetched', repos.length, 'repositories');
      
      // Filter out forked repositories and sort by last updated
      const filteredRepos = repos
        .filter(repo => !repo.fork)
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
      
      console.log('GitHubService: Returning', filteredRepos.length, 'non-forked repositories');
      return filteredRepos;
    } catch (error) {
      console.error('GitHubService: Failed to fetch GitHub repositories:', error);
      throw error;
    }
  }

  static async getRepositoryDetails(owner: string, repo: string): Promise<GitHubRepository> {
    try {
      const token = await this.getAuthToken();
      
      if (!token) {
        throw new Error('No GitHub access token available');
      }

      const response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
        headers: {
          'Authorization': `token ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to fetch repository details:', error);
      throw error;
    }
  }

  // Test method to verify GitHub API connectivity
  static async testConnection(): Promise<boolean> {
    try {
      const token = await this.getAuthToken();
      
      if (!token) {
        console.log('GitHubService: No token available for connection test');
        return false;
      }

      console.log('GitHubService: Testing GitHub API connection...');
      console.log('GitHubService: Token preview (first 10 chars):', token.substring(0, 10) + '...');
      
      // Try both authorization header formats
      const headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'VibeCatcher-Dev'
      };
      
      // Method 1: Try Bearer token format (OAuth app)
      let response = await fetch('https://api.github.com/user', {
        headers: {
          ...headers,
          'Authorization': `Bearer ${token}`
        }
      });

      // Method 2: If Bearer fails, try token format (Personal Access Token)
      if (!response.ok && response.status === 401) {
        console.log('GitHubService: Bearer token failed, trying token format...');
        response = await fetch('https://api.github.com/user', {
          headers: {
            ...headers,
            'Authorization': `token ${token}`
          }
        });
      }

      if (response.ok) {
        const userData = await response.json();
        console.log('GitHubService: Connection test successful, user:', userData.login);
        return true;
      } else {
        console.warn('GitHubService: Connection test failed, status:', response.status);
        console.warn('GitHubService: Response headers:', Object.fromEntries(response.headers.entries()));
        return false;
      }
    } catch (error) {
      console.error('GitHubService: Connection test error:', error);
      return false;
    }
  }

  // Method to clear stored token (useful for sign out)
  static clearToken(): void {
    localStorage.removeItem('github_access_token');
    console.log('GitHubService: Cleared stored GitHub token');
  }

  // Method to refresh token by forcing re-authentication
  static async refreshToken(): Promise<boolean> {
    try {
      console.log('GitHubService: Attempting to refresh GitHub token...');
      
      // Clear the old token
      this.clearToken();
      
      // Check if we're in a browser environment
      if (typeof window !== 'undefined') {
        // Redirect to GitHub OAuth flow
        console.log('GitHubService: Redirecting to GitHub OAuth...');
        // This will trigger the sign-in flow again
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('GitHubService: Failed to refresh token:', error);
      return false;
    }
  }

  // Method to validate token format and suggest fixes
  static validateToken(token: string): { isValid: boolean; suggestions: string[] } {
    const suggestions: string[] = [];
    let isValid = true;

    if (!token || token.length < 20) {
      isValid = false;
      suggestions.push('Token appears too short');
    }

    if (token.includes(' ')) {
      isValid = false;
      suggestions.push('Token contains spaces - may be malformed');
    }

    if (token.startsWith('ghp_')) {
      suggestions.push('Token appears to be a GitHub Personal Access Token');
    } else if (token.startsWith('gho_')) {
      suggestions.push('Token appears to be a GitHub OAuth App token');
    } else {
      suggestions.push('Token format not recognized - may be malformed');
    }

    return { isValid, suggestions };
  }
}
