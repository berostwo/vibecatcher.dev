import { FirebaseUserService } from './firebase-user-service';

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
  default_branch: string;
}

export class GitHubService {
  static async getAuthToken(userId: string): Promise<string | null> {
    try {
      const token = await FirebaseUserService.getGitHubToken(userId);
      if (token) {
        console.log('GitHubService: Found token in Firebase for user:', userId);
        return token;
      } else {
        console.log('GitHubService: No valid token found in Firebase for user:', userId);
        return null;
      }
    } catch (error) {
      console.error('GitHubService: Error getting token from Firebase:', error);
      return null;
    }
  }

  static async getUserRepositories(userId: string): Promise<GitHubRepository[]> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        throw new Error('No GitHub access token available. Please sign in with GitHub again.');
      }

      console.log('GitHubService: Fetching repositories for user:', userId);
      console.log('GitHubService: Token format check:', token.substring(0, 10) + '...');
      
      // For OAuth tokens (gho_), we should use Bearer format
      // For personal access tokens (ghp_), we can use either format
      const isOAuthToken = token.startsWith('gho_');
      console.log('GitHubService: Token type - OAuth:', isOAuthToken);
      
      let response;
      let authMethod = '';
      
      if (isOAuthToken) {
        // OAuth tokens should use Bearer format
        console.log('GitHubService: Using Bearer token for OAuth');
        response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100&visibility=all', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
        authMethod = 'Bearer';
      } else {
        // Personal access tokens can use either format
        console.log('GitHubService: Using Bearer token for PAT');
        response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100&visibility=all', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
        authMethod = 'Bearer';
      }

      console.log('GitHubService: Repository API response status:', response.status);
      console.log('GitHubService: Repository API response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
        console.error('GitHubService: Failed to fetch repositories:', response.status, errorData);
        console.error('GitHubService: Auth method used:', authMethod);
        console.error('GitHubService: Token preview:', token.substring(0, 10) + '...');
        
        if (response.status === 401) {
          // Token is invalid, remove it from Firebase
          await FirebaseUserService.removeGitHubToken(userId);
          throw new Error('GitHub access token is invalid. Please sign in with GitHub again.');
        }
        
        throw new Error(`Failed to fetch repositories: ${errorData.message || response.statusText}`);
      }

      const repos: GitHubRepository[] = await response.json();
      console.log('GitHubService: Raw repositories from API:', repos.length);
      console.log('GitHubService: First few repos:', repos.slice(0, 3).map(r => ({ name: r.name, private: r.private, fork: r.fork })));
      
      // If we got 0 repos, let's check what the API actually returned
      if (repos.length === 0) {
        console.log('GitHubService: WARNING - 0 repositories returned from API');
        console.log('GitHubService: Full API response:', repos);
        console.log('GitHubService: Response status was:', response.status);
        console.log('GitHubService: Response headers:', Object.fromEntries(response.headers.entries()));
        
        // Let's try a different endpoint to see if the user has any repos at all
        console.log('GitHubService: Trying alternative endpoint to check user info...');
        const userResponse = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
        
        if (userResponse.ok) {
          const userData = await userResponse.json();
          console.log('GitHubService: User data from alternative endpoint:', userData);
          console.log('GitHubService: User public repos count:', userData.public_repos);
          console.log('GitHubService: User total private repos count:', userData.total_private_repos);
        }
      }
      
      // Filter out forked repositories and sort by last updated
      const filteredRepos = repos
        .filter(repo => !repo.fork)
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

      console.log(`GitHubService: Successfully fetched ${filteredRepos.length} repositories (filtered from ${repos.length} total)`);
      console.log('GitHubService: Filtered repos:', filteredRepos.map(r => r.name));
      
      return filteredRepos;
    } catch (error) {
      console.error('GitHubService: Failed to fetch GitHub repositories:', error);
      throw error;
    }
  }

  static async getRepositoryDetails(userId: string, owner: string, repo: string): Promise<any> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        throw new Error('No GitHub access token available');
      }

      const response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch repository details: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('GitHubService: Failed to fetch repository details:', error);
      throw error;
    }
  }

  static async testConnection(userId: string): Promise<boolean> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        console.log('GitHubService: No token available for connection test');
        return false;
      }

      console.log('GitHubService: Testing GitHub API connection...');
      console.log('GitHubService: Token preview (first 10 chars):', token.substring(0, 10) + '...');

      // Try Bearer token first
      let response = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        }
      });

      // If Bearer fails, try token format
      if (response.status === 401) {
        console.log('GitHubService: Bearer token failed, trying token format...');
        response = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
      }

      if (response.ok) {
        const userData = await response.json();
        console.log('GitHubService: Connection successful, user:', userData.login);
        return true;
      } else {
        console.log('GitHubService: Connection test failed, status:', response.status);
        console.log('GitHubService: Response headers:', Object.fromEntries(response.headers.entries()));
        
        if (response.status === 401) {
          // Token is invalid, remove it from Firebase
          await FirebaseUserService.removeGitHubToken(userId);
          console.log('GitHubService: Invalid token removed from Firebase');
        }
        
        return false;
      }
    } catch (error) {
      console.error('GitHubService: Connection test error:', error);
      return false;
    }
  }

  // Static methods for token management (for backward compatibility)
  static async clearToken(userId: string): Promise<void> {
    try {
      await FirebaseUserService.removeGitHubToken(userId);
      console.log('GitHubService: Token cleared from Firebase for user:', userId);
    } catch (error) {
      console.error('GitHubService: Error clearing token:', error);
      throw error;
    }
  }

  static async refreshToken(userId: string): Promise<void> {
    try {
      // Remove expired token
      await FirebaseUserService.removeGitHubToken(userId);
      console.log('GitHubService: Expired token removed, user needs to re-authenticate');
      // Note: In a production app, you might implement token refresh logic here
      // For now, we'll require re-authentication
    } catch (error) {
      console.error('GitHubService: Error refreshing token:', error);
      throw error;
    }
  }

  static async validateToken(token: string): Promise<{ isValid: boolean; message: string }> {
    try {
      if (!token || token.length < 10) {
        return { isValid: false, message: 'Token appears to be too short' };
      }

      if (!token.startsWith('ghp_') && !token.startsWith('gho_') && !token.startsWith('ghu_') && !token.startsWith('ghs_') && !token.startsWith('ghr_')) {
        return { isValid: false, message: 'Token format does not match GitHub personal access token pattern' };
      }

      return { isValid: true, message: 'Token format appears valid' };
    } catch (error) {
      return { isValid: false, message: 'Error validating token format' };
    }
  }
}
