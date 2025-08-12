import { UserService } from './user-service';

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
      const token = await UserService.getGitHubToken(userId);
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
      
      // Try Bearer token first (standard OAuth)
      let response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        }
      });

      // If Bearer fails, try token format (personal access token)
      if (response.status === 401) {
        console.log('GitHubService: Bearer token failed, trying token format...');
        response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100', {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
      }

      if (!response.ok) {
        const errorData = await response.json();
        console.error('GitHubService: Failed to fetch repositories:', response.status, errorData);
        
        if (response.status === 401) {
          // Token is invalid, remove it from Firebase
          await UserService.removeGitHubToken(userId);
          throw new Error('GitHub access token is invalid. Please sign in with GitHub again.');
        }
        
        throw new Error(`Failed to fetch repositories: ${errorData.message || response.statusText}`);
      }

      const repos: GitHubRepository[] = await response.json();
      
      // Filter out forked repositories and sort by last updated
      const filteredRepos = repos
        .filter(repo => !repo.fork)
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

      console.log(`GitHubService: Successfully fetched ${filteredRepos.length} repositories (filtered from ${repos.length} total)`);
      
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
          await UserService.removeGitHubToken(userId);
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
      await UserService.removeGitHubToken(userId);
      console.log('GitHubService: Token cleared from Firebase for user:', userId);
    } catch (error) {
      console.error('GitHubService: Error clearing token:', error);
      throw error;
    }
  }

  static async refreshToken(userId: string): Promise<void> {
    try {
      // Remove expired token
      await UserService.removeGitHubToken(userId);
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
