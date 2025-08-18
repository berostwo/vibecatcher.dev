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
        console.log('GitHubService: Token found for user');
        return token;
      } else {
        console.log('GitHubService: No valid token found for user');
        return null;
      }
    } catch (error) {
      console.error('GitHubService: Error getting token from storage');
      return null;
    }
  }

  static async getUserRepositories(userId: string): Promise<GitHubRepository[]> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        throw new Error('Authorization required');
      }

      console.log('GitHubService: Fetching repositories');
      
      const isOAuthToken = token.startsWith('gho_');
      let response;
      let authMethod = '';
      
      if (isOAuthToken) {
        // OAuth tokens should use Bearer format
        response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=100&visibility=all', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
        authMethod = 'Bearer';
      } else {
        // Personal access tokens can use either format; use Bearer
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

      if (!response.ok) {
        // Do not log API error body or token details
        console.error('GitHubService: Failed to fetch repositories');
        console.error('GitHubService: Auth method used:', authMethod);
        
        if (response.status === 401) {
          // Token is invalid, remove it from storage
          await FirebaseUserService.removeGitHubToken(userId);
          throw new Error('Authorization failed');
        }
        
        throw new Error('Failed to fetch repositories');
      }

      const repos: GitHubRepository[] = await response.json();
      console.log('GitHubService: Repositories retrieved');
      
      // Filter out forked repositories and sort by last updated
      const filteredRepos = repos
        .filter(repo => !repo.fork)
        .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

      console.log(`GitHubService: Returning ${filteredRepos.length} repositories`);
      
      return filteredRepos;
    } catch (error) {
      console.error('GitHubService: Repository retrieval error');
      throw new Error('Failed to retrieve repositories');
    }
  }

  static async getRepositoryDetails(userId: string, owner: string, repo: string): Promise<any> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        throw new Error('Authorization required');
      }

      const response = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'VibeCatcher-Dev'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch repository details');
      }

      return await response.json();
    } catch (error) {
      console.error('GitHubService: Repository details error');
      throw new Error('Failed to fetch repository details');
    }
  }

  static async testConnection(userId: string): Promise<boolean> {
    try {
      const token = await this.getAuthToken(userId);
      if (!token) {
        console.log('GitHubService: No token available for connection test');
        return false;
      }

      console.log('GitHubService: Testing GitHub API connection');

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
        console.log('GitHubService: Bearer token failed, retrying with token format');
        response = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `token ${token}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VibeCatcher-Dev'
          }
        });
      }

      if (response.ok) {
        console.log('GitHubService: Connection successful');
        return true;
      } else {
        console.log('GitHubService: Connection test failed, status:', response.status);
        
        if (response.status === 401) {
          // Token is invalid, remove it from storage
          await FirebaseUserService.removeGitHubToken(userId);
          console.log('GitHubService: Invalid token removed from storage');
        }
        
        return false;
      }
    } catch (error) {
      console.error('GitHubService: Connection test error');
      return false;
    }
  }

  // Static methods for token management (for backward compatibility)
  static async clearToken(userId: string): Promise<void> {
    try {
      await FirebaseUserService.removeGitHubToken(userId);
      console.log('GitHubService: Token cleared for user');
    } catch (error) {
      console.error('GitHubService: Error clearing token');
      throw new Error('Failed to clear token');
    }
  }

  static async refreshToken(userId: string): Promise<void> {
    try {
      // Remove expired token
      await FirebaseUserService.removeGitHubToken(userId);
      console.log('GitHubService: Token removed; user must re-authenticate');
    } catch (error) {
      console.error('GitHubService: Error refreshing token');
      throw new Error('Failed to refresh token');
    }
  }

  static async validateToken(token: string): Promise<{ isValid: boolean; message: string }> {
    try {
      if (!token || token.length < 10) {
        return { isValid: false, message: 'Token appears to be too short' };
      }

      if (!token.startsWith('ghp_') && !token.startsWith('gho_') && !token.startsWith('ghu_') && !token.startsWith('ghs_') && !token.startsWith('ghr_')) {
        return { isValid: false, message: 'Token format is not recognized' };
      }

      return { isValid: true, message: 'Token format appears valid' };
    } catch (error) {
      return { isValid: false, message: 'Error validating token format' };
    }
  }
}
