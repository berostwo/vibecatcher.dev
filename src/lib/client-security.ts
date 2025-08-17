import { auth } from '@/lib/firebase';

// Client-side security utilities
export class ClientSecurity {
  private static csrfToken: string | null = null;
  private static tokenRefreshTimer: NodeJS.Timeout | null = null;

  // Initialize security features
  static async initialize() {
    try {
      // Set up token refresh monitoring
      this.setupTokenRefresh();
      
      // Generate initial CSRF token
      await this.refreshCSRFToken();
      
      console.log('🔒 Client security initialized');
    } catch (error) {
      console.error('❌ Failed to initialize client security:', error);
    }
  }

  // Get current user's ID token for API calls
  static async getIdToken(): Promise<string | null> {
    try {
      const user = auth.currentUser;
      if (!user) {
        return null;
      }
      
      return await user.getIdToken(true); // Force refresh
    } catch (error) {
      console.error('Failed to get ID token:', error);
      return null;
    }
  }

  // Generate or refresh CSRF token
  static async refreshCSRFToken(): Promise<string | null> {
    try {
      const user = auth.currentUser;
      if (!user) {
        this.csrfToken = null;
        return null;
      }

      const idToken = await this.getIdToken();
      if (!idToken) {
        return null;
      }

      // Request new CSRF token from server
      const response = await fetch('/api/csrf-token', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${idToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const { token } = await response.json();
        this.csrfToken = token;
        return token;
      }
    } catch (error) {
      console.error('Failed to refresh CSRF token:', error);
    }
    
    return null;
  }

  // Get current CSRF token
  static getCSRFToken(): string | null {
    return this.csrfToken;
  }

  // Setup automatic token refresh
  private static setupTokenRefresh() {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
    }

    // Refresh token every 50 minutes (tokens expire in 1 hour)
    this.tokenRefreshTimer = setInterval(async () => {
      try {
        await this.refreshCSRFToken();
      } catch (error) {
        console.error('Failed to refresh CSRF token:', error);
      }
    }, 50 * 60 * 1000);
  }

  // Clean up security resources
  static cleanup() {
    if (this.tokenRefreshTimer) {
      clearInterval(this.tokenRefreshTimer);
      this.tokenRefreshTimer = null;
    }
    this.csrfToken = null;
  }

  // Create secure headers for API calls
  static async getSecureHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // Add authentication token
    const idToken = await this.getIdToken();
    if (idToken) {
      headers['Authorization'] = `Bearer ${idToken}`;
    }

    // Add CSRF token
    const csrfToken = this.getCSRFToken();
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    return headers;
  }

  // Secure API call wrapper
  static async secureApiCall<T>(
    url: string,
    options: RequestInit = {}
  ): Promise<T> {
    try {
      const secureHeaders = await this.getSecureHeaders();
      
      const response = await fetch(url, {
        ...options,
        headers: {
          ...secureHeaders,
          ...options.headers,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Token expired, try to refresh
          await this.refreshCSRFToken();
          throw new Error('Authentication required');
        }
        
        if (response.status === 403) {
          throw new Error('Access denied');
        }
        
        if (response.status === 429) {
          throw new Error('Rate limit exceeded');
        }
        
        throw new Error(`API call failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Secure API call failed:', error);
      throw error;
    }
  }

  // Validate and sanitize user input
  static sanitizeInput(input: string, maxLength: number = 1000): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }
    
    // Remove potentially dangerous characters
    let sanitized = input
      .replace(/[<>]/g, '') // Remove < and >
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/data:/gi, '') // Remove data: protocol
      .trim();
    
    // Limit length
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }

  // Validate file upload
  static validateFile(file: File, maxSize: number = 10 * 1024 * 1024): boolean {
    if (file.size > maxSize) {
      return false;
    }
    
    const allowedExtensions = ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte'];
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
    
    return allowedExtensions.includes(fileExtension);
  }
}

// Export convenience functions
export const getSecureHeaders = () => ClientSecurity.getSecureHeaders();
export const secureApiCall = <T>(url: string, options?: RequestInit) => ClientSecurity.secureApiCall<T>(url, options);
export const sanitizeInput = (input: string, maxLength?: number) => ClientSecurity.sanitizeInput(input, maxLength);
export const validateFile = (file: File, maxSize?: number) => ClientSecurity.validateFile(file, maxSize);
