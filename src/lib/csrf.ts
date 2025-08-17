import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// In-memory CSRF token store (use Redis in production)
const csrfTokens = new Map<string, { token: string; expires: number }>();

export function generateCSRFToken(userId: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
  
  csrfTokens.set(userId, { token, expires });
  
  return token;
}

export function validateCSRFToken(userId: string, token: string): boolean {
  const storedData = csrfTokens.get(userId);
  
  if (!storedData) {
    return false;
  }
  
  // Check if token has expired
  if (Date.now() > storedData.expires) {
    csrfTokens.delete(userId);
    return false;
  }
  
  // Validate token
  if (storedData.token !== token) {
    return false;
  }
  
  return true;
}

export function revokeCSRFToken(userId: string): void {
  csrfTokens.delete(userId);
}

// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [userId, data] of csrfTokens.entries()) {
    if (now > data.expires) {
      csrfTokens.delete(userId);
    }
  }
}, 60 * 60 * 1000); // Clean up every hour

export function createCSRFMiddleware() {
  return (request: NextRequest, userId: string) => {
    const csrfToken = request.headers.get('x-csrf-token');
    
    if (!csrfToken) {
      return NextResponse.json(
        { error: 'CSRF token required' },
        { status: 403 }
      );
    }
    
    if (!validateCSRFToken(userId, csrfToken)) {
      return NextResponse.json(
        { error: 'Invalid CSRF token' },
        { status: 403 }
      );
    }
    
    return null; // Continue to next middleware/handler
  };
}
