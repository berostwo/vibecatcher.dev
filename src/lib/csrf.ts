import { NextRequest, NextResponse } from 'next/server';
import { FirebaseCSRFService } from './firebase-csrf';

export async function generateCSRFToken(userId: string): Promise<string> {
  return await FirebaseCSRFService.generateCSRFToken(userId);
}

export async function validateCSRFToken(userId: string, token: string): Promise<boolean> {
  return await FirebaseCSRFService.validateCSRFToken(userId, token);
}

export async function revokeCSRFToken(userId: string): Promise<void> {
  await FirebaseCSRFService.revokeCSRFToken(userId);
}

export function createCSRFMiddleware() {
  return async (request: NextRequest, userId: string) => {
    const csrfToken = request.headers.get('x-csrf-token');
    
    if (!csrfToken) {
      return NextResponse.json(
        { error: 'CSRF token required' },
        { status: 403 }
      );
    }
    
    const isValid = await validateCSRFToken(userId, csrfToken);
    if (!isValid) {
      return NextResponse.json(
        { error: 'Invalid CSRF token' },
        { status: 403 }
      );
    }
    
    return null; // Continue to next middleware/handler
  };
}
