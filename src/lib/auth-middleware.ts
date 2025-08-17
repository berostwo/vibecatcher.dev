import { NextRequest, NextResponse } from 'next/server';
import { auth } from 'firebase-admin';
import { initializeApp, getApps, cert } from 'firebase-admin/app';

// Initialize Firebase Admin if not already initialized
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

export async function authenticateRequest(request: NextRequest): Promise<{ user: auth.DecodedIdToken | null; error?: string }> {
  try {
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { user: null, error: 'Missing or invalid authorization header' };
    }

    const token = authHeader.split('Bearer ')[1];
    
    if (!token) {
      return { user: null, error: 'Invalid token format' };
    }

    try {
      const decodedToken = await auth().verifyIdToken(token);
      return { user: decodedToken };
    } catch (error) {
      return { user: null, error: 'Invalid or expired token' };
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return { user: null, error: 'Authentication failed' };
  }
}

export function requireAuth(handler: (request: NextRequest, user: auth.DecodedIdToken) => Promise<NextResponse>) {
  return async (request: NextRequest) => {
    const { user, error } = await authenticateRequest(request);
    
    if (error || !user) {
      return NextResponse.json(
        { error: error || 'Unauthorized' },
        { status: 401 }
      );
    }

    return handler(request, user);
  };
}
