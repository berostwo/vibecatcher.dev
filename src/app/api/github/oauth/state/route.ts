import { NextRequest, NextResponse } from 'next/server';
import { createRateLimitMiddleware, RATE_LIMITS } from '@/lib/rate-limit';

// Import the same state store from the callback route
// In production, this should be a shared service (Redis, database, etc.)
declare global {
  var oauthStateStore: Map<string, { state: string; timestamp: number; clientId: string }>;
}

// Initialize global state store if it doesn't exist
if (!global.oauthStateStore) {
  global.oauthStateStore = new Map<string, { state: string; timestamp: number; clientId: string }>();
}

export async function POST(request: NextRequest) {
  try {
    // Rate limiting
    const rateLimitCheck = await createRateLimitMiddleware(RATE_LIMITS.STRICT)(request);
    if (rateLimitCheck) return rateLimitCheck;

    const { state, clientId } = await request.json();

    if (!state || !clientId) {
      return NextResponse.json(
        { error: 'Missing state or clientId' },
        { status: 400 }
      );
    }

    // Validate state format
    const stateRegex = /^[a-f0-9]{32,}$/i;
    if (!stateRegex.test(state)) {
      return NextResponse.json(
        { error: 'Invalid state format' },
        { status: 400 }
      );
    }

    // Store OAuth state
    global.oauthStateStore.set(state, {
      state,
      timestamp: Date.now(),
      clientId
    });

    console.log('✅ OAuth state stored:', state.substring(0, 8) + '...');

    return NextResponse.json({ success: true });

  } catch (error) {
    console.error('❌ Error storing OAuth state:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
