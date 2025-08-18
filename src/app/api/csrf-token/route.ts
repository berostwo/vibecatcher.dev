import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth-middleware';
import { generateCSRFToken } from '@/lib/csrf';
import { createRateLimitMiddleware, RATE_LIMITS } from '@/lib/rate-limit';

async function generateCSRFTokenHandler(request: NextRequest, user: any) {
  try {
    // Rate limiting for CSRF token generation
    const rateLimitCheck = await createRateLimitMiddleware(RATE_LIMITS.STRICT)(request);
    if (rateLimitCheck) return rateLimitCheck;

    // Generate new CSRF token for the user
    const csrfToken = await generateCSRFToken(user.uid);

    return NextResponse.json({
      token: csrfToken,
      expires: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
    }, {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
      }
    });

  } catch (error) {
    console.error('CSRF token generation error:', error);
    return NextResponse.json(
      { error: 'Failed to generate CSRF token' },
      { status: 500 }
    );
  }
}

export const POST = requireAuth(generateCSRFTokenHandler);
