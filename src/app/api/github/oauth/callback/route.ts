import { NextRequest, NextResponse } from 'next/server';
import { createRateLimitMiddleware, RATE_LIMITS } from '@/lib/rate-limit';
import { createValidationMiddleware, GitHubOAuthSchema } from '@/lib/validation';

export async function POST(request: NextRequest) {
  try {
    // 1. RATE LIMITING - Prevent OAuth abuse
    const rateLimitCheck = createRateLimitMiddleware(RATE_LIMITS.STRICT)(request);
    if (rateLimitCheck) return rateLimitCheck;

    // 2. INPUT VALIDATION - Prevent injection attacks
    const validationCheck = createValidationMiddleware(GitHubOAuthSchema)(request);
    if (validationCheck) return validationCheck;

    // 3. EXTRACT VALIDATED DATA
    const { code, state } = (request as any).validatedData;

    // 4. STATE VALIDATION - Prevent CSRF attacks
    // Note: You should implement proper state validation here
    // This is a simplified version - in production, validate against stored state

    // 5. EXCHANGE AUTHORIZATION CODE FOR ACCESS TOKEN
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'VibeCatcher-Security-App/1.0', // Identify your app
      },
      body: JSON.stringify({
        client_id: process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI,
      }),
    });

    if (!tokenResponse.ok) {
      console.error('GitHub token exchange failed:', tokenResponse.status);
      return NextResponse.json(
        { error: 'Failed to exchange code for token' },
        { status: 500 }
      );
    }

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('GitHub OAuth error:', tokenData);
      return NextResponse.json(
        { error: 'OAuth authentication failed' }, // Generic error message
        { status: 400 }
      );
    }

    // 6. SECURE RESPONSE - Only return necessary data
    return NextResponse.json({
      access_token: tokenData.access_token,
      token_type: tokenData.token_type,
      scope: tokenData.scope,
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
    // 7. SECURE ERROR HANDLING - Don't leak sensitive information
    console.error('OAuth callback error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
