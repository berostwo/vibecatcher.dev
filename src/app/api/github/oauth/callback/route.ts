import { NextRequest, NextResponse } from 'next/server';
import { createRateLimitMiddleware, RATE_LIMITS } from '@/lib/rate-limit';
import { createValidationMiddleware, GitHubOAuthSchema } from '@/lib/validation';

// Use global state store for OAuth validation
// In production, use Redis, database, or secure session storage
declare global {
	var oauthStateStore: Map<string, { state: string; timestamp: number; clientId: string }>;
}

// Initialize global state store if it doesn't exist
if (!global.oauthStateStore) {
	global.oauthStateStore = new Map<string, { state: string; timestamp: number; clientId: string }>();
	
	// Clean up expired states every 5 minutes
	setInterval(() => {
		const now = Date.now();
		const fiveMinutesAgo = now - 5 * 60 * 1000;
		
		for (const [key, value] of global.oauthStateStore.entries()) {
			if (value.timestamp < fiveMinutesAgo) {
				global.oauthStateStore.delete(key);
			}
		}
	}, 5 * 60 * 1000);
}

// Helper function for OAuth state validation
function validateOAuthState(state: string, clientId: string): boolean {
	const storedState = global.oauthStateStore.get(state);
	
	if (!storedState) {
		return false;
	}
	
	// Check if state is expired (5 minutes)
	const now = Date.now();
	if (now - storedState.timestamp > 5 * 60 * 1000) {
		global.oauthStateStore.delete(state);
		return false;
	}
	
	// Check if client ID matches
	if (storedState.clientId !== clientId) {
		return false;
	}
	
	// Remove state after successful validation
	global.oauthStateStore.delete(state);
	return true;
}

export async function POST(request: NextRequest) {
	try {
		console.log('🔐 OAuth callback received');
		
		// 1. RATE LIMITING - Prevent OAuth abuse
		const rateLimitCheck = await createRateLimitMiddleware(RATE_LIMITS.STRICT)(request);
		if (rateLimitCheck) return rateLimitCheck;

		// 2. INPUT VALIDATION - Prevent injection attacks
		console.log('🔍 Validating OAuth request...');
		const validationCheck = await createValidationMiddleware(GitHubOAuthSchema)(request);
		if (validationCheck) {
			console.error('❌ Validation failed:', validationCheck);
			return validationCheck;
		}

		// 3. EXTRACT VALIDATED DATA
		const { code, state } = (request as any).validatedData;
		console.log('✅ Validation successful, code length:', code?.length, 'state:', state);

		// 4. STATE VALIDATION - Prevent CSRF attacks
		if (!state) {
			console.error('❌ Missing state parameter');
			return NextResponse.json(
				{ error: 'Missing state parameter' },
				{ status: 400 }
			);
		}

		// Validate state parameter format
		const stateRegex = /^[a-f0-9]{32,}$/i;
		if (!stateRegex.test(state)) {
			console.error('❌ Invalid state parameter format');
			return NextResponse.json(
				{ error: 'Invalid OAuth state format' },
				{ status: 400 }
			);
		}

		// Validate state length
		if (state.length < 32 || state.length > 128) {
			console.error('❌ State parameter length invalid:', state.length);
			return NextResponse.json(
				{ error: 'Invalid OAuth state' },
				{ status: 400 }
			);
		}

		// Get env vars and validate configuration
		const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID;
		const clientSecret = process.env.GITHUB_CLIENT_SECRET;
		const redirectUri = process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI;
		if (!clientId || !clientSecret || !redirectUri) {
			console.error('❌ GitHub OAuth env not configured', { hasClientId: !!clientId, hasClientSecret: !!clientSecret, hasRedirectUri: !!redirectUri });
			return NextResponse.json(
				{ error: 'OAuth configuration error' },
				{ status: 500 }
			);
		}

		// Validate OAuth state against stored state
		if (!validateOAuthState(state, clientId)) {
			console.error('❌ OAuth state validation failed');
			return NextResponse.json(
				{ error: 'Invalid or expired OAuth state' },
				{ status: 400 }
			);
		}

		console.log('✅ OAuth state validation successful');

		// 5. EXCHANGE AUTHORIZATION CODE FOR ACCESS TOKEN
		console.log('🔄 Exchanging code for token...');
		const form = new URLSearchParams();
		form.set('client_id', clientId);
		form.set('client_secret', clientSecret);
		form.set('code', code);
		form.set('redirect_uri', redirectUri);

		const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
			method: 'POST',
			headers: {
				'Accept': 'application/json',
				'Content-Type': 'application/x-www-form-urlencoded',
				'User-Agent': 'VibeCatcher-Security-App/1.0',
			},
			body: form.toString(),
		});

		if (!tokenResponse.ok) {
			const errorText = await tokenResponse.text();
			console.error('❌ GitHub token exchange failed:', tokenResponse.status, errorText);
			return NextResponse.json(
				{ error: 'OAuth token exchange failed' },
				{ status: 400 }
			);
		}

		const tokenData = await tokenResponse.json();
		console.log('✅ Token exchange response received');

		if (tokenData.error) {
			console.error('❌ GitHub OAuth error:', tokenData);
			return NextResponse.json(
				{ error: 'OAuth authentication failed' },
				{ status: 400 }
			);
		}

		// 6. SECURE RESPONSE - Only return necessary data
		console.log('🎉 OAuth callback completed successfully');
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
		console.error('❌ OAuth callback error:', error);
		return NextResponse.json(
			{ error: 'Internal server error' },
			{ status: 500 }
		);
	}
}
