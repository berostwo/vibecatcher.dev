import { NextRequest, NextResponse } from 'next/server';

// Simple in-memory cache to prevent duplicate code usage
const usedCodes = new Map<string, number>();

// Clean up old codes (older than 10 minutes)
const cleanupOldCodes = () => {
  const now = Date.now();
  const tenMinutesAgo = now - 10 * 60 * 1000;
  
  for (const [code, timestamp] of usedCodes.entries()) {
    if (timestamp < tenMinutesAgo) {
      usedCodes.delete(code);
    }
  }
};

export async function POST(request: NextRequest) {
  try {
    // Clean up old codes periodically
    cleanupOldCodes();
    
    console.log('=== OAuth Callback API Called ===');
    console.log('Timestamp:', new Date().toISOString());
    console.log('Request headers:', Object.fromEntries(request.headers.entries()));
    
    // Get the raw request body for debugging
    const rawBody = await request.text();
    console.log('Raw request body:', rawBody);
    
    let body;
    try {
      body = JSON.parse(rawBody);
    } catch (parseError) {
      console.error('Failed to parse request body as JSON:', parseError);
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }
    
    const { code, state } = body;

    if (!code || !state) {
      console.error('Missing code or state in request body:', body);
      return NextResponse.json(
        { error: 'Missing code or state parameter' },
        { status: 400 }
      );
    }

    // Check if this code has already been used
    if (usedCodes.has(code)) {
      console.error('OAuth code already used:', code.substring(0, 10) + '...');
      return NextResponse.json(
        { error: 'OAuth code has already been used' },
        { status: 400 }
      );
    }

    // Mark this code as used with timestamp
    usedCodes.set(code, Date.now());

    console.log('OAuth callback API called with code:', code.substring(0, 10) + '...', 'state:', state);
    console.log('=====================================');

    // Check if required environment variables are set
    if (!process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID) {
      console.error('Missing NEXT_PUBLIC_GITHUB_CLIENT_ID environment variable');
      return NextResponse.json(
        { error: 'GitHub OAuth not properly configured' },
        { status: 500 }
      );
    }

    if (!process.env.GITHUB_CLIENT_SECRET) {
      console.error('Missing GITHUB_CLIENT_SECRET environment variable');
      return NextResponse.json(
        { error: 'GitHub OAuth not properly configured' },
        { status: 500 }
      );
    }

    const redirectUri = process.env.NEXT_PUBLIC_GITHUB_REDIRECT_URI || `${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:9002'}/auth/github/callback`;
    
    console.log('Using redirect URI:', redirectUri);
    console.log('Using client ID:', process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID);

    // Exchange authorization code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: redirectUri,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('GitHub token exchange failed:', tokenResponse.status, errorText);
      return NextResponse.json(
        { error: `Failed to exchange code for token: ${tokenResponse.status} ${errorText}` },
        { status: 500 }
      );
    }

    const tokenData = await tokenResponse.json();
    console.log('GitHub token response received');
    console.log('Full token response:', JSON.stringify(tokenData, null, 2));
    console.log('Token response keys:', Object.keys(tokenData));
    console.log('Access token length:', tokenData.access_token ? tokenData.access_token.length : 'undefined');
    console.log('Access token preview:', tokenData.access_token ? `${tokenData.access_token.substring(0, 10)}...` : 'undefined');

    if (tokenData.error) {
      console.error('GitHub OAuth error:', tokenData);
      return NextResponse.json(
        { error: tokenData.error_description || tokenData.error || 'OAuth error' },
        { status: 400 }
      );
    }

    const { access_token } = tokenData;

    if (!access_token) {
      console.error('No access token in response:', tokenData);
      return NextResponse.json(
        { error: 'No access token received' },
        { status: 500 }
      );
    }

    console.log('Access token received successfully');
    console.log('Final access token length:', access_token.length);
    console.log('Final access token preview:', `${access_token.substring(0, 10)}...`);
    // Return the access token to the client
    return NextResponse.json({ access_token });

  } catch (error) {
    console.error('OAuth callback error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
