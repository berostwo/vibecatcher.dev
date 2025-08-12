import { NextRequest, NextResponse } from 'next/server';

// In-memory token storage (in production, use Redis or database)
const tokenStore = new Map<string, { token: string; expires: number }>();

export async function POST(request: NextRequest) {
  try {
    const { userId, accessToken } = await request.json();
    
    if (!userId || !accessToken) {
      return NextResponse.json(
        { error: 'Missing userId or accessToken' },
        { status: 400 }
      );
    }

    // Store token with expiration (1 hour)
    const expires = Date.now() + (60 * 60 * 1000);
    tokenStore.set(userId, { token: accessToken, expires });
    
    console.log(`Token stored for user ${userId}, expires at ${new Date(expires)}`);
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error storing token:', error);
    return NextResponse.json(
      { error: 'Failed to store token' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Missing userId parameter' },
        { status: 400 }
      );
    }

    const tokenData = tokenStore.get(userId);
    
    if (!tokenData) {
      return NextResponse.json(
        { error: 'Token not found' },
        { status: 404 }
      );
    }

    // Check if token is expired
    if (Date.now() > tokenData.expires) {
      tokenStore.delete(userId);
      return NextResponse.json(
        { error: 'Token expired' },
        { status: 401 }
      );
    }

    return NextResponse.json({ 
      token: tokenData.token,
      expires: tokenData.expires
    });
  } catch (error) {
    console.error('Error retrieving token:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve token' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { userId } = await request.json();
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Missing userId' },
        { status: 400 }
      );
    }

    tokenStore.delete(userId);
    console.log(`Token deleted for user ${userId}`);
    
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting token:', error);
    return NextResponse.json(
      { error: 'Failed to delete token' },
      { status: 500 }
    );
  }
}
