import { NextRequest, NextResponse } from 'next/server';

// In-memory storage for development (replace with database in production)
const tokenStore = new Map<string, { token: string; timestamp: number }>();

export async function POST(request: NextRequest) {
  try {
    const { userId, accessToken } = await request.json();

    if (!userId || !accessToken) {
      return NextResponse.json(
        { error: 'Missing userId or accessToken' },
        { status: 400 }
      );
    }

    // Store token with timestamp
    tokenStore.set(userId, {
      token: accessToken,
      timestamp: Date.now(),
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error storing token:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
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
      return NextResponse.json({ token: null });
    }

    // Check if token is expired (24 hours)
    const now = Date.now();
    if (now - tokenData.timestamp > 24 * 60 * 60 * 1000) {
      tokenStore.delete(userId);
      return NextResponse.json({ token: null });
    }

    return NextResponse.json({ token: tokenData.token });
  } catch (error) {
    console.error('Error retrieving token:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { userId } = await request.json();

    if (!userId) {
      return NextResponse.json(
        { error: 'Missing userId parameter' },
        { status: 400 }
      );
    }

    tokenStore.delete(userId);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting token:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
