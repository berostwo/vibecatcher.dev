import { NextRequest, NextResponse } from 'next/server';
import { FirebaseUserService } from '@/lib/firebase-user-service';

export async function POST(request: NextRequest) {
  try {
    const { userId, accessToken } = await request.json();

    if (!userId || !accessToken) {
      return NextResponse.json(
        { error: 'Missing userId or accessToken' },
        { status: 400 }
      );
    }

    // Store token securely in Firebase database
    await FirebaseUserService.updateUserToken(userId, accessToken);

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

    // Get token securely from Firebase database with expiration check
    // getGitHubToken already handles expiration validation internally
    const token = await FirebaseUserService.getGitHubToken(userId);
    
    if (!token) {
      return NextResponse.json({ token: null });
    }

    return NextResponse.json({ token });
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

    // Remove token securely from Firebase database
    await FirebaseUserService.removeGitHubToken(userId);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting token:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
