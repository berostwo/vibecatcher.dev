'use client';

import { useAuthContext } from '@/contexts/auth-context';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { user, loading } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    console.log('ProtectedRoute: Auth state changed:', { user: !!user, loading, userId: user?.uid });
    
    if (!loading && !user) {
      console.log('ProtectedRoute: No user, redirecting to home');
      router.push('/');
    }
  }, [user, loading, router]);

  // Show loading state while checking authentication
  if (loading) {
    console.log('ProtectedRoute: Still loading auth state');
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          <span className="text-muted-foreground">Loading...</span>
        </div>
      </div>
    );
  }

  // Don't render anything if user is not authenticated
  if (!user || !user.uid) {
    console.log('ProtectedRoute: No authenticated user, blocking access');
    return null;
  }

  console.log('ProtectedRoute: User authenticated, rendering dashboard');
  // Render protected content if user is authenticated
  return <>{children}</>;
}

