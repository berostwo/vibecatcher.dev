'use client';

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { useGitHubAuth } from '@/contexts/github-auth-context';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const router = useRouter();
  const { user, loading } = useGitHubAuth();

  useEffect(() => {
    if (!loading && !user) {
      console.log('ProtectedRoute: No user, redirecting to home');
      router.push('/');
    }
  }, [user, loading, router]);

  // Show loading state while checking authentication
  if (loading) {
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
  if (!user) {
    return null;
  }

  // Render protected content if user is authenticated
  return <>{children}</>;
}

