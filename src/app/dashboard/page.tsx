'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Github, History, ShieldCheck, ArrowRight, CheckCircle, ShoppingCart } from 'lucide-react'
import Link from 'next/link'
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page'
import { useAuth } from '@/contexts/auth-context'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

export default function DashboardPageContent() {
  const { user, githubToken, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !user) {
      router.replace('/');
    }
  }, [isLoading, user, router]);
  
  if (isLoading || (!user && typeof window !== 'undefined')) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Dashboard" description="An overview of your account and security audits." />
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </DashboardPage>
    );
  }
  
  if (!user) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Dashboard" description="An overview of your account and security audits." />
        <div className="flex flex-col items-center justify-center py-12 gap-4">
          <p className="text-muted-foreground">You must be signed in to view your dashboard.</p>
          <Button asChild>
            <Link href="/">Go to Home</Link>
          </Button>
        </div>
      </DashboardPage>
    );
  }
  
  return (
    <DashboardPage>
      <DashboardPageHeader title="Dashboard" description="An overview of your account and security audits." />
      
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-2 border-primary/20">
            <CardHeader>
                <div className="flex items-center space-x-4">
                    {user?.photoURL && (
                        <img 
                            src={user.photoURL} 
                            alt="Profile" 
                            className="w-16 h-16 rounded-full border-2 border-primary/30"
                        />
                    )}
                    <div>
                        <CardTitle className="flex items-center space-x-2">
                            <span>Hello, {user?.displayName || user?.email || 'User'}!</span>
                            {githubToken && (
                                <div className="flex items-center space-x-1 text-xs">
                                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                                    <span className="text-green-600 font-medium">GitHub Connected</span>
                                </div>
                            )}
                        </CardTitle>
                        {user?.displayName && user.displayName !== user.email && (
                            <p className="text-sm text-muted-foreground mt-1">
                                Welcome back to your security dashboard
                            </p>
                        )}
                        <CardDescription>
                            Ready to secure your code?
                        </CardDescription>
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <Button asChild>
                    <Link href="/dashboard/security-audit">
                        Start Audit
                        <ArrowRight className="ml-2 h-4 w-4"/>
                    </Link>
                </Button>
            </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Audits Available</CardTitle>
            <CheckCircle className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">8</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Repos</CardTitle>
            <Github className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <p className="text-xs text-muted-foreground">
              Connected via your GitHub account
            </p>
          </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Audits Performed</CardTitle>
            <History className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">42</div>
            <p className="text-xs text-muted-foreground">
              Across all connected repositories
            </p>
          </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues Found</CardTitle>
            <ShieldCheck className="h-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">3</div>
            <p className="text-xs text-muted-foreground">
              In the last 30 days
            </p>
          </CardContent>
        </Card>
      </div>
    </DashboardPage>
  )
}
