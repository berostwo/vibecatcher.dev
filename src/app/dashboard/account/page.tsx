'use client';

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Github } from "lucide-react"
import { DashboardPage, DashboardPageHeader } from "@/components/common/dashboard-page"
import { useAuth } from '@/contexts/auth-context'
import { useRouter } from 'next/navigation'
import { useEffect } from 'react'

export default function AccountPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !user) {
      router.replace('/');
    }
  }, [isLoading, user, router]);

  if (isLoading || (!user && typeof window !== 'undefined')) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Account" description="Manage your account details." />
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </DashboardPage>
    );
  }

  if (!user) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Account" description="Manage your account details." />
        <div className="flex flex-col items-center justify-center py-12 gap-4">
          <p className="text-muted-foreground">You must be signed in to view account information.</p>
          <Button onClick={() => router.push('/')}>Go to Home</Button>
        </div>
      </DashboardPage>
    );
  }

  return (
    <DashboardPage>
      <DashboardPageHeader title="Account" description="Manage your account details." />
      <Separator />

      <Card className="border-2 border-primary/20">
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>This is your public profile information.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
           <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16">
                    <AvatarImage src={user.photoURL || "https://github.com/shadcn.png"} alt="@user" />
                    <AvatarFallback>{(user.displayName || user.email || 'U').slice(0,2).toUpperCase()}</AvatarFallback>
                </Avatar>
                <div>
                    <p className="font-medium text-lg">{user.displayName || 'Your Name'}</p>
                    <p className="text-sm text-muted-foreground">{user.email || 'your.email@example.com'}</p>
                </div>
           </div>
           <div className="flex items-center gap-2 pt-2">
            <Github className="w-4 h-4 text-muted-foreground"/>
            <span className="text-sm text-muted-foreground">Connected to: your-github-username</span>
           </div>
        </CardContent>
        <CardFooter>
            <Button variant="outline">Edit Profile</Button>
        </CardFooter>
      </Card>
    </DashboardPage>
  )
}
