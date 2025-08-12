'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { ArrowRight, CheckCircle, RefreshCw } from 'lucide-react';
import Link from 'next/link';
import { useAuthContext } from '@/contexts/auth-context';
import { UserService } from '@/lib/user-service';

export default function DashboardPage() {
  const { user } = useAuthContext();
  const [userData, setUserData] = useState<any>(null);
  const [refreshedUserData, setRefreshedUserData] = useState<any>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showAuditAdded, setShowAuditAdded] = useState(false);

  // Load user data on component mount
  useEffect(() => {
    if (user) {
      loadUserData();
    }
  }, [user]);

  // Auto-refresh user data every 30 seconds
  useEffect(() => {
    if (!user) return;

    const interval = setInterval(() => {
      refreshUserData();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [user]);

  // Show audit added notification when count increases
  useEffect(() => {
    if (refreshedUserData && userData && refreshedUserData.auditsAvailable > userData.auditsAvailable) {
      setShowAuditAdded(true);
      setTimeout(() => setShowAuditAdded(false), 5000); // Hide after 5 seconds
    }
  }, [refreshedUserData, userData]);

  const loadUserData = async () => {
    if (!user) return;
    
    try {
      const data = await UserService.getUserData(user.uid);
      setUserData(data);
      setRefreshedUserData(data);
    } catch (error) {
      console.error('Error loading user data:', error);
    }
  };

  const refreshUserData = async () => {
    if (!user) return;
    
    setIsRefreshing(true);
    try {
      const data = await UserService.getUserData(user.uid);
      setRefreshedUserData(data);
    } catch (error) {
      console.error('Error refreshing user data:', error);
    } finally {
      setIsRefreshing(false);
    }
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  const displayName = userData?.displayName || user?.displayName || 'User';
  const userPhoto = userData?.photoURL || user?.photoURL;

  return (
    <div className="space-y-6">
      {/* Success notification */}
      {showAuditAdded && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 text-center">
          <div className="flex items-center justify-center gap-2 text-green-500">
            <CheckCircle className="h-5 w-5" />
            <span className="font-semibold">Audits Added!</span>
          </div>
        </div>
      )}

      {/* Welcome Card */}
      <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-2 border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-3">
            <Avatar className="h-10 w-10">
              <AvatarImage src={userPhoto} alt={displayName} />
              <AvatarFallback className="bg-primary text-primary-foreground">
                {displayName.charAt(0).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <span>Hello, {displayName}!</span>
          </CardTitle>
          <CardDescription>
            Ready to secure your code?
          </CardDescription>
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

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Audits Available */}
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Audits Available</CardTitle>
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-primary" />
              <Button
                variant="ghost"
                size="sm"
                onClick={refreshUserData}
                disabled={isRefreshing}
                className="h-6 w-6 p-0 hover:bg-primary/10"
                title="Refresh audit count"
              >
                <RefreshCw className={`h-3 w-3 ${isRefreshing ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold transition-all duration-300">
              {refreshedUserData?.auditsAvailable || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {refreshedUserData?.auditsAvailable === 1 ? '1 audit available' : `${refreshedUserData?.auditsAvailable || 0} audits available`}
            </p>
            {isRefreshing && (
              <p className="text-xs text-primary mt-2">Refreshing...</p>
            )}
            
            {/* Debug button - remove in production */}
            {process.env.NODE_ENV === 'development' && (
              <div className="mt-3 pt-3 border-t border-border">
                <div className="space-y-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={async () => {
                      if (!user) return;
                      try {
                        await UserService.addAudits(user.uid, 1);
                        console.log('✅ Test audit added');
                        refreshUserData();
                      } catch (error) {
                        console.error('❌ Test audit failed:', error);
                      }
                    }}
                    className="w-full text-xs"
                  >
                    Test: Add 1 Audit
                  </Button>
                  
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={async () => {
                      try {
                        const response = await fetch('/api/webhooks/stripe');
                        const data = await response.json();
                        console.log('🧪 Webhook test result:', data);
                        alert(`Webhook test: ${data.message}`);
                      } catch (error) {
                        console.error('❌ Webhook test failed:', error);
                        alert('Webhook test failed');
                      }
                    }}
                    className="w-full text-xs"
                  >
                    Test: Webhook Endpoint
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Total Audits Used */}
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Audits Used</CardTitle>
            <Badge variant="secondary">Lifetime</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {refreshedUserData?.totalAuditsUsed || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {refreshedUserData?.totalAuditsUsed === 1 ? '1 audit completed' : `${refreshedUserData?.totalAuditsUsed || 0} audits completed`}
            </p>
          </CardContent>
        </Card>

        {/* Account Status */}
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Account Status</CardTitle>
            <Badge variant="default" className="bg-green-500 hover:bg-green-600">Active</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">Active</div>
            <p className="text-xs text-muted-foreground">
              Your account is active and ready
            </p>
          </CardContent>
        </Card>

        {/* GitHub Integration */}
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">GitHub Integration</CardTitle>
            <Badge variant="outline">Connected</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-500">Connected</div>
            <p className="text-xs text-muted-foreground">
              GitHub OAuth active
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="border-2 border-primary/20">
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Get started with security auditing
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-4">
          <Button asChild variant="default" size="lg">
            <Link href="/dashboard/security-audit">
              <CheckCircle className="mr-2 h-5 w-5" />
              Start New Audit
            </Link>
          </Button>
          <Button asChild variant="outline" size="lg">
            <Link href="/dashboard/audit-history">
              <RefreshCw className="mr-2 h-5 w-5" />
              View History
            </Link>
          </Button>
          <Button asChild variant="outline" size="lg">
            <Link href="/dashboard/account">
              <CheckCircle className="mr-2 h-5 w-5" />
              Account Settings
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
