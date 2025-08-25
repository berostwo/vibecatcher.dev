'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ShieldCheck, Construction } from 'lucide-react';
import Link from 'next/link';
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page';

export default function SecurityAuditPage() {
  return (
    <DashboardPage>
      <DashboardPageHeader 
        title="Security Audit" 
        description="Security audit system is being rebuilt with the new worker architecture" 
      />
      
      <div className="space-y-6">
        <Card className="border-2 border-primary/20">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <Construction className="h-16 w-16 text-primary" />
            </div>
            <CardTitle className="text-2xl">Under Construction</CardTitle>
            <CardDescription>
              We're rebuilding the security audit system with a new, more powerful architecture
            </CardDescription>
      </CardHeader>
          <CardContent className="text-center space-y-4">
            <p className="text-muted-foreground">
              The security audit system is being completely rebuilt to work with our new modular worker architecture. 
              This will provide better performance, reliability, and more comprehensive security scanning.
            </p>
            
            <div className="bg-primary/10 rounded-lg p-4 border border-primary/30">
              <h4 className="font-semibold text-primary mb-2">What's New in the Rebuild:</h4>
              <ul className="text-sm text-left space-y-1">
                <li>• 5 specialized security scanners working in parallel</li>
                <li>• Improved accuracy and reduced false positives</li>
                <li>• Better performance and scalability</li>
                <li>• Enhanced AI-powered remediation prompts</li>
                <li>• Interactive audit workflow with status tracking</li>
              </ul>
            </div>
            
            <Button asChild>
              <Link href="/dashboard">
                Back to Dashboard
              </Link>
            </Button>
        </CardContent>
      </Card>
                </div>
    </DashboardPage>
  );
}
