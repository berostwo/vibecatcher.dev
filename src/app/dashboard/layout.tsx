'use client';

import { PropsWithChildren, useEffect, useRef, useState } from 'react';
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuItem, SidebarMenuButton, SidebarSeparator, SidebarProvider } from '@/components/ui/sidebar';
import { LogOut } from 'lucide-react';
import { useAuthContext } from '@/contexts/auth-context';
import { PaymentModeProvider, usePaymentMode } from '@/contexts/payment-mode-context';
import { StripePayment } from '@/components/common/stripe-payment';
import { AppSidebar } from '@/components/common/app-sidebar';
import { AppFooter } from '@/components/common/app-footer';
import { ProtectedRoute } from "@/components/common/protected-route";

function DashboardContent({ children }: PropsWithChildren) {
  const { isPaymentMode, setIsPaymentMode } = usePaymentMode();
  const { signOut, user } = useAuthContext();
  const sidebarRef = useRef<HTMLDivElement>(null);

  // Auto-scroll sidebar to bottom when payment mode expands
  useEffect(() => {
    if (isPaymentMode && sidebarRef.current) {
      const sidebar = sidebarRef.current;
      // Use setTimeout to ensure the DOM has updated with the expanded content
      setTimeout(() => {
        sidebar.scrollTo({
          top: sidebar.scrollHeight,
          behavior: 'smooth'
        });
      }, 100);
    }
  }, [isPaymentMode]);

  const handlePaymentSuccess = (packageId: string) => {
    console.log("Payment successful for package:", packageId);
    
    // Get audit count for this package
    const PACKAGE_TO_AUDITS: Record<string, number> = {
      single_audit: 1,
      five_audits: 5,
      ten_audits: 10,
    };
    
    const auditCount = PACKAGE_TO_AUDITS[packageId];
    if (auditCount) {
      console.log(`Adding ${auditCount} audits to local counter`);
      // This will be handled by the dashboard page's refresh mechanism
    }
  };

  return (
    <SidebarProvider>
      <div className="flex h-screen">
        <Sidebar 
          collapsible="icon" 
          variant="sidebar"
          className={`transition-all duration-500 ease-in-out ${
            isPaymentMode ? 'w-96' : 'w-64'
          }`}
        >
          <div 
            ref={sidebarRef}
            className="h-full flex flex-col"
          >
            {/* Scrollable content area */}
            <div className="flex-1 overflow-y-auto scrollbar-hide">
              <AppSidebar onPaymentSuccess={handlePaymentSuccess} />
            </div>
            
            {/* Footer positioned at bottom */}
            <SidebarFooter>
              {/* Purchase options */}
              <div className="p-2">
                <SidebarSeparator className="my-4" />
                <div className="transition-all duration-500 ease-in-out">
                  <StripePayment 
                    onPaymentStart={() => setIsPaymentMode(true)}
                    onPaymentEnd={() => setIsPaymentMode(false)}
                    onPaymentSuccess={handlePaymentSuccess}
                  />
                </div>
              </div>
              
              {/* Sign Out button */}
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton 
                    onClick={async () => {
                      try {
                        // Clear GitHub token first
                        const { GitHubService } = await import('@/lib/github-service');
                        await GitHubService.clearToken(user?.uid || '');
                        
                        // Then sign out from Firebase
                        await signOut();
                        
                        // Navigate to home page after successful sign out
                        window.location.href = '/';
                      } catch (error) {
                        console.error('Sign out failed:', error);
                        // Even if Firebase sign out fails, clear tokens and redirect
                        try {
                          const { GitHubService } = await import('@/lib/github-service');
                          await GitHubService.clearToken(user?.uid || '');
                        } catch (clearError) {
                          console.error('Failed to clear GitHub token:', clearError);
                        }
                        window.location.href = '/';
                      }
                    }}
                    tooltip={{ children: 'Sign Out', side: 'right', align: 'center' }}
                  >
                    <LogOut />
                    <span>Sign Out</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarFooter>
          </div>
        </Sidebar>
        <SidebarInset>
          <div className="flex flex-col px-4 sm:px-6 lg:px-8 min-h-screen transition-all duration-500 ease-in-out">
            {/* Header */}
            <header className="flex items-center justify-between py-6 border-b border-border">
              <div>
                <h1 className="text-2xl font-bold">Dashboard</h1>
                <p className="text-muted-foreground">Manage your security audits and account</p>
              </div>
            </header>
            
            {/* Main content */}
            <div className={`flex-grow pt-8 transition-all duration-500 ease-in-out ${
              isPaymentMode ? 'blur-sm pointer-events-none' : ''
            }`}>
              {children}
            </div>
            <AppFooter />
          </div>
        </SidebarInset>
      </div>
    </SidebarProvider>
  );
}

export default function DashboardLayout({ children }: PropsWithChildren) {
  return (
    <ProtectedRoute>
      <PaymentModeProvider>
        <DashboardContent>{children}</DashboardContent>
      </PaymentModeProvider>
    </ProtectedRoute>
  );
}
