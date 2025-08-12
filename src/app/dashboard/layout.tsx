"use client"

import type { PropsWithChildren } from "react"
import { useRef, useEffect } from "react"
import {
  SidebarProvider,
  Sidebar,
  SidebarInset,
  SidebarTrigger,
  SidebarFooter,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarSeparator,
} from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/common/app-sidebar"
import { AppFooter } from "@/components/common/app-footer";
import { ProtectedRoute } from "@/components/common/protected-route";
import { PaymentModeProvider, usePaymentMode } from "@/contexts/payment-mode-context";
import { LogOut } from "lucide-react";
import { useAuthContext } from "@/contexts/auth-context";
import { StripePayment } from "@/components/common/stripe-payment";

function DashboardContent({ children }: PropsWithChildren) {
  const { isPaymentMode, setIsPaymentMode } = usePaymentMode();
  const { signOut } = useAuthContext();
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

  return (
    <SidebarProvider>
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
            <AppSidebar />
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
                      GitHubService.clearToken();
                      
                      // Then sign out from Firebase
                      await signOut();
                      
                      // Navigate to home page after successful sign out
                      window.location.href = '/';
                    } catch (error) {
                      console.error('Sign out failed:', error);
                      // Even if Firebase sign out fails, clear tokens and redirect
                      const { GitHubService } = await import('@/lib/github-service');
                      GitHubService.clearToken();
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
          <div className="flex justify-between items-center">
            <div className="md:hidden">
              <SidebarTrigger />
            </div>
          </div>
          <div className="flex-grow pt-8">
            <div className={`transition-all duration-500 ease-in-out ${
              isPaymentMode ? 'blur-sm pointer-events-none' : ''
            }`}>
              {children}
            </div>
          </div>
          <AppFooter />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}

export default function DashboardLayout({ children }: PropsWithChildren) {
  return (
    <ProtectedRoute>
      <PaymentModeProvider>
        <DashboardContent>
          {children}
        </DashboardContent>
      </PaymentModeProvider>
    </ProtectedRoute>
  )
}
