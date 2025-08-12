"use client"

import type { PropsWithChildren } from "react"
import {
  SidebarProvider,
  Sidebar,
  SidebarInset,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/common/app-sidebar"
import { AppFooter } from "@/components/common/app-footer";
import { ProtectedRoute } from "@/components/common/protected-route";
import { PaymentModeProvider, usePaymentMode } from "@/contexts/payment-mode-context";

function DashboardContent({ children }: PropsWithChildren) {
  const { isPaymentMode } = usePaymentMode();

  return (
    <SidebarProvider>
      <Sidebar 
        collapsible="icon" 
        variant="sidebar"
        className={`transition-all duration-500 ease-in-out ${
          isPaymentMode ? 'w-96' : 'w-64'
        }`}
      >
        <AppSidebar />
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
