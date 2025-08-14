import type { PropsWithChildren } from "react"
import {
  Sidebar as UISidebar,
  SidebarInset,
  SidebarTrigger,
  SidebarProvider,
} from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/common/app-sidebar"
import { AppFooter } from "@/components/common/app-footer";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { ArrowRight, CheckCircle } from "lucide-react";
import { StripeProvider } from "@/components/providers/stripe-provider"
import { PaymentSidebarProvider } from "@/contexts/sidebar-context"
import { BlurWrapper } from "@/components/common/blur-wrapper"

export default function DashboardLayout({ children }: PropsWithChildren) {
  return (
    <StripeProvider>
      <SidebarProvider>
        <PaymentSidebarProvider>
          <UISidebar collapsible="icon" variant="sidebar">
            <AppSidebar />
          </UISidebar>
          <SidebarInset>
            <BlurWrapper>
              <div className="flex flex-col px-4 sm:px-6 lg:px-8 min-h-screen">
                <div className="flex justify-between items-center">
                  <div className="md:hidden">
                    <SidebarTrigger />
                  </div>
                </div>
                <div className="flex-grow pt-8">
                  {children}
                </div>
                <AppFooter />
              </div>
            </BlurWrapper>
          </SidebarInset>
        </PaymentSidebarProvider>
      </SidebarProvider>
    </StripeProvider>
  )
}
