'use client'

import { PropsWithChildren } from 'react'
import {
  Sidebar as UISidebar,
  SidebarInset,
  SidebarTrigger,
  SidebarProvider,
} from '@/components/ui/sidebar'
import { AppSidebar } from '@/components/common/app-sidebar'
import { AppFooter } from '@/components/common/app-footer'
import { BlurWrapper } from '@/components/common/blur-wrapper'
import { usePaymentSidebar } from '@/contexts/sidebar-context'

export default function DashboardShell({ children }: PropsWithChildren) {
  const { isExpanded } = usePaymentSidebar()

  // Dynamically widen the overlay sidebar when payment panel is expanded
  const sidebarWidth = isExpanded ? '24rem' : '16rem'

  return (
    <SidebarProvider>
      <UISidebar collapsible="offcanvas" variant="sidebar" style={{ ['--sidebar-width' as any]: sidebarWidth }}>
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
            <div className="flex-grow pt-8">{children}</div>
            <AppFooter />
          </div>
        </BlurWrapper>
      </SidebarInset>
    </SidebarProvider>
  )
}


