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

export default function DashboardLayout({ children }: PropsWithChildren) {
  return (
    <ProtectedRoute>
      <SidebarProvider>
        <Sidebar collapsible="icon" variant="sidebar">
          <AppSidebar />
        </Sidebar>
        <SidebarInset>
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
        </SidebarInset>
      </SidebarProvider>
    </ProtectedRoute>
  )
}
