import type { PropsWithChildren } from "react"
import { StripeProvider } from "@/components/providers/stripe-provider"
import { PaymentSidebarProvider } from "@/contexts/sidebar-context"
import DashboardShell from "@/components/common/dashboard-shell"

export default function DashboardLayout({ children }: PropsWithChildren) {
  return (
    <StripeProvider>
      <PaymentSidebarProvider>
        <DashboardShell>{children}</DashboardShell>
      </PaymentSidebarProvider>
    </StripeProvider>
  )
}
