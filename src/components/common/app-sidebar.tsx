"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useState } from "react"
import {
  LayoutDashboard,
  ShieldCheck,
  History,
  User,
  LogOut,
  Shield,
  ShoppingCart,
  LayoutTemplate,
} from "lucide-react"

import {
  SidebarHeader,
  SidebarContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarFooter,
  SidebarSeparator,
} from "@/components/ui/sidebar"
import { Button } from "@/components/ui/button"
import { useAuth } from "@/contexts/auth-context"
import { usePaymentSidebar } from "@/contexts/sidebar-context"
import { STRIPE_PRODUCTS } from "@/lib/stripe"
import { PaymentForm } from "@/components/payment/payment-form"
import { StripeProvider } from "@/components/providers/stripe-provider"

export function AppSidebar() {
  const pathname = usePathname()
  const { signOut, user, isLoading, githubToken } = useAuth()
  const { selectedProduct, setSelectedProduct, isExpanded, setIsExpanded } = usePaymentSidebar()

  const menuItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/dashboard/security-audit", label: "Security Audit", icon: ShieldCheck },
    { href: "/dashboard/audit-history", label: "Audit History", icon: History },
    { href: "/dashboard/template", label: "Template", icon: LayoutTemplate },
    { href: "/dashboard/account", label: "Account", icon: User },
  ]

  const handleProductSelect = (productId: string) => {
    setSelectedProduct(productId)
    setIsExpanded(true)
  }

  const handlePaymentBack = () => {
    setSelectedProduct(null)
    setIsExpanded(false)
  }

  const handlePaymentSuccess = () => {
    setSelectedProduct(null)
    setIsExpanded(false)
    // TODO: Update user's audit count in database
  }

  return (
    <div className={`transition-all duration-300 ${isExpanded ? 'w-96' : 'w-full'}`}>
      <SidebarHeader className="border-b border-sidebar-border justify-center">
        <div className="flex flex-col items-center space-y-2 group-data-[collapsible=icon]:hidden">
          <h2 className="text-lg font-semibold tracking-tighter flex items-baseline justify-center">
            vibecatcher<Shield fill="currentColor" className="inline-block h-2 w-2 mx-0.5" />dev
          </h2>
          {isLoading ? (
            <div className="flex items-center space-x-2 text-xs text-muted-foreground">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
              <span>Loading...</span>
            </div>
          ) : user ? (
            <div className="flex flex-col items-center space-y-1">
              <div className="flex items-center space-x-1 text-xs">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-green-600">Firebase</span>
              </div>
              {githubToken && (
                <div className="flex items-center space-x-1 text-xs">
                  <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                  <span className="text-blue-600">GitHub</span>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center space-x-1 text-xs text-muted-foreground">
              <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
              <span>Not signed in</span>
            </div>
          )}
        </div>
      </SidebarHeader>
      <SidebarContent className="flex-grow p-2">
        <SidebarMenu>
          {menuItems.map((item) => (
            <SidebarMenuItem key={item.href}>
              <SidebarMenuButton
                asChild
                isActive={pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href))}
                tooltip={{ children: item.label, side: 'right', align: 'center' }}
              >
                <Link href={item.href}>
                  <item.icon />
                  <span>{item.label}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
        <div className="mt-auto group-data-[collapsible=icon]:hidden">
            {selectedProduct ? (
              <div className="space-y-4">
                <SidebarSeparator className="my-4" />
                <StripeProvider>
                  <PaymentForm
                    productId={selectedProduct}
                    onBack={handlePaymentBack}
                    onSuccess={handlePaymentSuccess}
                  />
                </StripeProvider>
              </div>
            ) : (
              <>
                <SidebarSeparator className="my-4" />
                <div className="space-y-2">
                     {Object.values(STRIPE_PRODUCTS).map((product) => (
                        <Button 
                          key={product.id} 
                          variant="outline" 
                          className="w-full justify-between h-auto p-3 bg-sidebar-accent border-2 border-primary/20 hover:bg-background/50"
                          onClick={() => handleProductSelect(product.id)}
                        >
                             <div>
                                <p className="text-sm font-medium text-left">{product.name}</p>
                                <p className="text-xs text-muted-foreground text-left">${product.price}</p>
                            </div>
                            <ShoppingCart className="h-4 w-4 text-primary" />
                        </Button>
                     ))}
                </div>
              </>
            )}
        </div>
      </SidebarContent>
      <SidebarFooter>
         <SidebarMenu>
           <SidebarMenuItem>
             <SidebarMenuButton 
               onClick={async () => {
                 if (confirm('Are you sure you want to sign out?')) {
                   try {
                     await signOut()
                     // Redirect to home page after sign out
                     window.location.href = '/'
                   } catch (error) {
                     console.error('Error signing out')
                     // Still redirect to home page even if there's an error
                     window.location.href = '/'
                   }
                 }
               }}
               tooltip={{ children: 'Sign Out', side: 'right', align: 'center' }}
               className="w-full hover:bg-destructive/10 hover:text-destructive"
             >
                <LogOut />
                <span>Sign Out</span>
             </SidebarMenuButton>
            </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </div>
  )
}
