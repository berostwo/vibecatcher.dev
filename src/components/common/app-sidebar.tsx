"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard,
  ShieldCheck,
  History,
  User,
  LogOut,
  Shield,
  ShoppingCart,
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
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { StripePayment } from "./stripe-payment"
import { usePaymentMode } from "@/contexts/payment-mode-context"

export function AppSidebar() {
  const pathname = usePathname()
  const { isPaymentMode, setIsPaymentMode } = usePaymentMode()

  const menuItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/dashboard/security-audit", label: "Security Audit", icon: ShieldCheck },
    { href: "/dashboard/audit-history", label: "Audit History", icon: History },
    { href: "/dashboard/account", label: "Account", icon: User },
  ]

  const handlePaymentStart = () => {
    setIsPaymentMode(true)
  }

  const handlePaymentEnd = () => {
    setIsPaymentMode(false)
  }

  return (
    <>
      <SidebarHeader className="border-b border-sidebar-border justify-center">
        <h2 className="text-lg font-semibold tracking-tighter group-data-[collapsible=icon]:hidden flex items-baseline justify-center">
          vibecatcher<Shield fill="currentColor" className="inline-block h-2 w-2 mx-0.5" />dev
        </h2>
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
        <div className={`mt-auto group-data-[collapsible=icon]:hidden transition-all duration-500 ease-in-out ${
          isPaymentMode ? 'p-4' : 'p-2'
        }`}>
            <SidebarSeparator className="my-4" />
            <div className={`transition-all duration-500 ease-in-out ${
              isPaymentMode ? 'scale-105' : 'scale-100'
            }`}>
              <StripePayment 
                onPaymentStart={handlePaymentStart}
                onPaymentEnd={handlePaymentEnd}
              />
            </div>
        </div>
      </SidebarContent>
      <SidebarFooter>
         <SidebarMenu>
           <SidebarMenuItem>
             <SidebarMenuButton asChild tooltip={{ children: 'Sign Out', side: 'right', align: 'center' }}>
                <Link href="/">
                    <LogOut />
                    <span>Sign Out</span>
                </Link>
             </SidebarMenuButton>
            </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </>
  )
}
