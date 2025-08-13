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

export function AppSidebar() {
  const pathname = usePathname()

  const menuItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/dashboard/security-audit", label: "Security Audit", icon: ShieldCheck },
    { href: "/dashboard/audit-history", label: "Audit History", icon: History },
    { href: "/dashboard/template", label: "Template", icon: LayoutTemplate },
    { href: "/dashboard/account", label: "Account", icon: User },
  ]

  const purchaseOptions = [
    { title: "Single Audit", price: "$4.99" },
    { title: "5 Audits", price: "$11.99" },
    { title: "10 Audits", price: "$18.99" },
  ]

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
        <div className="mt-auto group-data-[collapsible=icon]:hidden">
            <SidebarSeparator className="my-4" />
            <div className="space-y-2">
                 {purchaseOptions.map((option) => (
                    <Button key={option.title} variant="outline" className="w-full justify-between h-auto p-3 bg-sidebar-accent border-2 border-primary/20 hover:bg-background/50">
                         <div>
                            <p className="text-sm font-medium text-left">{option.title}</p>
                            <p className="text-xs text-muted-foreground text-left">{option.price}</p>
                        </div>
                        <ShoppingCart className="h-4 w-4 text-primary" />
                    </Button>
                 ))}
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
