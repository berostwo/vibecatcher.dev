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
} from "lucide-react"

import {
  SidebarHeader,
  SidebarContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
} from "@/components/ui/sidebar"
import { useAuthContext } from "@/contexts/auth-context"
import { GitHubService } from "@/lib/github-service"

export function AppSidebar() {
  const pathname = usePathname()
  const { signOut } = useAuthContext()

  const menuItems = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/dashboard/security-audit", label: "Security Audit", icon: ShieldCheck },
    { href: "/dashboard/audit-history", label: "Audit History", icon: History },
    { href: "/dashboard/account", label: "Account", icon: User },
  ]

  return (
    <>
      <SidebarHeader className="border-b border-sidebar-border justify-center">
        <h2 className="text-lg font-semibold tracking-tighter group-data-[collapsible=icon]:hidden flex items-baseline justify-center">
          vibecatcher<Shield fill="currentColor" className="inline-block h-2 w-2 mx-0.5" />dev
        </h2>
      </SidebarHeader>
      <SidebarContent className="flex-grow p-2 min-h-0">
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
      </SidebarContent>
    </>
  )
}
