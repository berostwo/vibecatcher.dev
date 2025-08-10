'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { 
  Shield, 
  FileText, 
  Settings, 
  LogOut, 
  Menu, 
  X,
  User,
  Crown,
  Zap,
  Home
} from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: Home },
  { name: 'New Audit', href: '/dashboard/audit', icon: Shield },
  { name: 'Reports', href: '/dashboard/reports', icon: FileText },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
]

export default function Sidebar() {
  const [isOpen, setIsOpen] = useState(false)
  const pathname = usePathname()
  const { user, userProfile, signOut } = useAuth()

  const handleSignOut = async () => {
    try {
      await signOut()
    } catch (error) {
      console.error('Sign out error:', error)
    }
  }

  const getSubscriptionIcon = (plan: string) => {
    switch (plan) {
      case 'pro':
        return <Crown className="w-4 h-4 text-yellow-400" />
      case 'basic':
        return <Zap className="w-4 h-4 text-blue-400" />
      default:
        return <Shield className="w-4 h-4 text-green-400" />
    }
  }

  const getSubscriptionColor = (plan: string) => {
    switch (plan) {
      case 'pro':
        return 'bg-gradient-to-r from-yellow-500/20 to-orange-500/20 border-yellow-500/30'
      case 'basic':
        return 'bg-gradient-to-r from-blue-500/20 to-purple-500/20 border-blue-500/30'
      default:
        return 'bg-gradient-to-r from-green-500/20 to-emerald-500/20 border-green-500/30'
    }
  }

  return (
    <>
      {/* Mobile menu button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-dark-900 border border-dark-800 rounded-lg text-white hover:bg-dark-800 transition-colors"
      >
        {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Sidebar */}
      <motion.div
        initial={false}
        animate={{ 
          x: isOpen ? 0 : '-100%',
          opacity: isOpen ? 1 : 0
        }}
        transition={{ duration: 0.3 }}
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 bg-dark-900 border-r border-dark-800 lg:translate-x-0 lg:static lg:inset-0",
          "transform transition-transform duration-300 ease-in-out lg:transition-none"
        )}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="p-6 border-b border-dark-800">
            <Link href="/dashboard" className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-primary-400 to-accent-400 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold gradient-text">vibecatcher.dev</span>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6">
            <ul className="space-y-2">
              {navigation.map((item) => {
                const isActive = pathname === item.href
                return (
                  <li key={item.name}>
                    <Link
                      href={item.href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                        isActive
                          ? "bg-primary-600/20 text-primary-400 border border-primary-500/30"
                          : "text-dark-300 hover:text-white hover:bg-dark-800"
                      )}
                      onClick={() => setIsOpen(false)}
                    >
                      <item.icon className="w-5 h-5" />
                      {item.name}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </nav>

          {/* User Profile */}
          {user && userProfile && (
            <div className="p-4 border-t border-dark-800">
              {/* Subscription Status */}
              <div className={cn(
                "p-3 rounded-lg border mb-3",
                getSubscriptionColor(userProfile.subscription?.plan || 'free')
              )}>
                <div className="flex items-center gap-2 mb-2">
                  {getSubscriptionIcon(userProfile.subscription?.plan || 'free')}
                  <span className="text-sm font-medium text-white capitalize">
                    {userProfile.subscription?.plan || 'free'} Plan
                  </span>
                </div>
                <div className="text-xs text-dark-300">
                  {userProfile.subscription?.plan === 'free' ? (
                    <span>1 audit remaining</span>
                  ) : userProfile.subscription?.plan === 'single' ? (
                    <span>Single audit</span>
                  ) : (
                    <span>
                      {userProfile.subscription?.auditsRemaining || 0} audits remaining
                    </span>
                  )}
                </div>
              </div>

              {/* User Info */}
              <div className="flex items-center gap-3 p-3 bg-dark-800 rounded-lg mb-3">
                <div className="w-10 h-10 rounded-full overflow-hidden bg-dark-700">
                  {userProfile.photoURL ? (
                    <img 
                      src={userProfile.photoURL} 
                      alt={userProfile.displayName}
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center">
                      <User className="w-5 h-5 text-dark-400" />
                    </div>
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    {userProfile.displayName}
                  </p>
                  <p className="text-xs text-dark-400 truncate">
                    {userProfile.email}
                  </p>
                </div>
              </div>

              {/* Sign Out */}
              <button
                onClick={handleSignOut}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium text-dark-300 hover:text-white hover:bg-dark-800 rounded-lg transition-colors"
              >
                <LogOut className="w-5 h-5" />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </motion.div>

      {/* Backdrop for mobile */}
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
    </>
  )
}
