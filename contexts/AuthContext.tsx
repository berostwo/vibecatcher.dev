'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { 
  User, 
  signInWithPopup, 
  signOut as firebaseSignOut,
  onAuthStateChanged,
  GithubAuthProvider
} from 'firebase/auth'
import { auth, githubProvider } from '@/lib/firebase'
import { doc, getDoc, setDoc } from 'firebase/firestore'
import { db } from '@/lib/firebase'

interface UserProfile {
  uid: string
  email: string
  displayName: string
  photoURL: string
  githubUsername?: string
  createdAt: Date
  lastLoginAt: Date
  subscription?: {
    plan: 'free' | 'single' | 'basic' | 'pro'
    status: 'active' | 'canceled' | 'expired'
    currentPeriodEnd?: Date
    auditsRemaining?: number
  }
}

interface AuthContextType {
  user: User | null
  userProfile: UserProfile | null
  loading: boolean
  signInWithGitHub: () => Promise<void>
  signOut: () => Promise<void>
  refreshUserProfile: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setUser(user)
      
      if (user) {
        await fetchUserProfile(user.uid)
      } else {
        setUserProfile(null)
      }
      
      setLoading(false)
    })

    return () => unsubscribe()
  }, [])

  const fetchUserProfile = async (uid: string) => {
    try {
      const userDoc = await getDoc(doc(db, 'users', uid))
      
      if (userDoc.exists()) {
        setUserProfile(userDoc.data() as UserProfile)
      } else {
        // Create new user profile
        const newProfile: UserProfile = {
          uid,
          email: user?.email || '',
          displayName: user?.displayName || '',
          photoURL: user?.photoURL || '',
          githubUsername: user?.providerData[0]?.providerId === 'github.com' 
            ? user?.providerData[0]?.displayName || ''
            : undefined,
          createdAt: new Date(),
          lastLoginAt: new Date(),
          subscription: {
            plan: 'free',
            status: 'active',
            auditsRemaining: 1
          }
        }
        
        await setDoc(doc(db, 'users', uid), newProfile)
        setUserProfile(newProfile)
      }
    } catch (error) {
      console.error('Error fetching user profile:', error)
    }
  }

  const signInWithGitHub = async () => {
    try {
      const result = await signInWithPopup(auth, githubProvider)
      
      if (result.user) {
        // Update last login time
        if (userProfile) {
          const updatedProfile = { ...userProfile, lastLoginAt: new Date() }
          await setDoc(doc(db, 'users', result.user.uid), updatedProfile)
          setUserProfile(updatedProfile)
        }
      }
    } catch (error: any) {
      console.error('GitHub sign in error:', error)
      throw error
    }
  }

  const signOut = async () => {
    try {
      await firebaseSignOut(auth)
      setUserProfile(null)
    } catch (error) {
      console.error('Sign out error:', error)
      throw error
    }
  }

  const refreshUserProfile = async () => {
    if (user) {
      await fetchUserProfile(user.uid)
    }
  }

  const value: AuthContextType = {
    user,
    userProfile,
    loading,
    signInWithGitHub,
    signOut,
    refreshUserProfile
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
