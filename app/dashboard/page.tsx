'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  Shield, 
  Clock, 
  CheckCircle, 
  AlertTriangle, 
  TrendingUp, 
  Plus,
  ArrowRight,
  FileText,
  Zap
} from 'lucide-react'
import Link from 'next/link'
import { auth } from '@/lib/firebase'

// Disable prerendering for this page
export const dynamic = 'force-dynamic'

interface AuditSummary {
  id: string
  repository: string
  status: 'completed' | 'in-progress' | 'failed'
  completedAt?: Date
  vulnerabilities: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

export default function Dashboard() {
  const [recentAudits, setRecentAudits] = useState<AuditSummary[]>([])
  const [stats, setStats] = useState({
    totalAudits: 0,
    completedAudits: 0,
    criticalIssues: 0,
    averageScore: 0
  })

  // Fetch real data from Firebase
  useEffect(() => {
    const fetchAudits = async () => {
      try {
        const user = auth.currentUser
        if (!user) return

        const token = await user.getIdToken()
        const response = await fetch('/api/audit', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        })

        if (response.ok) {
          const data = await response.json()
          const audits = data.audits || []
          
          // Transform audits for dashboard display
          const transformedAudits = audits.slice(0, 5).map((audit: any) => ({
            id: audit.id,
            repository: audit.repository,
            status: audit.status,
            completedAt: audit.completedAt ? new Date(audit.completedAt.seconds * 1000) : undefined,
            vulnerabilities: audit.summary || { critical: 0, high: 0, medium: 0, low: 0 }
          }))

          setRecentAudits(transformedAudits)

          // Calculate stats
          const totalAudits = audits.length
          const completedAudits = audits.filter((a: any) => a.status === 'completed').length
          const criticalIssues = audits.reduce((sum: number, a: any) => sum + (a.summary?.critical || 0), 0)
          const averageScore = audits.length > 0 
            ? Math.round(audits.reduce((sum: number, a: any) => sum + (a.score || 0), 0) / audits.length)
            : 0

          setStats({
            totalAudits,
            completedAudits,
            criticalIssues,
            averageScore
          })
        }
      } catch (error) {
        console.error('Failed to fetch audits:', error)
      }
    }

    fetchAudits()
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-400 bg-green-400/10 border-green-400/20'
      case 'in-progress':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
      case 'failed':
        return 'text-red-400 bg-red-400/10 border-red-400/20'
      default:
        return 'text-dark-400 bg-dark-400/10 border-dark-400/20'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4" />
      case 'in-progress':
        return <Clock className="w-4 h-4" />
      case 'failed':
        return <AlertTriangle className="w-4 h-4" />
      default:
        return <Clock className="w-4 h-4" />
    }
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-dark-300">Welcome back! Here's an overview of your security audits.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="card"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Total Audits</p>
              <p className="text-2xl font-bold text-white">{stats.totalAudits}</p>
            </div>
            <div className="w-12 h-12 bg-primary-600/20 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary-400" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="card"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Completed</p>
              <p className="text-2xl font-bold text-white">{stats.completedAudits}</p>
            </div>
            <div className="w-12 h-12 bg-green-600/20 rounded-lg flex items-center justify-center">
              <CheckCircle className="w-6 h-6 text-green-400" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="card"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Critical Issues</p>
              <p className="text-2xl font-bold text-white">{stats.criticalIssues}</p>
            </div>
            <div className="w-12 h-12 bg-red-600/20 rounded-lg flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="card"
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-dark-400 text-sm">Avg Score</p>
              <p className="text-2xl font-bold text-white">{stats.averageScore}%</p>
            </div>
            <div className="w-12 h-12 bg-accent-600/20 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-accent-400" />
            </div>
          </div>
        </motion.div>
      </div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.4 }}
        className="card mb-8"
      >
        <h2 className="text-xl font-semibold text-white mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Link
            href="/dashboard/audit"
            className="flex items-center gap-4 p-4 bg-dark-800 rounded-lg hover:bg-dark-700 transition-colors group"
          >
            <div className="w-12 h-12 bg-primary-600/20 rounded-lg flex items-center justify-center group-hover:bg-primary-600/30 transition-colors">
              <Plus className="w-6 h-6 text-primary-400" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-white">New Security Audit</h3>
              <p className="text-sm text-dark-300">Scan a new repository for vulnerabilities</p>
            </div>
            <ArrowRight className="w-5 h-5 text-dark-400 group-hover:text-white transition-colors" />
          </Link>

          <Link
            href="/dashboard/reports"
            className="flex items-center gap-4 p-4 bg-dark-800 rounded-lg hover:bg-dark-700 transition-colors group"
          >
            <div className="w-12 h-12 bg-accent-600/20 rounded-lg flex items-center justify-center group-hover:bg-accent-600/30 transition-colors">
              <FileText className="w-6 h-6 text-accent-400" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-white">View Reports</h3>
              <p className="text-sm text-dark-300">Check your previous audit results</p>
            </div>
            <ArrowRight className="w-5 h-5 text-dark-400 group-hover:text-white transition-colors" />
          </Link>
        </div>
      </motion.div>

      {/* Recent Audits */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.5 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Recent Audits</h2>
          <Link
            href="/dashboard/reports"
            className="text-primary-400 hover:text-primary-300 text-sm font-medium flex items-center gap-2"
          >
            View All <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        {recentAudits.length === 0 ? (
          <div className="text-center py-12">
            <Zap className="w-16 h-16 text-dark-600 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No audits yet</h3>
            <p className="text-dark-400 mb-6">Start your first security audit to see results here.</p>
            <Link href="/dashboard/audit" className="btn-primary">
              Start Your First Audit
            </Link>
          </div>
        ) : (
          <div className="space-y-4">
            {recentAudits.map((audit) => (
              <div
                key={audit.id}
                className="flex items-center justify-between p-4 bg-dark-800 rounded-lg hover:bg-dark-700 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center border ${getStatusColor(audit.status)}`}>
                    {getStatusIcon(audit.status)}
                  </div>
                  <div>
                    <h3 className="font-medium text-white">{audit.repository}</h3>
                    <p className="text-sm text-dark-400">
                      {audit.completedAt?.toLocaleDateString()}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <div className="flex items-center gap-2 text-sm">
                      {audit.vulnerabilities.critical > 0 && (
                        <span className="text-red-400 font-medium">
                          {audit.vulnerabilities.critical} Critical
                        </span>
                      )}
                      {audit.vulnerabilities.high > 0 && (
                        <span className="text-orange-400 font-medium">
                          {audit.vulnerabilities.high} High
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-dark-400">
                      {audit.vulnerabilities.medium} Medium, {audit.vulnerabilities.low} Low
                    </p>
                  </div>
                  
                  <Link
                    href={`/dashboard/reports/${audit.id}`}
                    className="text-primary-400 hover:text-primary-300"
                  >
                    <ArrowRight className="w-5 h-5" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  )
}
