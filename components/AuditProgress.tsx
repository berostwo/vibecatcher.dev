'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, Clock, CheckCircle, AlertTriangle, Zap } from 'lucide-react'

interface AuditProgressProps {
  auditId: string
  onComplete?: () => void
}

interface AuditStatus {
  status: 'in-progress' | 'completed' | 'failed'
  progress: number
  currentStep: string
  estimatedTime: number
  vulnerabilities?: any[]
  score?: number
}

export default function AuditProgress({ auditId, onComplete }: AuditProgressProps) {
  const [status, setStatus] = useState<AuditStatus>({
    status: 'in-progress',
    progress: 0,
    currentStep: 'Initializing security scan...',
    estimatedTime: 10,
  })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const checkProgress = async () => {
      try {
        const user = auth.currentUser
        if (!user) return

        const token = await user.getIdToken()
        const response = await fetch(`/api/audit?id=${auditId}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        })

        if (response.ok) {
          const data = await response.json()
          const audit = data.audit

          if (audit.status === 'completed') {
            setStatus({
              status: 'completed',
              progress: 100,
              currentStep: 'Security audit completed!',
              estimatedTime: 0,
              vulnerabilities: audit.vulnerabilities,
              score: audit.score,
            })
            onComplete?.()
          } else if (audit.status === 'failed') {
            setStatus({
              status: 'failed',
              progress: 0,
              currentStep: 'Audit failed',
              estimatedTime: 0,
            })
            setError(audit.error || 'Unknown error occurred')
          } else {
            // Calculate progress based on time elapsed
            const startTime = new Date(audit.createdAt.seconds * 1000).getTime()
            const now = Date.now()
            const elapsed = (now - startTime) / 1000 / 60 // in minutes
            const progress = Math.min(Math.round((elapsed / 10) * 100), 95) // Assume 10 minutes total

            const steps = [
              'Initializing security scan...',
              'Cloning repository...',
              'Analyzing code structure...',
              'Scanning for vulnerabilities...',
              'Generating security report...',
              'Finalizing results...',
            ]

            const stepIndex = Math.floor((progress / 100) * steps.length)
            const currentStep = steps[Math.min(stepIndex, steps.length - 1)]

            setStatus({
              status: 'in-progress',
              progress,
              currentStep,
              estimatedTime: Math.max(0, 10 - elapsed),
            })
          }
        }
      } catch (error) {
        console.error('Failed to check audit progress:', error)
      }
    }

    // Check progress every 5 seconds
    const interval = setInterval(checkProgress, 5000)
    checkProgress() // Check immediately

    return () => clearInterval(interval)
  }, [auditId, onComplete])

  const getStatusIcon = () => {
    switch (status.status) {
      case 'completed':
        return <CheckCircle className="w-8 h-8 text-green-400" />
      case 'failed':
        return <AlertTriangle className="w-8 h-8 text-red-400" />
      default:
        return <Shield className="w-8 h-8 text-primary-400" />
    }
  }

  const getStatusColor = () => {
    switch (status.status) {
      case 'completed':
        return 'text-green-400'
      case 'failed':
        return 'text-red-400'
      default:
        return 'text-primary-400'
    }
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card text-center"
      >
        <AlertTriangle className="w-16 h-16 text-red-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-white mb-2">Audit Failed</h3>
        <p className="text-dark-300 mb-4">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="btn-primary"
        >
          Try Again
        </button>
      </motion.div>
    )
  }

  if (status.status === 'completed') {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card text-center"
      >
        <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-white mb-2">Audit Completed!</h3>
        <p className="text-dark-300 mb-4">
          Security scan finished successfully
        </p>
        
        {status.score !== undefined && (
          <div className="mb-4">
            <div className="text-3xl font-bold text-white mb-2">
              Security Score: {status.score}/100
            </div>
            <div className={`text-lg ${
              status.score >= 80 ? 'text-green-400' :
              status.score >= 60 ? 'text-yellow-400' : 'text-red-400'
            }`}>
              {status.score >= 80 ? 'Excellent' :
               status.score >= 60 ? 'Good' : 'Needs Improvement'}
            </div>
          </div>
        )}

        {status.vulnerabilities && status.vulnerabilities.length > 0 && (
          <div className="mb-4">
            <p className="text-dark-300 mb-2">
              Found {status.vulnerabilities.length} security issue{status.vulnerabilities.length !== 1 ? 's' : ''}
            </p>
            <div className="flex justify-center gap-2 text-sm">
              {status.vulnerabilities.filter((v: any) => v.severity === 'critical').length > 0 && (
                <span className="bg-red-500/20 text-red-400 px-2 py-1 rounded">
                  {status.vulnerabilities.filter((v: any) => v.severity === 'critical').length} Critical
                </span>
              )}
              {status.vulnerabilities.filter((v: any) => v.severity === 'high').length > 0 && (
                <span className="bg-orange-500/20 text-orange-400 px-2 py-1 rounded">
                  {status.vulnerabilities.filter((v: any) => v.severity === 'high').length} High
                </span>
              )}
            </div>
          </div>
        )}

        <button
          onClick={() => window.location.href = '/dashboard/reports'}
          className="btn-primary"
        >
          View Full Report
        </button>
      </motion.div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="card"
    >
      <div className="flex items-center gap-4 mb-6">
        {getStatusIcon()}
        <div>
          <h3 className="text-xl font-semibold text-white">Security Audit in Progress</h3>
          <p className="text-dark-300">Analyzing your repository for vulnerabilities</p>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm text-dark-300">Progress</span>
          <span className="text-sm font-medium text-white">{status.progress}%</span>
        </div>
        <div className="w-full bg-dark-800 rounded-full h-3">
          <motion.div
            className="bg-gradient-to-r from-primary-500 to-accent-500 h-3 rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${status.progress}%` }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          />
        </div>
      </div>

      {/* Current Step */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Zap className="w-5 h-5 text-primary-400" />
          <span className="text-sm font-medium text-white">Current Step</span>
        </div>
        <p className="text-dark-300">{status.currentStep}</p>
      </div>

      {/* Estimated Time */}
      <div className="flex items-center gap-3 text-sm text-dark-400">
        <Clock className="w-4 h-4" />
        <span>
          {status.estimatedTime > 0 
            ? `Estimated time remaining: ${Math.round(status.estimatedTime)} minutes`
            : 'Almost done...'
          }
        </span>
      </div>

      {/* Progress Animation */}
      <div className="mt-6 pt-6 border-t border-dark-800">
        <div className="flex items-center justify-center gap-2">
          <div className="w-2 h-2 bg-primary-400 rounded-full animate-pulse" />
          <div className="w-2 h-2 bg-primary-400 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }} />
          <div className="w-2 h-2 bg-primary-400 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }} />
        </div>
      </div>
    </motion.div>
  )
}
