'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  Search, 
  Filter, 
  Calendar, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  ArrowRight,
  FileText,
  Shield,
  TrendingUp,
  Eye,
  Download,
  ExternalLink
} from 'lucide-react'
import Link from 'next/link'
import { auth } from '@/lib/firebase'

// Disable prerendering for this page
export const dynamic = 'force-dynamic'

interface Vulnerability {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  file: string
  line: number
  cwe: string
  fix: string
  aiPrompt: string
}

interface AuditReport {
  id: string
  repository: string
  branch: string
  framework: string
  status: 'completed' | 'in-progress' | 'failed'
  createdAt: Date
  completedAt?: Date
  vulnerabilities: Vulnerability[]
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  score: number
  duration: number // in minutes
}

export default function ReportsPage() {
  const [reports, setReports] = useState<AuditReport[]>([])
  const [filteredReports, setFilteredReports] = useState<AuditReport[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [selectedReport, setSelectedReport] = useState<AuditReport | null>(null)

  // Fetch real data from Firebase
  useEffect(() => {
    const fetchReports = async () => {
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
          
          // Transform audits to match the reports interface
          const transformedReports: AuditReport[] = audits.map((audit: any) => ({
            id: audit.id,
            repository: audit.repository,
            branch: audit.branch || 'main',
            framework: audit.framework,
            status: audit.status,
            createdAt: new Date(audit.createdAt.seconds * 1000),
            completedAt: audit.completedAt ? new Date(audit.completedAt.seconds * 1000) : undefined,
            duration: audit.duration || 0,
            score: audit.score || 0,
            vulnerabilities: audit.vulnerabilities || [],
            summary: audit.summary || {
              total: 0,
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0
            }
          }))

          setReports(transformedReports)
          setFilteredReports(transformedReports)
        }
      } catch (error) {
        console.error('Failed to fetch reports:', error)
      }
    }

    fetchReports()
  }, [])

  useEffect(() => {
    let filtered = reports

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(report =>
        report.repository.toLowerCase().includes(searchTerm.toLowerCase()) ||
        report.framework.toLowerCase().includes(searchTerm.toLowerCase())
      )
    }

    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(report => report.status === statusFilter)
    }

    // Severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(report => {
        if (severityFilter === 'critical') return report.summary.critical > 0
        if (severityFilter === 'high') return report.summary.high > 0
        if (severityFilter === 'medium') return report.summary.medium > 0
        if (severityFilter === 'low') return report.summary.low > 0
        return true
      })
    }

    setFilteredReports(filtered)
  }, [reports, searchTerm, statusFilter, severityFilter])

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

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-400/10 border-red-400/20'
      case 'high':
        return 'text-orange-400 bg-orange-400/10 border-orange-400/20'
      case 'medium':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
      case 'low':
        return 'text-blue-400 bg-blue-400/10 border-blue-400/20'
      case 'info':
        return 'text-gray-400 bg-gray-400/10 border-gray-400/20'
      default:
        return 'text-dark-400 bg-dark-400/10 border-dark-400/20'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400'
    if (score >= 80) return 'text-yellow-400'
    if (score >= 70) return 'text-orange-400'
    return 'text-red-400'
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Security Audit Reports</h1>
        <p className="text-dark-300">
          View and analyze your security audit results. Track vulnerabilities and get actionable fixes.
        </p>
      </div>

      {/* Filters and Search */}
      <div className="card mb-8">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-dark-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search repositories or frameworks..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="input-field w-full pl-10"
            />
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input-field min-w-[150px]"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="in-progress">In Progress</option>
            <option value="failed">Failed</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="input-field min-w-[150px]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Reports Grid */}
      {filteredReports.length === 0 ? (
        <div className="card text-center py-12">
          <FileText className="w-16 h-16 text-dark-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No reports found</h3>
          <p className="text-dark-400 mb-6">
            {searchTerm || statusFilter !== 'all' || severityFilter !== 'all'
              ? 'Try adjusting your filters or search terms.'
              : 'Start your first security audit to see results here.'}
          </p>
          {!searchTerm && statusFilter === 'all' && severityFilter === 'all' && (
            <Link href="/dashboard/audit" className="btn-primary">
              Start Your First Audit
            </Link>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {filteredReports.map((report) => (
            <motion.div
              key={report.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
              className="card hover:scale-[1.02] transition-transform duration-200 cursor-pointer"
              onClick={() => setSelectedReport(report)}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-white mb-1">{report.repository}</h3>
                  <div className="flex items-center gap-2 text-sm text-dark-400">
                    <span>{report.framework}</span>
                    <span>•</span>
                    <span>{report.branch}</span>
                  </div>
                </div>
                <div className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(report.status)}`}>
                  <div className="flex items-center gap-1">
                    {getStatusIcon(report.status)}
                    {report.status.replace('-', ' ')}
                  </div>
                </div>
              </div>

              {/* Score and Stats */}
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div className="text-center">
                  <div className={`text-2xl font-bold ${getScoreColor(report.score)}`}>
                    {report.status === 'completed' ? `${report.score}%` : '--'}
                  </div>
                  <div className="text-xs text-dark-400">Security Score</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-white">
                    {report.duration > 0 ? `${report.duration}m` : '--'}
                  </div>
                  <div className="text-xs text-dark-400">Duration</div>
                </div>
              </div>

              {/* Vulnerabilities Summary */}
              {report.status === 'completed' && (
                <div className="mb-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-4 h-4 text-dark-400" />
                    <span className="text-sm text-dark-400">Vulnerabilities</span>
                  </div>
                  <div className="flex gap-2">
                    {report.summary.critical > 0 && (
                      <span className="px-2 py-1 bg-red-400/10 text-red-400 text-xs rounded border border-red-400/20">
                        {report.summary.critical} Critical
                      </span>
                    )}
                    {report.summary.high > 0 && (
                      <span className="px-2 py-1 bg-orange-400/10 text-orange-400 text-xs rounded border border-orange-400/20">
                        {report.summary.high} High
                      </span>
                    )}
                    {report.summary.medium > 0 && (
                      <span className="px-2 py-1 bg-yellow-400/10 text-yellow-400 text-xs rounded border border-yellow-400/20">
                        {report.summary.medium} Medium
                      </span>
                    )}
                    {report.summary.low > 0 && (
                      <span className="px-2 py-1 bg-blue-400/10 text-blue-400 text-xs rounded border border-blue-400/20">
                        {report.summary.low} Low
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Footer */}
              <div className="flex items-center justify-between pt-4 border-t border-dark-800">
                <div className="flex items-center gap-2 text-sm text-dark-400">
                  <Calendar className="w-4 h-4" />
                  {report.createdAt.toLocaleDateString()}
                </div>
                <div className="flex items-center gap-2 text-primary-400 hover:text-primary-300">
                  <span className="text-sm font-medium">View Details</span>
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Detailed Report Modal */}
      {selectedReport && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="bg-dark-900 border border-dark-800 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
          >
            {/* Modal Header */}
            <div className="p-6 border-b border-dark-800">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold text-white mb-2">{selectedReport.repository}</h2>
                  <div className="flex items-center gap-4 text-dark-400">
                    <span>{selectedReport.framework}</span>
                    <span>•</span>
                    <span>{selectedReport.branch}</span>
                    <span>•</span>
                    <span>{selectedReport.createdAt.toLocaleDateString()}</span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="text-dark-400 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Modal Content */}
            <div className="p-6">
              {selectedReport.status === 'completed' ? (
                <div className="space-y-6">
                  {/* Score and Summary */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="card text-center">
                      <div className={`text-4xl font-bold mb-2 ${getScoreColor(selectedReport.score)}`}>
                        {selectedReport.score}%
                      </div>
                      <div className="text-dark-400">Security Score</div>
                    </div>
                    <div className="card text-center">
                      <div className="text-4xl font-bold text-white mb-2">
                        {selectedReport.duration}m
                      </div>
                      <div className="text-dark-400">Scan Duration</div>
                    </div>
                    <div className="card text-center">
                      <div className="text-4xl font-bold text-white mb-2">
                        {selectedReport.summary.total}
                      </div>
                      <div className="text-dark-400">Total Issues</div>
                    </div>
                  </div>

                  {/* Vulnerabilities */}
                  <div>
                    <h3 className="text-xl font-semibold text-white mb-4">Vulnerabilities Found</h3>
                    <div className="space-y-4">
                      {selectedReport.vulnerabilities.map((vuln) => (
                        <div key={vuln.id} className="card border-l-4 border-l-red-500">
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-3">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                                {vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)}
                              </span>
                              <span className="text-sm text-dark-400">{vuln.category}</span>
                            </div>
                            <span className="text-sm text-dark-400">
                              {vuln.file}:{vuln.line}
                            </span>
                          </div>
                          
                          <h4 className="text-lg font-medium text-white mb-2">{vuln.title}</h4>
                          <p className="text-dark-300 mb-3">{vuln.description}</p>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <h5 className="text-sm font-medium text-white mb-2">Recommended Fix</h5>
                              <p className="text-sm text-dark-300">{vuln.fix}</p>
                            </div>
                            <div>
                              <h5 className="text-sm font-medium text-white mb-2">AI Fix Prompt</h5>
                              <div className="bg-dark-800 rounded p-3">
                                <p className="text-sm text-dark-300 font-mono">{vuln.aiPrompt}</p>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex gap-4">
                    <button className="btn-primary flex items-center gap-2">
                      <Download className="w-4 h-4" />
                      Download Report
                    </button>
                    <button className="btn-secondary flex items-center gap-2">
                      <ExternalLink className="w-4 h-4" />
                      Share Report
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12">
                  <Clock className="w-16 h-16 text-dark-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-white mb-2">Audit in Progress</h3>
                  <p className="text-dark-400">
                    This security audit is currently running. You'll be notified when it's complete.
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
