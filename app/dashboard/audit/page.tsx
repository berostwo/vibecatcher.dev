'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Github, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  ArrowRight,
  Zap,
  FileText,
  Code,
  ExternalLink
} from 'lucide-react'
import { useRouter } from 'next/navigation'
import toast from 'react-hot-toast'
import { auth } from '@/lib/firebase'

// Disable prerendering for this page
export const dynamic = 'force-dynamic'

interface AuditForm {
  repositoryUrl: string
  repositoryName: string
  branch: string
  framework: string
  description: string
}

const frameworks = [
  'React/Next.js',
  'Vue.js',
  'Angular',
  'Node.js/Express',
  'Python/Django',
  'Python/Flask',
  'Ruby on Rails',
  'PHP/Laravel',
  'Go',
  'Rust',
  'Other'
]

export default function AuditPage() {
  const [form, setForm] = useState<AuditForm>({
    repositoryUrl: '',
    repositoryName: '',
    branch: 'main',
    framework: '',
    description: ''
  })
  const [isLoading, setIsLoading] = useState(false)
  const [currentStep, setCurrentStep] = useState(1)
  const router = useRouter()

  const handleInputChange = (field: keyof AuditForm, value: string) => {
    setForm(prev => ({ ...prev, [field]: value }))
  }

  const extractRepoInfo = (url: string) => {
    try {
      const githubMatch = url.match(/github\.com\/([^\/]+)\/([^\/]+)/)
      if (githubMatch) {
        const [, owner, repo] = githubMatch
        const repoName = repo.replace('.git', '')
        setForm(prev => ({
          ...prev,
          repositoryName: repoName,
          repositoryUrl: url
        }))
      }
    } catch (error) {
      console.error('Error parsing repository URL:', error)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!form.repositoryUrl || !form.repositoryName || !form.framework) {
      toast.error('Please fill in all required fields')
      return
    }

    setIsLoading(true)
    
    try {
      // Get current user's ID token
      const user = auth.currentUser
      if (!user) {
        toast.error('Please sign in to continue')
        return
      }

      const token = await user.getIdToken()
      
      // Submit audit request to API
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          repositoryUrl: form.repositoryUrl,
          branch: form.branch,
          framework: form.framework,
          description: form.description,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to initiate audit')
      }

      const result = await response.json()
      
      toast.success('Security audit initiated! Redirecting to dashboard...')
      
      // Redirect to dashboard where they can see the audit progress
      router.push('/dashboard')
    } catch (error) {
      console.error('Audit submission error:', error)
      toast.error(error instanceof Error ? error.message : 'Failed to initiate audit. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const nextStep = () => setCurrentStep(prev => Math.min(prev + 1, 3))
  const prevStep = () => setCurrentStep(prev => Math.max(prev - 1, 1))

  return (
    <div className="max-w-4xl mx-auto p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">New Security Audit</h1>
        <p className="text-dark-300">
          Scan your repository for security vulnerabilities and get actionable fixes.
        </p>
      </div>

      {/* Progress Steps */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          {[1, 2, 3].map((step) => (
            <div key={step} className="flex items-center">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
                step <= currentStep 
                  ? 'bg-primary-600 border-primary-500 text-white' 
                  : 'bg-dark-800 border-dark-600 text-dark-400'
              }`}>
                {step < currentStep ? <CheckCircle className="w-5 h-5" /> : step}
              </div>
              {step < 3 && (
                <div className={`w-16 h-1 mx-2 ${
                  step < currentStep ? 'bg-primary-600' : 'bg-dark-600'
                }`} />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between mt-2 text-sm">
          <span className={currentStep >= 1 ? 'text-primary-400' : 'text-dark-400'}>
            Repository Info
          </span>
          <span className={currentStep >= 2 ? 'text-primary-400' : 'text-dark-400'}>
            Framework & Details
          </span>
          <span className={currentStep >= 3 ? 'text-primary-400' : 'text-dark-400'}>
            Review & Submit
          </span>
        </div>
      </div>

      {/* Form */}
      <motion.div
        key={currentStep}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.3 }}
        className="card"
      >
        <form onSubmit={handleSubmit}>
          {/* Step 1: Repository Information */}
          {currentStep === 1 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-4">Repository Information</h2>
                <p className="text-dark-300 mb-6">
                  Provide details about the repository you want to audit for security vulnerabilities.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Repository URL <span className="text-red-400">*</span>
                </label>
                <div className="flex gap-3">
                  <input
                    type="url"
                    value={form.repositoryUrl}
                    onChange={(e) => handleInputChange('repositoryUrl', e.target.value)}
                    placeholder="https://github.com/username/repository"
                    className="input-field flex-1"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => extractRepoInfo(form.repositoryUrl)}
                    className="btn-secondary whitespace-nowrap"
                  >
                    <Github className="w-4 h-4 mr-2" />
                    Auto-fill
                  </button>
                </div>
                <p className="text-sm text-dark-400 mt-1">
                  We'll automatically extract repository name and owner from GitHub URLs.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Repository Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={form.repositoryName}
                  onChange={(e) => handleInputChange('repositoryName', e.target.value)}
                  placeholder="my-awesome-app"
                  className="input-field w-full"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Branch <span className="text-red-400">*</span>
                </label>
                <select
                  value={form.branch}
                  onChange={(e) => handleInputChange('branch', e.target.value)}
                  className="input-field w-full"
                  required
                >
                  <option value="main">main</option>
                  <option value="master">master</option>
                  <option value="develop">develop</option>
                  <option value="staging">staging</option>
                </select>
              </div>

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={nextStep}
                  disabled={!form.repositoryUrl || !form.repositoryName}
                  className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next Step <ArrowRight className="w-4 h-4 ml-2" />
                </button>
              </div>
            </div>
          )}

          {/* Step 2: Framework & Details */}
          {currentStep === 2 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-4">Framework & Details</h2>
                <p className="text-dark-300 mb-6">
                  Help us understand your tech stack for more accurate security analysis.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Primary Framework <span className="text-red-400">*</span>
                </label>
                <select
                  value={form.framework}
                  onChange={(e) => handleInputChange('framework', e.target.value)}
                  className="input-field w-full"
                  required
                >
                  <option value="">Select a framework</option>
                  {frameworks.map((fw) => (
                    <option key={fw} value={fw}>{fw}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-white mb-2">
                  Description
                </label>
                <textarea
                  value={form.description}
                  onChange={(e) => handleInputChange('description', e.target.value)}
                  placeholder="Brief description of your application and any specific security concerns..."
                  rows={4}
                  className="input-field w-full resize-none"
                />
                <p className="text-sm text-dark-400 mt-1">
                  Optional: Help us understand your application better for more targeted analysis.
                </p>
              </div>

              <div className="flex justify-between">
                <button
                  type="button"
                  onClick={prevStep}
                  className="btn-secondary"
                >
                  Previous Step
                </button>
                <button
                  type="button"
                  onClick={nextStep}
                  disabled={!form.framework}
                  className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next Step <ArrowRight className="w-4 h-4 ml-2" />
                </button>
              </div>
            </div>
          )}

          {/* Step 3: Review & Submit */}
          {currentStep === 3 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-4">Review & Submit</h2>
                <p className="text-dark-300 mb-6">
                  Review your audit configuration and submit to begin the security scan.
                </p>
              </div>

              <div className="bg-dark-800 rounded-lg p-6 space-y-4">
                <h3 className="text-lg font-medium text-white mb-4">Audit Configuration</h3>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-sm text-dark-400">Repository:</span>
                    <p className="text-white font-medium">{form.repositoryName}</p>
                  </div>
                  <div>
                    <span className="text-sm text-dark-400">Branch:</span>
                    <p className="text-white font-medium">{form.branch}</p>
                  </div>
                  <div>
                    <span className="text-sm text-dark-400">Framework:</span>
                    <p className="text-white font-medium">{form.framework}</p>
                  </div>
                  <div>
                    <span className="text-sm text-dark-400">URL:</span>
                    <a 
                      href={form.repositoryUrl} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary-400 hover:text-primary-300 text-sm flex items-center gap-1"
                    >
                      View Repository <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>

                {form.description && (
                  <div>
                    <span className="text-sm text-dark-400">Description:</span>
                    <p className="text-white">{form.description}</p>
                  </div>
                )}
              </div>

              <div className="bg-primary-900/20 border border-primary-500/30 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-primary-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <h4 className="font-medium text-white mb-2">What happens next?</h4>
                    <ul className="text-sm text-dark-300 space-y-1">
                      <li>• We'll clone your repository and analyze the codebase</li>
                      <li>• Our AI-powered security engine will scan for vulnerabilities</li>
                      <li>• You'll receive a detailed report with actionable fixes</li>
                      <li>• Typical scan time: 5-15 minutes depending on repository size</li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="flex justify-between">
                <button
                  type="button"
                  onClick={prevStep}
                  className="btn-secondary"
                >
                  Previous Step
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isLoading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                      Initiating Audit...
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 mr-2" />
                      Start Security Audit
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </form>
      </motion.div>

      {/* Features Preview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6"
      >
        <div className="card text-center">
          <div className="w-12 h-12 bg-primary-600/20 rounded-lg flex items-center justify-center mx-auto mb-4">
            <Shield className="w-6 h-6 text-primary-400" />
          </div>
          <h3 className="font-semibold text-white mb-2">Comprehensive Scan</h3>
          <p className="text-sm text-dark-300">
            We analyze your entire codebase for security vulnerabilities, dependency issues, and best practices.
          </p>
        </div>

        <div className="card text-center">
          <div className="w-12 h-12 bg-accent-600/20 rounded-lg flex items-center justify-center mx-auto mb-4">
            <Zap className="w-6 h-6 text-accent-400" />
          </div>
          <h3 className="font-semibold text-white mb-2">AI-Powered Analysis</h3>
          <p className="text-sm text-dark-300">
            Our advanced AI understands your code context and provides specific, actionable security fixes.
          </p>
        </div>

        <div className="card text-center">
          <div className="w-12 h-12 bg-green-600/20 rounded-lg flex items-center justify-center mx-auto mb-4">
            <FileText className="w-6 h-6 text-green-400" />
          </div>
          <h3 className="font-semibold text-white mb-2">Detailed Reports</h3>
          <p className="text-sm text-dark-300">
            Get comprehensive reports with severity levels, explanations, and copy-paste fix prompts.
          </p>
        </div>
      </motion.div>
    </div>
  )
}
