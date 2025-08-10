'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Github, Shield, Zap, Target, CheckCircle, ArrowRight, Star, Users, Code } from 'lucide-react'
import { signInWithPopup } from 'firebase/auth'
import { auth, githubProvider } from '@/lib/firebase'
import { useRouter } from 'next/navigation'
import toast from 'react-hot-toast'

export default function LandingPage() {
  const [isLoading, setIsLoading] = useState(false)
  const router = useRouter()

  const handleGitHubSignIn = async () => {
    try {
      setIsLoading(true)
      const result = await signInWithPopup(auth, githubProvider)
      if (result.user) {
        toast.success('Welcome to VibeCatcher! 🚀')
        router.push('/dashboard')
      }
    } catch (error: any) {
      console.error('Sign in error:', error)
      if (error.code === 'auth/popup-closed-by-user') {
        toast.error('Sign in was cancelled')
      } else {
        toast.error('Failed to sign in. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const features = [
    {
      icon: Shield,
      title: 'Enterprise Security',
      description: 'Comprehensive security audits covering all critical vulnerabilities your app might have.'
    },
    {
      icon: Zap,
      title: 'AI-Powered Analysis',
      description: 'Advanced GPT-4 analysis that understands your codebase and identifies real security risks.'
    },
    {
      icon: Target,
      title: 'Actionable Fixes',
      description: 'Get specific prompts you can copy-paste into your AI assistant to fix each security issue.'
    },
    {
      icon: CheckCircle,
      title: 'Ship with Confidence',
      description: 'Know your app is secure before you deploy. No more worrying about security breaches.'
    }
  ]

  const pricing = [
    {
      name: 'Single Audit',
      price: '$4.99',
      description: 'Perfect for one-time projects',
      features: ['1 Security Audit', 'Detailed Report', 'AI Fix Prompts', '30-day Support'],
      popular: false
    },
    {
      name: 'Basic Plan',
      price: '$9.99',
      period: '/month',
      description: 'Great for active developers',
      features: ['8 Audits per Month', 'Priority Support', 'Custom Rules', 'Team Access'],
      popular: true
    },
    {
      name: 'Pro Plan',
      price: '$14.99',
      period: '/month',
      description: 'For power users & teams',
      features: ['20 Audits per Month', 'Advanced Analytics', 'API Access', 'Dedicated Support'],
      popular: false
    }
  ]

  return (
    <div className="min-h-screen bg-dark-950">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 glass-effect">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold gradient-text">vibecatcher.dev</h1>
            </div>
            <button
              onClick={handleGitHubSignIn}
              disabled={isLoading}
              className="btn-github"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Github className="w-5 h-5" />
              )}
              {isLoading ? 'Signing in...' : 'Sign in with GitHub'}
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <h1 className="text-5xl md:text-7xl font-bold mb-6">
              <span className="gradient-text">vibecatcher.dev</span>
            </h1>
            <p className="text-3xl md:text-4xl font-semibold text-white mb-8">
              Ship with confidence.
            </p>
            <p className="text-xl md:text-2xl text-dark-300 mb-12 max-w-3xl mx-auto">
              We catch the bad vibes first. Enterprise-level security audits for vibe coders, 
              microsaas entrepreneurs, and solopreneurs.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <button
                onClick={handleGitHubSignIn}
                disabled={isLoading}
                className="btn-github text-lg px-8 py-4"
              >
                {isLoading ? (
                  <div className="w-6 h-6 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <Github className="w-6 h-6" />
                )}
                {isLoading ? 'Signing in...' : 'Get Started with GitHub'}
              </button>
              <button className="btn-secondary text-lg px-8 py-4">
                Learn More <ArrowRight className="w-5 h-5 ml-2" />
              </button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-dark-900/50">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Why VibeCoders Choose Us
            </h2>
            <p className="text-xl text-dark-300 max-w-3xl mx-auto">
              Built specifically for developers who want to ship fast without compromising security.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
                className="card text-center group hover:scale-105 transition-transform duration-300"
              >
                <div className="w-16 h-16 bg-primary-600/20 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:bg-primary-600/30 transition-colors">
                  <feature.icon className="w-8 h-8 text-primary-400" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">{feature.title}</h3>
                <p className="text-dark-300">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-dark-300 max-w-3xl mx-auto">
              Choose the plan that fits your development workflow. No hidden fees, no surprises.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {pricing.map((plan, index) => (
              <motion.div
                key={plan.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
                className={`card relative ${plan.popular ? 'ring-2 ring-primary-500 scale-105' : ''}`}
              >
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                    <span className="bg-primary-500 text-white px-4 py-2 rounded-full text-sm font-semibold">
                      Most Popular
                    </span>
                  </div>
                )}
                
                <div className="text-center mb-8">
                  <h3 className="text-2xl font-bold text-white mb-2">{plan.name}</h3>
                  <div className="flex items-baseline justify-center gap-1">
                    <span className="text-4xl font-bold text-white">{plan.price}</span>
                    {plan.period && <span className="text-dark-400">{plan.period}</span>}
                  </div>
                  <p className="text-dark-300 mt-2">{plan.description}</p>
                </div>

                <ul className="space-y-3 mb-8">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-center gap-3">
                      <CheckCircle className="w-5 h-5 text-primary-400 flex-shrink-0" />
                      <span className="text-dark-200">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button className="w-full btn-primary">
                  Get Started
                </button>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-gradient-to-r from-primary-900/20 to-accent-900/20">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
          >
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Ready to Ship with Confidence?
            </h2>
            <p className="text-xl text-dark-300 mb-8">
              Join thousands of developers who trust VibeCatcher to secure their applications.
            </p>
            <button
              onClick={handleGitHubSignIn}
              disabled={isLoading}
              className="btn-github text-lg px-8 py-4"
            >
              {isLoading ? (
                <div className="w-6 h-6 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <Github className="w-6 h-6" />
              )}
              {isLoading ? 'Signing in...' : 'Start Your Security Journey'}
            </button>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-4 sm:px-6 lg:px-8 border-t border-dark-800">
        <div className="max-w-7xl mx-auto">
          <div className="text-center">
            <h3 className="text-2xl font-bold gradient-text mb-4">vibecatcher.dev</h3>
            <p className="text-dark-400 mb-6">
              Ship with confidence. We catch the bad vibes first.
            </p>
            <div className="flex justify-center items-center gap-6 text-dark-400">
              <span>© 2024 VibeCatcher.dev</span>
              <span>•</span>
              <span>Privacy Policy</span>
              <span>•</span>
              <span>Terms of Service</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
