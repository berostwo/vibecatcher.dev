
"use client"

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Github, ScanLine, FileJson2, Wand2, ShieldAlert, Code, Terminal, AlertTriangle, Info, CheckCircle, Shield } from 'lucide-react'
import Link from 'next/link'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from '@/components/ui/badge'
import { AppFooter } from '@/components/common/app-footer'
import { useAuthContext } from '@/contexts/auth-context'
import { useState } from 'react'


const mockVulnerabilities = [
  {
    id: 'vuln-1',
    title: 'Cross-Site Scripting (XSS)',
    file: 'src/views/Profile.js',
    line: 78,
    severity: 'Critical',
    description: 'A reflected XSS vulnerability was discovered. User-provided data from query parameters is rendered without proper sanitization, allowing attackers to inject malicious scripts.',
    remediation: "Sanitize user input with a library like DOMPurify before rendering it. Replace `element.innerHTML = userInput` with `element.textContent = userInput` or use a safe templating engine.",
  },
  {
    id: 'vuln-2',
    title: 'Outdated Dependency: `lodash`',
    file: 'package.json',
    line: 32,
    severity: 'High',
    description: 'The version of `lodash` (4.17.15) in use has a known high-severity prototype pollution vulnerability. This could lead to remote code execution or application crashes.',
    remediation: "Update `lodash` to the latest version. Run `npm install lodash@latest` and verify that no breaking changes have been introduced.",
  },
  {
    id: 'vuln-3',
    title: 'Insecure `target=\'_blank\'` usage',
    file: 'src/components/ExternalLink.jsx',
    line: 15,
    severity: 'Medium',
    description: "Links that use `target='_blank'` without `rel='noopener noreferrer'` are vulnerable to tab-nabbing, which can pose a security risk to users.",
    remediation: "Add the attribute `rel='noopener noreferrer'` to all anchor tags that use `target='_blank'` to prevent the new page from accessing the `window.opener` property."
  },
];

const getSeverityStyles = (severity: string) => {
  switch (severity) {
    case 'Critical':
      return {
        icon: <ShieldAlert className="h-5 w-5 text-red-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-500/10',
        textColor: 'text-red-500',
      };
    case 'High':
      return {
        icon: <AlertTriangle className="h-5 w-5 text-orange-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-500/10',
        textColor: 'text-orange-500',
      };
    case 'Medium':
      return {
        icon: <Info className="h-5 w-5 text-yellow-500" />,
        badgeVariant: 'secondary' as const,
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-500/10',
        textColor: 'text-yellow-500',
      };
    default:
      return {
        icon: <CheckCircle className="h-5 w-5 text-green-500" />,
        badgeVariant: 'outline' as const,
        borderColor: 'border-gray-500/50',
        bgColor: 'bg-green-500/10',
        textColor: 'text-green-500',
      };
  }
};


export default function Home() {
  const { user, signInWithGoogle, loading } = useAuthContext();
  const [isSigningIn, setIsSigningIn] = useState(false);
  const healthScore = 47;
  
  const getHealthColor = (score: number) => {
    if (score > 85) return 'text-green-500';
    if (score > 60) return 'text-yellow-500';
    if (score > 40) return 'text-orange-500';
    return 'text-red-500';
  }

  const handleSignIn = async () => {
    try {
      setIsSigningIn(true);
      await signInWithGoogle();
    } catch (error) {
      console.error('Sign in error:', error);
    } finally {
      setIsSigningIn(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground p-4 overflow-x-hidden">
      <main className="flex flex-col items-center justify-center flex-1 text-center animate-fade-in-up">
        <div className="relative flex items-center justify-center mb-2">
            <div aria-hidden="true" className="absolute inset-0 grid grid-cols-2 -space-x-52 opacity-40 transition-opacity duration-1000 group-hover:opacity-100 dark:opacity-20">
                <div className="h-56 bg-gradient-to-br from-primary to-purple-400 blur-3xl dark:h-96" />
                <div className="h-56 bg-gradient-to-r from-accent to-cyan-400 blur-3xl dark:h-96" />
            </div>
            <h1 className="text-5xl md:text-7xl font-bold font-headline tracking-tighter text-gray-200 flex items-baseline">
            vibecatcher<Shield fill="currentColor" className="inline-block h-3 md:h-4 w-3 md:w-4 mx-0.5" />dev
            </h1>
        </div>
        <p className="mt-4 text-xl md:text-2xl text-muted-foreground max-w-2xl">
          Ship with confidence.
          <br />
          We catch the bad vibes first.
        </p>
        <p className="mt-6 text-sm text-muted-foreground max-w-md">
          Drop your repo link. Get an actionable security report in minutes. We
          tailor prompts to fix your security risks with OpenAI GPT.
        </p>
        <div className="mt-8">
          {user ? (
            <div className="flex flex-col items-center gap-4">
              <p className="text-sm text-muted-foreground">
                Welcome back, {user.displayName || user.email}!
              </p>
              <Button asChild size="lg" className="bg-primary hover:bg-black text-primary-foreground font-semibold shadow-lg transition-transform transform hover:scale-105">
                <Link href="/dashboard">
                  <Github className="mr-2 h-5 w-5" />
                  Go to Dashboard
                </Link>
              </Button>
            </div>
          ) : (
            <Button 
              onClick={handleSignIn}
              disabled={loading || isSigningIn}
              size="lg" 
              className="bg-primary hover:bg-black text-primary-foreground font-semibold shadow-lg transition-transform transform hover:scale-105"
            >
              <Github className="mr-2 h-5 w-5" />
              {isSigningIn ? 'Signing in...' : 'Continue with GitHub'}
            </Button>
          )}
        </div>

        <section className="mt-16 w-full max-w-5xl">
            <h2 className="text-3xl font-bold font-headline mb-8">How It Works</h2>
            <div className="grid gap-8 md:grid-cols-3">
              <Card className="border-2 border-primary/20">
                <CardHeader className="items-center text-center">
                    <div className="p-3 rounded-full bg-primary/10 mb-4">
                        <ScanLine className="h-8 w-8 text-primary" />
                    </div>
                  <CardTitle>1. Comprehensive Analysis</CardTitle>
                </CardHeader>
                <CardContent className="text-center text-muted-foreground text-sm">
                  Our system performs a deep static analysis of your codebase, meticulously identifying potential security vulnerabilities, logical flaws, and deviations from industry best practices.
                </CardContent>
              </Card>
              <Card className="border-2 border-primary/20">
                <CardHeader className="items-center text-center">
                    <div className="p-3 rounded-full bg-primary/10 mb-4">
                        <FileJson2 className="h-8 w-8 text-primary" />
                    </div>
                  <CardTitle>2. Intelligent Triage</CardTitle>
                </CardHeader>
                <CardContent className="text-center text-muted-foreground text-sm">
                  Findings are compiled and categorized, with each issue assessed for severity and impact. This intelligent prioritization allows your team to focus on the most critical threats first.
                </CardContent>
              </Card>
              <Card className="border-2 border-primary/20">
                <CardHeader className="items-center text-center">
                    <div className="p-3 rounded-full bg-primary/10 mb-4">
                        <Wand2 className="h-8 w-8 text-primary" />
                    </div>
                  <CardTitle>3. AI-Powered Remediation</CardTitle>
                </CardHeader>
                <CardContent className="text-center text-muted-foreground text-sm">
                  Receive actionable, context-aware code fixes and custom-generated prompts designed to resolve each specific security issue, including a master prompt to address all findings simultaneously.
                </CardContent>
              </Card>
            </div>
        </section>

        <section className="mt-16 w-full max-w-5xl text-left">
           <h2 className="text-3xl font-bold font-headline mb-8 text-center">Enterprise-Grade Reporting</h2>
            <Card className="bg-card/50 border-2 border-primary/20 shadow-2xl shadow-primary/10">
                <CardHeader>
                    <div className="flex flex-col md:flex-row justify-between items-start mb-6">
                        <div className="mb-4 md:mb-0">
                            <CardTitle className="text-2xl">Audit Report: `your-awesome-repo`</CardTitle>
                            <CardDescription>3 vulnerabilities found. See details below.</CardDescription>
                        </div>
                    </div>
                    <div className="space-y-4 text-center">
                        <div className="grid grid-cols-2 gap-4">
                            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-muted-foreground">Total Findings</h4>
                                <p className="text-4xl font-bold">3</p>
                            </div>
                            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
                                <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
                            </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-red-400">Critical</h4>
                                <p className="text-4xl font-bold text-red-500">1</p>
                            </div>
                            <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-orange-400">High</h4>
                                <p className="text-4xl font-bold text-orange-500">1</p>
                            </div>
                            <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
                                <p className="text-4xl font-bold text-yellow-500">1</p>
                            </div>
                            <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-4">
                                <h4 className="text-sm font-medium text-green-400">Low</h4>
                                <p className="text-4xl font-bold text-green-500">0</p>
                            </div>
                        </div>
                        <Accordion type="single" collapsible className="w-full">
                            <AccordionItem value="master-prompt" className="border border-foreground/20 bg-foreground/5 rounded-lg shadow-sm">
                                <AccordionTrigger className="hover:no-underline px-4 py-3">
                                    <div className="flex items-center gap-2 text-foreground">
                                       <Terminal className="mr-2 h-4 w-4"/> View Master Prompt
                                    </div>
                                </AccordionTrigger>
                                <AccordionContent className="px-4 pb-4">
                                   <div className="bg-black/80 rounded-md p-3 text-left">
                                        <pre className="text-xs text-green-300 whitespace-pre-wrap font-code text-left">
                                            {`You are an expert security engineer. Given the following list of vulnerabilities, provide the necessary code changes to remediate all of them. For each vulnerability, explain the risk and the fix.

Vulnerability 1: Cross-Site Scripting (XSS) in 'src/views/Profile.js' on line 78.
Description: A reflected XSS vulnerability was discovered...
...

Vulnerability 2: Outdated Dependency: 'lodash' in 'package.json'.
Description: The version of 'lodash' has a known high-severity vulnerability...
...

Vulnerability 3: Insecure 'target=_blank' usage in 'src/components/ExternalLink.jsx'.
Description: Links using 'target=_blank' without 'rel=noopener noreferrer' are a security risk...
...

Provide a git-compatible diff for each required code change.`}
                                        </pre>
                                    </div>
                                </AccordionContent>
                            </AccordionItem>
                        </Accordion>
                    </div>
                </CardHeader>
                <CardContent>
                    <Accordion type="single" collapsible className="w-full">
                         {mockVulnerabilities.map((vuln) => {
                            const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity);
                            return (
                                <AccordionItem value={vuln.id} key={vuln.id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
                                    <AccordionTrigger className="hover:no-underline">
                                        <div className="flex items-center gap-4 w-full">
                                            {icon}
                                            <div className="flex-grow text-left">
                                                <p className={`font-semibold ${textColor}`}>{vuln.title}</p>
                                                <p className="text-sm text-muted-foreground font-mono">{vuln.file}:{vuln.line}</p>
                                            </div>
                                        </div>
                                    </AccordionTrigger>
                                    <AccordionContent className="pt-2">
                                        <p className="text-sm text-foreground/80 mb-4">{vuln.description}</p>
                                        <div className="bg-card/50 p-4 rounded-md border border-border">
                                            <h4 className="font-semibold mb-2 flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation Prompt</h4>
                                            <div className="bg-black/80 rounded-md p-3">
                                                <pre className="text-xs text-green-300 whitespace-pre-wrap font-code">
                                                    {`Explain the security vulnerability "${vuln.title}" found in the file \`${vuln.file}\` and provide the corrected code snippet to fix it. The vulnerability is described as: "${vuln.description}". The recommended fix is: "${vuln.remediation}"`}
                                                </pre>
                                            </div>
                                        </div>
                                    </AccordionContent>
                                </AccordionItem>
                            );
                        })}
                    </Accordion>
                </CardContent>
            </Card>
        </section>

      </main>
      <AppFooter />
    </div>
  )

    
}

    

    

