"use client"

import { useState, useMemo, useEffect } from "react"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, Loader2, CheckCircle, ShieldAlert, AlertTriangle, Info, Terminal, Code, Github, RefreshCw } from "lucide-react"
import { DashboardPage, DashboardPageHeader } from "@/components/common/dashboard-page"
import { useAuth } from "@/contexts/auth-context"
import { GitHubService, GitHubRepository } from "@/lib/github-service"

// Types for audit data
interface Vulnerability {
  id: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  file: string;
  line: number;
  description: string;
  remediation: string;
}

interface AuditSummary {
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface AuditResults {
  repoName: string;
  summary: AuditSummary;
  vulnerabilities: Vulnerability[];
}

// Mock audit results data (keeping this for now as placeholder)
const mockAuditResultsData: Record<string, AuditResults> = {
  "default": {
    repoName: "default",
    summary: { totalIssues: 3, critical: 1, high: 1, medium: 1, low: 0 },
    vulnerabilities: [
      { id: "VULN-002", title: "Cross-Site Scripting (XSS)", severity: "Critical", file: "src/components/Comment.tsx", line: 42, description: "User-provided content is rendered without proper sanitization, allowing for potential XSS attacks.", remediation: "Use a library like `dompurify` to sanitize HTML content before rendering it with `dangerouslySetInnerHTML`." },
      { id: "VULN-001", title: "Outdated Dependency: `react-scripts`", severity: "High", file: "package.json", line: 25, description: "The version of `react-scripts` used in this project is outdated and has known security vulnerabilities.", remediation: "Update `react-scripts` to the latest version by running `npm install react-scripts@latest`." },
      { id: "VULN-003", title: "Insecure `target='_blank'` usage", severity: "Medium", file: "src/components/Footer.tsx", line: 15, description: "Links using `target='_blank'` without `rel='noopener noreferrer'` are a security risk.", remediation: "Add `rel='noopener noreferrer'` to all `<a>` tags that have `target='_blank'`." },
    ],
  }
}

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


type AuditResultsType = AuditResults | null;

const AuditReport = ({ results }: { results: NonNullable<AuditResultsType> }) => {
    const healthScore = useMemo(() => {
        if (!results.summary.totalIssues) return 100;
        const weightedScore = (results.summary.critical * 10) + (results.summary.high * 5) + (results.summary.medium * 2) + (results.summary.low * 1);
        const maxScore = results.summary.totalIssues * 10;
        return Math.max(0, Math.round((1 - (weightedScore / maxScore)) * 100));
    }, [results]);
    
  const getHealthColor = (score: number) => {
    if (score > 85) return 'text-green-500';
    if (score > 60) return 'text-yellow-500';
    if (score > 40) return 'text-orange-500';
    return 'text-red-500';
  }

  const severityOrder = useMemo(() => ['Critical', 'High', 'Medium', 'Low'], []);
  const sortedVulnerabilities = useMemo(() => {
    return results.vulnerabilities.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)) || [];
  }, [results, severityOrder]);

  return (
    <Card className="bg-card/50 border-2 border-primary/20 shadow-2xl shadow-primary/10">
      <CardHeader>
        <div className="flex flex-col md:flex-row justify-between items-start mb-6">
          <div className="mb-4 md:mb-0">
            <CardTitle className="text-2xl">Audit Report: `{results.repoName}`</CardTitle>
            <CardDescription>{results.summary.totalIssues} vulnerabilities found. See details below.</CardDescription>
          </div>
        </div>
        <div className="space-y-4 text-center">
          <div className="grid grid-cols-2 gap-4">
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Total Findings</h4>
              <p className="text-4xl font-bold">{results.summary.totalIssues}</p>
            </div>
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
              <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-red-400">Critical</h4>
              <p className="text-4xl font-bold text-red-500">{results.summary.critical}</p>
            </div>
            <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-orange-400">High</h4>
              <p className="text-4xl font-bold text-orange-500">{results.summary.high}</p>
            </div>
            <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
              <p className="text-4xl font-bold text-yellow-500">{results.summary.medium}</p>
            </div>
            <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-green-400">Low</h4>
              <p className="text-4xl font-bold text-green-500">{results.summary.low}</p>
            </div>
          </div>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="master-prompt" className="border border-foreground/20 bg-foreground/5 rounded-lg shadow-sm">
              <AccordionTrigger className="hover:no-underline px-4 py-3">
                <div className="flex items-center gap-2 text-foreground">
                  <Terminal className="mr-2 h-4 w-4" /> View Master Prompt
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-4 pb-4">
                <div className="bg-black/80 rounded-md p-3 text-left">
                  <pre className="text-xs text-green-300 whitespace-pre-wrap font-code text-left">
                    {`You are an expert security engineer. Given the following list of vulnerabilities, provide the necessary code changes to remediate all of them. For each vulnerability, explain the risk and the fix.

${sortedVulnerabilities.map((v, i) => `Vulnerability ${i + 1}: ${v.title} in '${v.file}' on line ${v.line}.\nDescription: ${v.description}...`).join('\n\n')}

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
          {sortedVulnerabilities.map((vuln) => {
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
  )
}

export default function SecurityAuditPage() {
  const { user, githubToken } = useAuth()
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [auditResults, setAuditResults] = useState<AuditResultsType>(null)
  const [repositories, setRepositories] = useState<GitHubRepository[]>([])
  const [isLoadingRepos, setIsLoadingRepos] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fetch user's GitHub repositories
  useEffect(() => {
    const fetchRepositories = async () => {
      if (!user || !githubToken) {
        setError("Please sign in with GitHub to access your repositories")
        return
      }

      setIsLoadingRepos(true)
      setError(null)
      
      try {
        const repos = await GitHubService.getUserRepositories(user.uid)
        setRepositories(repos)
        console.log('Fetched repositories:', repos)
      } catch (err) {
        console.error('Error fetching repositories:', err)
        setError(err instanceof Error ? err.message : 'Failed to fetch repositories')
      } finally {
        setIsLoadingRepos(false)
      }
    }

    fetchRepositories()
  }, [user, githubToken])

  const handleAudit = async () => {
    if (!selectedRepo || !user) return;
    
    setIsLoading(true);
    setError(null);
    console.log('🚀 Starting security audit for:', selectedRepo);
    
    try {
      // Add timeout to the fetch request
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 900000); // 15 minutes timeout
      
      console.log('📡 Calling worker at:', process.env.NEXT_PUBLIC_SECURITY_WORKER_URL);
      
      const response = await fetch(process.env.NEXT_PUBLIC_SECURITY_WORKER_URL!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository_url: `https://github.com/berostwo/${selectedRepo}`
        }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      console.log('📥 Worker response status:', response.status);
      console.log('📥 Worker response headers:', Object.fromEntries(response.headers.entries()));
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('❌ Worker error response:', errorText);
        throw new Error(`Audit failed: ${response.status} - ${errorText}`);
      }
      
      const auditResults = await response.json();
      console.log('✅ Audit completed successfully:', auditResults);
      setAuditResults(auditResults);
      
    } catch (error: unknown) {
      console.error('❌ Audit failed:', error);
      
      if (error instanceof Error && error.name === 'AbortError') {
        setError('Audit timed out after 15 minutes. The repository might be too large or complex.');
      } else if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Audit failed with unknown error');
      }
    } finally {
      setIsLoading(false);
      console.log('🏁 Audit process finished');
    }
  };

  const handleRefreshRepos = async () => {
    if (!user) return
    setIsLoadingRepos(true)
    setError(null)
    try {
      const repos = await GitHubService.getUserRepositories(user.uid)
      setRepositories(repos)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh repositories')
    } finally {
      setIsLoadingRepos(false)
    }
  }

  return (
    <DashboardPage>
      <DashboardPageHeader title="Security Audit" description="Select a GitHub repository to start your security audit." />
      
      {/* Repository Selection Card */}
      <Card className="border-2 border-primary/20">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Github className="h-5 w-5" />
                Select Repository
                {repositories.length > 0 && (
                  <Badge variant="outline" className="ml-2">
                    {repositories.length} repo{repositories.length !== 1 ? 's' : ''}
                  </Badge>
                )}
              </CardTitle>
              <CardDescription>
                Choose a repository from your GitHub account to begin the audit process.
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefreshRepos}
              disabled={isLoadingRepos}
              className="flex items-center gap-2"
            >
              <RefreshCw className={`h-4 w-4 ${isLoadingRepos ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 rounded-md">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}
          
          {isLoadingRepos ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>Loading your repositories...</span>
            </div>
          ) : repositories.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Github className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium mb-2">No repositories found</p>
              <p className="text-sm">
                {!user || !githubToken 
                  ? "Please sign in with GitHub to access your repositories"
                  : "You don't have any repositories yet, or they're all private"
                }
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <Select onValueChange={setSelectedRepo} disabled={isLoading}>
                <SelectTrigger className="w-full md:w-[300px]">
                  <SelectValue placeholder="Select a repository" />
                </SelectTrigger>
                <SelectContent>
                  {repositories.map((repo) => (
                    <SelectItem key={repo.id} value={repo.name}>
                      <div className="flex items-center gap-2">
                        <span>{repo.name}</span>
                        {repo.private && (
                          <Badge variant="secondary" className="text-xs">Private</Badge>
                        )}
                        {repo.language && (
                          <Badge variant="outline" className="text-xs">{repo.language}</Badge>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              {selectedRepo && (
                <div className="mt-4 p-4 bg-muted/50 rounded-lg border">
                  <h4 className="font-medium mb-2">Selected Repository</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Name:</span>
                      <p className="font-mono">{selectedRepo}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Language:</span>
                      <p>{repositories.find(r => r.name === selectedRepo)?.language || 'Unknown'}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Visibility:</span>
                      <p>{repositories.find(r => r.name === selectedRepo)?.private ? 'Private' : 'Public'}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Last Updated:</span>
                      <p>{repositories.find(r => r.name === selectedRepo)?.updated_at ? new Date(repositories.find(r => r.name === selectedRepo)!.updated_at).toLocaleDateString() : 'Unknown'}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
        <CardFooter>
          <Button onClick={handleAudit} disabled={!selectedRepo || isLoading || repositories.length === 0}>
            {isLoading ? (
              <div className="flex items-center gap-2">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Running Security Audit... (This may take 5-10 minutes)
              </div>
            ) : (
              <>
                Start Audit <ArrowRight className="ml-2 h-4 w-4" />
              </>
            )}
          </Button>
        </CardFooter>
      </Card>

      {auditResults && auditResults.summary.totalIssues > 0 && (
        <AuditReport results={auditResults} />
      )}

      {auditResults && auditResults.summary.totalIssues === 0 && (
         <Card className="border-green-500/30">
            <CardHeader className="flex-row items-center gap-4">
                <CheckCircle className="w-8 h-8 text-green-500" />
                <div>
                    <CardTitle>No Issues Found!</CardTitle>
                    <CardDescription>
                        Excellent! Your repository `{auditResults.repoName}` passed the security audit.
                    </CardDescription>
                </div>
            </CardHeader>
        </Card>
      )}

    </DashboardPage>
  )
}
