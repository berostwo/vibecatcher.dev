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
import { ArrowRight, Loader2, CheckCircle, ShieldAlert, AlertTriangle, Info, Terminal, Code, Github, RefreshCw, GitBranch, Search, Brain, FileText, XCircle, Play } from "lucide-react"
import { DashboardPage, DashboardPageHeader } from "@/components/common/dashboard-page"
import { useAuth } from "@/contexts/auth-context"
import { GitHubService, GitHubRepository } from "@/lib/github-service"
import { useToast } from "@/hooks/use-toast"

// Types for audit data
interface Vulnerability {
  rule_id: string;
  message: string;
  severity: string;
  file_path: string;
  line_number: number;
  description: string;
  remediation: string;
  occurrences: number; // Added for enterprise-grade report
  locations?: { file_path: string; line_number: number }[]; // Added for enterprise-grade report
}

interface AuditSummary {
  total_vulnerabilities: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  files_scanned: number;
  scan_duration: number;
  critical_severity: number; // Added for enterprise-grade report
}

interface AuditResults {
  summary: AuditSummary;
  vulnerabilities: Vulnerability[];
  repository_info: {
    url: string;
    name: string;
    scan_timestamp: string;
  };
  scan_timestamp: string;
  gpt_analysis: {
    analysis: string;
    model_used: string;
    tokens_used: number;
    timestamp: string;
  };
}

// Mock audit results data (keeping this for now as placeholder)
const mockAuditResultsData: Record<string, AuditResults> = {
  "default": {
    summary: { 
      total_vulnerabilities: 3, 
      high_severity: 1, 
      medium_severity: 1, 
      low_severity: 1, 
      files_scanned: 10,
      scan_duration: 45.2,
      critical_severity: 0 // Added for mock data
    },
    vulnerabilities: [
      { 
        rule_id: "VULN-002", 
        message: "Cross-Site Scripting (XSS)", 
        severity: "error", 
        file_path: "src/components/Comment.tsx", 
        line_number: 42, 
        description: "User-provided content is rendered without proper sanitization, allowing for potential XSS attacks.", 
        remediation: "Use a library like `dompurify` to sanitize HTML content before rendering it with `dangerouslySetInnerHTML`.",
        occurrences: 1, // Added for mock data
        locations: [{ file_path: "src/components/Comment.tsx", line_number: 42 }] // Added for mock data
      },
      { 
        rule_id: "VULN-001", 
        message: "Outdated Dependency: `react-scripts`", 
        severity: "warning", 
        file_path: "package.json", 
        line_number: 25, 
        description: "The version of `react-scripts` used in this project is outdated and has known security vulnerabilities.", 
        remediation: "Update `react-scripts` to the latest version by running `npm install react-scripts@latest`.",
        occurrences: 1, // Added for mock data
        locations: [{ file_path: "package.json", line_number: 25 }] // Added for mock data
      },
      { 
        rule_id: "VULN-003", 
        message: "Insecure `target='_blank'` usage", 
        severity: "info", 
        file_path: "src/components/Footer.tsx", 
        line_number: 15, 
        description: "Links using `target='_blank'` without `rel='noopener noreferrer'` are a security risk.", 
        remediation: "Add `rel='noopener noreferrer'` to all `<a>` tags that have `target='_blank'`.",
        occurrences: 1, // Added for mock data
        locations: [{ file_path: "src/components/Footer.tsx", line_number: 15 }] // Added for mock data
      },
    ],
    repository_info: {
      url: "https://github.com/berostwo/default",
      name: "default",
      scan_timestamp: "2025-08-14T10:00:00Z"
    },
    scan_timestamp: "2025-08-14T10:00:45Z",
    gpt_analysis: {
      analysis: "Mock GPT-4 analysis for testing purposes.",
      model_used: "gpt-4-turbo-preview",
      tokens_used: 150,
      timestamp: "2025-08-14T10:00:45Z"
    }
  }
}

const getSeverityStyles = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'error':
      return {
        icon: <ShieldAlert className="h-5 w-5 text-red-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-500/10',
        textColor: 'text-red-500',
      };
    case 'warning':
      return {
        icon: <AlertTriangle className="h-5 w-5 text-orange-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-500/10',
        textColor: 'text-orange-500',
      };
    case 'info':
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
        bgColor: 'bg-gray-500/10',
        textColor: 'text-gray-500',
      };
  }
};


type AuditResultsType = AuditResults | null;

const AuditReport = ({ results }: { results: NonNullable<AuditResultsType> }) => {
    const healthScore = useMemo(() => {
        if (!results.summary.total_vulnerabilities) return 100;
        
        // Enterprise risk scoring: Critical (10), High (7), Medium (4), Low (1)
        const weightedScore = (
            results.summary.critical_severity * 10 + 
            results.summary.high_severity * 7 + 
            results.summary.medium_severity * 4 + 
            results.summary.low_severity * 1
        );
        const maxScore = results.summary.total_vulnerabilities * 10;
        return Math.max(0, Math.round((1 - (weightedScore / maxScore)) * 100));
    }, [results]);
    
    const getHealthColor = (score: number) => {
        if (score >= 90) return 'text-green-500';
        if (score >= 70) return 'text-yellow-500';
        if (score >= 50) return 'text-orange-500';
        return 'text-red-500';
    };

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'text-red-600 bg-red-50 border-red-200';
            case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
            case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
            case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
            default: return 'text-gray-600 bg-gray-50 border-gray-200';
        }
    };

    const getSeverityIcon = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return <ShieldAlert className="h-5 w-5 text-red-500" />;
            case 'high': return <AlertTriangle className="h-5 w-5 text-orange-500" />;
            case 'medium': return <Info className="h-5 w-5 text-yellow-500" />;
            case 'low': return <CheckCircle className="h-5 w-5 text-blue-500" />;
            default: return <Info className="h-5 w-5 text-gray-500" />;
        }
    };

    const severityOrder = useMemo(() => ['critical', 'high', 'medium', 'low'], []);
    const sortedVulnerabilities = useMemo(() => {
        return results.vulnerabilities.sort((a, b) => 
            severityOrder.indexOf(a.severity.toLowerCase()) - severityOrder.indexOf(b.severity.toLowerCase())
        ) || [];
    }, [results, severityOrder]);

    return (
        <div className="space-y-6 max-w-full overflow-hidden">
            {/* Executive Summary Card */}
            <Card className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/20 dark:to-indigo-950/20 border-2 border-blue-200 dark:border-blue-800">
                <CardHeader className="text-center">
                    <CardTitle className="text-2xl text-blue-900 dark:text-blue-100">
                        🚀 Security Audit Executive Summary
                    </CardTitle>
                    <CardDescription className="text-blue-700 dark:text-blue-300">
                        Repository: {results.repository_info.name} | Scan Date: {new Date(results.scan_timestamp).toLocaleDateString()}
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                        <div className="space-y-2">
                            <div className="text-3xl font-bold text-blue-900 dark:text-blue-100">
                                {results.summary.total_vulnerabilities}
                            </div>
                            <div className="text-sm text-blue-700 dark:text-blue-300">Total Findings</div>
                        </div>
                        <div className="space-y-2">
                            <div className={`text-3xl font-bold ${getHealthColor(healthScore)}`}>
                                {healthScore}%
                            </div>
                            <div className="text-sm text-blue-700 dark:text-blue-300">Security Score</div>
                        </div>
                        <div className="space-y-2">
                            <div className="text-3xl font-bold text-blue-900 dark:text-blue-100">
                                {results.summary.files_scanned}
                            </div>
                            <div className="text-sm text-blue-700 dark:text-blue-300">Files Scanned</div>
                        </div>
                        <div className="space-y-2">
                            <div className="text-3xl font-bold text-blue-900 dark:text-blue-100">
                                {results.summary.scan_duration.toFixed(1)}s
                            </div>
                            <div className="text-sm text-blue-700 dark:text-blue-300">Scan Duration</div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Severity Breakdown Card */}
            <Card className="border-2 border-primary/20">
                <CardHeader>
                    <CardTitle className="text-xl">📊 Security Findings by Severity</CardTitle>
                    <CardDescription>Risk assessment and priority breakdown</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div className="text-center p-4 rounded-lg border-2 border-red-200 bg-red-50 dark:bg-red-950/20 dark:border-red-800">
                            <div className="text-3xl font-bold text-red-600 dark:text-red-400">
                                {results.summary.critical_severity}
                            </div>
                            <div className="text-sm font-medium text-red-700 dark:text-red-300">Critical</div>
                            <div className="text-xs text-red-600 dark:text-red-400">Fix within 24h</div>
                        </div>
                        <div className="text-center p-4 rounded-lg border-2 border-orange-200 bg-orange-50 dark:bg-orange-950/20 dark:border-orange-800">
                            <div className="text-3xl font-bold text-orange-600 dark:text-orange-400">
                                {results.summary.high_severity}
                            </div>
                            <div className="text-sm font-medium text-orange-700 dark:text-orange-300">High</div>
                            <div className="text-xs text-orange-600 dark:text-orange-400">Fix within 1 week</div>
                        </div>
                        <div className="text-center p-4 rounded-lg border-2 border-yellow-200 bg-yellow-50 dark:bg-yellow-950/20 dark:border-yellow-800">
                            <div className="text-3xl font-bold text-yellow-600 dark:text-yellow-400">
                                {results.summary.medium_severity}
                            </div>
                            <div className="text-sm font-medium text-yellow-700 dark:text-yellow-300">Medium</div>
                            <div className="text-xs text-yellow-600 dark:text-yellow-400">Fix within 1 month</div>
                        </div>
                        <div className="text-center p-4 rounded-lg border-2 border-blue-200 bg-blue-50 dark:bg-blue-950/20 dark:border-blue-800">
                            <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
                                {results.summary.low_severity}
                            </div>
                            <div className="text-sm font-medium text-blue-700 dark:text-blue-300">Low</div>
                            <div className="text-xs text-blue-600 dark:text-blue-400">Fix within 3 months</div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Master Remediation Prompt Card */}
            <Card className="border-2 border-green-200 bg-green-50 dark:bg-green-950/20 dark:border-green-800">
                <CardHeader>
                    <CardTitle className="text-xl text-green-800 dark:text-green-200">
                        🎯 Master Remediation Prompt
                    </CardTitle>
                    <CardDescription className="text-green-700 dark:text-green-300">
                        Use this prompt in Cursor/GPT to fix ALL security issues at once
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <Accordion type="single" collapsible>
                        <AccordionItem value="master-prompt">
                            <AccordionTrigger className="text-green-800 dark:text-green-200 hover:text-green-900 dark:hover:text-green-100">
                                <div className="flex items-center gap-2">
                                    <Terminal className="h-5 w-5" />
                                    Click to view Master Prompt
                                </div>
                            </AccordionTrigger>
                            <AccordionContent>
                                <div className="bg-black/90 rounded-md p-4 text-left">
                                    <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono overflow-x-auto">
                                        {results.gpt_analysis.analysis}
                                    </pre>
                                </div>
                            </AccordionContent>
                        </AccordionItem>
                    </Accordion>
                </CardContent>
            </Card>

            {/* Individual Vulnerabilities Card */}
            <Card className="border-2 border-primary/20">
                <CardHeader>
                    <CardTitle className="text-xl">🔍 Detailed Vulnerability Analysis</CardTitle>
                    <CardDescription>Individual security issues with remediation guidance</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        {sortedVulnerabilities.map((vuln, index) => (
                            <div key={index} className={`p-4 rounded-lg border-2 ${getSeverityColor(vuln.severity)}`}>
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-center gap-3">
                                        {getSeverityIcon(vuln.severity)}
                                        <div>
                                            <h4 className="font-semibold text-lg break-words">{vuln.rule_id}</h4>
                                            <div className="flex items-center gap-2 text-sm">
                                                <Badge variant="outline" className="capitalize">
                                                    {vuln.severity}
                                                </Badge>
                                                <Badge variant="secondary">
                                                    {vuln.occurrences} occurrence{vuln.occurrences !== 1 ? 's' : ''}
                                                </Badge>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div className="space-y-3">
                                    <div>
                                        <h5 className="font-medium mb-1">Description</h5>
                                        <p className="text-sm break-words">{vuln.description}</p>
                                    </div>
                                    
                                    <div>
                                        <h5 className="font-medium mb-1">Security Message</h5>
                                        <p className="text-sm break-words">{vuln.message}</p>
                                    </div>
                                    
                                    <div>
                                        <h5 className="font-medium mb-1">Locations</h5>
                                        <div className="space-y-1">
                                            {vuln.locations?.slice(0, 5).map((location, locIndex) => (
                                                <div key={locIndex} className="text-sm font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                                                    {location.file_path}:{location.line_number}
                                                </div>
                                            ))}
                                            {vuln.locations && vuln.locations.length > 5 && (
                                                <div className="text-sm text-gray-500">
                                                    +{vuln.locations.length - 5} more locations
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    
                                    <div>
                                        <h5 className="font-medium mb-1">Remediation</h5>
                                        <p className="text-sm break-words">{vuln.remediation}</p>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
};

export default function SecurityAuditPage() {
  const { user, githubToken } = useAuth()
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [auditResults, setAuditResults] = useState<AuditResultsType>(null)
  const [repositories, setRepositories] = useState<GitHubRepository[]>([])
  const [isLoadingRepos, setIsLoadingRepos] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [auditProgress, setAuditProgress] = useState<{
    phase: string;
    progress: number;
    message: string;
    startTime: Date | null;
    estimatedDuration: number;
  }>({
    phase: 'idle',
    progress: 0,
    message: 'Ready to start audit',
    startTime: null,
    estimatedDuration: 0
  });
  const { toast } = useToast();

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
    
    // Initialize progress tracking
    const startTime = new Date();
    const estimatedDuration = 10 * 60 * 1000; // 10 minutes estimate
    
    setAuditProgress({
      phase: 'starting',
      progress: 0,
      message: 'Initializing security audit...',
      startTime,
      estimatedDuration
    });

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
      
      // Complete progress
      setAuditProgress(prev => ({
        ...prev,
        phase: 'completed',
        progress: 100,
        message: 'Audit completed successfully!'
      }));

      toast({
        title: "Audit completed!",
        description: `Found ${auditResults.summary?.total_vulnerabilities || 0} security issues.`,
      });
      
    } catch (error: unknown) {
      console.error('❌ Audit failed:', error);
      
      if (error instanceof Error && error.name === 'AbortError') {
        setError('Audit timed out after 15 minutes. The repository might be too large or complex.');
      } else if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Audit failed with unknown error');
      }

      setAuditProgress(prev => ({
        ...prev,
        phase: 'failed',
        progress: 0,
        message: `Audit failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      }));

      toast({
        title: "Audit failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
      console.log('🏁 Audit process finished');
      
      // Reset progress after a delay
      setTimeout(() => {
        setAuditProgress({
          phase: 'idle',
          progress: 0,
          message: 'Ready to start audit',
          startTime: null,
          estimatedDuration: 0
        });
      }, 3000);
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

  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case 'starting': return <Loader2 className="h-4 w-4 animate-spin" />;
      case 'cloning': return <GitBranch className="h-4 w-4" />;
      case 'scanning': return <Search className="h-4 w-4" />;
      case 'analyzing': return <Brain className="h-4 w-4" />;
      case 'generating': return <FileText className="h-4 w-4" />;
      case 'completed': return <CheckCircle className="h-4 w-4" />;
      case 'failed': return <XCircle className="h-4 w-4" />;
      default: return <Play className="h-4 w-4" />;
    }
  };

  const getPhaseColor = (phase: string) => {
    switch (phase) {
      case 'starting': return 'text-blue-600';
      case 'cloning': return 'text-green-600';
      case 'scanning': return 'text-orange-600';
      case 'analyzing': return 'text-purple-600';
      case 'generating': return 'text-indigo-600';
      case 'completed': return 'text-green-600';
      case 'failed': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

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

      {auditResults && auditResults.summary && auditResults.summary.total_vulnerabilities > 0 && (
        <div className="space-y-6">
          <AuditReport results={auditResults} />
        </div>
      )}

      {auditResults && auditResults.summary && auditResults.summary.total_vulnerabilities === 0 && (
         <Card className="border-green-500/30">
            <CardHeader className="flex-row items-center gap-4">
                <CheckCircle className="w-8 h-8 text-green-500" />
                <div>
                    <CardTitle>No Issues Found!</CardTitle>
                    <CardDescription>
                        Excellent! Your repository `{auditResults.repository_info?.name || 'Unknown'}` passed the security audit.
                    </CardDescription>
                </div>
            </CardHeader>
        </Card>
      )}

      {/* Debug: Show raw audit results for troubleshooting */}
      {auditResults && (
        <Card className="border-blue-500/30 mt-6">
          <CardHeader>
            <CardTitle className="text-blue-600">Debug: Raw Audit Results</CardTitle>
            <CardDescription>Raw data structure returned from worker (click to expand)</CardDescription>
          </CardHeader>
          <CardContent>
            <Accordion type="single" collapsible>
              <AccordionItem value="debug-data">
                <AccordionTrigger>Click to view raw data</AccordionTrigger>
                <AccordionContent>
                  <pre className="text-xs bg-gray-100 dark:bg-gray-900 p-4 rounded overflow-auto max-h-96">
                    {JSON.stringify(auditResults, null, 2)}
                  </pre>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </CardContent>
        </Card>
      )}

      {/* Progress Tracking */}
      {auditProgress.phase !== 'idle' && (
        <Card className="border-2 border-primary/20 mt-6">
          <CardHeader className="flex-row items-center gap-4">
            <div className={`flex items-center gap-2 ${getPhaseColor(auditProgress.phase)}`}>
              {getPhaseIcon(auditProgress.phase)}
              <span className="font-semibold">{auditProgress.message}</span>
            </div>
            <div className="flex-1 text-right text-sm text-muted-foreground">
              {auditProgress.progress}%
            </div>
          </CardHeader>
          <CardContent>
            <div className="w-full bg-gray-200 rounded-full h-2 dark:bg-gray-700">
              <div
                className="bg-primary h-2 rounded-full"
                style={{ width: `${auditProgress.progress}%` }}
              ></div>
            </div>
            {auditProgress.startTime && (
              <p className="text-xs text-muted-foreground mt-2">
                Started at: {new Date(auditProgress.startTime).toLocaleTimeString()}
              </p>
            )}
            {auditProgress.estimatedDuration > 0 && (
              <p className="text-xs text-muted-foreground">
                Estimated Duration: {Math.round(auditProgress.estimatedDuration / 60000)} minutes
              </p>
            )}
          </CardContent>
        </Card>
      )}

    </DashboardPage>
  )
}
