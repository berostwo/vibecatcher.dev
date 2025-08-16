'use client';

import { useState, useEffect, useMemo } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { GitHubService } from '@/lib/github-service';
import { FirebaseUserService } from '@/lib/firebase-user-service';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { ErrorBoundary } from '@/components/error-boundary';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CheckCircle, ShieldAlert, AlertTriangle, Info, Terminal, Code } from 'lucide-react';

interface Repository {
  name: string;
  private: boolean;
  description: string | null;
}

interface SecurityFinding {
  rule_id: string;
  severity: string;
  message: string;
  description: string;
  file_path: string;
  line_number: number;
  end_line: number;
  code_snippet: string;
  cwe_ids: string[];
  owasp_ids: string[];
  impact: string;
  likelihood: string;
  confidence: string;
  remediation: string;
  occurrences: number;
}

interface ScanResults {
  summary: {
    total_findings: number;
    condensed_findings: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    files_scanned: number;
    scan_duration: number;
  };
  findings: SecurityFinding[];
  condensed_findings: SecurityFinding[];
  condensed_remediations: { [key: string]: string };
  master_remediation: string;
  scan_duration: number;
  timestamp: string;
  repository_info: {
    name: string;
    url: string;
    size: string;
    file_count: number;
  };
  error?: string;
  error_type?: string;
}

// Helper function to get severity color
const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-600 text-white hover:bg-red-700';
    case 'high':
      return 'bg-orange-600 text-white hover:bg-orange-700';
    case 'medium':
      return 'bg-yellow-600 text-white hover:bg-yellow-700';
    case 'low':
      return 'bg-blue-600 text-white hover:bg-blue-700';
    default:
      return 'bg-gray-600 text-white hover:bg-gray-700';
  }
};

// Helper function to render file location
const renderFileLocation = (finding: SecurityFinding) => {
  if (finding.line_number === finding.end_line) {
    return `${finding.file_path}:${finding.line_number}`;
  }
  return `${finding.file_path}:${finding.line_number}-${finding.end_line}`;
};

// EXACT TEMPLATE COMPONENT - Copied from template page
const getSeverityStyles = (severity: string) => {
  switch (severity) {
    case 'Critical':
      return {
        icon: <ShieldAlert className="h-5 w-5 text-red-500" />,
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-500/10',
        textColor: 'text-red-500',
      };
    case 'High':
      return {
        icon: <AlertTriangle className="h-5 w-5 text-orange-500" />,
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-500/10',
        textColor: 'text-orange-500',
      };
    case 'Medium':
      return {
        icon: <Info className="h-5 w-5 text-yellow-500" />,
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-500/10',
        textColor: 'text-yellow-500',
      };
    default:
      return {
        icon: <CheckCircle className="h-5 w-5 text-green-500" />,
        borderColor: 'border-gray-500/50',
        bgColor: 'bg-green-500/10',
        textColor: 'text-green-500',
      };
  }
};

const AuditReportTemplate = ({ results, masterRemediation }: { 
  results: {
    repoName: string;
    summary: {
      totalIssues: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    vulnerabilities: Array<{
      id: string;
      title: string;
      severity: string;
      file: string;
      line: number;
      description: string;
      remediation: string;
      occurrences: number;
    }>;
  };
  masterRemediation: string;
}) => {
  // AUTO-COLLAPSE: Track which card is currently expanded
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  
  const healthScore = useMemo(() => {
    if (!results.summary.totalIssues) return 100;
    const weightedScore = (results.summary.critical * 10) + (results.summary.high * 5) + (results.summary.medium * 2) + (results.summary.low * 1);
    const maxScore = results.summary.totalIssues * 10;
    return Math.max(0, Math.round((1 - (weightedScore / (maxScore || 1))) * 100));
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

${sortedVulnerabilities.map((v: any, i: number) => `Vulnerability ${i + 1}: ${v.title} in '${v.file}' on line ${v.line}.\nDescription: ${v.description}...`).join('\n\n')}

Provide a git-compatible diff for each required code change.`}
                  </pre>
                </div>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="master-remediation" className="border border-foreground/20 bg-foreground/5 rounded-lg shadow-sm">
              <AccordionTrigger className="hover:no-underline px-4 py-3">
                <div className="flex items-center gap-2 text-foreground">
                  <Code className="mr-2 h-4 w-4" /> View Master Remediation Plan
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-4 pb-4">
                <div className="bg-black/80 rounded-md p-3 text-left">
                  <pre className="text-xs text-green-300 whitespace-pre-wrap font-code text-left">
                    {masterRemediation || "Master remediation plan will be generated for all findings."}
                  </pre>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>
      </CardHeader>
      <CardContent>
        <Accordion 
          type="single" 
          collapsible 
          className="w-full"
          value={expandedCard || undefined}
          onValueChange={(value) => setExpandedCard(value)}
        >
          {sortedVulnerabilities.map((vuln: any) => {
            const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity);
            return (
              <AccordionItem value={vuln.id} key={vuln.id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
                <AccordionTrigger className="hover:no-underline">
                  <div className="flex items-center gap-4 w-full">
                    {icon}
                    <div className="flex-grow text-left">
                      <p className={`font-semibold ${textColor}`}>{vuln.title}</p>
                                             <div className="flex items-center gap-2">
                         <p className="text-sm text-muted-foreground font-mono">
                           {vuln.occurrences > 1 
                             ? `${vuln.file}:${vuln.line} (${vuln.occurrences} occurrences)`
                             : `${vuln.file}:${vuln.line}`
                           }
                         </p>
                       </div>
                    </div>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pt-2">
                  <p className="text-sm text-foreground/80 mb-4">{vuln.description}</p>
                  
                  {/* Show all file locations if multiple occurrences */}
                  {vuln.occurrences > 1 && (
                    <div className="bg-muted p-3 rounded-md mb-4">
                      <h4 className="font-semibold mb-2 text-sm">All Locations:</h4>
                      <div className="space-y-1">
                        {vuln.file.split(', ').map((filePath: string, index: number) => (
                          <p key={index} className="text-xs font-mono text-muted-foreground">
                            {filePath}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}
                  
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
};

export default function SecurityAuditPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepository, setSelectedRepository] = useState<string>('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [userGitHubUsername, setUserGitHubUsername] = useState<string>('');
  
  // PROGRESS TRACKING: State for real-time progress updates
  const [scanProgress, setScanProgress] = useState<{
    step: string;
    progress: number;
  } | null>(null);

  // DEBUG: Log progress changes
  useEffect(() => {
    if (scanProgress) {
      console.log('📊 Progress state updated:', scanProgress);
    }
  }, [scanProgress]);

  useEffect(() => {
    if (user) {
      fetchRepositories();
      fetchGitHubUsername();
    }
  }, [user]);

  const fetchGitHubUsername = async () => {
    try {
      const firebaseUser = await FirebaseUserService.getUserByUid(user!.uid);
      if (firebaseUser?.githubUsername) {
        setUserGitHubUsername(firebaseUser.githubUsername);
      }
    } catch (error) {
      console.error('Error fetching GitHub username:', error);
    }
  };

  const fetchRepositories = async () => {
    try {
      const repos = await GitHubService.getUserRepositories(user!.uid);
      setRepositories(repos);
    } catch (error) {
      console.error('Error fetching repositories:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch repositories',
        variant: 'destructive',
      });
    }
  };

  const handleAudit = async () => {
    if (!selectedRepository || !userGitHubUsername) {
      toast({
        title: 'Error',
        description: 'Please select a repository and ensure GitHub access',
        variant: 'destructive',
      });
      return;
    }

    setIsScanning(true);
    setScanResults(null);
    setScanProgress(null); // Reset progress
    
    // PROGRESS TRACKING: Simple progress tracking
    
    try {
      // Get GitHub token from user service
      const firebaseUser = await FirebaseUserService.getUserByUid(user!.uid);
      const githubToken = firebaseUser?.githubAccessToken;

      if (!githubToken) {
        throw new Error('GitHub token not found. Please re-authenticate with GitHub.');
      }

      const repositoryUrl = `https://github.com/${userGitHubUsername}/${selectedRepository}`;

      // PROGRESS TRACKING: Start with initial progress
      setScanProgress({
        step: "Initializing scan...",
        progress: 0
      });

      // Start the security scan FIRST
      const response = await fetch('https://chatgpt-security-scanner-505997387504.us-central1.run.app/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repository_url: repositoryUrl,
          github_token: githubToken,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // PROGRESS TRACKING: Simple progress updates during scan
      console.log('🚀 Starting security scan...');

      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }

      setScanResults(data);
      toast({
        title: 'Success',
        description: `Security audit completed! Found ${data.summary.total_findings} issues.`,
      });

    } catch (error) {
      console.error('Audit failed:', error);
      toast({
        title: 'Audit Failed',
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: 'destructive',
      });
    } finally {
      // PROGRESS TRACKING: Set final progress
      setScanProgress(prev => prev ? {
        ...prev,
        step: "Scan complete!",
        progress: 100
      } : null);
      
      setIsScanning(false);
    }
  };

  const getSeverityCount = (severity: string) => {
    if (!scanResults?.condensed_findings) return 0;
    return scanResults.condensed_findings.filter(f => f.severity.toLowerCase() === severity.toLowerCase()).length;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Audit</h1>
          <p className="text-muted-foreground">
            Comprehensive security analysis powered by ChatGPT for bulletproof applications
          </p>
        </div>
      </div>

      {/* Repository Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Repository</CardTitle>
          <CardDescription>
            Choose a repository to perform a comprehensive security audit
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center space-x-4">
            <Select value={selectedRepository} onValueChange={setSelectedRepository}>
              <SelectTrigger className="w-[400px]">
              <SelectValue placeholder="Select a repository" />
            </SelectTrigger>
            <SelectContent>
                {repositories.map((repo) => (
                  <SelectItem key={repo.name} value={repo.name}>
                    <div className="flex items-center space-x-2">
                      <span>{repo.name}</span>
                      {repo.private && (
                        <Badge variant="secondary" className="text-xs">
                          Private
                        </Badge>
                      )}
                    </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
            <Button 
              onClick={handleAudit} 
              disabled={!selectedRepository || isScanning}
              className="min-w-[120px]"
            >
              {isScanning ? 'Scanning...' : 'Run Security Audit'}
            </Button>
          </div>
          
                     {/* PROGRESS BAR: Beautiful purple progress tracking */}
           {isScanning && scanProgress && (
             <div className="space-y-3 pt-4">
                          <div className="flex justify-between text-sm text-muted-foreground">
             <span className="font-medium">{scanProgress.step}</span>
             <span className="font-mono">{Math.round(scanProgress.progress)}%</span>
           </div>
               <div className="w-full bg-muted rounded-full h-3">
                 <div 
                   className="bg-purple-600 h-3 rounded-full transition-all duration-500 ease-out shadow-sm"
                   style={{ width: `${scanProgress.progress}%` }}
                 />
               </div>
             </div>
           )}
        </CardContent>
      </Card>

      {/* Scan Results - Using EXACT Template Format */}
      {scanResults && (
        <AuditReportTemplate 
          results={{
            repoName: scanResults.repository_info.name,
            summary: {
              totalIssues: scanResults.summary.total_findings,
              critical: scanResults.summary.critical_count,
              high: scanResults.summary.high_count,
              medium: scanResults.summary.medium_count,
              low: scanResults.summary.low_count
            },
            vulnerabilities: scanResults.condensed_findings.map((finding, index) => {
              // Get the remediation prompt from the worker's condensed_remediations
              const remediationPrompt = scanResults.condensed_remediations?.[finding.rule_id] || 
                "Remediation prompt will be generated for this finding type.";
              
              return {
                id: finding.rule_id || `VULN-${index + 1}`,
                title: finding.message,
                severity: finding.severity,
                file: finding.file_path,
                line: finding.line_number,
                description: finding.description,
                remediation: remediationPrompt,
                occurrences: finding.occurrences || 1
              };
            })
          }}
          masterRemediation={scanResults.master_remediation}
        />
      )}
    </div>
  );
}
