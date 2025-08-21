'use client';

import { useState, useEffect, useMemo } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { GitHubService } from '@/lib/github-service';
import { FirebaseUserService } from '@/lib/firebase-user-service';
import { FirebaseAuditService, SecurityAudit } from '@/lib/firebase-audit-service';
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
import React from 'react';

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
    codebase_health: number;
    files_scanned: number;
    scan_duration: number;
  };
  findings: SecurityFinding[];
  condensed_findings: SecurityFinding[];
  condensed_remediations: { [key: string]: string };
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

const AuditReportTemplate = ({ results }: { 
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
          {/* Master remediation UI removed */}
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
                            ? `${vuln.occurrences} occurrences`
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
  
  // SIMPLE PROGRESS TRACKING - now includes time remaining
  const [currentStep, setCurrentStep] = useState<string>('Initializing scan...');
  const [currentProgress, setCurrentProgress] = useState<number>(0);
  const [elapsedTime, setElapsedTime] = useState<string>('0s');
  const [timeRemaining, setTimeRemaining] = useState<string>('Calculating...');
  
  // PERSISTENT AUDIT STATE: Track current audit across page refreshes
  const [currentAudit, setCurrentAudit] = useState<SecurityAudit | null>(null);

  // REAL PROGRESS POLLING - Actually communicate with worker
  const [progressPollingInterval, setProgressPollingInterval] = useState<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (user) {
      fetchRepositories();
      fetchGitHubUsername();
      checkExistingAudit();
    }
  }, [user]);

  // REAL PROGRESS POLLING: Poll worker's /progress endpoint for real-time updates
  useEffect(() => {
    if (isScanning && currentAudit?.id) {
      console.log('🚀 STARTING ROBUST PROGRESS POLLING...');
      
      // Add a small delay to allow worker to initialize scan state
      const initialDelay = setTimeout(() => {
        console.log('⏳ Initial delay completed, starting progress polling...');
      }, 2000); // 2 second delay
      
      const interval = setInterval(async () => {
        try {
          console.log('🔄 POLLING FOR PROGRESS...');
          
          // DISTRIBUTED PROGRESS SYSTEM: Get the correct worker for this audit
          let workerUrl: string;
          
          try {
            // Get the worker URL from Firestore for this specific audit
            const audit = await FirebaseAuditService.getAuditById(currentAudit.id);
            if (audit?.workerUrl) {
              workerUrl = `${audit.workerUrl}/progress/${currentAudit.id}`;
              console.log('📡 POLLING CORRECT WORKER:', workerUrl);
            } else {
              // Fallback to the main worker if no worker URL is set
              workerUrl = 'https://chatgpt-security-scanner-505997387504.us-central1.run.app/progress';
              console.log('⚠️ No worker URL found, falling back to main worker:', workerUrl);
            }
          } catch (error) {
            console.warn('Could not get worker URL, falling back to main worker:', error);
            workerUrl = 'https://chatgpt-security-scanner-505997387504.us-central1.run.app/progress';
          }
          
          // Also check the debug endpoint to see global state
          try {
            const debugResponse = await fetch('https://chatgpt-security-scanner-505997387504.us-central1.run.app/debug/global-state');
            if (debugResponse.ok) {
              const debugData = await debugResponse.json();
              console.log('🔍 WORKER DEBUG STATE:', debugData);
            }
          } catch (debugError) {
            console.warn('Could not fetch debug state:', debugError);
          }
          
          const response = await fetch(workerUrl);
          console.log('📡 WORKER POLL RESPONSE STATUS:', response.status);
          
          if (response.ok) {
            const progressData = await response.json();
            console.log('📡 WORKER PROGRESS DATA:', progressData);
            
            if (progressData && progressData.step && (typeof progressData.percentage === 'number' || typeof progressData.progress === 'number')) {
              console.log('✅ WORKER PROGRESS UPDATE:', progressData);
              console.log('📊 CURRENT SCAN STATE - Step:', progressData.step, 'Progress:', typeof progressData.percentage === 'number' ? progressData.percentage : progressData.progress);
              setCurrentStep(progressData.step);
              setCurrentProgress(typeof progressData.percentage === 'number' ? progressData.percentage : progressData.progress);
              if (progressData.elapsed_time) setElapsedTime(progressData.elapsed_time);
              if (progressData.time_remaining) setTimeRemaining(progressData.time_remaining);
              
              // Check if scan completed by checking worker progress
              if (progressData.percentage === 100) {
                console.log('🎉 SCAN COMPLETED - STOPPING POLLING');
                setIsScanning(false);
                // The scan results will be fetched from Firestore when the worker completes
              }
            } else if (progressData.status === 'no_scan_running') {
              console.log('⚠️ Worker reports no scan running - scan may not have started yet, continuing to poll...');
              console.log('📊 FRONTEND STATE - isScanning:', isScanning, 'currentProgress:', currentProgress, 'currentStep:', currentStep);
              // Don't treat this as an error - just continue polling
              
              // If we were previously scanning and now get "no scan running", the scan might have completed
              if (isScanning && currentProgress > 0) {
                console.log('🎉 SCAN COMPLETED - Worker reports no scan running after progress');
                setIsScanning(false);
                // The scan results will be fetched from Firestore when the worker completes
              }
            } else if (progressData.status === 'wrong_worker') {
              console.log('⚠️ Wrong worker - this worker is not handling the requested audit');
              console.log('📊 WRONG WORKER INFO:', progressData);
              // This worker is not handling the requested audit, try to find the correct one
              // The frontend will automatically retry with the correct worker URL from Firestore
            } else {
              console.log('⚠️ Invalid worker progress data format:', progressData);
            }
          } else {
            console.error('❌ WORKER POLL FAILED:', response.status, response.statusText);
          }
        } catch (e) {
          console.error('❌ PROGRESS POLLING ERROR:', e);
        }
      }, 1000); // Poll every 1 second for more responsive updates
      
      setProgressPollingInterval(interval as unknown as NodeJS.Timeout);
      return () => {
        clearInterval(interval);
        clearTimeout(initialDelay);
      };
    }
  }, [isScanning, currentAudit?.id, currentProgress, currentStep]);

  // Cleanup polling when scan completes
  useEffect(() => {
    if (!isScanning && progressPollingInterval) {
      clearInterval(progressPollingInterval);
      setProgressPollingInterval(null);
    }
  }, [isScanning, progressPollingInterval]);

  // Check for existing active audit on page load/refresh
  const checkExistingAudit = async () => {
    if (!user) return;
    
    try {
      const activeAudit = await FirebaseAuditService.getActiveAudit(user.uid);
      if (activeAudit) {
        console.log('🔍 Found existing active audit:', activeAudit);
        setCurrentAudit(activeAudit);
        
        if (activeAudit.status === 'running') {
          setIsScanning(true);
          if (activeAudit.progress) {
            setCurrentStep(activeAudit.progress.step);
            setCurrentProgress(activeAudit.progress.progress);
          }
        } else if (activeAudit.status === 'completed' && activeAudit.scanResults) {
          setScanResults(activeAudit.scanResults);
          setIsScanning(false);
        }
      }
    } catch (error) {
      console.error('Error checking existing audit:', error);
    }
  };

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

    // Check if user already has an active audit
    try {
      const hasActive = await FirebaseAuditService.hasActiveAudit(user!.uid);
      if (hasActive) {
        toast({
          title: 'Audit Already Running',
          description: 'You already have a security audit in progress. Please wait for it to complete.',
          variant: 'destructive',
        });
        return;
      }
    } catch (error) {
      console.error('Error checking active audit:', error);
    }

    setIsScanning(true);
    setScanResults(null);
    
    // RESET PROGRESS TO 0
    setCurrentStep('Initializing scan...');
    setCurrentProgress(0);
    
    try {
      // Input validation
      if (!selectedRepository || typeof selectedRepository !== 'string') {
        throw new Error('Invalid repository selection. Please select a valid repository.');
      }

      if (!userGitHubUsername || typeof userGitHubUsername !== 'string') {
        throw new Error('Invalid GitHub username. Please re-authenticate with GitHub.');
      }

      // Validate repository name format (GitHub username/repo-name)
      const repoNameRegex = /^[a-zA-Z0-9._-]+$/;
      if (!repoNameRegex.test(selectedRepository)) {
        throw new Error('Invalid repository name format. Repository names can only contain letters, numbers, dots, underscores, and hyphens.');
      }

      // Validate GitHub username format
      if (!repoNameRegex.test(userGitHubUsername)) {
        throw new Error('Invalid GitHub username format.');
      }

      // Get GitHub token from user service
      const firebaseUser = await FirebaseUserService.getUserByUid(user!.uid);
      const githubToken = firebaseUser?.githubAccessToken;

      if (!githubToken) {
        throw new Error('GitHub token not found. Please re-authenticate with GitHub.');
      }

      // Validate GitHub token format (basic check)
      if (!githubToken.startsWith('ghp_') && !githubToken.startsWith('gho_') && !githubToken.startsWith('ghu_')) {
        throw new Error('Invalid GitHub token format. Please re-authenticate with GitHub.');
      }

      const repositoryUrl = `https://github.com/${userGitHubUsername}/${selectedRepository}`;

      // Create audit record in Firebase FIRST
      const auditId = await FirebaseAuditService.createAudit(
        user!.uid,
        repositoryUrl,
        selectedRepository
      );
      
      console.log('🔍 Created audit record:', auditId);
      setCurrentAudit({
        id: auditId,
        userId: user!.uid,
        repositoryUrl,
        repositoryName: selectedRepository,
        status: 'pending',
        progress: null,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      // Update status to running
      await FirebaseAuditService.updateAuditStatus(auditId, 'running');

      // START REAL PROGRESS TRACKING
      setCurrentStep('Starting scan...');
      setCurrentProgress(0);

      // Start the security scan
      console.log('🚀 Starting security scan...');
      
      console.log('🚀 Starting security scan for repository');
      console.log('📍 Repository URL:', repositoryUrl);
      
      const response = await fetch('https://chatgpt-security-scanner-505997387504.us-central1.run.app/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repository_url: repositoryUrl,
          github_token: githubToken,
          audit_id: auditId,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      // Get the scan results
      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }

      console.log('🎉 Scan completed with results!', data);
      
      // Set final progress
      setCurrentStep('Scan complete!');
      setCurrentProgress(100);
      
      // Save completed audit results to Firebase
      await FirebaseAuditService.updateAuditStatus(auditId, 'completed', data);
      
      // Update local state
      setScanResults(data);
      setCurrentAudit(prev => prev ? { ...prev, status: 'completed', scanResults: data } : null);
      
      toast({
        title: 'Success',
        description: `Security audit completed! Found ${data.summary.total_findings} issues.`,
      });

    } catch (error) {
      console.error('Audit failed:', error);
      
      // Save failed audit to Firebase
      if (currentAudit) {
        await FirebaseAuditService.updateAuditStatus(
          currentAudit.id, 
          'failed', 
          undefined, 
          error instanceof Error ? error.message : 'Unknown error occurred'
        );
        setCurrentAudit(prev => prev ? { ...prev, status: 'failed' } : null);
      }
      
      toast({
        title: 'Audit Failed',
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: 'destructive',
      });
    } finally {
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
          <h1 className="text-6xl font-bold font-headline uppercase italic -mb-6 text-primary/50">Security Audit</h1>
          <p className="text-muted-foreground mt-4">
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
            {isScanning && (
              <Button 
                onClick={() => {
                  setIsScanning(false);
                  setCurrentStep('Initializing scan...');
                  setCurrentProgress(0);
                  setCurrentAudit(null);
                  toast({
                    title: 'Scan Reset',
                    description: 'Scanning state has been reset. You can start a new scan.',
                  });
                }}
                variant="outline"
                className="min-w-[120px]"
              >
                Reset Scan
              </Button>
            )}
            <Button 
              onClick={async () => {
                try {
                  // Clean up any stale audits
                  if (currentAudit && (currentAudit.status === 'running' || currentAudit.status === 'pending')) {
                    await FirebaseAuditService.updateAuditStatus(
                      currentAudit.id, 
                      'failed', 
                      undefined, 
                      'Manual cleanup - user reset'
                    );
                    setCurrentAudit(null);
                    setIsScanning(false);
                    setCurrentStep('Initializing scan...');
                    setCurrentProgress(0);
                    toast({
                      title: 'Cleanup Complete',
                      description: 'Stale audit has been cleaned up. You can start a new scan.',
                    });
                  } else {
                    toast({
                      title: 'No Cleanup Needed',
                      description: 'No stale audits found.',
                    });
                  }
                } catch (error) {
                  console.error('Cleanup failed:', error);
                  toast({
                    title: 'Cleanup Failed',
                    description: 'Failed to clean up stale audit.',
                    variant: 'destructive',
                  });
                }
              }}
              variant="outline"
              className="min-w-[120px]"
            >
              Cleanup Stale
            </Button>
            <Button 
              onClick={async () => {
                try {
                  // Call worker cleanup endpoint for stuck audits
                  if (currentAudit) {
                    const response = await fetch('https://chatgpt-security-scanner-505997387504.us-central1.run.app/cleanup-stuck-audit', {
                      method: 'POST',
                      headers: {
                        'Content-Type': 'application/json',
                      },
                      body: JSON.stringify({
                        audit_id: currentAudit.id,
                      }),
                    });
                    
                    if (response.ok) {
                      // Also cleanup in Firestore
                      await FirebaseAuditService.updateAuditStatus(
                        currentAudit.id, 
                        'failed', 
                        undefined, 
                        'Manual cleanup - worker reset'
                      );
                      setCurrentAudit(null);
                      setIsScanning(false);
                      setCurrentStep('Initializing scan...');
                      setCurrentProgress(0);
                      toast({
                        title: 'Worker Cleanup Complete',
                        description: 'Stuck audit has been cleaned up on both worker and database.',
                      });
                    } else {
                      throw new Error('Worker cleanup failed');
                    }
                  } else {
                    toast({
                      title: 'No Audit to Cleanup',
                      description: 'No current audit found.',
                    });
                  }
                } catch (error) {
                  console.error('Worker cleanup failed:', error);
                  toast({
                    title: 'Worker Cleanup Failed',
                    description: 'Failed to cleanup stuck audit on worker.',
                    variant: 'destructive',
                  });
                }
              }}
              variant="outline"
              className="min-w-[120px]"
            >
              Force Worker Reset
            </Button>
          </div>
          
          {/* SIMPLE PROGRESS BAR with time remaining */}
          {isScanning && (
            <div className="space-y-3 pt-4">
              <div className="flex justify-between text-sm text-muted-foreground">
                <span className="font-medium">{currentStep}</span>
                <span className="font-mono">ETA: {timeRemaining}</span>
              </div>
              <div className="w-full bg-muted rounded-full h-3">
                <div 
                  className="bg-purple-600 h-3 rounded-full transition-all duration-500 ease-out shadow-sm"
                  style={{ width: `${currentProgress}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-muted-foreground">
                <span className="font-mono">Elapsed: {elapsedTime}</span>
                <span className="font-mono">{Math.round(currentProgress)}%</span>
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
              totalIssues: scanResults.summary.condensed_findings,
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
        />
      )}
    </div>
  );
}
