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
import { CheckCircle, ShieldAlert, AlertTriangle, Info, Terminal, Code, ShieldCheck, Copy, ChevronDown } from 'lucide-react';
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

const AuditReportTemplate = ({ results, currentAudit }: { 
  results: {
    repoName: string;
    summary: {
      totalIssues: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      resolvedCount: number;
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
      status?: 'open' | 'resolved' | 'false_positive';
    }>;
  };
  currentAudit?: SecurityAudit | null;
}) => {
  // AUTO-COLLAPSE: Track which card is currently expanded
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const { toast } = useToast();
  
  // Copy to clipboard function
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied to clipboard!",
        description: "Remediation prompt copied successfully",
        duration: 2000,
      });
    } catch (err) {
      console.error('Failed to copy text: ', err);
      toast({
        title: "Copy failed",
        description: "Failed to copy to clipboard",
        variant: "destructive",
        duration: 3000,
      });
    }
  };

  // Add timeout tracking for polling
  const [pollingStartTime, setPollingStartTime] = useState<number | null>(null);
  
  // Handle status change for findings
  const handleStatusChange = async (findingId: string, newStatus: string) => {
    // Validate the status
    if (!['open', 'resolved', 'false_positive'].includes(newStatus)) {
      return;
    }
    
    const validStatus = newStatus as 'open' | 'resolved' | 'false_positive';
    
    try {
      // Generate a hash for the finding content to enable cross-audit learning
      const finding = results.vulnerabilities.find(v => v.id === findingId);
      if (!finding) return;
      
      const findingContent = `${finding.title}-${finding.description}`;
      const findingHash = btoa(findingContent).slice(0, 16); // Simple hash for demo
      
      // Update the vulnerability status in the results
      const updatedVulnerabilities = results.vulnerabilities.map(vuln => 
        vuln.id === findingId ? { ...vuln, status: validStatus } : vuln
      );
      
      // Recalculate resolved count
      const resolvedCount = updatedVulnerabilities.filter(v => 
        v.status === 'resolved' || v.status === 'false_positive'
      ).length;
      
      // Update the results object
      results.vulnerabilities = updatedVulnerabilities;
      results.summary.resolvedCount = resolvedCount;
      
      // Persist to backend if we have an audit ID and status is not 'open'
      if (currentAudit?.id && validStatus !== 'open') {
        await FirebaseAuditService.updateFindingStatus(
          currentAudit.id,
          findingId,
          validStatus,
          currentAudit.userId || 'unknown',
          findingHash
        );
      }
      
      toast({
        title: "Status Updated",
        description: `Finding marked as ${newStatus} and saved`,
        duration: 2000,
      });
    } catch (error) {
      console.error('Error updating finding status:', error);
      toast({
        title: "Error",
        description: "Failed to save status change",
        variant: "destructive",
        duration: 3000,
      });
    }
  };
  
    const healthScore = useMemo(() => {
        if (!results.summary.totalIssues) return 100;
        
        // Calculate outstanding issues (excluding resolved and false positives)
        const outstandingIssues = results.vulnerabilities.filter(v => v.status === 'open').length;
        
        if (outstandingIssues === 0) return 100;
        
        // Calculate weighted score only for outstanding issues
        const weightedScore = results.vulnerabilities
            .filter(v => v.status === 'open')
            .reduce((score, vuln) => {
                switch (vuln.severity.toLowerCase()) {
                    case 'critical': return score + 10;
                    case 'high': return score + 5;
                    case 'medium': return score + 2;
                    case 'low': return score + 1;
                    default: return score;
                }
            }, 0);
        
        const maxScore = outstandingIssues * 10;
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
          {/* Findings Resolved Card */}
          <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-4">
            <h4 className="text-sm font-medium text-green-400">Findings Resolved</h4>
            <p className="text-4xl font-bold text-green-500">{results.summary.resolvedCount || 0}</p>
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Outstanding Issues</h4>
              <p className="text-4xl font-bold">{results.vulnerabilities.filter(v => v.status === 'open').length}</p>
            </div>
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
              <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-red-400">Critical</h4>
              <p className="text-4xl font-bold text-red-500">
                {results.vulnerabilities.filter(v => v.status === 'open' && v.severity.toLowerCase() === 'critical').length}
              </p>
            </div>
            <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-orange-400">High</h4>
              <p className="text-4xl font-bold text-orange-500">
                {results.vulnerabilities.filter(v => v.status === 'open' && v.severity.toLowerCase() === 'high').length}
              </p>
            </div>
            <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
              <p className="text-4xl font-bold text-yellow-500">
                {results.vulnerabilities.filter(v => v.status === 'open' && v.severity.toLowerCase() === 'medium').length}
              </p>
            </div>
            <div className="border border-blue-500/50 bg-blue-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-blue-400">Low</h4>
              <p className="text-4xl font-bold text-blue-500">
                {results.vulnerabilities.filter(v => v.status === 'open' && v.severity.toLowerCase() === 'low').length}
              </p>
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
          {sortedVulnerabilities
            .filter((vuln: any) => vuln.status === 'open')
            .map((vuln: any) => {
            const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity);
            return (
              <AccordionItem value={vuln.id} key={vuln.id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
                <div className="flex items-center gap-4 w-full py-4">
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
                  <div className="flex items-center gap-2">
                    <Select value={vuln.status || 'open'} onValueChange={(value) => handleStatusChange(vuln.id, value)}>
                      <SelectTrigger className="w-32 h-8 text-xs">
                        <SelectValue placeholder="Mark as..." />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="open">Open</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                      </SelectContent>
                    </Select>
                    <AccordionTrigger className="hover:no-underline ml-2">
                      <div className="h-8 w-8 p-0 flex items-center justify-center">
                        <ChevronDown className="h-4 w-4" />
                      </div>
                    </AccordionTrigger>
                  </div>
                </div>
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
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation Prompt</h4>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(`Explain the security vulnerability "${vuln.title}" found in the file \`${vuln.file}\` and provide the corrected code snippet to fix it. The vulnerability is described as: "${vuln.description}". The recommended fix is: "${vuln.remediation}"`)}
                        className="h-8 w-8 p-0 hover:bg-primary/10"
                      >
                        <Copy className="h-4 w-4 text-muted-foreground hover:text-primary" />
                      </Button>
                    </div>
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

        {/* Resolved and False Positive Sections */}
        <div className="space-y-6 mt-8">
          {/* Resolved Findings Section */}
          {results.vulnerabilities.filter(v => v.status === 'resolved').length > 0 && (
            <div className="border border-green-500/30 bg-green-500/5 rounded-lg p-4">
              <h4 className="font-semibold text-lg text-green-600 mb-4 flex items-center">
                <CheckCircle className="h-5 w-5 mr-2" />
                Resolved Findings ({results.vulnerabilities.filter(v => v.status === 'resolved').length})
              </h4>
              <div className="space-y-3">
                {results.vulnerabilities
                  .filter(v => v.status === 'resolved')
                  .map((vuln) => (
                    <div key={vuln.id} className="bg-card/50 border border-green-200 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex-grow">
                          <p className="font-medium text-green-700">{vuln.title}</p>
                          <p className="text-sm text-muted-foreground font-mono">
                            {vuln.file}:{vuln.line}
                          </p>
                        </div>
                        <Badge className="bg-green-100 text-green-700 border-green-200">
                          Resolved
                        </Badge>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* False Positive Findings Section */}
          {results.vulnerabilities.filter(v => v.status === 'false_positive').length > 0 && (
            <div className="border border-orange-500/30 bg-orange-500/5 rounded-lg p-4">
              <h4 className="font-semibold text-lg text-orange-600 mb-4 flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2" />
                False Positives ({results.vulnerabilities.filter(v => v.status === 'false_positive').length})
              </h4>
              <div className="space-y-3">
                {results.vulnerabilities
                  .filter(v => v.status === 'false_positive')
                  .map((vuln) => (
                    <div key={vuln.id} className="bg-card/50 border border-orange-200 rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex-grow">
                          <p className="font-medium text-orange-700">{vuln.title}</p>
                          <p className="text-sm text-muted-foreground font-mono">
                            {vuln.file}:{vuln.line}
                          </p>
                        </div>
                        <Badge className="bg-orange-100 text-orange-700 border-orange-200">
                          False Positive
                        </Badge>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
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
  
  // SIMPLE PROGRESS TRACKING
  const [currentStep, setCurrentStep] = useState<string>('Initializing scan...');
  const [currentProgress, setCurrentProgress] = useState<number>(0);
  
  // PERSISTENT AUDIT STATE: Track current audit across page refreshes
  const [currentAudit, setCurrentAudit] = useState<SecurityAudit | null>(null);

  // REAL PROGRESS POLLING - Actually communicate with worker
  const [progressPollingInterval, setProgressPollingInterval] = useState<NodeJS.Timeout | null>(null);
  const [pollingStartTime, setPollingStartTime] = useState<number | null>(null);
  
  // MOST RECENT AUDIT: Display the user's latest completed audit
  const [mostRecentAudit, setMostRecentAudit] = useState<SecurityAudit | null>(null);

  useEffect(() => {
    if (user) {
      fetchRepositories();
      fetchGitHubUsername();
      checkExistingAudit();
      fetchMostRecentAudit();
    }
  }, [user]);

  // REAL PROGRESS POLLING: Poll worker's /progress endpoint for real-time updates
  useEffect(() => {
    if (isScanning && currentAudit?.id) {
      console.log('🚀 STARTING ROBUST PROGRESS POLLING...');
      
      // Add a small delay to allow worker to initialize scan state
      const initialDelay = setTimeout(() => {
        console.log('⏳ Initial delay completed, starting progress polling...');
        setPollingStartTime(Date.now()); // Start tracking polling time
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
              
              // Check if scan completed by checking worker progress status
              if (progressData.status === 'scan_completed') {
                console.log('🎉 SCAN COMPLETED - Worker reports completion!');
          setIsScanning(false);
                
                // Fetch the completed audit results from Firestore
                try {
                  console.log('🔍 Fetching completed audit results from Firestore...');
                  const completedAudit = await FirebaseAuditService.getAuditById(progressData.audit_id);
                  
                  if (completedAudit && completedAudit.scanResults) {
                    console.log('✅ Found completed audit results:', completedAudit.scanResults);
                    setScanResults(completedAudit.scanResults);
                    setCurrentAudit(completedAudit);
                  } else {
                    console.log('⚠️ Audit completed but no results found yet, will retry...');
                    // Set a timeout to retry fetching results
                    setTimeout(async () => {
                      try {
                        const retryAudit = await FirebaseAuditService.getAuditById(progressData.audit_id);
                        if (retryAudit && retryAudit.scanResults) {
                          console.log('✅ Retry successful - found audit results:', retryAudit.scanResults);
                          setScanResults(retryAudit.scanResults);
                          setCurrentAudit(retryAudit);
                        }
                      } catch (retryError) {
                        console.error('❌ Retry failed:', retryError);
                      }
                    }, 2000); // Wait 2 seconds before retry
                  }
                } catch (fetchError) {
                  console.error('❌ Failed to fetch completed audit results:', fetchError);
                }
              } else if (progressData.percentage === 100 && progressData.status === 'scan_running') {
                console.log('📊 Progress at 100% but scan still running - waiting for completion...');
                // Don't stop scanning yet - wait for the worker to mark completion
              }
            } else if (progressData.status === 'no_scan_running') {
              console.log('⚠️ Worker reports no scan running - scan may not have started yet, continuing to poll...');
              console.log('📊 FRONTEND STATE - isScanning:', isScanning, 'currentProgress:', currentProgress, 'currentStep:', currentStep);
              
              // If we were previously scanning and now get "no scan running", the scan might have completed
              if (isScanning && currentProgress > 0) {
                console.log('🎉 SCAN COMPLETED - Worker reports no scan running after progress');
                setIsScanning(false);
                
                // Try to fetch the completed audit results from Firestore
                if (currentAudit?.id) {
                  try {
                    console.log('🔍 Fetching completed audit results after worker completion...');
                    const completedAudit = await FirebaseAuditService.getAuditById(currentAudit.id);
                    
                    if (completedAudit && completedAudit.scanResults) {
                      console.log('✅ Found completed audit results:', completedAudit.scanResults);
                      setScanResults(completedAudit.scanResults);
                      setCurrentAudit(completedAudit);
                    }
                  } catch (fetchError) {
                    console.error('❌ Failed to fetch completed audit results:', fetchError);
                  }
                }
              }
              
              // If we've been polling for too long with no scan running, stop the polling
              if (isScanning && currentProgress === 0 && currentStep === 'Starting scan...') {
                const pollingDuration = Date.now() - (pollingStartTime || Date.now());
                if (pollingDuration > 30000) { // 30 seconds timeout
                  console.log('⏰ TIMEOUT: Been polling for 30+ seconds with no scan progress, stopping...');
                  setIsScanning(false);
                  setCurrentStep('Scan failed to start');
                  setCurrentProgress(0);
                  setPollingStartTime(null);
                }
              }
            } else if (progressData.status === 'wrong_worker') {
              console.log('⚠️ Wrong worker - this worker is not handling the requested audit');
              console.log('📊 WRONG WORKER INFO:', progressData);
              // This worker is not handling the requested audit, try to find the correct one
              // The frontend will automatically retry with the correct worker URL from Firestore
            } else if (progressData.status === 'scan_completed') {
              console.log('🎉 SCAN COMPLETED - Worker reports completion!');
            setIsScanning(false);
              
              // Fetch the completed audit results from Firestore
              try {
                console.log('🔍 Fetching completed audit results from Firestore...');
                const completedAudit = await FirebaseAuditService.getAuditById(progressData.audit_id);
                
                if (completedAudit && completedAudit.scanResults) {
                  console.log('✅ Found completed audit results:', completedAudit.scanResults);
                  setScanResults(completedAudit.scanResults);
                  setCurrentAudit(completedAudit);
                } else {
                  console.log('⚠️ Audit completed but no results found yet, will retry...');
                  // Set a timeout to retry fetching results
                  setTimeout(async () => {
                    try {
                      const retryAudit = await FirebaseAuditService.getAuditById(progressData.audit_id);
                      if (retryAudit && retryAudit.scanResults) {
                        console.log('✅ Retry successful - found audit results:', retryAudit.scanResults);
                        setScanResults(retryAudit.scanResults);
                        setCurrentAudit(retryAudit);
                      }
                    } catch (retryError) {
                      console.error('❌ Retry failed:', retryError);
                    }
                  }, 2000); // Wait 2 seconds before retry
                }
              } catch (fetchError) {
                console.error('❌ Failed to fetch completed audit results:', fetchError);
              }
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

  const fetchMostRecentAudit = async () => {
    try {
      const audits = await FirebaseAuditService.getAuditHistory(user!.uid, 50);
      if (audits && audits.length > 0) {
        // Find the most recent completed audit
        const completedAudits = audits.filter((audit: SecurityAudit) => 
          audit.status === 'completed' && audit.scanResults
        );
        
        if (completedAudits.length > 0) {
          // Sort by creation date and get the most recent
          const mostRecent = completedAudits.sort((a: SecurityAudit, b: SecurityAudit) => 
            new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
          )[0];
          
          setMostRecentAudit(mostRecent);
        }
      }
    } catch (error) {
      console.error('Error fetching most recent audit:', error);
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
          
          {/* SIMPLE PROGRESS BAR */}
          {isScanning && (
             <div className="space-y-3 pt-4">
               <div className="flex justify-between text-sm text-muted-foreground">
                <span className="font-medium">{currentStep}</span>
                <span className="font-mono">{Math.round(currentProgress)}%</span>
               </div>
               <div className="w-full bg-muted rounded-full h-3">
                 <div 
                   className="bg-purple-600 h-3 rounded-full transition-all duration-500 ease-out shadow-sm"
                  style={{ width: `${currentProgress}%` }}
                 />
               </div>
             </div>
           )}
        </CardContent>
      </Card>

      {/* Most Recent Security Report Header */}
      <Card className="border-2 border-primary/20">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center space-x-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span>Most Recent Security Report</span>
          </CardTitle>
          <CardDescription>
            Your latest security audit results and findings
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Most Recent Security Report Content */}
      {mostRecentAudit && mostRecentAudit.scanResults ? (
                    <AuditReportTemplate 
                      currentAudit={mostRecentAudit}
                      results={{
                        repoName: mostRecentAudit.scanResults.repository_info?.name || 'Unknown',
                        summary: {
                          totalIssues: mostRecentAudit.scanResults.summary?.condensed_findings || 0,
                          critical: mostRecentAudit.scanResults.summary?.critical_count || 0,
                          high: mostRecentAudit.scanResults.summary?.high_count || 0,
                          medium: mostRecentAudit.scanResults.summary?.medium_count || 0,
                          low: mostRecentAudit.scanResults.summary?.low_count || 0,
                          resolvedCount: 0 // Will be calculated from findings status
                        },
                    vulnerabilities: mostRecentAudit.scanResults.condensed_findings?.map((finding: any, index: number) => ({
                      id: `finding-${index}`,
                      title: finding.message || 'Security Finding',
                      severity: finding.severity || 'Medium',
                      file: finding.file_path || 'Unknown file',
                      line: finding.line_number || 0,
                      description: finding.description || 'No description available',
                      remediation: finding.remediation || 'Remediation prompt will be generated for this finding type.',
                      occurrences: finding.occurrences || 1,
                      status: 'open' as const
                    })) || []
                  }}
                />
      ) : (
        <Card className="border-2 border-primary/20">
          <CardContent className="text-center py-8">
            <ShieldCheck className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-muted-foreground mb-2">No security reports yet</p>
            <p className="text-sm text-muted-foreground">Run your first security audit to see results here</p>
          </CardContent>
        </Card>
      )}

      {/* Scan Results - Using EXACT Template Format */}
      {scanResults && (
        <AuditReportTemplate 
          currentAudit={currentAudit}
          results={{
            repoName: scanResults.repository_info.name,
            summary: {
              totalIssues: scanResults.summary.condensed_findings,
              critical: scanResults.summary.critical_count,
              high: scanResults.summary.high_count,
              medium: scanResults.summary.medium_count,
              low: scanResults.summary.low_count,
              resolvedCount: 0 // Will be calculated from findings status
            },
            vulnerabilities: scanResults.condensed_findings.map((finding, index) => {
              // Get the remediation prompt from the worker's condensed_remediations
              const remediationPrompt = scanResults.condensed_remediations?.[finding.rule_id] || 
                "Remediation prompt will be generated for this finding type.";
              
              return {
                id: finding.rule_id || `VULN-${1}`,
                title: finding.message,
                severity: finding.severity,
                file: finding.file_path,
                line: finding.line_number,
                description: finding.description,
                remediation: remediationPrompt,
                occurrences: finding.occurrences || 1,
                status: 'open' as const
              };
            })
          }}
        />
      )}
                </div>
  );
}
