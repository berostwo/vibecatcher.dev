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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, ShieldCheck, RefreshCw } from 'lucide-react';
import React from 'react';
import AuditReportTemplate from '@/components/audit-report-template';

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

// Shared AuditReportTemplate component is now imported from @/components/audit-report-template

// Old template component removed - now using shared AuditReportTemplate

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

  // Handle status changes for most recent audit
  const handleMostRecentStatusChange = async (findingId: string, newStatus: 'open' | 'resolved' | 'false_positive') => {
    if (!mostRecentAudit?.id) return;
    
    try {
      // Generate a hash for the finding content
      const finding = mostRecentAudit.scanResults?.condensed_findings?.find(f => f.rule_id === findingId);
      if (!finding) return;
      
      const findingContent = `${finding.message}-${finding.description}`;
      const findingHash = btoa(findingContent).slice(0, 16);
      
      // Update backend
      await FirebaseAuditService.updateFindingStatus(
        mostRecentAudit.id,
        findingId,
        newStatus,
        mostRecentAudit.userId || 'unknown',
        findingHash
      );
      
      // Update local state
      setMostRecentAudit(prev => prev ? {
        ...prev,
        findingStatuses: {
          ...prev.findingStatuses,
          [findingId]: {
            status: newStatus,
            timestamp: new Date(),
            userId: prev.userId || 'unknown',
            findingHash: findingHash
          }
        },
        scanResults: prev.scanResults ? {
          ...prev.scanResults,
          summary: {
            ...prev.scanResults.summary,
            codebase_health: calculateUpdatedHealthScore(prev.scanResults.condensed_findings, findingId, newStatus)
          }
        } : prev.scanResults
      } : null);
      
      toast({
        title: "Status updated!",
        description: `Finding marked as ${newStatus}`,
        duration: 2000,
      });
      
    } catch (error) {
      console.error('Failed to update finding status:', error);
      toast({
        title: "Update failed",
        description: "Failed to update finding status",
        variant: "destructive",
        duration: 3000,
      });
    }
  };
  
  // Calculate updated health score when a finding status changes
  const calculateUpdatedHealthScore = (findings: any[], findingId: string, newStatus: 'open' | 'resolved' | 'false_positive') => {
    // Create a temporary status map for this calculation
    const tempStatuses: { [key: string]: string } = {};
    tempStatuses[findingId] = newStatus;
    
    // Filter out resolved and false positive findings
    const openFindings = findings.filter(finding => {
      const status = tempStatuses[finding.rule_id] || finding.status || 'open';
      return status === 'open';
    });
    
    if (openFindings.length === 0) return 100; // All findings resolved
    
    let totalPenalty = 0;
    let maxPossiblePenalty = 0;
    
    openFindings.forEach(finding => {
      const severity = finding?.severity || 'Medium';
      let penalty = 0;
      let maxPenalty = 0;
      
      switch (severity) {
        case 'Critical':
          penalty = 8;
          maxPenalty = 8;
          break;
        case 'High':
          penalty = 5;
          maxPenalty = 5;
          break;
        case 'Medium':
          penalty = 3;
          maxPenalty = 3;
          break;
        case 'Low':
          penalty = 1;
          maxPenalty = 1;
          break;
        default:
          penalty = 2;
          maxPenalty = 2;
      }
      
      const occurrencePenalty = Math.min(penalty * Math.min(finding?.occurrences || 1, 2), maxPenalty);
      totalPenalty += occurrencePenalty;
      maxPossiblePenalty += maxPenalty;
    });
    
    const penaltyPercentage = Math.min((totalPenalty / maxPossiblePenalty) * 100, 95);
    return Math.max(5, Math.round(100 - penaltyPercentage));
  };
  
  // Handle status changes for scan results
  const handleScanResultsStatusChange = async (findingId: string, newStatus: 'open' | 'resolved' | 'false_positive') => {
    if (!currentAudit?.id || !scanResults) return;
    
    try {
      // Generate a hash for the finding content
      const finding = scanResults.condensed_findings.find(f => f.rule_id === findingId);
      if (!finding) return;
      
      const findingContent = `${finding.message}-${finding.description}`;
      const findingHash = btoa(findingContent).slice(0, 16);
      
      // Update backend
      await FirebaseAuditService.updateFindingStatus(
        currentAudit.id,
        findingId,
        newStatus,
        currentAudit.userId || 'unknown',
        findingHash
      );
      
      // Update local state
      setScanResults(prev => prev ? {
        ...prev,
        condensed_findings: prev.condensed_findings.map(f => 
          f.rule_id === findingId ? { ...f, status: newStatus } : f
        ),
        summary: {
          ...prev.summary,
          codebase_health: calculateUpdatedHealthScore(prev.condensed_findings, findingId, newStatus)
        }
      } : null);
      
      toast({
        title: "Status updated!",
        description: `Finding marked as ${newStatus}`,
        duration: 2000,
      });
      
    } catch (error) {
      console.error('Failed to update finding status:', error);
      toast({
        title: "Update failed",
        description: "Failed to update finding status",
        variant: "destructive",
        duration: 3000,
      });
    }
  };
  
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

  const handleResetAllAudits = async () => {
    if (!user) {
      toast({
        title: 'Error',
        description: 'User not logged in.',
        variant: 'destructive',
      });
      return;
    }

    try {
      const audits = await FirebaseAuditService.getAuditHistory(user.uid, 100); // Get all audits for the user
      const failedAudits = audits.filter((audit: SecurityAudit) => audit.status === 'failed');

      if (failedAudits.length === 0) {
        toast({
          title: 'No Failed Audits',
          description: 'No failed audits found to reset.',
        });
        return;
      }

      const confirmed = confirm(`Are you sure you want to reset ${failedAudits.length} failed audits? This action cannot be undone.`);

      if (confirmed) {
        for (const audit of failedAudits) {
          await FirebaseAuditService.updateAuditStatus(
            audit.id,
            'pending', // Reset to pending state
            undefined,
            'Manual reset'
          );
          toast({
            title: 'Resetting Audit',
            description: `Resetting audit: ${audit.repositoryName}`,
          });
        }
        toast({
          title: 'Audits Reset',
          description: `Successfully reset ${failedAudits.length} failed audits.`,
        });
      }
    } catch (error) {
      console.error('Failed to reset all failed audits:', error);
      toast({
        title: 'Reset Failed',
        description: 'Failed to reset failed audits.',
        variant: 'destructive',
      });
    }
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
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold">Select Repository</h2>
          {/* 🚀 PRODUCTION-READY: Manual cleanup button for stuck audits */}
          <Button
            variant="outline"
            size="sm"
            onClick={handleResetAllAudits}
            className="text-orange-600 border-orange-600 hover:bg-orange-50"
            title="Reset all stuck audits if you're experiencing issues"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Reset All Audits
          </Button>
        </div>
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
          vulnerabilities={mostRecentAudit.scanResults.condensed_findings || []}
          condensed_remediations={mostRecentAudit.scanResults.condensed_remediations || {}}
          findingStatuses={mostRecentAudit.findingStatuses || {}}
          onStatusChange={handleMostRecentStatusChange}
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

      {/* Scan Results - Using Shared Template Format */}
      {scanResults && (
        <AuditReportTemplate 
          vulnerabilities={scanResults.condensed_findings || []}
          condensed_remediations={scanResults.condensed_remediations || {}}
          findingStatuses={currentAudit?.findingStatuses || {}}
          onStatusChange={handleScanResultsStatusChange}
        />
      )}
                </div>
  );
}
