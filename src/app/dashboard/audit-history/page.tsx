'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { FirebaseAuditService, SecurityAudit } from '@/lib/firebase-audit-service';
import { AuditSecurityService } from '@/lib/audit-security';
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Badge, BadgeProps } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import {
  CheckCircle, 
  Clock, 
  Download,
  Loader2,
  SquareMenu
} from 'lucide-react';
import AuditReportTemplate from '@/components/audit-report-template';

// Using shared AuditReportTemplate component


export default function AuditHistoryPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [auditHistory, setAuditHistory] = useState<SecurityAudit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
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

  useEffect(() => {
    if (user) {
      fetchAuditHistory();
    }
  }, [user]);

  const fetchAuditHistory = async () => {
    if (!user) return;
    
    try {
      setLoading(true);
      const audits = await FirebaseAuditService.getAuditHistory(user.uid);
      
      // Sanitize all audit data before setting in state
      const sanitizedAudits = audits.map(audit => AuditSecurityService.sanitizeAuditData(audit)).filter(Boolean);
      
      setAuditHistory(sanitizedAudits);
      setError(null);
    } catch (err) {
      console.error('Error fetching audit history');
      setError('Failed to load audit history');
    } finally {
      setLoading(false);
    }
  };

  const getBadgeVariant = (issues: number): BadgeProps["variant"] => {
    if (issues > 5) return "destructive"
    if (issues > 0) return "secondary"
    return "default"
  }

  const getHealthColor = (score: number) => {
    if (score > 85) return 'text-green-500';
    if (score > 60) return 'text-yellow-500';
    if (score > 40) return 'text-orange-500';
    return 'text-red-500';
  }

  // Handle status change for findings
  const handleStatusChange = async (auditId: string, findingId: string, newStatus: string) => {
    // Validate the status
    if (!['open', 'resolved', 'false_positive'].includes(newStatus)) {
      return;
    }
    
    const validStatus = newStatus as 'open' | 'resolved' | 'false_positive';
    
    try {
      // Generate a hash for the finding content to enable cross-audit learning
      const audit = auditHistory.find(a => a.id === auditId);
      if (!audit) return;
      
      const finding = audit.scanResults?.condensed_findings?.find(f => f.rule_id === findingId);
      if (!finding) return;
      
      const findingContent = `${finding.message}-${finding.description}`;
      const findingHash = btoa(findingContent).slice(0, 16); // Simple hash for demo
      
      // Update the vulnerability status in the backend
      await FirebaseAuditService.updateFindingStatus(
        auditId,
        findingId,
        validStatus,
        audit.userId || 'unknown',
        findingHash
      );
      
      // Update local state
      setAuditHistory(prev => prev.map(a => {
        if (a.id === auditId) {
          let updatedFindingStatuses;
          
          if (validStatus === 'open') {
            // Remove the finding status if it's being set back to 'open'
            const { [findingId]: removed, ...remainingStatuses } = a.findingStatuses || {};
            updatedFindingStatuses = remainingStatuses;
          } else {
            // Add or update the finding status
            updatedFindingStatuses = {
              ...a.findingStatuses,
              [findingId]: {
                status: validStatus,
                timestamp: new Date(),
                userId: a.userId || 'unknown',
                findingHash: btoa(`${validStatus}-${findingId}`).slice(0, 16)
              }
            };
          }
          
          // Recalculate health score using the same logic
          const openFindings = (a.scanResults?.condensed_findings || []).filter(finding => {
            const status = updatedFindingStatuses[finding.rule_id]?.status;
            return !status || status === 'open';
          });
          
          let updatedHealthScore = 100;
          if (openFindings.length > 0) {
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
            updatedHealthScore = Math.max(5, Math.round(100 - penaltyPercentage));
          }
          
          return {
            ...a,
            findingStatuses: updatedFindingStatuses,
            scanResults: a.scanResults ? {
              ...a.scanResults,
              summary: {
                ...a.scanResults.summary,
                codebase_health: updatedHealthScore
              }
            } : a.scanResults
          } as SecurityAudit;
        }
        return a;
      }));
      
      toast({
        title: "Status updated!",
        description: `Finding marked as ${validStatus}`,
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

  const downloadAuditAsJSON = (audit: SecurityAudit) => {
    try {
      // Create a clean audit object for download
      const auditData = {
        id: audit.id,
        repositoryName: audit.repositoryName,
        status: audit.status,
        createdAt: audit.createdAt?.toDate?.() || audit.createdAt,
        completedAt: audit.completedAt?.toDate?.() || audit.completedAt,
        scanResults: audit.scanResults,
        error: audit.error
      };

      // Convert to JSON string
      const jsonString = JSON.stringify(auditData, null, 2);
      
      // Create blob and download
      const blob = new Blob([jsonString], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      
      // Create download link
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-audit-${audit.repositoryName}-${audit.id}.json`;
      
      // Trigger download
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading audit');
      alert('Failed to download audit. Please try again.');
    }
  };




  if (loading) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Audit History" description="Review and track the history of your previous audits." />
        <div className="flex items-center justify-center py-12">
          <div className="flex items-center space-x-2">
            <Loader2 className="h-6 w-6 animate-spin" />
            <span>Loading audit history...</span>
          </div>
        </div>
      </DashboardPage>
    );
  }

  if (error) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Audit History" description="Review and track the history of your previous audits." />
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <p className="text-red-500 mb-4">{error}</p>
            <button 
              onClick={fetchAuditHistory}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              Try Again
            </button>
          </div>
        </div>
      </DashboardPage>
    );
  }

  if (auditHistory.length === 0) {
    return (
      <DashboardPage>
        <DashboardPageHeader title="Audit History" description="Review and track the history of your previous audits." />
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <p className="text-muted-foreground mb-4">No audit history found</p>
            <p className="text-sm text-muted-foreground">
              Run your first security audit to see results here
            </p>
          </div>
        </div>
      </DashboardPage>
    );
  }

  return (
    <DashboardPage>
      <DashboardPageHeader title="Audit History" description="Review and track the history of your previous audits." />
      <Accordion type="single" collapsible className="w-full space-y-4">
        {auditHistory.map((audit) => {
          // Skip audits without scan results
          if (!audit.scanResults) return null;
          
          const summary = audit.scanResults.summary;
          const vulnerabilities = audit.scanResults.condensed_findings || [];
          
          // Sort vulnerabilities by severity (Critical -> High -> Medium -> Low)
          const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
            const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
            // Normalize severity to handle case variations and edge cases
            const normalizeSeverity = (severity: string) => {
              if (!severity) return 'Medium';
              const normalized = severity.trim().toLowerCase();
              if (normalized.includes('critical')) return 'Critical';
              if (normalized.includes('high')) return 'High';
              if (normalized.includes('medium')) return 'Medium';
              if (normalized.includes('low')) return 'Low';
              return 'Medium';
            };
            
            const aSeverity = normalizeSeverity(a?.severity);
            const bSeverity = normalizeSeverity(b?.severity);
            
            return (severityOrder[aSeverity] || 4) - (severityOrder[bSeverity] || 4);
          });
          
          // Calculate accurate codebase health score based on actual findings
          const calculateHealthScore = (findings: any[], findingStatuses?: { [key: string]: any }) => {
            if (findings.length === 0) return 100; // Perfect if no issues
            
            // Filter out resolved and false positive findings
            const openFindings = findings.filter(finding => {
              if (!findingStatuses) return true; // If no statuses, consider all findings open
              const status = findingStatuses[finding.rule_id]?.status;
              return !status || status === 'open';
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
                  penalty = 8; // Critical issues heavily impact health
                  maxPenalty = 8;
                  break;
                case 'High':
                  penalty = 5; // High issues significantly impact health
                  maxPenalty = 5;
                  break;
                case 'Medium':
                  penalty = 3; // Medium issues moderately impact health
                  maxPenalty = 3;
                  break;
                case 'Low':
                  penalty = 1; // Low issues slightly impact health
                  maxPenalty = 1;
                  break;
                default:
                  penalty = 2;
                  maxPenalty = 2;
              }
              
              // Apply penalty based on occurrences (capped at 2x)
              const occurrencePenalty = Math.min(penalty * Math.min(finding?.occurrences || 1, 2), maxPenalty);
              totalPenalty += occurrencePenalty;
              maxPossiblePenalty += maxPenalty;
            });
            
            // Calculate health percentage with more realistic scaling
            const penaltyPercentage = Math.min((totalPenalty / maxPossiblePenalty) * 100, 95); // Cap at 95% penalty
            const healthScore = Math.max(5, Math.round(100 - penaltyPercentage)); // Minimum 5% health
            return healthScore;
          };
          
          const healthScore = calculateHealthScore(sortedVulnerabilities, audit.findingStatuses);
          
          return (
          <AccordionItem
            value={audit.id}
            key={audit.id}
            className="rounded-lg border-2 border-primary/20 bg-card/50 shadow-sm px-4"
          >
            <div className="flex items-center justify-between w-full">
              <AccordionTrigger className="hover:no-underline flex-1">
                <div className="flex items-center gap-4">
                    <SquareMenu className="h-4 w-4 text-primary" />
                    <span className="font-medium">{audit.repositoryName}</span>
                </div>
              </AccordionTrigger>
              <div className="flex items-center gap-4 ml-4">
                <button
                  onClick={() => downloadAuditAsJSON(audit)}
                  className="flex items-center gap-2 px-3 py-1.5 text-xs bg-primary/10 text-primary hover:bg-primary/20 rounded-md transition-colors"
                  title="Download audit as JSON"
                >
                  <Download className="h-3 w-3" />
                  Download
                </button>
                    <div className="hidden sm:flex items-center gap-2 text-muted-foreground">
                        <Clock className="h-4 w-4" />
                        <span>{audit.completedAt ? new Date(audit.completedAt.toDate()).toLocaleDateString() : 'Unknown'}</span>
                    </div>
                </div>
              </div>
            <AccordionContent className="pt-2 pb-4">
              {summary.total_findings > 0 ? (
                <AuditReportTemplate
                  vulnerabilities={sortedVulnerabilities}
                  condensed_remediations={audit.scanResults?.condensed_remediations || {}}
                  findingStatuses={audit.findingStatuses || {}}
                  onStatusChange={(findingId, newStatus) => handleStatusChange(audit.id, findingId, newStatus)}
                />
                    


                    

                    

                    

              ) : (
                <div className="flex flex-col items-center justify-center text-center text-muted-foreground p-8">
                    <CheckCircle className="w-12 h-12 text-green-500 mb-4" />
                    <h3 className="text-lg font-semibold text-foreground">No Issues Found</h3>
                    <p>Excellent! This repository passed the security audit.</p>
                </div>
              )}
              

            </AccordionContent>
          </AccordionItem>
        )})}
      </Accordion>
    </DashboardPage>
  )
}
