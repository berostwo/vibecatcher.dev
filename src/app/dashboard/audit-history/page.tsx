'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { FirebaseAuditService, SecurityAudit } from '@/lib/firebase-audit-service';
import { AuditSecurityService } from '@/lib/audit-security';
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Badge, BadgeProps } from '@/components/ui/badge';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  CheckCircle, 
  SquareMenu, 
  Clock, 
  Download, 
  Code,
  Loader2
} from 'lucide-react';

// This will be replaced with real data from Firebase


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


export default function AuditHistoryPage() {
  const { user } = useAuth();
  const [auditHistory, setAuditHistory] = useState<SecurityAudit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
            const aSeverity = a?.severity || 'Medium';
            const bSeverity = b?.severity || 'Medium';
            return (severityOrder[aSeverity as keyof typeof severityOrder] || 4) - (severityOrder[bSeverity as keyof typeof severityOrder] || 4);
          });
          
          // Calculate accurate codebase health score based on actual findings
          const calculateHealthScore = (findings: any[]) => {
            if (findings.length === 0) return 100; // Perfect if no issues
            
            let totalPenalty = 0;
            let maxPossiblePenalty = 0;
            
            findings.forEach(finding => {
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
          
          const healthScore = calculateHealthScore(sortedVulnerabilities);
          
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
                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-center">
                        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-muted-foreground">Total Findings</h4>
                            <p className="text-4xl font-bold">{sortedVulnerabilities.length}</p>
                        </div>
                        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
                            <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                      <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-red-400">Critical</h4>
                        <p className="text-2xl font-bold text-red-500">{summary.critical_count}</p>
                      </div>
                      <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-orange-400">High</h4>
                        <p className="text-2xl font-bold text-orange-500">{summary.high_count}</p>
                      </div>
                      <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
                        <p className="text-2xl font-bold text-yellow-500">{summary.medium_count}</p>
                      </div>
                      <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-green-400">Low</h4>
                        <p className="text-2xl font-bold text-green-500">{summary.low_count}</p>
                      </div>
                    </div>
                    
                    {/* Master Remediation Plan */}
                    {audit.scanResults?.master_remediation && (
                      <div className="mt-4">
                        <Accordion type="single" collapsible className="w-full">
                          <AccordionItem value="master-remediation" className="rounded-lg border border-white/30 bg-card/50 shadow-sm">
                            <AccordionTrigger className="hover:no-underline px-4">
                              <div className="flex items-center gap-3">
                                <ShieldAlert className="h-5 w-5 text-white" />
                                <span className="font-semibold text-lg text-white">Master Remediation Plan</span>
                              </div>
                            </AccordionTrigger>
                            <AccordionContent className="px-4 pb-4">
                              <div className="bg-black/80 rounded-md p-4">
                                <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono leading-relaxed" dangerouslySetInnerHTML={{ __html: audit.scanResults.master_remediation }} />
                              </div>
                            </AccordionContent>
                          </AccordionItem>
                        </Accordion>
                      </div>
                    )}
                    
                    <Accordion type="single" collapsible className="w-full">
                        {sortedVulnerabilities.map((vuln) => {
                            const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity);
                            const remediation = audit.scanResults?.condensed_remediations?.[vuln.rule_id] || 
                              "Remediation prompt will be generated for this finding type.";
                            
                            return (
                            <AccordionItem value={vuln.rule_id} key={vuln.rule_id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
                                <AccordionTrigger className="hover:no-underline">
                                    <div className="flex items-center gap-4 w-full">
                                        {icon}
                                        <div className="flex-grow text-left">
                                            <p className={`font-semibold ${textColor}`} dangerouslySetInnerHTML={{ __html: vuln.message }} />
                                            <p className="text-sm text-muted-foreground font-mono">
                                              {vuln.occurrences > 1 
                                                ? `${vuln.occurrences} occurrences`
                                                : `${vuln.file_path}:${vuln.line_number}`
                                              }
                                            </p>
                                        </div>
                                    </div>
                                </AccordionTrigger>
                                <AccordionContent className="pt-2">
                                    <p className="text-sm text-foreground/80 mb-4" dangerouslySetInnerHTML={{ __html: vuln.description }} />
                                    <div className="bg-card/50 p-4 rounded-md border border-border">
                                        <h4 className="font-semibold mb-2 flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation</h4>
                                        <div className="bg-black/80 rounded-md p-3">
                                            <pre className="text-xs text-green-300 whitespace-pre-wrap font-code" dangerouslySetInnerHTML={{ __html: remediation }} />
                                        </div>
                                    </div>
                                </AccordionContent>
                            </AccordionItem>
                            );
                        })}
                    </Accordion>
                </div>
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
