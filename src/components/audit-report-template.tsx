import React from 'react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  CheckCircle, 
  Code, 
  Copy 
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface Vulnerability {
  rule_id: string;
  message: string;
  description: string;
  severity: string;
  occurrences: number;
  file_path?: string;
  line_number?: number;
  file?: string;
  line?: number;
  status?: 'open' | 'resolved' | 'false_positive';
}

interface AuditReportTemplateProps {
  vulnerabilities: Vulnerability[];
  condensed_remediations?: { [key: string]: string };
  findingStatuses?: { [key: string]: any };
  onStatusChange?: (findingId: string, newStatus: 'open' | 'resolved' | 'false_positive') => void;
  showStatusDropdown?: boolean;
  isReadOnly?: boolean;
}

const getSeverityStyles = (severity: string, status?: 'open' | 'resolved' | 'false_positive') => {
  // If finding is resolved or false positive, use green styling
  if (status === 'resolved' || status === 'false_positive') {
    return {
      icon: <CheckCircle className="h-5 w-5 text-green-500" />,
      borderColor: 'border-green-500/50',
      bgColor: 'bg-green-500/10',
      textColor: 'text-green-500',
    };
  }
  
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
  
  const normalizedSeverity = normalizeSeverity(severity);
  
  // Use severity-based styling
  switch (normalizedSeverity) {
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
    case 'Low':
      return {
        icon: <CheckCircle className="h-5 w-5 text-blue-500" />,
        borderColor: 'border-blue-500/50',
        bgColor: 'bg-blue-500/10',
        textColor: 'text-blue-500',
      };
    default:
      return {
        icon: <Info className="h-5 w-5 text-yellow-500" />,
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-500/10',
        textColor: 'text-yellow-500',
      };
  }
};

export default function AuditReportTemplate({
  vulnerabilities,
  condensed_remediations = {},
  findingStatuses = {},
  onStatusChange,
  showStatusDropdown = true,
  isReadOnly = false
}: AuditReportTemplateProps) {
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

  // Calculate counts
  const resolvedCount = sortedVulnerabilities.filter(v => 
    findingStatuses[v.rule_id]?.status === 'resolved' || 
    findingStatuses[v.rule_id]?.status === 'false_positive'
  ).length;

  const openFindings = sortedVulnerabilities.filter(v => 
    !findingStatuses[v.rule_id]?.status || 
    findingStatuses[v.rule_id]?.status === 'open'
  );

  const criticalCount = openFindings.filter(v => {
    const normalizedSeverity = (v.severity || 'Medium').trim().toLowerCase();
    return normalizedSeverity.includes('critical');
  }).length;

  const highCount = openFindings.filter(v => {
    const normalizedSeverity = (v.severity || 'Medium').trim().toLowerCase();
    return normalizedSeverity.includes('high');
  }).length;

  const mediumCount = openFindings.filter(v => {
    const normalizedSeverity = (v.severity || 'Medium').trim().toLowerCase();
    return normalizedSeverity.includes('medium');
  }).length;

  const lowCount = openFindings.filter(v => {
    const normalizedSeverity = (v.severity || 'Medium').trim().toLowerCase();
    return normalizedSeverity.includes('low');
  }).length;

  // Calculate health score
  const calculateHealthScore = () => {
    if (openFindings.length === 0) return 100;
    
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

  const healthScore = calculateHealthScore();

  const getHealthColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-yellow-500';
    if (score >= 40) return 'text-orange-500';
    return 'text-red-500';
  };

  return (
    <div className="space-y-4">
      {/* Findings Resolved Card */}
      <div className="border-2 border-green-500/50 bg-green-500/10 rounded-lg p-4 text-center">
        <h4 className="text-sm font-medium text-green-600">Findings Resolved</h4>
        <p className="text-4xl font-bold text-green-600">{resolvedCount}</p>
      </div>
      
      <div className="grid grid-cols-2 gap-4 text-center">
        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
          <h4 className="text-sm font-medium text-muted-foreground">Outstanding Issues</h4>
          <p className="text-4xl font-bold">{openFindings.length}</p>
        </div>
        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
          <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
          <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-2">
          <h4 className="text-sm font-medium text-red-400">Critical</h4>
          <p className="text-2xl font-bold text-red-500">{criticalCount}</p>
        </div>
        <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-2">
          <h4 className="text-sm font-medium text-orange-400">High</h4>
          <p className="text-2xl font-bold text-orange-500">{highCount}</p>
        </div>
        <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-2">
          <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
          <p className="text-2xl font-bold text-yellow-500">{mediumCount}</p>
        </div>
        <div className="border border-blue-500/50 bg-blue-500/10 rounded-lg p-2">
          <h4 className="text-sm font-medium text-blue-400">Low</h4>
          <p className="text-2xl font-bold text-blue-500">{lowCount}</p>
        </div>
      </div>

      {/* Individual Vulnerability Findings */}
      <Accordion type="single" collapsible className="w-full">
        {sortedVulnerabilities.map((vuln) => {
          const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity, findingStatuses[vuln.rule_id]?.status);
          const remediation = condensed_remediations[vuln.rule_id] || "Remediation prompt will be generated for this finding type.";
          
          return (
            <AccordionItem value={vuln.rule_id} key={vuln.rule_id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
              <div className="flex items-center gap-4 w-full py-4">
                {icon}
                <div className="flex-grow text-left">
                  <p className={`font-semibold ${textColor}`} dangerouslySetInnerHTML={{ __html: vuln.message }} />
                  <div className="flex items-center gap-2">
                    <p className="text-sm text-muted-foreground font-mono">
                      {vuln.occurrences > 1 
                        ? `${vuln.occurrences} occurrences`
                        : `${vuln.file_path || vuln.file}:${vuln.line_number || vuln.line}`
                      }
                    </p>
                  </div>
                </div>
                {showStatusDropdown && !isReadOnly && (
                  <div onClick={(e) => e.stopPropagation()}>
                    <Select 
                      value={findingStatuses[vuln.rule_id]?.status || 'open'} 
                      onValueChange={(value) => onStatusChange?.(vuln.rule_id, value as 'open' | 'resolved' | 'false_positive')}
                    >
                      <SelectTrigger className={`w-36 h-10 text-sm ${bgColor} ${borderColor} ${textColor}`}>
                        <SelectValue placeholder="Mark as..." />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="open">Open</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <AccordionTrigger className="hover:no-underline p-0 h-auto [&[data-state=open]>svg]:hidden [&>svg]:hidden">
                  <div className="w-6 h-6" />
                </AccordionTrigger>
              </div>
              <AccordionContent className="pt-2">
                <p className="text-sm text-foreground/80 mb-4" dangerouslySetInnerHTML={{ __html: vuln.description }} />
                <div className="bg-card/50 p-4 rounded-md border border-border">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation Prompt</h4>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(remediation)}
                      className="h-8 w-8 p-0 hover:bg-primary/10"
                    >
                      <Copy className="h-4 w-4 text-muted-foreground hover:text-primary" />
                    </Button>
                  </div>
                  <div className="bg-black/80 rounded-md p-3">
                    <pre className="text-xs text-green-300 whitespace-pre-wrap font-code" dangerouslySetInnerHTML={{ __html: remediation }} />
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
        {sortedVulnerabilities.filter(v => 
          findingStatuses[v.rule_id]?.status === 'resolved'
        ).length > 0 && (
          <div className="border border-green-500/30 bg-green-500/5 rounded-lg p-4">
            <h4 className="font-semibold text-lg text-green-600 mb-4 flex items-center">
              <CheckCircle className="h-5 w-5 mr-2" />
              Resolved Findings ({sortedVulnerabilities.filter(v => 
                findingStatuses[v.rule_id]?.status === 'resolved'
              ).length})
            </h4>
            <div className="space-y-3">
              {sortedVulnerabilities
                .filter(v => findingStatuses[v.rule_id]?.status === 'resolved')
                .map((vuln) => (
                  <div key={vuln.rule_id} className="bg-card/50 border border-green-200 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex-grow">
                        <p className="font-medium text-green-700" dangerouslySetInnerHTML={{ __html: vuln.message }} />
                        <p className="text-sm text-muted-foreground font-mono">
                          {vuln.file_path || vuln.file}:{vuln.line_number || vuln.line}
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
        {sortedVulnerabilities.filter(v => 
          findingStatuses[v.rule_id]?.status === 'false_positive'
        ).length > 0 && (
          <div className="border border-orange-500/30 bg-orange-500/5 rounded-lg p-4">
            <h4 className="font-semibold text-lg text-orange-600 mb-4 flex items-center">
              <CheckCircle className="h-5 w-5 mr-2" />
              False Positives ({sortedVulnerabilities.filter(v => 
                findingStatuses[v.rule_id]?.status === 'false_positive'
              ).length})
            </h4>
            <div className="space-y-3">
              {sortedVulnerabilities
                .filter(v => findingStatuses[v.rule_id]?.status === 'false_positive')
                .map((vuln) => (
                  <div key={vuln.rule_id} className="bg-card/50 border border-orange-200 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex-grow">
                        <p className="font-medium text-orange-700" dangerouslySetInnerHTML={{ __html: vuln.message }} />
                        <p className="text-sm text-muted-foreground font-mono">
                          {vuln.file_path || vuln.file}:{vuln.line_number || vuln.line}
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
    </div>
  );
}
