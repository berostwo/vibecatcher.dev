'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { GitHubService } from '@/lib/github-service';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { ErrorBoundary } from '@/components/error-boundary';

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
}

interface ScanResults {
  findings: SecurityFinding[];
  errors: any[];
  paths_scanned: string[];
  paths_skipped: string[];
  scan_results: any;
  processed_results?: any;
  scan_duration: number;
  timestamp: string;
  error?: string;
  error_type?: string;
}

// Helper function to extract severity breakdown from findings
const getSeverityBreakdown = (findings: SecurityFinding[]) => {
  const breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
  
  findings.forEach(finding => {
    const severity = finding.severity.toLowerCase();
    if (severity === 'critical') breakdown.critical++;
    else if (severity === 'high') breakdown.high++;
    else if (severity === 'medium') breakdown.medium++;
    else if (severity === 'low') breakdown.low++;
  });
  
  return breakdown;
};

// Helper function to map Semgrep severity to our format
const mapSemgrepSeverity = (semgrepSeverity: string): string => {
  const severity = semgrepSeverity.toLowerCase();
  if (severity === 'error') return 'critical';
  if (severity === 'warning') return 'high';
  if (severity === 'info') return 'medium';
  return 'low';
};

// Helper function to process Semgrep findings into our format
const processSemgrepFindings = (semgrepResults: any): SecurityFinding[] => {
  if (!semgrepResults || !Array.isArray(semgrepResults)) return [];
  
  return semgrepResults.map((result: any) => {
    // Safely extract location information
    const startLine = result.start?.line || 0;
    const endLine = result.end?.line || startLine;
    const filePath = result.path || 'unknown-file';
    
    // Safely extract metadata
    const metadata = result.extra?.metadata || {};
    const cweIds = Array.isArray(metadata.cwe) ? metadata.cwe : [];
    const owaspIds = Array.isArray(metadata.owasp) ? metadata.owasp : [];
    
    return {
      rule_id: result.check_id || 'unknown-rule',
      severity: mapSemgrepSeverity(result.extra?.severity || 'info'),
      message: result.extra?.message || 'Security issue detected',
      description: result.extra?.description || 'No description available',
      file_path: filePath,
      line_number: startLine,
      end_line: endLine,
      code_snippet: result.extra?.lines || 'No code available',
      cwe_ids: cweIds,
      owasp_ids: owaspIds,
      impact: metadata.impact || 'Unknown',
      likelihood: metadata.likelihood || 'Unknown',
      confidence: metadata.confidence || 'Unknown'
    };
  });
};

// Helper function to safely render file paths and line numbers
const renderFileLocation = (finding: SecurityFinding) => {
  const filePath = finding.file_path || 'unknown-file';
  const startLine = finding.line_number || 0;
  const endLine = finding.end_line || startLine;
  
  if (endLine !== startLine) {
    return `📁 ${filePath}:${startLine}-${endLine}`;
  } else {
    return `📁 ${filePath}:${startLine}`;
  }
};

// Helper function to safely render arrays
const renderArray = (items: any[], fallback: string = 'None') => {
  if (!Array.isArray(items) || items.length === 0) {
    return fallback;
  }
  return items.join(', ');
};

const getSeverityColor = (severity: string) => {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-600 text-white';
    case 'high': return 'bg-orange-600 text-white';
    case 'medium': return 'bg-yellow-600 text-white';
    case 'low': return 'bg-blue-600 text-white';
    default: return 'bg-gray-600 text-white';
  }
};

// Enhanced data validation function
const validateScanResults = (results: any): ScanResults | null => {
  try {
    if (!results || typeof results !== 'object') {
      console.warn('Invalid scan results format:', results);
      return null;
    }

    // Ensure findings is always an array
    const findings = Array.isArray(results.findings) ? results.findings : [];
    
    // Ensure errors is always an array
    const errors = Array.isArray(results.errors) ? results.errors : [];
    
    // Ensure paths are always arrays
    const paths_scanned = Array.isArray(results.paths_scanned) ? results.paths_scanned : [];
    const paths_skipped = Array.isArray(results.paths_skipped) ? results.paths_skipped : [];
    
    // Ensure scan_results exists
    const scan_results = results.scan_results || results;
    
    // Ensure numeric values
    const scan_duration = typeof results.scan_duration === 'number' ? results.scan_duration : 0;
    const timestamp = results.timestamp || new Date().toISOString();

    return {
      findings,
      errors,
      paths_scanned,
      paths_skipped,
      scan_results,
      processed_results: results.processed_results,
      scan_duration,
      timestamp,
      error: results.error,
      error_type: results.error_type
    };
  } catch (error) {
    console.error('Error validating scan results:', error);
    return null;
  }
};

// Safe rendering component for findings
const SafeFindingDisplay = ({ finding }: { finding: SecurityFinding }) => {
  try {
    return (
      <div className="border rounded-lg p-4 space-y-3">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge className={getSeverityColor(finding.severity)}>
                {String(finding.severity || 'Unknown')}
              </Badge>
              <span className="font-mono text-sm text-muted-foreground">
                {String(finding.rule_id || 'unknown-rule')}
              </span>
            </div>
            <h4 className="font-medium">{String(finding.message || 'No message')}</h4>
            <p className="text-sm text-muted-foreground">
              {String(finding.description || 'No description')}
            </p>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-4 text-sm">
            <span className="font-mono">
              {renderFileLocation(finding)}
            </span>
            {finding.impact && finding.impact !== 'Unknown' && (
              <span>Impact: {String(finding.impact)}</span>
            )}
            {finding.likelihood && finding.likelihood !== 'Unknown' && (
              <span>Likelihood: {String(finding.likelihood)}</span>
            )}
          </div>

          {Array.isArray(finding.cwe_ids) && finding.cwe_ids.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">CWE:</span>
              {finding.cwe_ids.map((cwe, i) => (
                <Badge key={i} variant="outline" className="text-xs">
                  {String(cwe || 'Unknown')}
                </Badge>
              ))}
            </div>
          )}

          {Array.isArray(finding.owasp_ids) && finding.owasp_ids.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">OWASP:</span>
              {finding.owasp_ids.map((owasp, i) => (
                <Badge key={i} variant="outline" className="text-xs">
                  {String(owasp || 'Unknown')}
                </Badge>
              ))}
            </div>
          )}

          {finding.code_snippet && finding.code_snippet !== 'No code available' && (
            <div className="bg-gray-50 p-3 rounded border">
              <pre className="text-sm font-mono text-gray-800 whitespace-pre-wrap">
                {String(finding.code_snippet)}
              </pre>
            </div>
          )}
        </div>
      </div>
    );
  } catch (error) {
    console.error('Error rendering finding:', error, finding);
    return (
      <div className="border rounded-lg p-4 bg-red-50">
        <p className="text-red-800">Error rendering security finding. Check console for details.</p>
      </div>
    );
  }
};

export default function SecurityAuditPage() {
  const { user, githubToken } = useAuth();
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const { toast } = useToast();

  // Fetch user's repositories
  useEffect(() => {
    const fetchRepositories = async () => {
      if (!user || !githubToken) {
        setError("Please sign in with GitHub to access your repositories");
        return;
      }
      
      setIsLoadingRepos(true);
      setError(null);
      
      try {
        const repos = await GitHubService.getUserRepositories(user.uid);
        setRepositories(repos);
      } catch (err) {
        console.error('Error fetching repositories:', err);
        setError(err instanceof Error ? err.message : 'Failed to fetch repositories');
      } finally {
        setIsLoadingRepos(false);
      }
    };

    fetchRepositories();
  }, [user, githubToken]);

  const handleAudit = async () => {
    if (!selectedRepo || !user) return;
    
    setIsLoading(true);
    setError(null);
    setScanResults(null);
    
    try {
      const response = await fetch(process.env.NEXT_PUBLIC_SECURITY_WORKER_URL!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository_url: `https://github.com/${user.displayName}/${selectedRepo}`,
          github_token: githubToken
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Audit failed: ${response.status} - ${errorText}`);
      }

      const results = await response.json();
      
      // Validate response structure
      if (!results || typeof results !== 'object') {
        throw new Error('Invalid response format from worker');
      }
      
      // Check if it's an error response
      if (results.error) {
        setScanResults(results); // Show error in results
        toast({
          title: "Scan completed with errors",
          description: results.error,
          variant: "destructive",
        });
        return;
      }
      
      // Process the new worker response format
      const processedResults: ScanResults = {
        findings: processSemgrepFindings(results.findings || []),
        errors: results.errors || [],
        paths_scanned: results.paths_scanned || [],
        paths_skipped: results.paths_skipped || [],
        scan_results: results.scan_results || results,
        processed_results: results.processed_results,
        scan_duration: results.scan_duration || 0,
        timestamp: results.timestamp || new Date().toISOString()
      };
      
      // Validate the processed results
      const validatedResults = validateScanResults(processedResults);
      if (!validatedResults) {
        throw new Error('Failed to validate scan results format');
      }
      
      setScanResults(validatedResults);
      
      const totalFindings = validatedResults.findings.length;
      const filesScanned = validatedResults.paths_scanned.length;
      
      toast({
        title: "Security scan completed!",
        description: `Found ${totalFindings} security issues in ${filesScanned} files.`,
      });
      
    } catch (error: unknown) {
      console.error('Audit failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Audit failed with unknown error';
      setError(errorMessage);
      
      toast({
        title: "Audit failed",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Audit</h1>
        <p className="text-muted-foreground">
          Comprehensive security analysis of your repository using enterprise-grade Semgrep rules.
        </p>
      </div>

      {/* Repository Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Repository</CardTitle>
          <CardDescription>
            Choose a repository to scan for security vulnerabilities
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Select onValueChange={setSelectedRepo} value={selectedRepo || undefined}>
            <SelectTrigger>
              <SelectValue placeholder="Select a repository" />
            </SelectTrigger>
            <SelectContent>
              {repositories.map((repo) => (
                <SelectItem key={repo.name} value={repo.name}>
                  <div className="flex items-center gap-2">
                    <span>{repo.name}</span>
                    {repo.private && <Badge variant="secondary">Private</Badge>}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button 
            onClick={handleAudit} 
            disabled={!selectedRepo || isLoading || isLoadingRepos}
            className="w-full"
          >
            {isLoading ? 'Scanning...' : 'Run Security Scan'}
          </Button>

          {error && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-red-800">{error}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Results */}
      {scanResults && (
        <div className="space-y-6">
          {/* Error Boundary Wrapper */}
          <ErrorBoundary>
            {/* Summary */}
            <Card>
              <CardHeader>
                <CardTitle>Scan Summary</CardTitle>
                <CardDescription>
                  Overview of security findings and scan statistics
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-600">
                      {Array.isArray(scanResults.findings) ? scanResults.findings.length : 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Total Issues</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {Array.isArray(scanResults.paths_scanned) ? scanResults.paths_scanned.length : 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Files Scanned</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {scanResults.scan_results?.paths?.scanned && Array.isArray(scanResults.scan_results.paths.scanned) ? scanResults.scan_results.paths.scanned.length : 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Files Processed</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-purple-600">
                      {typeof scanResults.scan_duration === 'number' ? scanResults.scan_duration.toFixed(1) : '0'}s
                    </div>
                    <div className="text-sm text-muted-foreground">Scan Duration</div>
                  </div>
                </div>

                <Separator className="my-4" />

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center">
                    <div className="text-xl font-bold text-red-600">
                      {getSeverityBreakdown(Array.isArray(scanResults.findings) ? scanResults.findings : []).critical}
                    </div>
                    <div className="text-sm text-muted-foreground">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold text-orange-600">
                      {getSeverityBreakdown(Array.isArray(scanResults.findings) ? scanResults.findings : []).high}
                    </div>
                    <div className="text-sm text-muted-foreground">High</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold text-yellow-600">
                      {getSeverityBreakdown(Array.isArray(scanResults.findings) ? scanResults.findings : []).medium}
                    </div>
                    <div className="text-sm text-muted-foreground">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className="text-xl font-bold text-blue-600">
                      {getSeverityBreakdown(Array.isArray(scanResults.findings) ? scanResults.findings : []).low}
                    </div>
                    <div className="text-sm text-muted-foreground">Low</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </ErrorBoundary>

          {/* Security Findings */}
          <ErrorBoundary>
            {Array.isArray(scanResults.findings) && scanResults.findings.length > 0 ? (
              <Card>
                <CardHeader>
                  <CardTitle>Security Findings</CardTitle>
                  <CardDescription>
                    Detailed list of security vulnerabilities found in your codebase
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scanResults.findings.map((finding, index) => (
                      <SafeFindingDisplay key={index} finding={finding} />
                    ))}
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardHeader>
                  <CardTitle>No Security Issues Found</CardTitle>
                  <CardDescription>
                    Great news! No security vulnerabilities were detected in your codebase.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground">
                    This could mean your code is secure, or you may want to review the scan configuration 
                    to ensure all relevant security rules were applied.
                  </p>
                </CardContent>
              </Card>
            )}
          </ErrorBoundary>

          {/* Raw Semgrep Output */}
          <ErrorBoundary>
            {scanResults.scan_results && (
              <Card>
                <CardHeader>
                  <CardTitle>Raw Semgrep Output</CardTitle>
                  <CardDescription>
                    Complete raw output from Semgrep for debugging and analysis
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="bg-gray-50 p-4 rounded border">
                    <pre className="text-sm font-mono text-gray-800 whitespace-pre-wrap overflow-auto max-h-96">
                      {JSON.stringify(scanResults.scan_results, null, 2)}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            )}
          </ErrorBoundary>

          {/* Scan Errors */}
          <ErrorBoundary>
            {scanResults.errors && scanResults.errors.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Scan Errors and Warnings</CardTitle>
                  <CardDescription>
                    Issues encountered during the security scan
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {scanResults.errors.map((error, index) => {
                      // Safely extract error information
                      const errorType = typeof error.type === 'string' ? error.type : 'Error';
                      const errorMessage = typeof error.message === 'string' ? error.message : JSON.stringify(error);
                      const errorPath = typeof error.path === 'string' ? error.path : null;
                      
                      return (
                        <div key={index} className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                          <div className="flex items-start gap-2">
                            <span className="text-yellow-600">⚠️</span>
                            <div className="flex-1">
                              <p className="text-sm font-medium text-yellow-800">
                                {errorType}
                              </p>
                              <p className="text-sm text-yellow-700">
                                {errorMessage}
                              </p>
                              {errorPath && (
                                <p className="text-xs text-yellow-600 mt-1">
                                  File: {errorPath}
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </ErrorBoundary>

          {/* Scan Statistics */}
          <ErrorBoundary>
            <Card>
              <CardHeader>
                <CardTitle>Scan Statistics</CardTitle>
                <CardDescription>
                  Detailed information about the scan execution
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className="text-center">
                    <div className="text-lg font-semibold text-blue-600">
                      {Array.isArray(scanResults.paths_scanned) ? scanResults.paths_scanned.length : 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Files Scanned</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-semibold text-orange-600">
                      {Array.isArray(scanResults.paths_skipped) ? scanResults.paths_skipped.length : 0}
                    </div>
                    <div className="text-sm text-muted-foreground">Files Skipped</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-semibold text-green-600">
                      {typeof scanResults.scan_duration === 'number' ? scanResults.scan_duration.toFixed(1) : '0'}s
                    </div>
                    <div className="text-sm text-muted-foreground">Total Time</div>
                  </div>
                </div>
                
                {typeof scanResults.timestamp === 'string' && scanResults.timestamp && (
                  <div className="mt-4 pt-4 border-t">
                    <p className="text-sm text-muted-foreground text-center">
                      Scan completed at: {new Date(scanResults.timestamp).toLocaleString()}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </ErrorBoundary>

          {/* Debug Info - Show if there are issues */}
          <ErrorBoundary>
            {scanResults.error && (
              <Card>
                <CardHeader>
                  <CardTitle>Scan Error</CardTitle>
                  <CardDescription>
                    There was an error during the security scan
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                    <p className="text-red-800 font-medium">Error: {String(scanResults.error)}</p>
                    {scanResults.error_type && (
                      <p className="text-red-700 text-sm mt-1">Type: {String(scanResults.error_type)}</p>
                    )}
                    {typeof scanResults.scan_duration === 'number' && (
                      <p className="text-red-700 text-sm mt-1">Failed after: {scanResults.scan_duration}s</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </ErrorBoundary>

          {/* Raw Response Debug */}
          <ErrorBoundary>
            <Card>
              <CardHeader>
                <CardTitle>Raw Response Debug</CardTitle>
                <CardDescription>
                  Complete response from worker for debugging
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-gray-50 p-4 rounded border">
                  <pre className="text-sm font-mono text-gray-800 whitespace-pre-wrap overflow-auto max-h-96">
                    {JSON.stringify(scanResults, null, 2)}
                  </pre>
                </div>
              </CardContent>
            </Card>
          </ErrorBoundary>
        </div>
      )}
    </div>
  );
}
