'use client';

import { useState, useEffect } from 'react';
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

export default function SecurityAuditPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepository, setSelectedRepository] = useState<string>('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResults | null>(null);
  const [userGitHubUsername, setUserGitHubUsername] = useState<string>('');

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

    try {
      // Get GitHub token from user service
      const firebaseUser = await FirebaseUserService.getUserByUid(user!.uid);
      const githubToken = firebaseUser?.githubAccessToken;

      if (!githubToken) {
        throw new Error('GitHub token not found. Please re-authenticate with GitHub.');
      }

      const repositoryUrl = `https://github.com/${userGitHubUsername}/${selectedRepository}`;

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
        </CardContent>
      </Card>

      {/* Scan Results */}
      {scanResults && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Findings</CardTitle>
                <Badge variant="outline">{scanResults.summary.total_findings}</Badge>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{scanResults.summary.total_findings}</div>
                <p className="text-xs text-muted-foreground">
                  {scanResults.summary.files_scanned} files scanned
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
                <Badge className="bg-red-600 text-white">{scanResults.summary.critical_count}</Badge>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">{scanResults.summary.critical_count}</div>
                <p className="text-xs text-muted-foreground">Immediate attention required</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">High Issues</CardTitle>
                <Badge className="bg-orange-600 text-white">{scanResults.summary.high_count}</Badge>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600">{scanResults.summary.high_count}</div>
                <p className="text-xs text-muted-foreground">Address soon</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scan Duration</CardTitle>
                <Badge variant="outline">{Math.round(scanResults.summary.scan_duration)}s</Badge>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{Math.round(scanResults.summary.scan_duration)}s</div>
                <p className="text-xs text-muted-foreground">Analysis completed</p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Results */}
          <Tabs defaultValue="findings" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="findings">Security Findings</TabsTrigger>
              <TabsTrigger value="condensed">Condensed Issues</TabsTrigger>
              <TabsTrigger value="remediation">Master Remediation</TabsTrigger>
              <TabsTrigger value="details">Repository Details</TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>All Security Findings</CardTitle>
                  <CardDescription>
                    Complete list of security vulnerabilities found in your codebase
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scanResults.findings.map((finding, index) => (
                      <div key={index} className="border rounded-lg p-4 space-y-3">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                              <span className="font-mono text-sm text-muted-foreground">
                                {finding.rule_id}
                              </span>
                            </div>
                            <h4 className="font-medium">{finding.message}</h4>
                            <p className="text-sm text-muted-foreground">
                              {finding.description}
                            </p>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center gap-4 text-sm">
                            <span className="font-mono">
                              {renderFileLocation(finding)}
                            </span>
                            <span>Impact: {finding.impact}</span>
                            <span>Likelihood: {finding.likelihood}</span>
                          </div>

                          {finding.cwe_ids.length > 0 && (
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">CWE:</span>
                              {finding.cwe_ids.map((cwe, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {cwe}
                                </Badge>
                              ))}
                            </div>
                          )}

                          {finding.owasp_ids.length > 0 && (
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">OWASP:</span>
                              {finding.owasp_ids.map((owasp, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {owasp}
                                </Badge>
                              ))}
                            </div>
                          )}

                          <div className="bg-muted p-3 rounded-md">
                            <p className="text-sm font-medium mb-2">Code Snippet:</p>
                            <code className="text-xs bg-background p-2 rounded block">
                              {finding.code_snippet}
                            </code>
                          </div>

                          <div className="bg-blue-50 p-3 rounded-md border border-blue-200">
                            <p className="text-sm font-medium mb-2 text-blue-800">Remediation:</p>
                            <p className="text-sm text-blue-700">{finding.remediation}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="condensed" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Condensed Security Issues</CardTitle>
                  <CardDescription>
                    Similar findings grouped together with occurrence counts
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scanResults.condensed_findings.map((finding, index) => (
                      <div key={index} className="border rounded-lg p-4 space-y-3">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                              <Badge variant="outline" className="bg-blue-100 text-blue-800">
                                {finding.occurrences} occurrence{finding.occurrences > 1 ? 's' : ''}
                              </Badge>
                            </div>
                            <h4 className="font-medium">{finding.message}</h4>
                            <p className="text-sm text-muted-foreground">
                              {finding.description}
                            </p>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div className="flex items-center gap-4 text-sm">
                            <span className="font-mono">
                              {renderFileLocation(finding)}
                            </span>
                            <span>Impact: {finding.impact}</span>
                            <span>Likelihood: {finding.likelihood}</span>
                          </div>

                          <div className="bg-blue-50 p-3 rounded-md border border-blue-200">
                            <p className="text-sm font-medium mb-2 text-blue-800">Remediation:</p>
                            <p className="text-sm text-blue-700">{finding.remediation}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="remediation" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Master Remediation Plan</CardTitle>
                  <CardDescription>
                    Comprehensive plan to fix all security issues in order of priority
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-sm max-w-none">
                    <div className="whitespace-pre-wrap bg-muted p-4 rounded-md">
                      {scanResults.master_remediation}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="details" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Repository Information</CardTitle>
                  <CardDescription>
                    Details about the scanned repository
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm font-medium">Repository Name</p>
                      <p className="text-sm text-muted-foreground">{scanResults.repository_info.name}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium">Repository Size</p>
                      <p className="text-sm text-muted-foreground">{scanResults.repository_info.size}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium">Files Scanned</p>
                      <p className="text-sm text-muted-foreground">{scanResults.repository_info.file_count}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium">Scan Duration</p>
                      <p className="text-sm text-muted-foreground">{Math.round(scanResults.scan_duration)} seconds</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
  );
}
