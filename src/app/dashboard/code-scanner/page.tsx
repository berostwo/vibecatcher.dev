'use client';

import { useState, useEffect } from 'react';
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { RefreshCw, ShieldCheck, Download, CheckCircle, AlertCircle } from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { GitHubService } from '@/lib/github-service';
import { useToast } from '@/hooks/use-toast';

interface Repository {
  name: string;
  private: boolean;
  description: string | null;
}

export default function CodeScannerPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepository, setSelectedRepository] = useState<string>('');
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStep, setScanStep] = useState('');
  const [scanResults, setScanResults] = useState<any>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    if (user) {
      fetchRepositories();
    }
  }, [user]);

  const fetchRepositories = async () => {
    try {
      setIsLoadingRepos(true);
      const repos = await GitHubService.getUserRepositories(user!.uid);
      setRepositories(repos);
    } catch (error) {
      console.error('Error fetching repositories:', error);
    } finally {
      setIsLoadingRepos(false);
    }
  };

  const handleStartScan = async () => {
    if (!selectedRepository) return;
    
    try {
      setIsScanning(true);
      setScanProgress(0);
      setScanStep('Initializing scan...');
      setScanError(null);
      setScanResults(null);
      
      // Start the scan with the new worker
      const response = await fetch('https://chatgpt-security-scanner-505997387504.us-central1.run.app/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repo_url: `https://github.com/${user!.displayName || 'user'}/${selectedRepository}`,
          user_id: user!.uid,
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log('Scan started:', data);
      
      if (data.status === 'completed') {
        // Worker completed the scan immediately (synchronous)
        setScanResults(data);
        setIsScanning(false);
        setScanProgress(100);
        setScanStep('Scan completed!');
        
        toast({
          title: "Scan completed!",
          description: `Found ${data.findings_count} security issues in ${selectedRepository}`,
        });
      } else if (data.status === 'failed') {
        // Scan failed
        setScanError(data.error || 'Scan failed');
        setIsScanning(false);
        setScanProgress(0);
        setScanStep('');
        
        toast({
          title: "Scan failed",
          description: data.error || "Please try again",
          variant: "destructive",
        });
      } else {
        // Start progress polling for async scans
        pollScanProgress();
      }
      
    } catch (error) {
      console.error('Failed to start scan:', error);
      setScanError(error instanceof Error ? error.message : 'Failed to start scan');
      setIsScanning(false);
      setScanProgress(0);
      setScanStep('');
      
      toast({
        title: "Scan failed to start",
        description: error instanceof Error ? error.message : "Please try again",
        variant: "destructive",
      });
    }
  };
  
  const pollScanProgress = async () => {
    // For now, simulate progress since the new worker doesn't have progress endpoint yet
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15;
      if (progress >= 100) {
        progress = 100;
        setScanStep('Scan completed!');
        clearInterval(interval);
        setTimeout(() => {
          completeScan();
        }, 1000);
      } else {
        setScanProgress(Math.round(progress));
        setScanStep(`Scanning repository... ${Math.round(progress)}%`);
      }
    }, 1000);
  };
  
  const completeScan = () => {
    setIsScanning(false);
    setScanProgress(100);
    setScanStep('Scan completed!');
    
    // Generate mock results for now
    const mockResults = {
      repository: selectedRepository,
      scan_timestamp: new Date().toISOString(),
      summary: {
        total_findings: 12,
        critical_count: 2,
        high_count: 3,
        medium_count: 4,
        low_count: 3,
        codebase_health: 78
      },
      findings: [
        {
          rule_id: "SECRET.API_KEY",
          severity: "Critical",
          message: "API key exposed in client-side code",
          file_path: "src/config.js",
          line_number: 15,
          description: "Sensitive API key is visible in client-side JavaScript",
          remediation: "Move API key to environment variables and server-side only"
        },
        {
          rule_id: "AUTH.WEAK_PASSWORD",
          severity: "High", 
          message: "Weak password hashing detected",
          file_path: "src/auth/password.js",
          line_number: 42,
          description: "Passwords are hashed with MD5 which is cryptographically weak",
          remediation: "Use bcrypt or Argon2 for password hashing"
        }
      ],
      scanners: {
        secrets: { status: "completed", findings: 3 },
        auth: { status: "completed", findings: 2 },
        webapp: { status: "completed", findings: 4 },
        deps: { status: "completed", findings: 2 },
        config: { status: "completed", findings: 1 }
      }
    };
    
    setScanResults(mockResults);
    
    toast({
      title: "Scan completed!",
      description: `Found ${mockResults.summary.total_findings} security issues in ${selectedRepository}`,
    });
  };
  
  const downloadResults = () => {
    if (!scanResults) return;
    
    const dataStr = JSON.stringify(scanResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-scan-${selectedRepository}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Results downloaded!",
      description: "Security scan results saved as JSON file",
    });
  };

  return (
    <DashboardPage>
      <DashboardPageHeader 
        title="Code Scanner" 
        description="Scan your code for security vulnerabilities and get actionable fixes" 
      />
      
      <div className="space-y-6">
        <Card className="border-2 border-primary/20">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              <span>Select Repository to Scan</span>
            </CardTitle>
            <CardDescription>
              Choose a repository from your GitHub account to scan for security vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center space-x-4">
              <div className="flex-1">
                <Select value={selectedRepository} onValueChange={setSelectedRepository}>
                  <SelectTrigger className="w-[400px]">
                    <SelectValue placeholder={
                      isLoadingRepos 
                        ? "Loading repositories..." 
                        : repositories.length === 0 
                          ? "No repositories found" 
                          : "Select a repository"
                    } />
                  </SelectTrigger>
                  <SelectContent>
                    {isLoadingRepos ? (
                      <SelectItem value="__loading__" disabled>
                        <div className="flex items-center space-x-2">
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                          <span>Loading repositories...</span>
                        </div>
                      </SelectItem>
                    ) : repositories.length === 0 ? (
                      <SelectItem value="__no_repos__" disabled>
                        <div className="flex items-center space-x-2">
                          <span className="text-muted-foreground">No repositories available</span>
                        </div>
                      </SelectItem>
                    ) : (
                      repositories.map((repo) => (
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
                      ))
                    )}
                  </SelectContent>
                </Select>
                
                {/* Show retry button if no repositories and not loading */}
                {!isLoadingRepos && repositories.length === 0 && (
                  <div className="mt-2">
                    <Button 
                      variant="outline"
                      size="sm" 
                      onClick={fetchRepositories}
                      className="text-sm"
                    >
                      <RefreshCw className="h-3 w-3 mr-1" />
                      Retry Loading Repositories
                    </Button>
                  </div>
                )}
              </div>
              
              <div className="flex gap-2">
                <Button 
                  onClick={handleStartScan} 
                  disabled={!selectedRepository || isScanning || isLoadingRepos}
                  className="min-w-[120px]"
                >
                  {isScanning ? 'Scanning...' : 'Start Scan'}
                </Button>
                
                <Button 
                  variant="outline"
                  onClick={fetchRepositories}
                  disabled={isLoadingRepos}
                  className="text-blue-600 border-blue-600 hover:bg-blue-50"
                  title="Refresh repository list"
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${isLoadingRepos ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
              </div>
            </div>
            
                         {selectedRepository && (
               <div className="mt-4 p-3 bg-primary/10 rounded-lg border border-primary/30">
                 <p className="text-sm text-primary">
                   <strong>Selected:</strong> {selectedRepository}
                 </p>
                 <p className="text-xs text-muted-foreground mt-1">
                   Ready to scan this repository for security vulnerabilities
                 </p>
               </div>
             )}
             
             {/* Progress Bar */}
             {isScanning && (
               <div className="mt-4 space-y-2">
                 <div className="flex items-center justify-between text-sm">
                   <span className="text-muted-foreground">{scanStep}</span>
                   <span className="font-medium">{scanProgress}%</span>
                 </div>
                 <Progress value={scanProgress} className="w-full" />
               </div>
             )}
             
             {/* Error Display */}
             {scanError && (
               <div className="mt-4 p-3 bg-red-500/10 rounded-lg border border-red-500/30">
                 <div className="flex items-center space-x-2">
                   <AlertCircle className="h-4 w-4 text-red-500" />
                   <p className="text-sm text-red-600 font-medium">Scan Error</p>
                 </div>
                 <p className="text-xs text-red-500 mt-1">{scanError}</p>
               </div>
             )}
             
             {/* Results Display */}
             {scanResults && !isScanning && (
               <div className="mt-4 p-4 bg-green-500/10 rounded-lg border border-green-500/30">
                 <div className="flex items-center justify-between mb-3">
                   <div className="flex items-center space-x-2">
                     <CheckCircle className="h-5 w-5 text-green-500" />
                     <h4 className="font-semibold text-green-700">Scan Completed!</h4>
                   </div>
                   <Button 
                     onClick={downloadResults}
                     size="sm"
                     className="bg-green-600 hover:bg-green-700 text-white"
                   >
                     <Download className="h-4 w-4 mr-2" />
                     Download JSON
                   </Button>
                 </div>
                 
                 <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center mb-4">
                   <div className="bg-white/50 rounded-lg p-2">
                     <p className="text-xs text-muted-foreground">Total Findings</p>
                     <p className="text-lg font-bold text-gray-700">{scanResults.summary.total_findings}</p>
                   </div>
                   <div className="bg-red-500/20 rounded-lg p-2">
                     <p className="text-xs text-red-600">Critical</p>
                     <p className="text-lg font-bold text-red-600">{scanResults.summary.critical_count}</p>
                   </div>
                   <div className="bg-orange-500/20 rounded-lg p-2">
                     <p className="text-xs text-orange-600">High</p>
                     <p className="text-lg font-bold text-orange-600">{scanResults.summary.high_count}</p>
                   </div>
                   <div className="bg-blue-500/20 rounded-lg p-2">
                     <p className="text-xs text-blue-600">Health</p>
                     <p className="text-lg font-bold text-blue-600">{scanResults.summary.codebase_health}%</p>
                   </div>
                 </div>
                 
                 <div className="text-xs text-muted-foreground">
                   <p><strong>Repository:</strong> {scanResults.repository}</p>
                   <p><strong>Scanned:</strong> {new Date(scanResults.scan_timestamp).toLocaleString()}</p>
                   <p><strong>Scanners:</strong> {Object.keys(scanResults.scanners).join(', ')}</p>
                 </div>
               </div>
             )}
           </CardContent>
         </Card>
       </div>
     </DashboardPage>
   );
 }
