'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ShieldCheck, Github, RefreshCw, AlertCircle, CheckCircle, AlertTriangle } from 'lucide-react';
import { GitHubService, GitHubRepository } from '@/lib/github-service';
import { useGitHubAuth } from '@/contexts/github-auth-context';
import { FirebaseUserService } from '@/lib/firebase-user-service';

// Mock audit results data (replace with real audit logic later)
const mockAuditResultsData = {
  critical: 2,
  high: 5,
  medium: 8,
  low: 12,
  total: 27,
  score: 78,
  recommendations: [
    'Update dependencies to latest versions',
    'Implement proper input validation',
    'Add rate limiting to API endpoints',
    'Enable security headers',
    'Review authentication flow'
  ]
};

export default function SecurityAuditPage() {
  const { user, forceGitHubReauth } = useGitHubAuth();
  const [repositories, setRepositories] = useState<GitHubRepository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [isLoadingRepos, setIsLoadingRepos] = useState(false);
  const [isWaitingForToken, setIsWaitingForToken] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuditing, setIsAuditing] = useState(false);

  // Load user data on component mount
  useEffect(() => {
    if (user) {
      // Check if GitHub token is available before loading repositories
      checkTokenAndLoadRepositories();
    }
  }, [user]);

  const checkTokenAndLoadRepositories = async () => {
    if (!user?.firebaseUser) return;
    
    setIsWaitingForToken(true);
    
    try {
      // First check if token is available
      const token = await GitHubService.getAuthToken(user.firebaseUser.uid);
      if (token) {
        console.log('GitHub token available, loading repositories...');
        setIsWaitingForToken(false);
        loadRepositories();
      } else {
        console.log('GitHub token not available, checking if user needs to re-authenticate...');
        
        // Check if this is a returning user who never had a token stored
        const userData = await FirebaseUserService.getUserByUid(user.firebaseUser.uid);
        if (userData && !userData.githubAccessToken) {
          console.log('User has no stored GitHub token - forcing re-authentication');
          setIsWaitingForToken(false);
          setError('GitHub authentication required. Please sign out and sign in again to access repositories.');
          return;
        }
        
        // If user has a token but it's invalid, wait a bit and try again
        console.log('GitHub token not yet available, waiting...');
        setTimeout(() => {
          checkTokenAndLoadRepositories();
        }, 1000);
      }
    } catch (error) {
      console.error('Error checking token availability:', error);
      setIsWaitingForToken(false);
      setError('Failed to check GitHub authentication. Please try again.');
    }
  };

  const loadRepositories = async () => {
    if (!user) return;
    
    setIsLoadingRepos(true);
    setError(null);
    
    try {
      // Test connection first
      const isConnected = await GitHubService.testConnection(user.firebaseUser.uid);
      if (!isConnected) {
        setError('GitHub connection failed. Please check your authentication.');
        return;
      }
      
      // Fetch repositories
      const repos = await GitHubService.getUserRepositories(user.firebaseUser.uid);
      setRepositories(repos);
      
      if (repos.length === 0) {
        setError('No repositories found. Make sure you have access to repositories on GitHub.');
      }
    } catch (error: any) {
      console.error('Error loading repositories:', error);
      setError(error.message || 'Failed to load repositories');
    } finally {
      setIsLoadingRepos(false);
    }
  };

  const handleRetryConnection = () => {
    loadRepositories();
  };

  const handleReauthenticate = async () => {
    try {
      await forceGitHubReauth();
      // This will redirect to sign-in page
    } catch (error) {
      console.error('Re-authentication failed:', error);
      setError('Re-authentication failed. Please try signing out and back in.');
    }
  };

  const handleStartAudit = async () => {
    if (!selectedRepo) return;
    
    setIsAuditing(true);
    try {
      // Mock audit process (replace with real audit logic)
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Redirect to results or show results
      console.log('Audit completed for:', selectedRepo);
    } catch (error) {
      console.error('Audit failed:', error);
      setError('Audit failed. Please try again.');
    } finally {
      setIsAuditing(false);
    }
  };

  const handleManualTokenCheck = async () => {
    if (!user) return;
    
    setIsWaitingForToken(true);
    setError(null);
    
    try {
      console.log('Manual token check initiated...');
      
              // Check if user has any token data in Firestore
        const userData = await FirebaseUserService.getUserByUid(user.firebaseUser.uid);
      console.log('User data from Firestore:', userData);
      
      if (!userData || !userData.githubAccessToken) {
        setError('No GitHub token found. You need to sign out and sign in again to get a fresh token.');
        setIsWaitingForToken(false);
        return;
      }
      
      // Try to get the token
      const token = await GitHubService.getAuthToken(user.firebaseUser.uid);
      if (token) {
        console.log('Token found, testing with GitHub API...');
        const isValid = await GitHubService.testConnection(user.firebaseUser.uid);
        
        if (isValid) {
          console.log('Token is valid, loading repositories...');
          setIsWaitingForToken(false);
          loadRepositories();
        } else {
          setError('GitHub token is invalid. Please sign out and sign in again.');
          setIsWaitingForToken(false);
        }
      } else {
        setError('Failed to retrieve GitHub token. Please sign out and sign in again.');
        setIsWaitingForToken(false);
      }
    } catch (error) {
      console.error('Manual token check failed:', error);
      setError('Token check failed. Please sign out and sign in again.');
      setIsWaitingForToken(false);
    }
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Security Audit</h1>
        <p className="text-muted-foreground">
          Select a repository to perform a comprehensive security analysis
        </p>
      </div>

      {/* Repository Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Github className="h-5 w-5" />
            Select Repository
          </CardTitle>
          <CardDescription>
            Choose a repository from your GitHub account to audit
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive" className="mb-6">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Authentication Error</AlertTitle>
              <AlertDescription className="mt-2">
                {error}
                <div className="mt-3">
                  <Button 
                    onClick={handleReauthenticate} 
                    variant="outline" 
                    size="sm"
                    className="mr-2"
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Re-authenticate with GitHub
                  </Button>
                  <Button 
                    onClick={() => setError(null)} 
                    variant="ghost" 
                    size="sm"
                  >
                    Dismiss
                  </Button>
                </div>
              </AlertDescription>
            </Alert>
          )}

          {isWaitingForToken && (
            <div className="flex items-center justify-center py-8">
              <div className="flex items-center gap-2">
                <RefreshCw className="h-5 w-5 animate-spin" />
                <span>Waiting for GitHub authentication...</span>
              </div>
            </div>
          )}

          {isLoadingRepos ? (
            <div className="flex items-center justify-center py-8">
              <div className="flex items-center gap-2">
                <RefreshCw className="h-5 w-5 animate-spin" />
                <span>Loading repositories...</span>
              </div>
            </div>
          ) : repositories.length > 0 ? (
            <div className="space-y-4">
              <Select value={selectedRepo} onValueChange={setSelectedRepo}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose a repository to audit" />
            </SelectTrigger>
            <SelectContent>
                  {repositories.map((repo) => (
                    <SelectItem key={repo.id} value={repo.full_name}>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{repo.name}</span>
                        <Badge variant="outline" className="text-xs">
                          {repo.private ? 'Private' : 'Public'}
                        </Badge>
                        {repo.language && (
                          <Badge variant="secondary" className="text-xs">
                            {repo.language}
                          </Badge>
                        )}
                      </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

              {selectedRepo && (
                <div className="p-4 bg-muted/50 rounded-lg">
                  <h3 className="font-semibold mb-2">Selected Repository</h3>
                  <p className="text-sm text-muted-foreground">
                    {selectedRepo}
                  </p>
                  <Button 
                    onClick={handleStartAudit}
                    disabled={isAuditing}
                    className="mt-3"
                  >
                    {isAuditing ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Starting Audit...
              </>
            ) : (
              <>
                        <ShieldCheck className="h-4 w-4 mr-2" />
                        Start Security Audit
              </>
            )}
          </Button>
                </div>
              )}
            </div>
          ) : !error ? (
            <div className="text-center py-8 text-muted-foreground">
              <Github className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No repositories found</p>
              <p className="text-sm">Make sure you have access to repositories on GitHub</p>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Debug Panel - Development Only */}
      {process.env.NODE_ENV === 'development' && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle className="text-sm text-muted-foreground">Debug Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            <div>User ID: {user?.firebaseUser?.uid}</div>
            <div>GitHub Token Status: {repositories.length > 0 ? 'Present' : 'Missing'}</div>
            <div>Repositories Loaded: {repositories.length}</div>
            <div className="space-y-2">
              <Button 
                variant="outline" 
                size="sm" 
                onClick={async () => {
                  try {
                    const result = await GitHubService.testConnection(user.firebaseUser.uid);
                    console.log('Connection test result:', result);
                    alert(`Connection test: ${result ? 'SUCCESS' : 'FAILED'}`);
                  } catch (error) {
                    console.error('Connection test error:', error);
                    alert('Connection test failed');
                  }
                }}
                className="w-full"
              >
                Test GitHub Connection
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={async () => {
                  try {
                    const token = await GitHubService.getAuthToken(user.firebaseUser.uid);
                    if (token) {
                      const validation = await GitHubService.validateToken(token);
                      console.log('Token validation:', validation);
                      alert(`Token validation: ${validation.message}`);
                    } else {
                      alert('No token found');
                    }
                  } catch (error) {
                    console.error('Token validation error:', error);
                    alert('Token validation failed');
                  }
                }}
                className="w-full"
              >
                Validate GitHub Token
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleManualTokenCheck}
              >
                Manual Token Check
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Mock Results Preview */}
      {selectedRepo && (
        <Card>
          <CardHeader>
            <CardTitle>Audit Preview</CardTitle>
                    <CardDescription>
              This is a preview of what the audit results will look like
                    </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-500">{mockAuditResultsData.critical}</div>
                <div className="text-sm text-muted-foreground">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-500">{mockAuditResultsData.high}</div>
                <div className="text-sm text-muted-foreground">High</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-500">{mockAuditResultsData.medium}</div>
                <div className="text-sm text-muted-foreground">Medium</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-500">{mockAuditResultsData.low}</div>
                <div className="text-sm text-muted-foreground">Low</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-semibold">Top Recommendations:</h4>
              <ul className="space-y-1">
                {mockAuditResultsData.recommendations.slice(0, 3).map((rec, index) => (
                  <li key={index} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
                </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
