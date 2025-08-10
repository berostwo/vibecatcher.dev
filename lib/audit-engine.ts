import OpenAI from 'openai';
import { Octokit } from '@octokit/rest';

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  file: string;
  line: number;
  cwe: string;
  fix: string;
  aiPrompt: string;
  confidence: number;
}

export interface AuditResult {
  id: string;
  repository: string;
  branch: string;
  framework: string;
  status: 'completed' | 'in-progress' | 'failed';
  createdAt: Date;
  completedAt?: Date;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  score: number;
  duration: number;
  metadata: {
    totalFiles: number;
    totalLines: number;
    languages: string[];
    dependencies: string[];
  };
}

export class SecurityAuditEngine {
  private openai: OpenAI;
  private octokit: Octokit;

  constructor() {
    this.openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });

    this.octokit = new Octokit({
      auth: process.env.GITHUB_TOKEN,
    });
  }

  async analyzeRepository(
    repositoryUrl: string,
    branch: string = 'main',
    framework: string,
    description?: string
  ): Promise<AuditResult> {
    const startTime = Date.now();
    
    try {
      // Extract repository info from URL
      const repoInfo = this.parseGitHubUrl(repositoryUrl);
      if (!repoInfo) {
        throw new Error('Invalid GitHub repository URL');
      }

      // Clone and analyze repository
      const codebase = await this.cloneRepository(repoInfo.owner, repoInfo.repo, branch);
      const vulnerabilities = await this.analyzeCodebase(codebase, framework, description);
      
      // Calculate security score
      const score = this.calculateSecurityScore(vulnerabilities);
      
      // Generate summary
      const summary = this.generateSummary(vulnerabilities);
      
      const duration = Math.round((Date.now() - startTime) / 1000 / 60); // in minutes

      return {
        id: this.generateAuditId(),
        repository: repoInfo.repo,
        branch,
        framework,
        status: 'completed',
        createdAt: new Date(),
        completedAt: new Date(),
        vulnerabilities,
        summary,
        score,
        duration,
        metadata: {
          totalFiles: codebase.files.length,
          totalLines: codebase.totalLines,
          languages: codebase.languages,
          dependencies: codebase.dependencies,
        },
      };
    } catch (error) {
      console.error('Audit failed:', error);
      throw error;
    }
  }

  private parseGitHubUrl(url: string): { owner: string; repo: string } | null {
    const match = url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace('.git', ''),
      };
    }
    return null;
  }

  private async cloneRepository(owner: string, repo: string, branch: string) {
    try {
      // Get repository contents
      const { data: contents } = await this.octokit.repos.getContent({
        owner,
        repo,
        path: '',
        ref: branch,
      });

      const files: Array<{ path: string; content: string; language: string }> = [];
      let totalLines = 0;
      const languages = new Set<string>();
      const dependencies = new Set<string>();

      // Recursively get all files
      await this.processDirectory(owner, repo, branch, '', files, languages, dependencies);

      // Calculate total lines
      totalLines = files.reduce((sum, file) => {
        return sum + file.content.split('\n').length;
      }, 0);

      return {
        files,
        totalLines,
        languages: Array.from(languages),
        dependencies: Array.from(dependencies),
      };
    } catch (error) {
      console.error('Failed to clone repository:', error);
      throw new Error('Failed to access repository. Make sure it\'s public or you have proper access.');
    }
  }

  private async processDirectory(
    owner: string,
    repo: string,
    branch: string,
    path: string,
    files: Array<{ path: string; content: string; language: string }>,
    languages: Set<string>,
    dependencies: Set<string>
  ) {
    try {
      const { data: contents } = await this.octokit.repos.getContent({
        owner,
        repo,
        path,
        ref: branch,
      });

      for (const item of contents) {
        if (item.type === 'file') {
          // Skip large files and binary files
          if (item.size > 1000000) continue; // Skip files larger than 1MB
          
          const fileExtension = item.name.split('.').pop()?.toLowerCase();
          if (this.isBinaryFile(fileExtension)) continue;

          try {
            const { data: fileData } = await this.octokit.repos.getContent({
              owner,
              repo,
              path: item.path,
              ref: branch,
            });

            if ('content' in fileData && fileData.content) {
              const content = Buffer.from(fileData.content, 'base64').toString('utf-8');
              const language = this.detectLanguage(item.name, content);
              
              files.push({
                path: item.path,
                content,
                language,
              });

              languages.add(language);
              
              // Extract dependencies
              this.extractDependencies(item.name, content, dependencies);
            }
          } catch (error) {
            console.warn(`Failed to read file ${item.path}:`, error);
          }
        } else if (item.type === 'dir') {
          // Skip certain directories
          if (['node_modules', '.git', 'dist', 'build', '.next'].includes(item.name)) {
            continue;
          }
          await this.processDirectory(owner, repo, branch, item.path, files, languages, dependencies);
        }
      }
    } catch (error) {
      console.warn(`Failed to process directory ${path}:`, error);
    }
  }

  private isBinaryFile(extension?: string): boolean {
    const binaryExtensions = ['png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'pdf', 'zip', 'tar', 'gz', 'exe', 'dll', 'so', 'dylib'];
    return extension ? binaryExtensions.includes(extension) : false;
  }

  private detectLanguage(filename: string, content: string): string {
    const extension = filename.split('.').pop()?.toLowerCase();
    
    const languageMap: Record<string, string> = {
      'js': 'JavaScript',
      'ts': 'TypeScript',
      'jsx': 'React/JSX',
      'tsx': 'React/TSX',
      'py': 'Python',
      'rb': 'Ruby',
      'php': 'PHP',
      'go': 'Go',
      'rs': 'Rust',
      'java': 'Java',
      'cs': 'C#',
      'cpp': 'C++',
      'c': 'C',
      'html': 'HTML',
      'css': 'CSS',
      'scss': 'SCSS',
      'sql': 'SQL',
      'json': 'JSON',
      'yaml': 'YAML',
      'yml': 'YAML',
      'md': 'Markdown',
      'sh': 'Shell',
      'ps1': 'PowerShell',
    };

    return languageMap[extension || ''] || 'Unknown';
  }

  private extractDependencies(filename: string, content: string, dependencies: Set<string>) {
    if (filename === 'package.json') {
      try {
        const pkg = JSON.parse(content);
        if (pkg.dependencies) {
          Object.keys(pkg.dependencies).forEach(dep => dependencies.add(dep));
        }
        if (pkg.devDependencies) {
          Object.keys(pkg.devDependencies).forEach(dep => dependencies.add(dep));
        }
      } catch (error) {
        console.warn('Failed to parse package.json');
      }
    } else if (filename === 'requirements.txt') {
      content.split('\n').forEach(line => {
        const dep = line.split('==')[0].split('>=')[0].split('<=')[0].trim();
        if (dep && !dep.startsWith('#')) {
          dependencies.add(dep);
        }
      });
    } else if (filename === 'Gemfile') {
      content.split('\n').forEach(line => {
        const match = line.match(/gem\s+['"]([^'"]+)['"]/);
        if (match) {
          dependencies.add(match[1]);
        }
      });
    }
  }

  private async analyzeCodebase(
    codebase: { files: Array<{ path: string; content: string; language: string }>; totalLines: number; languages: string[]; dependencies: string[] },
    framework: string,
    description?: string
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Analyze each file for security issues
    for (const file of codebase.files) {
      const fileVulnerabilities = await this.analyzeFile(file, framework, description);
      vulnerabilities.push(...fileVulnerabilities);
    }

    // Analyze dependencies for known vulnerabilities
    const dependencyVulnerabilities = await this.analyzeDependencies(codebase.dependencies);
    vulnerabilities.push(...dependencyVulnerabilities);

    return vulnerabilities;
  }

  private async analyzeFile(
    file: { path: string; content: string; language: string },
    framework: string,
    description?: string
  ): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      const prompt = this.generateSecurityPrompt(file, framework, description);
      
      const completion = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `You are a security expert analyzing code for vulnerabilities. Analyze the provided code and identify security issues. Return your response as a JSON array of vulnerabilities with the following structure:
            [
              {
                "title": "Brief vulnerability title",
                "description": "Detailed description of the vulnerability",
                "severity": "critical|high|medium|low|info",
                "category": "Injection|XSS|CSRF|Authentication|Authorization|Input Validation|Secrets Management|Other",
                "line": line_number,
                "fix": "Specific fix recommendation",
                "aiPrompt": "Copy-paste prompt for AI assistant to fix this issue",
                "confidence": confidence_score_0_to_1
              }
            ]
            
            Only return valid JSON. If no vulnerabilities found, return an empty array.`
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.1,
        max_tokens: 2000,
      });

      const response = completion.choices[0]?.message?.content;
      if (response) {
        try {
          const parsedVulnerabilities = JSON.parse(response);
          if (Array.isArray(parsedVulnerabilities)) {
            parsedVulnerabilities.forEach((vuln: any) => {
              if (vuln.title && vuln.severity) {
                vulnerabilities.push({
                  id: this.generateVulnerabilityId(),
                  title: vuln.title,
                  description: vuln.description || '',
                  severity: vuln.severity,
                  category: vuln.category || 'Other',
                  file: file.path,
                  line: vuln.line || 1,
                  cwe: this.mapCategoryToCWE(vuln.category),
                  fix: vuln.fix || '',
                  aiPrompt: vuln.aiPrompt || '',
                  confidence: vuln.confidence || 0.8,
                });
              }
            });
          }
        } catch (parseError) {
          console.warn('Failed to parse AI response:', parseError);
        }
      }
    } catch (error) {
      console.warn(`Failed to analyze file ${file.path}:`, error);
    }

    return vulnerabilities;
  }

  private generateSecurityPrompt(
    file: { path: string; content: string; language: string },
    framework: string,
    description?: string
  ): string {
    return `Analyze this ${file.language} code for security vulnerabilities:

File: ${file.path}
Framework: ${framework}
${description ? `Description: ${description}\n` : ''}

Code:
\`\`\`${file.language}
${file.content}
\`\`\`

Focus on:
- SQL injection
- XSS vulnerabilities
- CSRF attacks
- Authentication bypasses
- Authorization flaws
- Input validation issues
- Hardcoded secrets
- Insecure dependencies
- Framework-specific vulnerabilities

Identify the line numbers and provide specific, actionable fixes.`;
  }

  private async analyzeDependencies(dependencies: string[]): Promise<Vulnerability[]> {
    // This would integrate with vulnerability databases like NVD, Snyk, etc.
    // For now, return empty array - implement later
    return [];
  }

  private mapCategoryToCWE(category: string): string {
    const cweMap: Record<string, string> = {
      'Injection': 'CWE-89',
      'XSS': 'CWE-79',
      'CSRF': 'CWE-352',
      'Authentication': 'CWE-287',
      'Authorization': 'CWE-285',
      'Input Validation': 'CWE-20',
      'Secrets Management': 'CWE-798',
      'Other': 'CWE-200',
    };
    
    return cweMap[category] || 'CWE-200';
  }

  private calculateSecurityScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) return 100;
    
    let totalScore = 100;
    const weights = {
      critical: 25,
      high: 15,
      medium: 10,
      low: 5,
      info: 1,
    };

    vulnerabilities.forEach(vuln => {
      totalScore -= weights[vuln.severity] || 0;
    });

    return Math.max(0, Math.round(totalScore));
  }

  private generateSummary(vulnerabilities: Vulnerability[]): {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  } {
    const summary = {
      total: vulnerabilities.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    vulnerabilities.forEach(vuln => {
      summary[vuln.severity]++;
    });

    return summary;
  }

  private generateAuditId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateVulnerabilityId(): string {
    return `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
