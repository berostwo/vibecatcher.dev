export interface SecurityVulnerability {
  id: string;
  title: string;
  file: string;
  line: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
}

export interface AuditReport {
  id: string;
  userId: string;
  repositoryUrl: string;
  repositoryName: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  vulnerabilities: SecurityVulnerability[];
  healthScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  createdAt: Date;
  completedAt?: Date;
  error?: string;
  metadata: {
    language: string;
    framework?: string;
    totalFiles: number;
    analysisTime: number;
  };
}

export interface AuditRequest {
  userId: string;
  repositoryUrl: string;
  repositoryName: string;
  branch?: string;
  accessToken?: string;
}

export interface OpenAIResponse {
  vulnerabilities: SecurityVulnerability[];
  healthScore: number;
  summary: string;
  recommendations: string[];
}

export interface GitHubRepository {
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  language: string;
  size: number;
  updated_at: string;
}

