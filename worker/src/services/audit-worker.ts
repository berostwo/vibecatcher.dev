import { AuditRequest, AuditReport, SecurityVulnerability } from '../types';
import { FirebaseAdminService } from './firebase-admin';
import { OpenAIAuditService } from './openai-audit';
import { GitHubService } from './github-service';

export class AuditWorkerService {
  private firebaseService: FirebaseAdminService;
  private openaiService: OpenAIAuditService;
  private githubService: GitHubService;

  constructor() {
    this.firebaseService = new FirebaseAdminService();
    this.openaiService = new OpenAIAuditService();
    this.githubService = new GitHubService();
  }

  // Main method to process an audit request
  async processAuditRequest(request: AuditRequest): Promise<string> {
    let reportId: string | undefined;
    let repoPath: string | undefined;

    try {
      // Verify user has audits available
      const auditCheck = await this.firebaseService.verifyUserAudits(request.userId);
      if (!auditCheck.hasAudits) {
        throw new Error('No audits available');
      }

      // Create initial audit report
      const initialReport: Omit<AuditReport, 'id'> = {
        userId: request.userId,
        repositoryUrl: request.repositoryUrl,
        repositoryName: request.repositoryName,
        status: 'pending',
        vulnerabilities: [],
        healthScore: 0,
        totalFindings: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        createdAt: new Date(),
        metadata: {
          language: 'Unknown',
          totalFiles: 0,
          analysisTime: 0
        }
      };

      reportId = await this.firebaseService.createAuditReport(initialReport);

      // Update status to processing
      await this.firebaseService.updateAuditReportStatus(reportId, 'processing');

      // Clone repository
      const cloneResult = await this.githubService.cloneRepository(
        request.repositoryUrl,
        request.accessToken,
        request.branch
      );
      repoPath = cloneResult.path;

      // Update metadata with file count
      await this.firebaseService.updateAuditReportStatus(reportId, 'processing', {
        metadata: {
          ...initialReport.metadata,
          totalFiles: cloneResult.files.length,
          language: cloneResult.files[0]?.language || 'Unknown'
        }
      });

      // Perform security audit with OpenAI
      const startTime = Date.now();
      const auditResult = await this.openaiService.performSecurityAudit(
        request.repositoryName,
        cloneResult.files
      );
      const analysisTime = Date.now() - startTime;

      // Calculate vulnerability counts
      const criticalCount = auditResult.vulnerabilities.filter(v => v.severity === 'Critical').length;
      const highCount = auditResult.vulnerabilities.filter(v => v.severity === 'High').length;
      const mediumCount = auditResult.vulnerabilities.filter(v => v.severity === 'Medium').length;
      const lowCount = auditResult.vulnerabilities.filter(v => v.severity === 'Low').length;

      // Update audit report with results
      await this.firebaseService.updateAuditReportStatus(reportId, 'completed', {
        vulnerabilities: auditResult.vulnerabilities,
        healthScore: auditResult.healthScore,
        totalFindings: auditResult.vulnerabilities.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        metadata: {
          ...initialReport.metadata,
          totalFiles: cloneResult.files.length,
          language: cloneResult.files[0]?.language || 'Unknown',
          analysisTime
        }
      });

      // Use one audit from user's account
      await this.firebaseService.useAudit(request.userId);

      console.log(`Audit completed successfully for ${request.repositoryName}. Report ID: ${reportId}`);
      return reportId;

    } catch (error) {
      console.error('Audit processing error:', error);
      
      // Update report status to failed if we have a report ID
      if (reportId) {
        await this.firebaseService.updateAuditReportStatus(reportId, 'failed', {
          error: error instanceof Error ? error.message : 'Unknown error occurred'
        });
      }

      throw error;
    } finally {
      // Clean up temporary files
      if (repoPath) {
        await this.githubService.cleanup(repoPath);
      }
    }
  }

  // Get audit report by ID
  async getAuditReport(reportId: string): Promise<AuditReport | null> {
    return await this.firebaseService.getAuditReport(reportId);
  }

  // Get user's audit reports
  async getUserAuditReports(userId: string): Promise<AuditReport[]> {
    return await this.firebaseService.getUserAuditReports(userId);
  }
}

