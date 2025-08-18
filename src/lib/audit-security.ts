import DOMPurify from 'dompurify';

/**
 * Security utilities for handling audit data safely
 */
export class AuditSecurityService {
  
  /**
   * Sanitize HTML content to prevent XSS attacks
   */
  static sanitizeHTML(content: string): string {
    if (!content || typeof content !== 'string') {
      return '';
    }
    
    try {
      // Use DOMPurify to sanitize HTML content
      return DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['strong', 'em', 'code', 'pre', 'br', 'p'],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true
      });
    } catch (error) {
      console.error('HTML sanitization failed:', error);
      // Fallback: escape HTML entities
      return this.escapeHTML(content);
    }
  }

  /**
   * Escape HTML entities as fallback sanitization
   */
  static escapeHTML(text: string): string {
    if (!text || typeof text !== 'string') {
      return '';
    }
    
    const htmlEscapes: { [key: string]: string } = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;'
    };
    
    return text.replace(/[&<>"'/]/g, (match) => htmlEscapes[match]);
  }

  /**
   * Validate and sanitize file paths to prevent path traversal
   */
  static sanitizeFilePath(filePath: string): string {
    if (!filePath || typeof filePath !== 'string') {
      return 'unknown';
    }
    
    // Remove any path traversal attempts
    let sanitized = filePath
      .replace(/\.\./g, '') // Remove .. sequences
      .replace(/\/\//g, '/') // Normalize double slashes
      .replace(/^\/+/, '') // Remove leading slashes
      .replace(/\/+$/, ''); // Remove trailing slashes
    
    // Limit length to prevent abuse
    if (sanitized.length > 200) {
      sanitized = sanitized.substring(0, 200) + '...';
    }
    
    // Only allow safe characters
    if (!/^[a-zA-Z0-9._\-\/]+$/.test(sanitized)) {
      return 'invalid-path';
    }
    
    return sanitized || 'unknown';
  }

  /**
   * Validate and sanitize line numbers
   */
  static sanitizeLineNumber(lineNumber: any): string {
    if (lineNumber === null || lineNumber === undefined) {
      return 'unknown';
    }
    
    const num = parseInt(lineNumber.toString(), 10);
    
    if (isNaN(num) || num < 0 || num > 999999) {
      return 'unknown';
    }
    
    return num.toString();
  }

  /**
   * Validate and sanitize repository names
   */
  static sanitizeRepositoryName(name: string): string {
    if (!name || typeof name !== 'string') {
      return 'Unknown Repository';
    }
    
    // Remove any HTML/script tags
    let sanitized = this.escapeHTML(name);
    
    // Limit length
    if (sanitized.length > 100) {
      sanitized = sanitized.substring(0, 100) + '...';
    }
    
    // Only allow safe characters
    if (!/^[a-zA-Z0-9._\-\s]+$/.test(sanitized)) {
      return 'Unknown Repository';
    }
    
    return sanitized || 'Unknown Repository';
  }

  /**
   * Validate and sanitize numeric values
   */
  static sanitizeNumber(value: any, defaultValue: number = 0): number {
    if (value === null || value === undefined) {
      return defaultValue;
    }
    
    const num = parseInt(value.toString(), 10);
    
    if (isNaN(num) || num < 0 || num > 999999) {
      return defaultValue;
    }
    
    return num;
  }

  /**
   * Validate and sanitize audit status
   */
  static sanitizeStatus(status: any): 'pending' | 'running' | 'completed' | 'failed' {
    if (!status || typeof status !== 'string') {
      return 'pending';
    }
    
    const validStatuses = ['pending', 'running', 'completed', 'failed'];
    
    if (validStatuses.includes(status)) {
      return status as any;
    }
    
    return 'pending';
  }

  /**
   * Comprehensive audit data sanitization
   */
  static sanitizeAuditData(audit: any): any {
    if (!audit || typeof audit !== 'object') {
      return null;
    }
    
    try {
      return {
        id: audit.id || 'unknown',
        userId: audit.userId || 'unknown',
        repositoryUrl: audit.repositoryUrl || '',
        repositoryName: this.sanitizeRepositoryName(audit.repositoryName),
        status: this.sanitizeStatus(audit.status),
        progress: audit.progress || null,
        scanResults: audit.scanResults ? this.sanitizeScanResults(audit.scanResults) : undefined,
        error: audit.error ? this.escapeHTML(audit.error) : undefined,
        error_type: audit.error_type ? this.escapeHTML(audit.error_type) : undefined,
        createdAt: audit.createdAt || null,
        updatedAt: audit.updatedAt || null,
        completedAt: audit.completedAt || null
      };
    } catch (error) {
      console.error('Audit data sanitization failed:', error);
      return null;
    }
  }

  /**
   * Sanitize scan results specifically
   */
  static sanitizeScanResults(scanResults: any): any {
    if (!scanResults || typeof scanResults !== 'object') {
      return null;
    }
    
    try {
      return {
        summary: scanResults.summary ? this.sanitizeSummary(scanResults.summary) : null,
        findings: Array.isArray(scanResults.findings) ? scanResults.findings.map((finding: any) => this.sanitizeFinding(finding)) : [],
        condensed_findings: Array.isArray(scanResults.condensed_findings) ? scanResults.condensed_findings.map((finding: any) => this.sanitizeFinding(finding)) : [],
        condensed_remediations: scanResults.condensed_remediations ? this.sanitizeRemediations(scanResults.condensed_remediations) : {},
        master_remediation: scanResults.master_remediation ? this.sanitizeHTML(scanResults.master_remediation) : '',
        scan_duration: this.sanitizeNumber(scanResults.scan_duration, 0),
        timestamp: scanResults.timestamp || '',
        repository_info: scanResults.repository_info ? this.sanitizeRepositoryInfo(scanResults.repository_info) : null
      };
    } catch (error) {
      console.error('Scan results sanitization failed:', error);
      return null;
    }
  }

  /**
   * Sanitize individual findings
   */
  static sanitizeFinding(finding: any): any {
    if (!finding || typeof finding !== 'object') {
      return null;
    }
    
    try {
      return {
        rule_id: finding.rule_id || 'unknown',
        severity: this.sanitizeSeverity(finding.severity),
        message: this.escapeHTML(finding.message || ''),
        description: this.escapeHTML(finding.description || ''),
        file_path: this.sanitizeFilePath(finding.file_path || ''),
        line_number: this.sanitizeLineNumber(finding.line_number),
        occurrences: this.sanitizeNumber(finding.occurrences, 1)
      };
    } catch (error) {
      console.error('Finding sanitization failed:', error);
      return null;
    }
  }

  /**
   * Sanitize severity levels
   */
  static sanitizeSeverity(severity: any): 'Critical' | 'High' | 'Medium' | 'Low' {
    if (!severity || typeof severity !== 'string') {
      return 'Medium';
    }
    
    const validSeverities = ['Critical', 'High', 'Medium', 'Low'];
    const normalized = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();
    
    if (validSeverities.includes(normalized)) {
      return normalized as any;
    }
    
    return 'Medium';
  }

  /**
   * Sanitize summary data
   */
  static sanitizeSummary(summary: any): any {
    if (!summary || typeof summary !== 'object') {
      return null;
    }
    
    try {
      return {
        total_findings: this.sanitizeNumber(summary.total_findings, 0),
        condensed_findings: this.sanitizeNumber(summary.condensed_findings, 0),
        critical_count: this.sanitizeNumber(summary.critical_count, 0),
        high_count: this.sanitizeNumber(summary.high_count, 0),
        medium_count: this.sanitizeNumber(summary.medium_count, 0),
        low_count: this.sanitizeNumber(summary.low_count, 0),
        codebase_health: this.sanitizeNumber(summary.codebase_health, 100),
        files_scanned: this.sanitizeNumber(summary.files_scanned, 0),
        scan_duration: this.sanitizeNumber(summary.scan_duration, 0)
      };
    } catch (error) {
      console.error('Summary sanitization failed:', error);
      return null;
    }
  }

  /**
   * Sanitize remediation data
   */
  static sanitizeRemediations(remediations: any): { [key: string]: string } {
    if (!remediations || typeof remediations !== 'object') {
      return {};
    }
    
    const sanitized: { [key: string]: string } = {};
    
    try {
      for (const [key, value] of Object.entries(remediations)) {
        if (typeof value === 'string') {
          sanitized[key] = this.sanitizeHTML(value);
        }
      }
    } catch (error) {
      console.error('Remediations sanitization failed:', error);
    }
    
    return sanitized;
  }

  /**
   * Sanitize repository info
   */
  static sanitizeRepositoryInfo(repoInfo: any): any {
    if (!repoInfo || typeof repoInfo !== 'object') {
      return null;
    }
    
    try {
      return {
        name: this.sanitizeRepositoryName(repoInfo.name || ''),
        url: repoInfo.url || '',
        size: this.escapeHTML(repoInfo.size || ''),
        file_count: this.sanitizeNumber(repoInfo.file_count, 0)
      };
    } catch (error) {
      console.error('Repository info sanitization failed:', error);
      return null;
    }
  }
}
