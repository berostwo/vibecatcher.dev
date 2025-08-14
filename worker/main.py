import os
import json
import asyncio
import aiohttp
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import logging
from flask import Flask, request, jsonify
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Production configuration
MAX_REPO_SIZE_MB = 100  # Maximum repository size to scan
MAX_SCAN_TIME_SECONDS = 600  # Maximum scan time (10 minutes)
ALLOWED_REPO_DOMAINS = ['github.com', 'gitlab.com', 'bitbucket.org']

# Performance monitoring thresholds
MIN_CLONE_TIME_SECONDS = 10      # Minimum expected clone time
MIN_SEMGREP_TIME_SECONDS = 30    # Minimum expected Semgrep time
MIN_GPT_TIME_SECONDS = 5         # Minimum expected GPT time
MIN_TOTAL_TIME_SECONDS = 120     # Minimum expected total time (2 minutes)

# Performance alert thresholds (warnings, not failures)
SUSPICIOUS_CLONE_TIME = 5        # Clone completes in < 5 seconds
SUSPICIOUS_SEMGREP_TIME = 15     # Semgrep completes in < 15 seconds  
SUSPICIOUS_GPT_TIME = 3          # GPT completes in < 3 seconds
SUSPICIOUS_TOTAL_TIME = 60       # Total audit < 1 minute

# Error handling and retry configuration
MAX_RETRIES = 3                   # Maximum retry attempts for transient failures
RETRY_DELAY_SECONDS = 2          # Delay between retries
GPT_FALLBACK_ENABLED = True      # Enable fallback analysis if GPT fails
SEMGREP_FALLBACK_RULES = ['p/owasp-top-ten']  # Fallback rules if primary rules fail

@dataclass
class Vulnerability:
    rule_id: str
    message: str
    severity: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    occurrences: int = 0
    locations: List[Dict[str, Any]] = None
    rule_metadata: Dict[str, Any] = None

class PerformanceMonitor:
    """Monitor performance and timing for security audit phases"""
    
    def __init__(self):
        self.phase_timings = {}
        self.performance_alerts = []
        self.start_time = None
        self.current_phase = None
    
    def start_phase(self, phase_name: str):
        """Start timing a phase"""
        self.current_phase = phase_name
        self.phase_timings[phase_name] = {
            'start': datetime.utcnow(),
            'end': None,
            'duration': None
        }
        logger.info(f"⏱️ Starting phase: {phase_name}")
    
    def end_phase(self, phase_name: str):
        """End timing a phase and check performance"""
        if phase_name in self.phase_timings:
            self.phase_timings[phase_name]['end'] = datetime.utcnow()
            duration = (self.phase_timings[phase_name]['end'] - self.phase_timings[phase_name]['start']).total_seconds()
            self.phase_timings[phase_name]['duration'] = duration
            
            # Check for suspicious timing
            self._check_performance_alerts(phase_name, duration)
            
            logger.info(f"⏱️ Phase '{phase_name}' completed in {duration:.2f}s")
    
    def _check_performance_alerts(self, phase_name: str, duration: float):
        """Check if phase timing is suspicious and log alerts"""
        alert = None
        
        if phase_name == 'clone' and duration < SUSPICIOUS_CLONE_TIME:
            alert = f"⚠️ SUSPICIOUS: Repository cloning completed in {duration:.2f}s (expected > {SUSPICIOUS_CLONE_TIME}s)"
        elif phase_name == 'semgrep' and duration < SUSPICIOUS_SEMGREP_TIME:
            alert = f"⚠️ SUSPICIOUS: Semgrep scan completed in {duration:.2f}s (expected > {SUSPICIOUS_SEMGREP_TIME}s)"
        elif phase_name == 'gpt' and duration < SUSPICIOUS_GPT_TIME:
            alert = f"⚠️ SUSPICIOUS: GPT analysis completed in {duration:.2f}s (expected > {SUSPICIOUS_GPT_TIME}s)"
        
        if alert:
            self.performance_alerts.append(alert)
            logger.warning(alert)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        total_duration = 0
        phase_breakdown = {}
        
        for phase, timing in self.phase_timings.items():
            if timing['duration'] is not None:
                total_duration += timing['duration']
                phase_breakdown[phase] = {
                    'duration': timing['duration'],
                    'start_time': timing['start'].isoformat(),
                    'end_time': timing['end'].isoformat() if timing['end'] else None
                }
        
        # Check total time
        if total_duration < SUSPICIOUS_TOTAL_TIME:
            total_alert = f"⚠️ SUSPICIOUS: Total audit completed in {total_duration:.2f}s (expected > {SUSPICIOUS_TOTAL_TIME}s)"
            self.performance_alerts.append(total_alert)
            logger.warning(total_alert)
        
        return {
            'total_duration': total_duration,
            'phase_breakdown': phase_breakdown,
            'performance_alerts': self.performance_alerts,
            'performance_score': self._calculate_performance_score(total_duration)
        }
    
    def _calculate_performance_score(self, total_duration: float) -> str:
        """Calculate performance score based on timing"""
        if total_duration < 60:
            return "SUSPICIOUS - Too fast for comprehensive audit"
        elif total_duration < 300:
            return "FAST - May indicate incomplete analysis"
        elif total_duration < 900:
            return "NORMAL - Expected timing for comprehensive audit"
        else:
            return "SLOW - May indicate large repository or complex analysis"
    
    def estimate_resource_usage(self, repo_size_mb: float, file_count: int, findings_count: int) -> Dict[str, Any]:
        """Estimate resource usage based on repository characteristics"""
        
        # Estimate CPU usage based on file count and findings
        estimated_cpu_cores = min(4, max(1, file_count // 100))  # 1 core per 100 files, max 4
        
        # Estimate memory usage based on repository size and findings
        base_memory_mb = 512  # Base memory for Semgrep
        file_memory_mb = file_count * 0.1  # ~0.1MB per file for parsing
        findings_memory_mb = findings_count * 0.05  # ~0.05MB per finding
        estimated_memory_mb = base_memory_mb + file_memory_mb + findings_memory_mb
        
        # Estimate expected duration based on repository characteristics
        expected_clone_time = max(10, repo_size_mb / 10)  # 10s base + 1s per 10MB
        expected_semgrep_time = max(30, file_count * 0.5)  # 30s base + 0.5s per file
        expected_gpt_time = max(5, findings_count * 0.2)   # 5s base + 0.2s per finding
        expected_total_time = expected_clone_time + expected_semgrep_time + expected_gpt_time
        
        return {
            'estimated_cpu_cores': estimated_cpu_cores,
            'estimated_memory_mb': round(estimated_memory_mb, 1),
            'expected_timings': {
                'clone': round(expected_clone_time, 1),
                'semgrep': round(expected_semgrep_time, 1),
                'gpt': round(expected_gpt_time, 1),
                'total': round(expected_total_time, 1)
            },
            'resource_intensity': self._calculate_resource_intensity(repo_size_mb, file_count, findings_count)
        }
    
    def _calculate_resource_intensity(self, repo_size_mb: float, file_count: int, findings_count: int) -> str:
        """Calculate resource intensity level"""
        intensity_score = (repo_size_mb / 100) + (file_count / 1000) + (findings_count / 100)
        
        if intensity_score < 1:
            return "LOW - Small repository, minimal resource usage"
        elif intensity_score < 3:
            return "MEDIUM - Moderate repository, standard resource usage"
        elif intensity_score < 6:
            return "HIGH - Large repository, significant resource usage"
        else:
            return "VERY HIGH - Very large repository, intensive resource usage"

class ErrorHandler:
    """Handle errors gracefully and provide recovery mechanisms"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.recovery_attempts = {}
    
    def add_error(self, phase: str, error: Exception, context: str = ""):
        """Add an error with context"""
        error_info = {
            'phase': phase,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.errors.append(error_info)
        logger.error(f"❌ Error in {phase}: {error} - {context}")
    
    def add_warning(self, phase: str, warning: str, context: str = ""):
        """Add a warning with context"""
        warning_info = {
            'phase': phase,
            'warning': warning,
            'context': context,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.warnings.append(warning_info)
        logger.warning(f"⚠️ Warning in {phase}: {warning} - {context}")
    
    def can_retry(self, phase: str) -> bool:
        """Check if we can retry a failed phase"""
        if phase not in self.recovery_attempts:
            self.recovery_attempts[phase] = 0
        return self.recovery_attempts[phase] < MAX_RETRIES
    
    def increment_retry(self, phase: str):
        """Increment retry count for a phase"""
        if phase not in self.recovery_attempts:
            self.recovery_attempts[phase] = 0
        self.recovery_attempts[phase] += 1
        logger.info(f"🔄 Retry attempt {self.recovery_attempts[phase]}/{MAX_RETRIES} for {phase}")
    
    def get_recovery_suggestion(self, phase: str, error: Exception) -> str:
        """Get recovery suggestion for a specific error"""
        error_type = type(error).__name__
        
        if phase == 'clone':
            if 'timeout' in str(error).lower():
                return "Try with a smaller repository or check network connectivity"
            elif 'authentication' in str(error).lower():
                return "Verify repository access permissions and credentials"
            else:
                return "Check repository URL validity and accessibility"
        
        elif phase == 'semgrep':
            if 'timeout' in str(error).lower():
                return "Repository may be too large, consider reducing scan scope"
            elif 'memory' in str(error).lower():
                return "Increase available memory or reduce scan complexity"
            else:
                return "Try with fallback security rules or manual configuration"
        
        elif phase == 'gpt':
            if 'api' in str(error).lower():
                return "Check OpenAI API key and rate limits"
            elif 'timeout' in str(error).lower():
                return "GPT analysis timed out, consider reducing analysis scope"
            else:
                return "Fallback analysis will be used"
        
        return "Review error details and try again"
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get comprehensive error summary"""
        return {
            'total_errors': len(self.errors),
            'total_warnings': len(self.warnings),
            'errors_by_phase': self._group_errors_by_phase(),
            'recovery_attempts': self.recovery_attempts,
            'overall_status': 'FAILED' if self.errors else 'SUCCESS' if not self.warnings else 'PARTIAL_SUCCESS'
        }
    
    def _group_errors_by_phase(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group errors by phase for better analysis"""
        grouped = {}
        for error in self.errors:
            phase = error['phase']
            if phase not in grouped:
                grouped[phase] = []
            grouped[phase].append(error)
        return grouped

class DataValidator:
    """Validate data quality and report structure adherence"""
    
    def __init__(self):
        self.validation_errors = []
        self.validation_warnings = []
    
    def validate_semgrep_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate Semgrep findings for completeness and quality"""
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'quality_score': 0,
            'missing_fields': []
        }
        
        if not findings:
            validation_result['warnings'].append("No security findings detected")
            return validation_result
        
        # Check for required fields in each finding
        required_fields = ['check_id', 'path', 'start', 'extra']
        missing_fields_count = 0
        
        for i, finding in enumerate(findings):
            missing_fields = []
            for field in required_fields:
                if field not in finding:
                    missing_fields.append(field)
                    missing_fields_count += 1
            
            if missing_fields:
                validation_result['warnings'].append(f"Finding {i} missing fields: {missing_fields}")
        
        # Check extra field completeness
        extra_fields = ['severity', 'message', 'description']
        incomplete_extras = 0
        
        for finding in findings:
            extra = finding.get('extra', {})
            for field in extra_fields:
                if field not in extra or not extra[field]:
                    incomplete_extras += 1
        
        # Calculate quality score
        total_fields = len(findings) * len(required_fields)
        quality_score = max(0, 100 - ((missing_fields_count + incomplete_extras) / total_fields * 100))
        validation_result['quality_score'] = round(quality_score, 1)
        
        # Set validation status
        if missing_fields_count > len(findings) * 0.5:  # More than 50% missing
            validation_result['is_valid'] = False
            validation_result['errors'].append("Too many findings missing required fields")
        
        if quality_score < 70:
            validation_result['warnings'].append(f"Data quality score is low: {quality_score}/100")
        
        return validation_result
    
    def validate_gpt_analysis(self, gpt_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Validate GPT analysis quality and completeness"""
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'quality_score': 0,
            'analysis_length': 0
        }
        
        if not gpt_analysis:
            validation_result['is_valid'] = False
            validation_result['errors'].append("GPT analysis is missing")
            return validation_result
        
        # Check for required fields
        required_fields = ['analysis', 'model_used', 'tokens_used']
        for field in required_fields:
            if field not in gpt_analysis:
                validation_result['errors'].append(f"Missing required field: {field}")
                validation_result['is_valid'] = False
        
        # Check analysis content quality
        analysis_content = gpt_analysis.get('analysis', '')
        validation_result['analysis_length'] = len(analysis_content)
        
        if len(analysis_content) < 100:
            validation_result['warnings'].append("GPT analysis is very short, may be incomplete")
            validation_result['quality_score'] = 30
        elif len(analysis_content) < 500:
            validation_result['warnings'].append("GPT analysis is short, may lack detail")
            validation_result['quality_score'] = 60
        elif len(analysis_content) < 1000:
            validation_result['quality_score'] = 80
        else:
            validation_result['quality_score'] = 95
        
        # Check for fallback indicators
        fallback_indicators = ['fallback', 'no description available', 'basic analysis']
        for indicator in fallback_indicators:
            if indicator.lower() in analysis_content.lower():
                validation_result['warnings'].append(f"Analysis contains fallback indicator: {indicator}")
                validation_result['quality_score'] = max(validation_result['quality_score'] - 20, 0)
        
        # Check token usage
        tokens_used = gpt_analysis.get('tokens_used', 0)
        if tokens_used == 0:
            validation_result['warnings'].append("No tokens used - may indicate fallback analysis")
            validation_result['quality_score'] = max(validation_result['quality_score'] - 30, 0)
        elif tokens_used < 100:
            validation_result['warnings'].append("Very few tokens used - analysis may be incomplete")
        
        return validation_result
    
    def validate_report_structure(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate overall report structure adherence"""
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'missing_sections': [],
            'structure_score': 0
        }
        
        required_sections = [
            'summary', 'vulnerabilities', 'repository_info', 
            'scan_timestamp', 'gpt_analysis'
        ]
        
        missing_sections = []
        for section in required_sections:
            if section not in audit_results:
                missing_sections.append(section)
                validation_result['errors'].append(f"Missing required section: {section}")
        
        if missing_sections:
            validation_result['is_valid'] = False
            validation_result['missing_sections'] = missing_sections
        
        # Check summary structure
        if 'summary' in audit_results:
            summary = audit_results['summary']
            summary_fields = ['total_vulnerabilities', 'critical_severity', 'high_severity', 'medium_severity', 'low_severity']
            for field in summary_fields:
                if field not in summary:
                    validation_result['warnings'].append(f"Summary missing field: {field}")
        
        # Check vulnerabilities structure
        if 'vulnerabilities' in audit_results:
            vulnerabilities = audit_results['vulnerabilities']
            if not isinstance(vulnerabilities, list):
                validation_result['errors'].append("Vulnerabilities section is not a list")
                validation_result['is_valid'] = False
            elif len(vulnerabilities) > 0:
                # Check first vulnerability structure
                first_vuln = vulnerabilities[0]
                vuln_fields = ['rule_id', 'message', 'severity', 'file_path', 'line_number']
                for field in vuln_fields:
                    if field not in first_vuln:
                        validation_result['warnings'].append(f"Vulnerability missing field: {field}")
        
        # Calculate structure score
        total_checks = len(required_sections) + 2  # +2 for summary and vulnerabilities checks
        passed_checks = total_checks - len(validation_result['errors'])
        validation_result['structure_score'] = round((passed_checks / total_checks) * 100, 1)
        
        return validation_result
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get comprehensive validation summary"""
        return {
            'total_validation_errors': len(self.validation_errors),
            'total_validation_warnings': len(self.validation_warnings),
            'overall_validation_status': 'FAILED' if self.validation_errors else 'PASSED' if not self.validation_warnings else 'WARNINGS'
        }

@dataclass
class AuditSummary:
    total_vulnerabilities: int
    critical_severity: int
    high_severity: int
    medium_severity: int
    low_severity: int
    files_scanned: int
    scan_duration: float

@dataclass
class AuditResults:
    summary: AuditSummary
    vulnerabilities: List[Vulnerability]
    repository_info: Dict[str, Any]
    scan_timestamp: str
    gpt_analysis: Dict[str, Any]

def validate_repository_url(url: str) -> bool:
    """Validate repository URL for security and format"""
    try:
        # Check if it's a valid URL
        if not url.startswith(('https://', 'http://')):
            return False
        
        # Check if it's from allowed domains
        domain = url.split('/')[2]
        if domain not in ALLOWED_REPO_DOMAINS:
            return False
        
        # Check for suspicious patterns
        if any(pattern in url.lower() for pattern in ['..', '~', 'localhost', '127.0.0.1']):
            return False
            
        return True
    except Exception:
        return False

class SecurityAuditor:
    def __init__(self, openai_api_key: str, gpt_model: str = "gpt-4o"):
        self.openai_api_key = openai_api_key
        self.gpt_model = gpt_model
        self.session = None
        self.performance_monitor = PerformanceMonitor()
        self.error_handler = ErrorHandler()
        self.data_validator = DataValidator()
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=300)  # 5 minute timeout
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def clone_repository(self, repo_url: str, temp_dir: str, github_token: str = None) -> str:
        """Clone repository to temporary directory with security checks and retry logic"""
        self.performance_monitor.start_phase('clone')
        
        while self.error_handler.can_retry('clone'):
            try:
                # Validate repository URL
                if not validate_repository_url(repo_url):
                    raise ValueError("Invalid or suspicious repository URL")
                
                # Extract repo name from URL
                repo_name = repo_url.split('/')[-1].replace('.git', '')
                if not repo_name or len(repo_name) > 100:
                    raise ValueError("Invalid repository name")
                
                repo_path = os.path.join(temp_dir, repo_name)
                
                # Prepare clone command with authentication if token provided
                clone_command = ['git', 'clone', '--depth', '1', '--single-branch']
                
                if github_token:
                    # For private repos, use token-based authentication
                    logger.info("Using GitHub token for private repository access")
                    # Convert HTTPS URL to include token: https://token@github.com/user/repo.git
                    if repo_url.startswith('https://github.com/'):
                        # Extract the path part after github.com/
                        path_part = repo_url.replace('https://github.com/', '')
                        authenticated_url = f"https://{github_token}@github.com/{path_part}"
                        clone_command.append(authenticated_url)
                    else:
                        clone_command.append(repo_url)
                else:
                    # For public repos, use original URL
                    logger.info("Cloning public repository without authentication")
                    clone_command.append(repo_url)
                
                clone_command.append(repo_path)
                
                logger.info(f"Clone command: {' '.join(clone_command[:3])}... {clone_command[-1]}")
                
                # Clone with timeout and security flags
                process = await asyncio.create_subprocess_exec(
                    *clone_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                except asyncio.TimeoutError:
                    process.kill()
                    raise Exception("Repository clone timed out")
                
                if process.returncode != 0:
                    raise Exception(f"Git clone failed: {stderr.decode()}")
                
                # Check repository size
                repo_size = sum(os.path.getsize(os.path.join(dirpath, filename))
                               for dirpath, dirnames, filenames in os.walk(repo_path)
                               for filename in filenames)
                repo_size_mb = repo_size / (1024 * 1024)
                
                if repo_size_mb > MAX_REPO_SIZE_MB:
                    raise Exception(f"Repository too large: {repo_size_mb:.1f}MB (max: {MAX_REPO_SIZE_MB}MB)")
                
                logger.info(f"Repository cloned successfully to {repo_path} (size: {repo_size_mb:.1f}MB)")
                
                self.performance_monitor.end_phase('clone')
                return repo_path
                
            except Exception as e:
                self.error_handler.add_error('clone', e, f"Attempt {self.error_handler.recovery_attempts.get('clone', 0) + 1}")
                
                if self.error_handler.can_retry('clone'):
                    self.error_handler.increment_retry('clone')
                    recovery_suggestion = self.error_handler.get_recovery_suggestion('clone', e)
                    logger.warning(f"🔄 Clone failed, retrying... Suggestion: {recovery_suggestion}")
                    
                    # Wait before retry
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                else:
                    self.performance_monitor.end_phase('clone')
                    logger.error(f"❌ Clone failed after {MAX_RETRIES} attempts")
                    raise
        
        # Should never reach here, but just in case
        self.performance_monitor.end_phase('clone')
        raise Exception("Clone failed - max retries exceeded")
    
    async def run_semgrep_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run comprehensive Semgrep security scan with enterprise-grade rules and retry logic"""
        self.performance_monitor.start_phase('semgrep')
        
        # Primary rules to try first
        primary_rules = [
            'p/owasp-top-ten',       # OWASP Top 10 - most stable
            'p/secrets',             # Secrets detection - essential
        ]
        
        # Fallback rules if primary rules fail
        fallback_rules = SEMGREP_FALLBACK_RULES
        
        while self.error_handler.can_retry('semgrep'):
            try:
                # Try primary rules first, then fallback if needed
                attempt_rules = primary_rules if self.error_handler.recovery_attempts.get('semgrep', 0) == 0 else fallback_rules
                
                # Build comprehensive scan command
                scan_command = [
                    'semgrep', 'scan',
                    '--json',
                    '--timeout', '600',      # 10 minute timeout for comprehensive scan
                    '--max-memory', '4096',  # 4GB memory limit
                    '--verbose',             # Detailed output
                    '--metrics', 'off',      # Disable metrics for privacy
                ]
                
                # Add rules
                for rule in attempt_rules:
                    scan_command.extend(['--config', rule])
                
                # Add target path
                scan_command.append(repo_path)
                
                logger.info(f"🔍 Running Semgrep scan with {len(attempt_rules)} rule sets (attempt {self.error_handler.recovery_attempts.get('semgrep', 0) + 1})")
                logger.info(f"🔍 Scan command: {' '.join(scan_command)}")
                
                # Run semgrep scan with comprehensive security rules
                process = await asyncio.create_subprocess_exec(
                    *scan_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=MAX_SCAN_TIME_SECONDS)
                except asyncio.TimeoutError:
                    process.kill()
                    raise Exception("Semgrep scan timed out - repository may be too large or complex")
                
                if process.returncode != 0 and process.returncode != 1:  # Semgrep returns 1 for findings
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    logger.error(f"Semgrep scan failed with return code {process.returncode}: {error_msg}")
                    raise Exception(f"Semgrep scan failed: {error_msg}")
                
                # Parse JSON output
                scan_results = json.loads(stdout.decode())
                findings_count = len(scan_results.get('results', []))
                files_scanned = len(scan_results.get('paths', {}).get('scanned', []))
                
                logger.info(f"🔍 Semgrep scan completed successfully!")
                logger.info(f"🔍 Files scanned: {files_scanned}")
                logger.info(f"🔍 Security findings: {findings_count}")
                
                # Log scan statistics
                if 'stats' in scan_results:
                    stats = scan_results['stats']
                    logger.info(f"🔍 Scan duration: {stats.get('time', {}).get('total', 'Unknown')}s")
                    logger.info(f"🔍 Rules run: {stats.get('rules', {}).get('total', 'Unknown')}")
                
                self.performance_monitor.end_phase('semgrep')
                return scan_results
                
            except Exception as e:
                self.error_handler.add_error('semgrep', e, f"Attempt {self.error_handler.recovery_attempts.get('semgrep', 0) + 1}")
                
                if self.error_handler.can_retry('semgrep'):
                    self.error_handler.increment_retry('semgrep')
                    recovery_suggestion = self.error_handler.get_recovery_suggestion('semgrep', e)
                    logger.warning(f"🔄 Semgrep scan failed, retrying with fallback rules... Suggestion: {recovery_suggestion}")
                    
                    # Wait before retry
                    await asyncio.sleep(RETRY_DELAY_SECONDS)
                else:
                    self.performance_monitor.end_phase('semgrep')
                    logger.error(f"❌ Semgrep scan failed after {MAX_RETRIES} attempts")
                    raise
        
        # Should never reach here, but just in case
        self.performance_monitor.end_phase('semgrep')
        raise Exception("Semgrep scan failed - max retries exceeded")
    
    async def analyze_with_gpt4(self, semgrep_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Semgrep results with GPT-4"""
        self.performance_monitor.start_phase('gpt')
        try:
            # Create prompt for GPT-4
            prompt = self._create_gpt_prompt(semgrep_results)
            
            # Call OpenAI API
            headers = {
                'Authorization': f'Bearer {self.openai_api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': self.gpt_model,
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a security expert analyzing code vulnerabilities. Provide clear, actionable remediation advice.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'max_tokens': 2000,
                'temperature': 0.1
            }
            
            async with self.session.post(
                'https://api.openai.com/v1/chat/completions',
                headers=headers,
                json=data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"OpenAI API error: {response.status} - {error_text}")
                
                result = await response.json()
                analysis = self._parse_gpt_response(result)
                
                logger.info("GPT-4 analysis completed successfully")
                self.performance_monitor.end_phase('gpt')
                return analysis
                
        except Exception as e:
            self.performance_monitor.end_phase('gpt')
            logger.error(f"Error analyzing with GPT-4: {e}")
            # Fallback to basic analysis
            return self._fallback_parse(semgrep_results)
    
    async def analyze_with_gpt4_processed(self, vulnerabilities: List[Vulnerability], semgrep_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze processed vulnerabilities with GPT-4 for enterprise-grade analysis"""
        self.performance_monitor.start_phase('gpt')
        try:
            # Create prompt for GPT-4 using processed vulnerability data
            prompt = self._create_gpt_prompt_processed(vulnerabilities, semgrep_results)
            
            # Call OpenAI API
            headers = {
                'Authorization': f'Bearer {self.openai_api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': self.gpt_model,
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a senior security engineer conducting an enterprise-grade security audit for a production application. Provide clear, actionable remediation advice that would pass an enterprise security review.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'max_tokens': 3000,  # Increased for comprehensive analysis
                'temperature': 0.1
            }
            
            logger.info(f"🤖 Calling OpenAI API with {len(vulnerabilities)} processed vulnerabilities")
            logger.info(f"🤖 Model: {self.gpt_model}")
            logger.info(f"🤖 Max tokens: {data['max_tokens']}")
            
            async with self.session.post(
                'https://api.openai.com/v1/chat/completions',
                headers=headers,
                json=data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"❌ OpenAI API error: {response.status} - {error_text}")
                    raise Exception(f"OpenAI API error: {response.status} - {error_text}")
                
                result = await response.json()
                analysis = self._parse_gpt_response(result)
                
                logger.info("✅ GPT-4 analysis completed successfully")
                logger.info(f"🤖 Tokens used: {analysis.get('tokens_used', 0)}")
                self.performance_monitor.end_phase('gpt')
                return analysis
                
        except Exception as e:
            self.performance_monitor.end_phase('gpt')
            logger.error(f"❌ Error analyzing with GPT-4: {e}")
            # Fallback to basic analysis
            return self._fallback_parse_processed(vulnerabilities)
    
    def _create_gpt_prompt(self, semgrep_results: Dict[str, Any]) -> str:
        """Create enterprise-grade prompt for GPT-4 analysis"""
        findings = semgrep_results.get('results', [])
        
        if not findings:
            return """No security vulnerabilities found in the codebase. 
            
Please provide a comprehensive analysis confirming this is accurate, including:
1. What security aspects were covered in the scan
2. Any potential areas that might need manual review
3. Recommendations for ongoing security practices
4. Compliance status assessment"""
        
        # Group findings by rule for better analysi
        rule_groups = {}
        for finding in findings:
            rule_id = finding.get('check_id', 'Unknown')
            if rule_id not in rule_groups:
                rule_groups[rule_id] = []
            rule_groups[rule_id].append(finding)
        
        prompt = f"""You are a senior security engineer conducting an enterprise-grade security audit for a production application.

ANALYSIS REQUEST:
Analyze these {len(findings)} security findings from Semgrep across {len(rule_groups)} unique vulnerability types.

SCAN CONTEXT:
- This is a production application audit
- Findings will be used by developers to remediate security issues
- Need enterprise-level analysis suitable for business stakeholders

FINDINGS TO ANALYZE:
"""
        
        # Provide grouped findings for better analysis
        for rule_id, rule_findings in list(rule_groups.items())[:15]:  # Limit to first 15 rule types
            prompt += f"""
RULE: {rule_id}
OCCURRENCES: {len(rule_findings)}
SEVERITY: {rule_findings[0].get('extra', {}).get('severity', 'Unknown')}
EXAMPLES:
"""
            # Show first 3 examples of each rule type
            for i, finding in enumerate(rule_findings[:3]):
                prompt += f"""  Example {i+1}: {finding.get('path', 'Unknown')}:{finding.get('start', {}).get('line', 'Unknown')}
    Message: {finding.get('extra', {}).get('message', 'Unknown')}
"""
        
        prompt += """

REQUIRED OUTPUT FORMAT:

1. EXECUTIVE SUMMARY (Business Stakeholders):
   - Overall risk assessment (Low/Medium/High/Critical)
   - Compliance status (OWASP Top 10, CWE Top 25)
   - Business impact assessment
   - Priority remediation timeline

2. TECHNICAL ANALYSIS (Developers):
   - For each unique vulnerability type:
     * Clear description of the security risk
     * Why this vulnerability is dangerous
     * Specific code examples showing the issue
     * Step-by-step remediation with code snippets
     * Best practices to prevent similar issues

3. MASTER REMEDIATION PROMPT (Cursor/AI Assistant):
   - A comprehensive prompt that a developer can give to Cursor/GPT to fix ALL issues
   - Include context about the codebase and specific files
   - Request git-compatible diffs for each fix
   - Ask for testing recommendations

4. COMPLIANCE MAPPING:
   - Map each finding to relevant security frameworks
   - OWASP Top 10 categories
   - CWE identifiers
   - Industry best practices

5. RISK SCORING:
   - CVSS-style scoring for each vulnerability type
   - Exploitability assessment
   - Business impact rating
   - Remediation priority (P0/P1/P2/P3)

6. REMEDIATION TIMELINE:
   - Immediate fixes (P0 - fix within 24 hours)
   - High priority (P1 - fix within 1 week)
   - Medium priority (P2 - fix within 1 month)
   - Low priority (P3 - fix within 3 months)

Provide professional, actionable advice that would pass an enterprise security review."""
        
        return prompt
    
    def _parse_gpt_response(self, gpt_result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GPT-4 response into structured format"""
        try:
            content = gpt_result['choices'][0]['message']['content']
            
            return {
                'analysis': content,
                'model_used': self.gpt_model,
                'tokens_used': gpt_result.get('usage', {}).get('total_tokens', 0),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error parsing GPT response: {e}")
            return self._fallback_parse({})
    
    def _fallback_parse(self, semgrep_results: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when GPT-4 fails"""
        findings = semgrep_results.get('results', [])
        
        return {
            'analysis': f"Fallback analysis: Found {len(findings)} security issues. Please review manually.",
            'model_used': 'fallback',
            'tokens_used': 0,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _create_gpt_prompt_processed(self, vulnerabilities: List[Vulnerability], semgrep_results: Dict[str, Any]) -> str:
        """Create enterprise-grade prompt for GPT-4 analysis using processed vulnerability data"""
        
        if not vulnerabilities:
            return """No security vulnerabilities found in the codebase. 
            
Please provide a comprehensive analysis confirming this is accurate, including:
1. What security aspects were covered in the scan
2. Any potential areas that might need manual review
3. Recommendations for ongoing security practices
4. Compliance status assessment"""
        
        # Build comprehensive prompt with processed vulnerability data
        prompt = f"""You are a senior security engineer conducting an enterprise-grade security audit for a production application.

ANALYSIS REQUEST:
Analyze these {len(vulnerabilities)} security vulnerability types from a comprehensive security scan.

SCAN CONTEXT:
- This is a production application audit
- Findings will be used by developers to remediate security issues
- Need enterprise-level analysis suitable for business stakeholders
- Repository: {semgrep_results.get('paths', {}).get('scanned', [])} files scanned

VULNERABILITIES TO ANALYZE:
"""
        
        # Provide detailed vulnerability information for analysis
        for i, vuln in enumerate(vulnerabilities):
            prompt += f"""
VULNERABILITY {i+1}:
- Rule ID: {vuln.rule_id}
- Severity: {vuln.severity.upper()}
- Occurrences: {vuln.occurrences}
- Primary Location: {vuln.file_path}:{vuln.line_number}
- Security Message: {vuln.message}
- Description: {vuln.description}
- All Locations: {len(vuln.locations) if vuln.locations else 0} instances
"""
            
            # Add metadata if available
            if vuln.rule_metadata:
                metadata = vuln.rule_metadata
                prompt += f"- CWE: {metadata.get('cwe', ['N/A'])[0] if metadata.get('cwe') else 'N/A'}\n"
                prompt += f"- OWASP: {metadata.get('owasp', ['N/A'])[0] if metadata.get('owasp') else 'N/A'}\n"
                prompt += f"- Impact: {metadata.get('impact', 'N/A')}\n"
                prompt += f"- Likelihood: {metadata.get('likelihood', 'N/A')}\n"
                prompt += f"- Confidence: {metadata.get('confidence', 'N/A')}\n"
        
        prompt += """

REQUIRED OUTPUT FORMAT:

1. EXECUTIVE SUMMARY (Business Stakeholders):
   - Overall risk assessment (Low/Medium/High/Critical)
   - Compliance status (OWASP Top 10, CWE Top 25)
   - Business impact assessment
   - Priority remediation timeline

2. TECHNICAL ANALYSIS (Developers):
   - For each unique vulnerability type:
     * Clear description of the security risk
     * Why this vulnerability is dangerous
     * Specific code examples showing the issue
     * Step-by-step remediation with code snippets
     * Best practices to prevent similar issues

3. MASTER REMEDIATION PROMPT (Cursor/AI Assistant):
   - A comprehensive prompt that a developer can give to Cursor/GPT to fix ALL issues
   - Include context about the codebase and specific files
   - Request git-compatible diffs for each fix
   - Ask for testing recommendations

4. COMPLIANCE MAPPING:
   - Map each finding to relevant security frameworks
   - OWASP Top 10 categories
   - CWE identifiers
   - Industry best practices

5. RISK SCORING:
   - CVSS-style scoring for each vulnerability type
   - Exploitability assessment
   - Business impact rating
   - Remediation priority (P0/P1/P2/P3)

6. REMEDIATION TIMELINE:
   - Immediate fixes (P0 - fix within 24 hours)
   - High priority (P1 - fix within 1 week)
   - Medium priority (P2 - fix within 1 month)
   - Low priority (P3 - fix within 3 months)

Provide professional, actionable advice that would pass an enterprise security review.
Focus on practical remediation steps that developers can implement immediately."""
        
        return prompt
    
    def _fallback_parse_processed(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Fallback analysis when GPT-4 fails, using processed vulnerability data"""
        return {
            'analysis': f"Fallback analysis: Found {len(vulnerabilities)} security vulnerability types. Please review manually. Each vulnerability has been processed and categorized with severity levels and occurrence counts.",
            'model_used': 'fallback',
            'tokens_used': 0,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def generate_audit_report(self, repo_url: str, github_token: str = None) -> Dict[str, Any]:
        """Generate complete security audit report"""
        start_time = datetime.utcnow()
        
        try:
            logger.info("🔍 === AUDIT REPORT GENERATION STARTING ===")
            logger.info(f"📁 Repository: {repo_url}")
            logger.info(f"⏰ Start time: {start_time.isoformat()}")
            logger.info(f"🔑 GitHub token provided: {'Yes' if github_token else 'No'}")
            
            # Create temporary directory
            logger.info("📁 Phase 1: Creating temporary directory...")
            with tempfile.TemporaryDirectory() as temp_dir:
                logger.info(f"✅ Temporary directory created: {temp_dir}")
                
                # Clone repository
                logger.info("📥 Phase 2: Cloning repository...")
                clone_start = datetime.utcnow()
                repo_path = await self.clone_repository(repo_url, temp_dir, github_token)
                clone_duration = (datetime.utcnow() - clone_start).total_seconds()
                logger.info(f"✅ Repository cloned successfully in {clone_duration:.2f}s")
                logger.info(f"📁 Repository path: {repo_path}")
                
                # Run Semgrep scan
                logger.info("🔍 Phase 3: Starting Semgrep security scan...")
                semgrep_start = datetime.utcnow()
                semgrep_results = await self.run_semgrep_scan(repo_path)
                semgrep_duration = (datetime.utcnow() - semgrep_start).total_seconds()
                logger.info(f"✅ Semgrep scan completed in {semgrep_duration:.2f}s")
                
                # Process findings
                logger.info("⚙️ Phase 4: Processing Semgrep findings...")
                process_start = datetime.utcnow()
                findings = semgrep_results.get('results', [])
                logger.info(f"📊 Raw findings count: {len(findings)}")
                
                # DATA FLOW VALIDATION: Verify Semgrep output before proceeding
                if not isinstance(findings, list):
                    raise ValueError("Semgrep results 'results' field is not a list")
                
                logger.info("✅ Semgrep output validation passed")
                
                # DATA QUALITY VALIDATION: Validate Semgrep findings completeness
                semgrep_validation = self.data_validator.validate_semgrep_findings(findings)
                if not semgrep_validation['is_valid']:
                    self.error_handler.add_error('validation', Exception("Semgrep findings validation failed"), 
                                               f"Quality score: {semgrep_validation['quality_score']}/100")
                    logger.error(f"❌ Semgrep findings validation failed: {semgrep_validation['errors']}")
                else:
                    logger.info(f"✅ Semgrep findings validation passed (Quality: {semgrep_validation['quality_score']}/100)")
                    if semgrep_validation['warnings']:
                        for warning in semgrep_validation['warnings']:
                            self.error_handler.add_warning('validation', warning, "Semgrep findings quality")
                
                vulnerabilities = []
                
                # Group findings by rule type and count occurrences
                rule_groups = {}
                for finding in findings:
                    rule_id = finding.get('check_id', 'Unknown')
                    if rule_id not in rule_groups:
                        rule_groups[rule_id] = {
                            'findings': [],
                            'severity': finding.get('extra', {}).get('severity', 'Unknown'),
                            'message': finding.get('extra', {}).get('message', 'Unknown'),
                            'description': finding.get('extra', {}).get('description', 'No description available'),
                            'rule_metadata': finding.get('extra', {}).get('metadata', {}),
                        }
                    rule_groups[rule_id]['findings'].append(finding)
                
                logger.info(f"📊 Unique rule types found: {len(rule_groups)}")
                
                # Create condensed vulnerability entries
                for rule_id, group_data in rule_groups.items():
                    findings_list = group_data['findings']
                    
                    # Collect all line numbers and file paths for this rule
                    locations = []
                    for finding in findings_list:
                        file_path = finding.get('path', 'Unknown')
                        line_number = finding.get('start', {}).get('line', 0)
                        locations.append({
                            'file_path': file_path,
                            'line_number': line_number,
                            'message': finding.get('extra', {}).get('message', 'Unknown')
                        })
                    
                    # Create condensed vulnerability entry
                    vuln = Vulnerability(
                        rule_id=rule_id,
                        message=group_data['message'],
                        severity=group_data['severity'],
                        file_path=locations[0]['file_path'],  # Primary location
                        line_number=locations[0]['line_number'],  # Primary line
                        description=group_data['description'],
                        remediation='See GPT analysis for detailed remediation steps'
                    )
                    
                    # Add occurrence data to the vulnerability
                    vuln.occurrences = len(findings_list)
                    vuln.locations = locations
                    vuln.rule_metadata = group_data['rule_metadata']
                    
                    vulnerabilities.append(vuln)
                
                logger.info(f"✅ Processed {len(vulnerabilities)} vulnerability types")
                process_duration = (datetime.utcnow() - process_start).total_seconds()
                logger.info(f"⏱️ Processing completed in {process_duration:.2f}s")
                
                # DATA FLOW VALIDATION: Verify vulnerability data before GPT analysis
                if not vulnerabilities:
                    logger.warning("⚠️ No vulnerabilities found - proceeding with empty analysis")
                else:
                    # Validate each vulnerability has required fields
                    for i, vuln in enumerate(vulnerabilities):
                        if not vuln.rule_id or not vuln.message or not vuln.file_path:
                            logger.warning(f"⚠️ Vulnerability {i} missing required fields: rule_id={vuln.rule_id}, message={vuln.message}, file_path={vuln.file_path}")
                    
                    logger.info("✅ Vulnerability data validation passed")
                
                # Enhanced severity mapping with proper categorization
                logger.info("🎯 Phase 5: Mapping vulnerability severities...")
                def map_severity(semgrep_severity: str) -> str:
                    """Map Semgrep severity to our categories"""
                    severity_lower = semgrep_severity.lower()
                    
                    # Critical vulnerabilities
                    if severity_lower in ['critical', 'error']:
                        return 'critical'
                    # High vulnerabilities  
                    elif severity_lower in ['high', 'warning']:
                        return 'high'
                    # Medium vulnerabilities
                    elif severity_lower in ['medium', 'moderate']:
                        return 'medium'
                    # Low vulnerabilities
                    elif severity_lower in ['low', 'info', 'note']:
                        return 'low'
                    # Default to medium if unknown
                    else:
                        return 'medium'
                
                # Count vulnerabilities by mapped severity
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for vuln in vulnerabilities:
                    mapped_severity = map_severity(vuln.severity)
                    severity_counts[mapped_severity] += 1
                
                # Update vulnerability severity to mapped value
                for vuln in vulnerabilities:
                    vuln.severity = map_severity(vuln.severity)
                
                logger.info(f"✅ Severity mapping completed: {severity_counts}")
                
                # DATA FLOW VALIDATION: Final check before GPT analysis
                logger.info("🔍 Final data validation before GPT analysis...")
                logger.info(f"📊 Vulnerabilities to analyze: {len(vulnerabilities)}")
                logger.info(f"📊 Total findings processed: {len(findings)}")
                logger.info(f"📊 Severity breakdown: {severity_counts}")
                
                # Analyze with GPT-4
                logger.info("🤖 Phase 6: Starting GPT-4 analysis...")
                gpt_start = datetime.utcnow()
                
                # CRITICAL FIX: Pass processed vulnerabilities to GPT, not raw Semgrep results
                # This ensures GPT has complete, structured data to analyze
                gpt_analysis = await self.analyze_with_gpt4_processed(vulnerabilities, semgrep_results)
                
                gpt_duration = (datetime.utcnow() - gpt_start).total_seconds()
                logger.info(f"✅ GPT-4 analysis completed in {gpt_duration:.2f}s")
                logger.info(f"🤖 Model used: {gpt_analysis.get('model_used', 'Unknown')}")
                logger.info(f"🔢 Tokens used: {gpt_analysis.get('tokens_used', 0)}")
                
                # DATA QUALITY VALIDATION: Validate GPT analysis quality
                gpt_validation = self.data_validator.validate_gpt_analysis(gpt_analysis)
                if not gpt_validation['is_valid']:
                    self.error_handler.add_error('validation', Exception("GPT analysis validation failed"), 
                                               f"Quality score: {gpt_validation['quality_score']}/100")
                    logger.error(f"❌ GPT analysis validation failed: {gpt_validation['errors']}")
                else:
                    logger.info(f"✅ GPT analysis validation passed (Quality: {gpt_validation['quality_score']}/100)")
                    if gpt_validation['warnings']:
                        for warning in gpt_validation['warnings']:
                            self.error_handler.add_warning('validation', warning, "GPT analysis quality")
                
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()
                
                # Get performance summary
                performance_summary = self.performance_monitor.get_performance_summary()
                
                # Estimate resource usage based on repository characteristics
                repo_size_mb = sum(os.path.getsize(os.path.join(dirpath, filename))
                                 for dirpath, dirnames, filenames in os.walk(repo_path)
                                 for filename in filenames) / (1024 * 1024)
                
                file_count = len(semgrep_results.get('paths', {}).get('scanned', []))
                findings_count = len(findings)
                
                resource_estimation = self.performance_monitor.estimate_resource_usage(
                    repo_size_mb, file_count, findings_count
                )
                
                # Log performance metrics
                logger.info("📊 === PERFORMANCE ANALYSIS ===")
                logger.info(f"⏱️ Total duration: {duration:.2f}s")
                logger.info(f"📈 Performance score: {performance_summary['performance_score']}")
                logger.info(f"💾 Repository size: {repo_size_mb:.1f}MB")
                logger.info(f"📁 Files scanned: {file_count}")
                logger.info(f"🔍 Findings count: {findings_count}")
                logger.info(f"⚡ Resource intensity: {resource_estimation['resource_intensity']}")
                logger.info(f"🖥️ Estimated CPU cores: {resource_estimation['estimated_cpu_cores']}")
                logger.info(f"💾 Estimated memory: {resource_estimation['estimated_memory_mb']}MB")
                
                # Log expected vs actual timing
                logger.info("⏱️ Expected vs Actual timing:")
                for phase in ['clone', 'semgrep', 'gpt', 'total']:
                    if phase in performance_summary['phase_breakdown']:
                        actual = performance_summary['phase_breakdown'][phase]['duration']
                        expected = resource_estimation['expected_timings'].get(phase, 'N/A')
                        if expected != 'N/A':
                            variance = ((actual - expected) / expected) * 100
                            logger.info(f"   {phase}: {actual:.1f}s (expected: {expected}s, variance: {variance:+.1f}%)")
                        else:
                            logger.info(f"   {phase}: {actual:.1f}s")
                
                if performance_summary['performance_alerts']:
                    logger.warning("⚠️ Performance alerts detected:")
                    for alert in performance_summary['performance_alerts']:
                        logger.warning(f"   {alert}")
                else:
                    logger.info("✅ No performance issues detected")
                
                # Log phase breakdown
                logger.info("📊 Phase breakdown:")
                for phase, timing in performance_summary['phase_breakdown'].items():
                    logger.info(f"   {phase}: {timing['duration']:.2f}s")
                
                # Create summary
                summary = AuditSummary(
                    total_vulnerabilities=len(vulnerabilities),
                    critical_severity=severity_counts['critical'],
                    high_severity=severity_counts['high'],
                    medium_severity=severity_counts['medium'],
                    low_severity=severity_counts['low'],
                    files_scanned=len(semgrep_results.get('paths', {}).get('scanned', [])),
                    scan_duration=duration
                )
                
                # Create final results with performance data
                results = AuditResults(
                    summary=summary,
                    vulnerabilities=vulnerabilities,
                    repository_info={
                        'url': repo_url,
                        'name': repo_url.split('/')[-1].replace('.git', ''),
                        'scan_timestamp': start_time.isoformat()
                    },
                    scan_timestamp=end_time.isoformat(),
                    gpt_analysis=gpt_analysis
                )
                
                # Add performance data to results
                results_dict = asdict(results)
                results_dict['performance_metrics'] = performance_summary
                results_dict['resource_estimation'] = resource_estimation
                results_dict['repository_stats'] = {
                    'size_mb': round(repo_size_mb, 1),
                    'file_count': file_count,
                    'findings_count': findings_count
                }
                
                # FINAL VALIDATION: Validate complete report structure
                report_validation = self.data_validator.validate_report_structure(results_dict)
                if not report_validation['is_valid']:
                    self.error_handler.add_error('validation', Exception("Report structure validation failed"), 
                                               f"Structure score: {report_validation['structure_score']}/100")
                    logger.error(f"❌ Report structure validation failed: {report_validation['errors']}")
                else:
                    logger.info(f"✅ Report structure validation passed (Structure: {report_validation['structure_score']}/100)")
                    if report_validation['warnings']:
                        for warning in report_validation['warnings']:
                            self.error_handler.add_warning('validation', warning, "Report structure")
                
                # Add validation data to results
                results_dict['validation_summary'] = {
                    'semgrep_validation': semgrep_validation,
                    'gpt_validation': gpt_validation,
                    'report_validation': report_validation,
                    'overall_validation': self.data_validator.get_validation_summary()
                }
                
                # Add error handling summary
                results_dict['error_summary'] = self.error_handler.get_error_summary()
                
                logger.info("📊 === AUDIT REPORT GENERATION COMPLETED ===")
                logger.info(f"⏰ End time: {end_time.isoformat()}")
                logger.info(f"⏱️ Total duration: {duration:.2f}s")
                logger.info(f"📊 Breakdown:")
                logger.info(f"   📥 Cloning: {clone_duration:.2f}s")
                logger.info(f"   🔍 Semgrep: {semgrep_duration:.2f}s")
                logger.info(f"   ⚙️ Processing: {process_duration:.2f}s")
                logger.info(f"   🤖 GPT: {gpt_duration:.2f}s")
                logger.info(f"   📊 Total: {duration:.2f}s")
                logger.info(f"🎯 Vulnerabilities found: {len(vulnerabilities)}")
                logger.info(f"📁 Files scanned: {summary.files_scanned}")
                
                # Log validation summary
                logger.info("🔍 === VALIDATION SUMMARY ===")
                logger.info(f"📊 Semgrep Quality: {semgrep_validation['quality_score']}/100")
                logger.info(f"🤖 GPT Quality: {gpt_validation['quality_score']}/100")
                logger.info(f"📋 Report Structure: {report_validation['structure_score']}/100")
                logger.info(f"❌ Total Errors: {self.error_handler.get_error_summary()['total_errors']}")
                logger.info(f"⚠️ Total Warnings: {self.error_handler.get_error_summary()['total_warnings']}")
                
                return results_dict
                
        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            logger.error(f"❌ === AUDIT REPORT GENERATION FAILED ===")
            logger.error(f"❌ Error: {e}")
            logger.error(f"❌ Failed after: {duration:.2f}s")
            logger.error(f"⏰ Failure time: {end_time.isoformat()}")
            raise

async def security_audit_worker(data: Dict[str, Any]) -> Dict[str, Any]:
    """Main worker function for security audits"""
    start_time = datetime.utcnow()
    
    try:
        logger.info("🚀 === SECURITY AUDIT WORKER STARTING ===")
        logger.info(f"⏰ Start time: {start_time.isoformat()}")
        
        # Extract parameters
        repo_url = data.get('repository_url')
        github_token = data.get('github_token')  # New: Extract GitHub token
        
        if not repo_url:
            raise ValueError("repository_url is required")
        
        logger.info(f"📁 Repository URL: {repo_url}")
        logger.info(f"🔑 GitHub token provided: {'Yes' if github_token else 'No'}")
        
        # Validate repository URL
        logger.info("🔍 Phase 1: Validating repository URL...")
        if not validate_repository_url(repo_url):
            raise ValueError("Invalid or suspicious repository URL")
        
        logger.info("✅ Repository URL validation passed")
        
        # Get API keys from environment
        logger.info("🔑 Phase 2: Validating environment variables...")
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        gpt_model = os.environ.get('GPT_MODEL', 'gpt-4o')
        
        logger.info(f"🔑 OpenAI API Key present: {'YES' if openai_api_key else 'NO'}")
        logger.info(f"🤖 GPT Model: {gpt_model}")
        
        if not openai_api_key:
            logger.error("❌ OPENAI_API_KEY environment variable is missing!")
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        logger.info("✅ OpenAI API key validation passed")
        
        # Create auditor and run analysis
        logger.info("🚀 Phase 3: Creating SecurityAuditor instance...")
        async with SecurityAuditor(openai_api_key, gpt_model) as auditor:
            logger.info("✅ SecurityAuditor created successfully")
            
            logger.info("🔍 Phase 4: Starting audit report generation...")
            results = await auditor.generate_audit_report(repo_url, github_token)
            
            logger.info("✅ Audit report generated successfully")
            
            # Calculate total duration
            end_time = datetime.utcnow()
            total_duration = (end_time - start_time).total_seconds()
            
            logger.info(f"⏰ End time: {end_time.isoformat()}")
            logger.info(f"⏱️ Total audit duration: {total_duration:.2f} seconds")
            logger.info("🏁 === SECURITY AUDIT WORKER COMPLETED ===")
            
            # Convert to dict for JSON serialization
            return asdict(results)
            
    except Exception as e:
        end_time = datetime.utcnow()
        total_duration = (end_time - start_time).total_seconds()
        
        logger.error(f"❌ === SECURITY AUDIT WORKER FAILED ===")
        logger.error(f"❌ Worker error: {e}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        logger.error(f"❌ Error details: {str(e)}")
        logger.error(f"⏱️ Failed after: {total_duration:.2f} seconds")
        logger.error(f"⏰ Failure time: {end_time.isoformat()}")
        
        return {
            'error': str(e),
            'error_type': type(e).__name__,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_until_failure': total_duration
        }

# Create Flask app
app = Flask(__name__)

# Add CORS headers
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    allowed_origins = [
        'http://localhost:9002',
        'http://localhost:3000',
        'https://vibecatcher.dev',
        'http://vibecatcher.dev'
    ]
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:9002'  # Default fallback
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['OPTIONS'])
def handle_options():
    origin = request.headers.get('Origin')
    allowed_origins = [
        'http://localhost:9002',
        'http://localhost:3000',
        'https://vibecatcher.dev',
        'http://vibecatcher.dev'
    ]
    
    response = jsonify({'status': 'ok'})
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:9002'  # Default fallback
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint for Cloud Run"""
    return jsonify({
        'status': 'healthy',
        'service': 'security-audit-worker',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/', methods=['POST'])
def security_audit():
    """Main endpoint for security audits"""
    try:
        logger.info("🌐 POST request received for security audit")
        logger.info(f"📋 Request headers: {dict(request.headers)}")
        
        data = request.get_json()
        if not data:
            logger.error("❌ No JSON data provided in request")
            return jsonify({'error': 'No data provided'}), 400
        
        logger.info(f"📥 Request data: {data}")
        
        # Run the audit
        logger.info("🚀 Starting async audit worker...")
        result = asyncio.run(security_audit_worker(data))
        logger.info(f"✅ Audit worker completed with result: {result}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"❌ HTTP handler error: {e}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        return jsonify({'error': str(e), 'error_type': type(e).__name__}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=False)
