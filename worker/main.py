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
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=300)  # 5 minute timeout
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def clone_repository(self, repo_url: str, temp_dir: str) -> str:
        """Clone repository to temporary directory with security checks"""
        try:
            # Validate repository URL
            if not validate_repository_url(repo_url):
                raise ValueError("Invalid or suspicious repository URL")
            
            # Extract repo name from URL
            repo_name = repo_url.split('/')[-1].replace('.git', '')
            if not repo_name or len(repo_name) > 100:
                raise ValueError("Invalid repository name")
            
            repo_path = os.path.join(temp_dir, repo_name)
            
            # Clone with timeout and security flags
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--single-branch', repo_url, repo_path,
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
            return repo_path
            
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            raise
    
    async def run_semgrep_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run comprehensive Semgrep security scan with enterprise-grade rules"""
        try:
            # Use comprehensive security rules for enterprise-level scanning
            semgrep_rules = [
                'p/security-audit',      # Security audit rules
                'p/owasp-top-ten',       # OWASP Top 10
                'p/secrets',             # Secrets detection
                'p/javascript',          # JavaScript security
                'p/python',              # Python security
                'p/php',                 # PHP security
                'p/java',                # Java security
                'p/go',                  # Go security
                'p/ruby',                # Ruby security
            ]
            
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
            for rule in semgrep_rules:
                scan_command.extend(['--config', rule])
            
            # Add target path
            scan_command.append(repo_path)
            
            logger.info(f"🔍 Running comprehensive Semgrep scan with {len(semgrep_rules)} rule sets...")
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
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error running Semgrep scan: {e}")
            raise
    
    async def analyze_with_gpt4(self, semgrep_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Semgrep results with GPT-4"""
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
                return analysis
                
        except Exception as e:
            logger.error(f"Error analyzing with GPT-4: {e}")
            # Fallback to basic analysis
            return self._fallback_parse(semgrep_results)
    
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
    
    async def generate_audit_report(self, repo_url: str) -> AuditResults:
        """Generate complete security audit report"""
        start_time = datetime.utcnow()
        
        try:
            # Create temporary director
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository
                repo_path = await self.clone_repository(repo_url, temp_dir)
                
                # Run Semgrep scan
                semgrep_results = await self.run_semgrep_scan(repo_path)
                
                # Analyze with GPT-4
                gpt_analysis = await self.analyze_with_gpt4(semgrep_results)
                
                # Process findings with enterprise-grade analysis
                findings = semgrep_results.get('results', [])
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
                
                # Create condensed vulnerability entries
                for rule_id, group_data in rule_groups.items():
                    findings_list = group_data['findings']
                    first_finding = findings_list[0]
                    
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
                
                # Enhanced severity mapping with proper categorization
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
                
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()
                
                summary = AuditSummary(
                    total_vulnerabilities=len(vulnerabilities),
                    critical_severity=severity_counts['critical'],
                    high_severity=severity_counts['high'],
                    medium_severity=severity_counts['medium'],
                    low_severity=severity_counts['low'],
                    files_scanned=len(semgrep_results.get('paths', {}).get('scanned', [])),
                    scan_duration=duration
                )
                
                # Create final results
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
                
                logger.info(f"Audit completed successfully in {duration:.2f} seconds")
                return results
                
        except Exception as e:
            logger.error(f"Error generating audit report: {e}")
            raise

async def security_audit_worker(data: Dict[str, Any]) -> Dict[str, Any]:
    """Main worker function for security audits"""
    try:
        logger.info("🔍 Starting security audit worker...")
        
        # Extract parameters
        repo_url = data.get('repository_url')
        if not repo_url:
            raise ValueError("repository_url is required")
        
        logger.info(f"📁 Repository URL: {repo_url}")
        
        # Validate repository URL
        if not validate_repository_url(repo_url):
            raise ValueError("Invalid or suspicious repository URL")
        
        logger.info("✅ Repository URL validation passed")
        
        # Get API keys from environment
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        gpt_model = os.environ.get('GPT_MODEL', 'gpt-4o')
        
        logger.info(f"🔑 OpenAI API Key present: {'YES' if openai_api_key else 'NO'}")
        logger.info(f"🤖 GPT Model: {gpt_model}")
        
        if not openai_api_key:
            logger.error("❌ OPENAI_API_KEY environment variable is missing!")
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        logger.info("✅ OpenAI API key validation passed")
        
        # Create auditor and run analysis
        logger.info("🚀 Creating SecurityAuditor instance...")
        async with SecurityAuditor(openai_api_key, gpt_model) as auditor:
            logger.info("✅ SecurityAuditor created successfully")
            
            logger.info("🔍 Starting audit report generation...")
            results = await auditor.generate_audit_report(repo_url)
            
            logger.info("✅ Audit report generated successfully")
            
            # Convert to dict for JSON serialization
            return asdict(results)
            
    except Exception as e:
        logger.error(f"❌ Worker error: {e}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        logger.error(f"❌ Error details: {str(e)}")
        return {
            'error': str(e),
            'error_type': type(e).__name__,
            'timestamp': datetime.utcnow().isoformat()
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
