import os
import json
import asyncio
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any
from datetime import datetime
import logging
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MAX_REPO_SIZE_MB = 500
MAX_SCAN_TIME_SECONDS = 600  # 10 minutes
ALLOWED_REPO_DOMAINS = ['github.com', 'gitlab.com', 'bitbucket.org']

class SecurityScanner:
    """Enterprise-grade security scanner using Semgrep"""
    
    def __init__(self):
        # Enterprise security rule sets for indie developers and micro-SaaS
        self.security_rules = [
            'p/owasp-top-ten',           # OWASP Top 10 vulnerabilities
            'p/secrets',                  # Hardcoded secrets and credentials
            'p/security-audit',           # Security audit patterns
            'p/javascript',               # JavaScript/Node.js security
            'p/typescript',               # TypeScript security
            'p/react',                    # React security patterns
            'p/nextjs',                   # Next.js specific security
            'p/nodejs',                   # Node.js security
            'p/express',                  # Express.js security
            'p/api-security',             # API security patterns
            'p/authentication',           # Authentication vulnerabilities
            'p/authorization',            # Authorization issues
            'p/input-validation',         # Input validation problems
            'p/sql-injection',            # SQL injection patterns
            'p/xss',                      # Cross-site scripting
            'p/csrf',                     # CSRF vulnerabilities
            'p/ssrf',                     # Server-side request forgery
            'p/deserialization',          # Insecure deserialization
            'p/command-injection',        # Command injection
            'p/path-traversal',           # Path traversal attacks
            'p/xxe',                      # XML external entity
            'p/weak-crypto',              # Weak cryptography
            'p/hardcoded-secrets',        # Hardcoded secrets
            'p/dependency-vulnerabilities', # Dependency issues
            'p/cloud-security',           # Cloud security patterns
            'p/container-security',       # Docker/K8s security
        ]
    
    def validate_repository_url(self, url: str) -> bool:
        """Validate repository URL for security and format"""
        try:
            if not url.startswith(('https://', 'http://')):
                return False
            
            domain = url.split('/')[2]
            if domain not in ALLOWED_REPO_DOMAINS:
                return False
            
            if any(pattern in url.lower() for pattern in ['..', '~', 'localhost', '127.0.0.1']):
                return False
                
            return True
        except Exception:
            return False
    
    async def clone_repository(self, repo_url: str, temp_dir: str, github_token: str = None) -> str:
        """Clone repository to temporary directory"""
        logger.info(f"📥 Cloning repository: {repo_url}")
        
        # Extract repo name from URL
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        if not repo_name or len(repo_name) > 100:
            raise ValueError("Invalid repository name")
        
        repo_path = os.path.join(temp_dir, repo_name)
        
        # Prepare clone command
        clone_command = ['git', 'clone', '--depth', '1', '--single-branch']
        
        if github_token:
            # For private repos, use token-based authentication
            if repo_url.startswith('https://github.com/'):
                path_part = repo_url.replace('https://github.com/', '')
                authenticated_url = f"https://{github_token}@github.com/{path_part}"
                clone_command.append(authenticated_url)
            else:
                clone_command.append(repo_url)
        else:
            clone_command.append(repo_url)
        
        clone_command.append(repo_path)
        
        # Clone repository
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
        
        logger.info(f"✅ Repository cloned successfully: {repo_size_mb:.1f}MB")
        return repo_path
    
    async def run_semgrep_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run comprehensive Semgrep security scan"""
        logger.info(f"🔍 Starting Semgrep security scan...")
        
        # Build scan command
        scan_command = [
            'semgrep', 'scan',
            '--json',
            '--timeout', '600',
            '--max-memory', '4096',
            '--verbose',
            '--metrics', 'off',
            '--no-git-ignore',
            '--no-ignore',
        ]
        
        # Add file type includes
        file_types = [
            '*.py', '*.js', '*.ts', '*.tsx', '*.jsx', '*.go', '*.java',
            '*.php', '*.rb', '*.yml', '*.yaml', '*.json', '*.xml',
            '*.sh', 'Dockerfile', '*.dockerfile', '*.md', '*.txt'
        ]
        
        for file_type in file_types:
            scan_command.extend(['--include', file_type])
        
        # Add security rules
        for rule in self.security_rules:
            scan_command.extend(['--config', rule])
        
        # Add target path
        scan_command.append(repo_path)
        
        logger.info(f"🔍 Running scan with {len(self.security_rules)} security rule sets")
        
        # Execute Semgrep scan
        process = await asyncio.create_subprocess_exec(
            *scan_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=MAX_SCAN_TIME_SECONDS)
        except asyncio.TimeoutError:
            process.kill()
            raise Exception("Semgrep scan timed out")
        
        if process.returncode != 0 and process.returncode != 1:  # Semgrep returns 1 for findings
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise Exception(f"Semgrep scan failed: {error_msg}")
        
        # Parse results
        scan_results = json.loads(stdout.decode())
        findings_count = len(scan_results.get('results', []))
        files_scanned = len(scan_results.get('paths', {}).get('scanned', []))
        
        logger.info(f"✅ Scan completed: {findings_count} findings in {files_scanned} files")
        
        return scan_results
    
    def process_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and organize Semgrep findings"""
        findings = scan_results.get('results', [])
        
        if not findings:
            return {
                'summary': {
                    'total_findings': 0,
                    'files_scanned': len(scan_results.get('paths', {}).get('scanned', [])),
                    'scan_duration': scan_results.get('stats', {}).get('time', {}).get('total', 0),
                    'rules_executed': scan_results.get('stats', {}).get('rules', {}).get('total', 0)
                },
                'findings': [],
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'raw_semgrep_output': scan_results
            }
        
        # Group findings by severity
        severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
        
        for finding in findings:
            severity = finding.get('extra', {}).get('severity', 'medium').lower()
            
            # Map Semgrep severity to our categories
            if severity in ['critical', 'error']:
                mapped_severity = 'critical'
            elif severity in ['high', 'warning']:
                mapped_severity = 'high'
            elif severity in ['medium', 'moderate']:
                mapped_severity = 'medium'
            else:
                mapped_severity = 'low'
            
            severity_groups[mapped_severity].append(finding)
        
        # Create processed findings
        processed_findings = []
        for severity, findings_list in severity_groups.items():
            for finding in findings_list:
                processed_finding = {
                    'rule_id': finding.get('check_id', 'Unknown'),
                    'severity': severity.upper(),
                    'message': finding.get('extra', {}).get('message', 'No message'),
                    'description': finding.get('extra', {}).get('description', 'No description'),
                    'file_path': finding.get('path', 'Unknown'),
                    'line_number': finding.get('start', {}).get('line', 0),
                    'end_line': finding.get('end', {}).get('line', 0),
                    'code_snippet': finding.get('extra', {}).get('lines', 'No code available'),
                    'cwe_ids': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                    'owasp_ids': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'impact': finding.get('extra', {}).get('metadata', {}).get('impact', 'Unknown'),
                    'likelihood': finding.get('extra', {}).get('metadata', {}).get('likelihood', 'Unknown'),
                    'confidence': finding.get('extra', {}).get('metadata', {}).get('confidence', 'Unknown')
                }
                processed_findings.append(processed_finding)
        
        # Count by severity
        severity_counts = {severity: len(findings) for severity, findings in severity_groups.items()}
        
        return {
            'summary': {
                'total_findings': len(findings),
                'files_scanned': len(scan_results.get('paths', {}).get('scanned', [])),
                'scan_duration': scan_results.get('stats', {}).get('time', {}).get('total', 0),
                'rules_executed': scan_results.get('stats', {}).get('rules', {}).get('total', 0)
            },
            'findings': processed_findings,
            'severity_breakdown': severity_counts,
            'raw_semgrep_output': scan_results
        }
    
    async def scan_repository(self, repo_url: str, github_token: str = None) -> Dict[str, Any]:
        """Main method to scan a repository for security vulnerabilities"""
        start_time = datetime.utcnow()
        
        try:
            logger.info(f"🚀 Starting security scan for: {repo_url}")
            
            # Validate URL
            if not self.validate_repository_url(repo_url):
                raise ValueError("Invalid or suspicious repository URL")
            
            # Create temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository
                repo_path = await self.clone_repository(repo_url, temp_dir, github_token)
                
                # Run Semgrep scan
                scan_results = await self.run_semgrep_scan(repo_path)
                
                # Process findings
                processed_results = self.process_findings(scan_results)
                
                # Add metadata
                processed_results['repository_info'] = {
                    'url': repo_url,
                    'name': repo_url.split('/')[-1].replace('.git', ''),
                    'scan_timestamp': start_time.isoformat()
                }
                
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()
                
                logger.info(f"✅ Security scan completed in {duration:.2f}s")
                logger.info(f"📊 Found {processed_results['summary']['total_findings']} security issues")
                
                return processed_results
                
        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            logger.error(f"❌ Security scan failed after {duration:.2f}s: {e}")
            
            return {
                'error': str(e),
                'error_type': type(e).__name__,
                'scan_duration': duration,
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
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:9002'
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['OPTIONS'])
def handle_options():
    response = jsonify({'status': 'ok'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'enterprise-semgrep-scanner',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })

@app.route('/', methods=['POST'])
def security_scan():
    """Main endpoint for security scans"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        repo_url = data.get('repository_url')
        github_token = data.get('github_token')
        
        if not repo_url:
            return jsonify({'error': 'repository_url is required'}), 400
        
        # Run the scan
        scanner = SecurityScanner()
        result = asyncio.run(scanner.scan_repository(repo_url, github_token))
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"HTTP handler error: {e}")
        return jsonify({'error': str(e), 'error_type': type(e).__name__}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=False)
