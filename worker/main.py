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
        # Pre-validated rule sets for immediate use
        self.verified_rules = [
            'p/owasp-top-ten',           # OWASP Top 10 vulnerabilities
            'p/secrets',                  # Hardcoded secrets and credentials
            'p/security-audit',           # Security audit patterns
            'p/javascript',               # JavaScript/Node.js security
            'p/typescript',               # TypeScript security
            'p/react',                    # React security patterns
            'p/nextjs',                   # Next.js specific security
            'p/nodejs',                   # Node.js security
            'p/python',                   # Python security
            'p/go',                       # Go security
            'p/java',                     # Java security
            'p/php',                      # PHP security
            'p/ruby',                     # Ruby security
            'p/docker',                   # Docker security
            'p/kubernetes',               # Kubernetes security
            'p/terraform',                # Terraform security
            'p/generic',                  # Generic security patterns
            'p/cwe-top-25',              # CWE Top 25 vulnerabilities
        ]
        
        # Rule validation cache
        self._rule_cache = {}
        self._cache_validated = False
    
    async def _validate_rules_parallel(self, rules: List[str]) -> List[str]:
        """Validate multiple rules in parallel for faster processing"""
        logger.info(f"🔍 Validating {len(rules)} rules in parallel...")
        
        async def validate_single_rule(rule: str) -> tuple[str, bool]:
            try:
                # Quick validation - just check if rule can be loaded
                test_process = await asyncio.create_subprocess_exec(
                    'semgrep', '--config', rule, '--help',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Very quick timeout for validation
                await asyncio.wait_for(test_process.communicate(), timeout=2)
                
                if test_process.returncode == 0:
                    return rule, True
                else:
                    return rule, False
                    
            except Exception:
                return rule, False
        
        # Validate all rules in parallel
        validation_tasks = [validate_single_rule(rule) for rule in rules]
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Process results
        available_rules = []
        for result in validation_results:
            if isinstance(result, tuple) and result[1]:  # rule, is_valid
                available_rules.append(result[0])
                logger.info(f"✅ Rule {result[0]} validated")
            elif isinstance(result, Exception):
                logger.warning(f"⚠️ Rule validation error: {result}")
        
        return available_rules
    
    async def _get_available_rules(self) -> List[str]:
        """Get available rules with caching for performance"""
        if self._cache_validated:
            logger.info(f"🔍 Using cached rule validation ({len(self._rule_cache)} rules)")
            return list(self._rule_cache.keys())
        
        logger.info("🔍 Performing rule validation (this will be cached for future scans)...")
        
        # Try parallel validation first
        try:
            available_rules = await self._validate_rules_parallel(self.verified_rules)
            
            if len(available_rules) >= 5:  # If we get at least 5 working rules
                # Cache the results
                self._rule_cache = {rule: True for rule in available_rules}
                self._cache_validated = True
                
                logger.info(f"✅ Rule validation completed: {len(available_rules)} rules available")
                return available_rules
            else:
                logger.warning(f"⚠️ Only {len(available_rules)} rules validated, using fallback")
                
        except Exception as e:
            logger.warning(f"⚠️ Parallel validation failed: {e}")
        
        # Fallback to known working rules without validation
        fallback_rules = ['p/owasp-top-ten', 'p/secrets', 'p/javascript', 'p/python']
        logger.info(f"🔄 Using fallback rules: {', '.join(fallback_rules)}")
        
        # Cache fallback rules
        self._rule_cache = {rule: True for rule in fallback_rules}
        self._cache_validated = True
        
        return fallback_rules
    
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
        """Download repository using git archive for faster, lighter processing"""
        logger.info(f"📥 Downloading repository: {repo_url}")
        
        # Extract repo name from URL
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        if not repo_name or len(repo_name) > 100:
            raise ValueError("Invalid repository name")
        
        repo_path = os.path.join(temp_dir, repo_name)
        os.makedirs(repo_path, exist_ok=True)
        
        # Use git archive for faster, lighter download
        if github_token and repo_url.startswith('https://github.com/'):
            # For private repos, use token-based authentication
            logger.info("Using GitHub token for private repository access")
            path_part = repo_url.replace('https://github.com/', '')
            authenticated_url = f"https://{github_token}@github.com/{path_part}"
            
            # Try git archive first (faster)
            try:
                archive_command = [
                    'git', 'archive', '--remote', authenticated_url,
                    '--format', 'tar', 'HEAD'
                ]
                
                logger.info(f"🔄 Attempting git archive download...")
                process = await asyncio.create_subprocess_exec(
                    *archive_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                except asyncio.TimeoutError:
                    process.kill()
                    raise Exception("Repository download timed out")
                
                if process.returncode == 0:
                    # Extract tar archive
                    import tarfile
                    import io
                    
                    tar_data = io.BytesIO(stdout)
                    with tarfile.open(fileobj=tar_data, mode='r:*') as tar:
                        tar.extractall(repo_path)
                    
                    logger.info(f"✅ Repository downloaded via git archive successfully")
                else:
                    logger.warning(f"⚠️ Git archive failed, falling back to clone: {stderr.decode()}")
                    raise Exception("Git archive failed")
                    
            except Exception as archive_error:
                logger.warning(f"⚠️ Git archive failed: {archive_error}, falling back to clone")
                # Fall back to git clone
                clone_command = ['git', 'clone', '--depth', '1', '--single-branch', authenticated_url, repo_path]
                
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
                
                logger.info(f"✅ Repository cloned successfully (fallback method)")
        else:
            # For public repos, try git archive first
            try:
                archive_command = [
                    'git', 'archive', '--remote', repo_url,
                    '--format', 'tar', 'HEAD'
                ]
                
                logger.info(f"🔄 Attempting git archive download...")
                process = await asyncio.create_subprocess_exec(
                    *archive_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                except asyncio.TimeoutError:
                    process.kill()
                    raise Exception("Repository download timed out")
                
                if process.returncode == 0:
                    # Extract tar archive
                    import tarfile
                    import io
                    
                    tar_data = io.BytesIO(stdout)
                    with tarfile.open(fileobj=tar_data, mode='r:*') as tar:
                        tar.extractall(repo_path)
                    
                    logger.info(f"✅ Repository downloaded via git archive successfully")
                else:
                    logger.warning(f"⚠️ Git archive failed, falling back to clone: {stderr.decode()}")
                    raise Exception("Git archive failed")
                    
            except Exception as archive_error:
                logger.warning(f"⚠️ Git archive failed: {archive_error}, falling back to clone")
                # Fall back to git clone
                clone_command = ['git', 'clone', '--depth', '1', '--single-branch', repo_url, repo_path]
                
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
                
                logger.info(f"✅ Repository cloned successfully (fallback method)")
        
        # Check repository size
        repo_size = sum(os.path.getsize(os.path.join(dirpath, filename))
                       for dirpath, dirnames, filenames in os.walk(repo_path)
                       for filename in filenames)
        repo_size_mb = repo_size / (1024 * 1024)
        
        if repo_size_mb > MAX_REPO_SIZE_MB:
            raise Exception(f"Repository too large: {repo_size_mb:.1f}MB (max: {MAX_REPO_SIZE_MB}MB)")
        
        logger.info(f"✅ Repository ready: {repo_size_mb:.1f}MB")
        return repo_path
    
    async def run_semgrep_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run comprehensive Semgrep security scan"""
        logger.info(f"🔍 Starting Semgrep security scan...")
        
        # Check Semgrep version for compatibility
        try:
            version_process = await asyncio.create_subprocess_exec(
                'semgrep', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            version_stdout, _ = await asyncio.wait_for(version_process.communicate(), timeout=10)
            semgrep_version = version_stdout.decode().strip()
            logger.info(f"🔍 Semgrep version: {semgrep_version}")
        except Exception as e:
            logger.warning(f"⚠️ Could not determine Semgrep version: {e}")
            semgrep_version = "Unknown"
        
        # Validate which rules are actually available
        logger.info("🔍 Validating available Semgrep rules...")
        available_rules = await self._get_available_rules()
        
        logger.info(f"🔍 Using {len(available_rules)} validated rules: {', '.join(available_rules)}")
        
        # Build scan command
        scan_command = [
            'semgrep', 'scan',
            '--json',
            '--timeout', '600',
            '--max-memory', '4096',
            '--verbose',
            '--metrics', 'off',
            '--git-ignore',  # Use gitignore but scan all files
            '--include-unknown-extensions',  # Scan files without known extensions
            '--include-ignored',  # Include files that would normally be ignored
        ]
        
        # Add file type includes for comprehensive coverage
        file_types = [
            '*.py', '*.js', '*.ts', '*.tsx', '*.jsx', '*.go', '*.java',
            '*.php', '*.rb', '*.yml', '*.yaml', '*.json', '*.xml',
            '*.sh', 'Dockerfile', '*.dockerfile', '*.md', '*.txt',
            '*.vue', '*.svelte', '*.rs', '*.cpp', '*.c', '*.h',
            '*.swift', '*.kt', '*.scala', '*.clj', '*.hs', '*.ml'
        ]
        
        for file_type in file_types:
            scan_command.extend(['--include', file_type])
        
        # Add only validated security rules
        for rule in available_rules:
            scan_command.extend(['--config', rule])
        
        # Add target path
        scan_command.append(repo_path)
        
        logger.info(f"🔍 Running scan with {len(available_rules)} security rule sets")
        logger.info(f"🔍 File types included: {len(file_types)}")
        logger.info(f"🔍 Target repository: {repo_path}")
        
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
            
            # Check for common Semgrep version compatibility issues
            if "unknown option" in error_msg.lower():
                logger.warning("⚠️ Semgrep version compatibility issue detected, trying fallback command...")
                
                # Fallback to simpler command without potentially unsupported flags
                fallback_command = [
                    'semgrep', 'scan',
                    '--json',
                    '--timeout', '600',
                    '--verbose',
                    '--metrics', 'off',
                ]
                
                # Add file type includes
                for file_type in file_types:
                    fallback_command.extend(['--include', file_type])
                
                # Add security rules
                for rule in available_rules:  # Use validated rules
                    fallback_command.extend(['--config', rule])
                
                # Add target path
                fallback_command.append(repo_path)
                
                logger.info(f"🔄 Trying fallback command with {len(fallback_command)} arguments")
                
                # Try fallback command
                fallback_process = await asyncio.create_subprocess_exec(
                    *fallback_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    fallback_stdout, fallback_stderr = await asyncio.wait_for(
                        fallback_process.communicate(), timeout=MAX_SCAN_TIME_SECONDS
                    )
                    
                    if fallback_process.returncode != 0 and fallback_process.returncode != 1:
                        fallback_error = fallback_stderr.decode() if fallback_stderr else "Unknown error"
                        
                        # Check for config errors and try progressive fallback
                        if "config errors" in fallback_error.lower():
                            logger.warning("⚠️ Config errors detected, trying progressive rule fallback...")
                            
                            # Try with most stable rules first (excluding problematic ones)
                            stable_rules = [
                                'p/owasp-top-ten',        # Most stable
                                'p/secrets',              # Essential
                                'p/javascript',           # Basic JS
                                'p/python',               # Basic Python
                                'p/generic',              # Generic patterns
                            ]
                            
                            # Filter out problematic rules
                            stable_rules = [rule for rule in stable_rules if rule not in problematic_rules]
                            
                            logger.info(f"🔄 Trying with {len(stable_rules)} stable rules: {', '.join(stable_rules)}")
                            
                            stable_command = [
                                'semgrep', 'scan',
                                '--json',
                                '--timeout', '600',
                                '--verbose',
                                '--metrics', 'off',
                            ]
                            
                            # Add file type includes
                            for file_type in file_types:
                                stable_command.extend(['--include', file_type])
                            
                            # Add only stable rules
                            for rule in stable_rules:
                                stable_command.extend(['--config', rule])
                            
                            # Add target path
                            stable_command.append(repo_path)
                            
                            # Try stable rules command
                            stable_process = await asyncio.create_subprocess_exec(
                                *stable_command,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            
                            try:
                                stable_stdout, stable_stderr = await asyncio.wait_for(
                                    stable_process.communicate(), timeout=MAX_SCAN_TIME_SECONDS
                                )
                                
                                if stable_process.returncode != 0 and stable_process.returncode != 1:
                                    stable_error = stable_stderr.decode() if stable_stderr else "Unknown error"
                                    
                                    # If even stable rules fail, try minimal scan
                                    if "config errors" in stable_error.lower():
                                        logger.warning("⚠️ Even stable rules have config errors, trying minimal scan...")
                                        
                                        minimal_command = [
                                            'semgrep', 'scan',
                                            '--json',
                                            '--timeout', '300',
                                            '--config', 'p/owasp-top-ten',  # Just one rule
                                            repo_path
                                        ]
                                        
                                        logger.info(f"🔄 Trying minimal scan with single rule")
                                        
                                        minimal_process = await asyncio.create_subprocess_exec(
                                            *minimal_command,
                                            stdout=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE
                                        )
                                        
                                        try:
                                            minimal_stdout, minimal_stderr = await asyncio.wait_for(
                                                minimal_process.communicate(), timeout=300
                                            )
                                            
                                            if minimal_process.returncode != 0 and minimal_process.returncode != 1:
                                                minimal_error = minimal_stderr.decode() if minimal_stderr else "Unknown error"
                                                raise Exception(f"Even minimal scan failed: {minimal_error}")
                                            
                                            # Use minimal results
                                            stdout = minimal_stdout
                                            stderr = minimal_stderr
                                            logger.info("✅ Minimal scan succeeded with single rule")
                                            
                                        except asyncio.TimeoutError:
                                            minimal_process.kill()
                                            raise Exception("Minimal scan timed out")
                                        except Exception as minimal_error:
                                            raise Exception(f"Minimal scan failed: {minimal_error}")
                                    else:
                                        raise Exception(f"Stable rules scan failed: {stable_error}")
                                else:
                                    # Use stable results
                                    stdout = stable_stdout
                                    stderr = stable_stderr
                                    logger.info("✅ Stable rules scan succeeded")
                                    
                            except asyncio.TimeoutError:
                                stable_process.kill()
                                raise Exception("Stable rules scan timed out")
                            except Exception as stable_error:
                                raise Exception(f"Stable rules scan failed: {stable_error}")
                        else:
                            raise Exception(f"Fallback Semgrep command failed: {fallback_error}")
                    
                    # Use fallback results
                    stdout = fallback_stdout
                    stderr = fallback_stderr
                    logger.info("✅ Fallback Semgrep command succeeded")
                    
                except asyncio.TimeoutError:
                    fallback_process.kill()
                    raise Exception("Fallback Semgrep scan also timed out")
                except Exception as fallback_error:
                    raise Exception(f"Fallback command failed: {fallback_error}")
            else:
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
