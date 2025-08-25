"""
VibeCatcher Security Scanner - Clean Orchestrator
Replaces the broken monolithic worker with a focused orchestrator
"""

import os
import json
import asyncio
import logging
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, List
import firebase_admin
from firebase_admin import credentials, firestore, storage
import requests
from urllib.parse import urlparse
import tarfile
import zipfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Firebase (prefer Application Default Credentials on Cloud Run)
try:
    firebase_admin.get_app()
except ValueError:
    try:
        cred_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
            firebase_admin.initialize_app(cred)
        else:
            # Use ADC when running on Cloud Run / GCP
            firebase_admin.initialize_app()
    except Exception:
        # Fallback: initialize without explicit creds (ADC)
        firebase_admin.initialize_app()

db = firestore.client()
try:
    bucket = storage.bucket()
except Exception:
    bucket = None

class SecurityScanOrchestrator:
    """Clean orchestrator that coordinates 5 specialized security scanners"""
    
    def __init__(self):
        self.audit_id = None
        self.repo_url = None
        self.scan_id = None
        
    async def start_scan(self, repo_url: str, github_token: str = None, user_id: str = None) -> Dict[str, Any]:
        """Main entry point - orchestrates the entire security scan"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting security scan for: {repo_url}")
        
        try:
            # If no github_token provided, try to resolve via user_id from Firestore
            if not github_token and user_id:
                try:
                    token_doc = db.collection('users').document(user_id).get()
                    if token_doc.exists:
                        data = token_doc.to_dict() or {}
                        candidate = data.get('githubAccessToken')
                        if isinstance(candidate, str) and len(candidate) > 10:
                            github_token = candidate
                            logger.info("🔐 GitHub token resolved from server-side store for user")
                        else:
                            logger.warning("⚠️ No GitHub token found for user; proceeding without token (public repos only)")
                    else:
                        logger.warning("⚠️ User document not found when resolving GitHub token")
                except Exception as resolve_err:
                    logger.warning(f"⚠️ Failed to resolve GitHub token for user: {resolve_err}")

            # Step 1: Create scan record
            self.scan_id = await self._create_scan_record(repo_url)
            logger.info(f"✅ Created scan record: {self.scan_id}")
            
            # Step 2: Download repository
            repo_path = await self._download_repository(repo_url, github_token)
            logger.info(f"✅ Downloaded repository to: {repo_path}")
            
            # Step 3: Run all 5 scanners in parallel
            scanner_results = await self._run_scanners(repo_path)
            logger.info(f"✅ All scanners completed: {len(scanner_results)} results")
            
            # Step 4: Aggregate results
            aggregated_findings = await self._aggregate_findings(scanner_results)
            logger.info(f"✅ Aggregated findings: {len(aggregated_findings)} total")
            
            # Step 5: Generate AI summary
            final_report = await self._generate_ai_summary(aggregated_findings, repo_path)
            logger.info(f"✅ AI summary generated")
            
            # Step 6: Save final results
            await self._save_final_results(final_report)
            logger.info(f"✅ Final results saved")
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"🎉 Scan completed successfully in {scan_duration:.1f}s")
            
            return {
                'scan_id': self.scan_id,
                'status': 'completed',
                'findings_count': len(aggregated_findings),
                'scan_duration': scan_duration,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            await self._mark_scan_failed(str(e))
            return {
                'scan_id': self.scan_id,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def _create_scan_record(self, repo_url: str) -> str:
        """Create a new scan record in Firestore"""
        scan_ref = db.collection('security_scans').document()
        scan_data = {
            'repo_url': repo_url,
            'status': 'running',
            'started_at': firestore.SERVER_TIMESTAMP,
            'scanners': ['secrets', 'auth', 'webapp', 'deps', 'deployment'],
            'progress': {
                'secrets': 'pending',
                'auth': 'pending', 
                'webapp': 'pending',
                'deps': 'pending',
                'deployment': 'pending'
            }
        }
        scan_ref.set(scan_data)
        return scan_ref.id
    
    async def _download_repository(self, repo_url: str, github_token: str = None) -> str:
        """Download repository to temporary directory"""
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix=f"vibecatcher_scan_")
        
        try:
            # Handle GitHub URLs
            if 'github.com' in repo_url:
                if repo_url.endswith('.git'):
                    repo_url = repo_url[:-4]
                
                # Convert to tarball URL
                if '/tree/' in repo_url:
                    # Specific branch/commit
                    parts = repo_url.split('/tree/')
                    repo_path = parts[0]
                    ref = parts[1]
                    tarball_url = f"{repo_path}/archive/{ref}.tar.gz"
                else:
                    # Default branch
                    tarball_url = f"{repo_url}/archive/refs/heads/main.tar.gz"
                    if not tarball_url.endswith('.tar.gz'):
                        tarball_url = f"{repo_url}/archive/refs/heads/master.tar.gz"
                
                # Download tarball
                headers = {}
                if github_token:
                    headers['Authorization'] = f'token {github_token}'
                
                response = requests.get(tarball_url, headers=headers, stream=True)
                response.raise_for_status()
                
                # Save and extract
                tarball_path = os.path.join(temp_dir, "repo.tar.gz")
                with open(tarball_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Extract
                with tarfile.open(tarball_path, 'r:gz') as tar:
                    tar.extractall(temp_dir)
                
                # Find extracted directory
                extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d)) and d != '__pycache__']
                if extracted_dirs:
                    repo_path = os.path.join(temp_dir, extracted_dirs[0])
                else:
                    repo_path = temp_dir
                    
            else:
                # Handle other Git URLs (clone)
                import subprocess
                subprocess.run(['git', 'clone', repo_url, temp_dir], check=True)
                repo_path = temp_dir
            
            logger.info(f"✅ Repository downloaded to: {repo_path}")
            return repo_path
            
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Failed to download repository: {e}")
    
    async def _run_scanners(self, repo_path: str) -> List[Dict[str, Any]]:
        """Run all 5 scanners in parallel"""
        scanners = [
            ('secrets', self._run_secrets_scanner),
            ('auth', self._run_auth_scanner),
            ('webapp', self._run_webapp_scanner),
            ('deps', self._run_deps_scanner),
            ('deployment', self._run_deployment_scanner)
        ]
        
        # Run all scanners concurrently
        tasks = []
        for scanner_name, scanner_func in scanners:
            task = asyncio.create_task(self._run_scanner_with_progress(scanner_name, scanner_func, repo_path))
            tasks.append(task)
        
        # Wait for all to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        scanner_results = []
        for i, result in enumerate(results):
            scanner_name = scanners[i][0]
            if isinstance(result, Exception):
                logger.error(f"❌ Scanner {scanner_name} failed: {result}")
                scanner_results.append({
                    'scanner': scanner_name,
                    'status': 'failed',
                    'error': str(result),
                    'findings': []
                })
            else:
                scanner_results.append(result)
        
        return scanner_results
    
    async def _run_scanner_with_progress(self, scanner_name: str, scanner_func, repo_path: str) -> Dict[str, Any]:
        """Run a scanner and update progress"""
        try:
            # Update progress to running
            await self._update_scanner_progress(scanner_name, 'running')
            
            # Run scanner
            start_time = datetime.now()
            findings = await scanner_func(repo_path)
            duration = (datetime.now() - start_time).total_seconds()
            
            # Update progress to completed
            await self._update_scanner_progress(scanner_name, 'completed')
            
            return {
                'scanner': scanner_name,
                'status': 'completed',
                'findings': findings,
                'duration_ms': int(duration * 1000),
                'counts': self._count_findings(findings)
            }
            
        except Exception as e:
            await self._update_scanner_progress(scanner_name, 'failed')
            raise e
    
    async def _run_secrets_scanner(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scanner 1: Secrets & Keys"""
        findings = []
        
        # Common secret patterns
        secret_patterns = [
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key', 'high'),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Secret Key', 'medium'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'high'),
            (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', 'high'),
            (r'AIza[0-9A-Za-z-_]{35}', 'Google API Key', 'medium'),
            (r'mongodb://[^\\s]+', 'MongoDB Connection String', 'medium'),
            (r'postgresql://[^\\s]+', 'PostgreSQL Connection String', 'medium'),
            (r'mysql://[^\\s]+', 'MySQL Connection String', 'medium')
        ]
        
        # Scan all files
        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith(('.env', '.config', '.json', '.yaml', '.yml', '.js', '.ts', '.py', '.go', '.rs', '.php', '.rb', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Check for secrets
                        for pattern, description, severity in secret_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                findings.append({
                                    'rule_id': f'SECRET.{description.upper().replace(" ", "_")}',
                                    'severity': severity,
                                    'file': os.path.relpath(file_path, repo_path),
                                    'line': content[:match.start()].count('\n') + 1,
                                    'message': f'Potential {description} exposed',
                                    'evidence': match.group()[:20] + '...' if len(match.group()) > 20 else match.group(),
                                    'remediation': f'Remove {description} from source code and use environment variables or secret management'
                                })
                    except Exception:
                        continue
        
        logger.info(f"🔍 Secrets scanner found {len(findings)} potential secrets")
        return findings
    
    async def _run_auth_scanner(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scanner 2: Auth & Session Security"""
        findings = []
        
        # Language-specific auth patterns
        auth_patterns = [
            # JavaScript/TypeScript
            (r'httpOnly:\s*false', 'JavaScript: Cookie missing httpOnly flag', 'high'),
            (r'secure:\s*false', 'JavaScript: Cookie missing secure flag', 'high'),
            (r'secret:\s*["\'][^"\']+["\']', 'JavaScript: Hardcoded secret in config', 'high'),
            
            # Python
            (r'debug\s*=\s*True', 'Python: Debug mode enabled', 'high'),
            (r'secret_key\s*=\s*["\'][^"\']+["\']', 'Python: Hardcoded secret key', 'high'),
            
            # Go
            (r'Secure:\s*false', 'Go: Cookie not secure', 'high'),
            (r'HttpOnly:\s*false', 'Go: Cookie not httpOnly', 'high'),
            
            # PHP
            (r'session\.cookie_httponly\s*=\s*0', 'PHP: Session cookie not httpOnly', 'high'),
            (r'session\.cookie_secure\s*=\s*0', 'PHP: Session cookie not secure', 'high'),
            
            # Ruby
            (r'config\.force_ssl\s*=\s*false', 'Ruby: SSL not enforced', 'high')
        ]
        
        # Scan for auth issues
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.php', '.rb')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern, description, severity in auth_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                findings.append({
                                    'rule_id': f'AUTH.{description.split(":")[0].upper().replace(" ", "_")}',
                                    'severity': severity,
                                    'file': os.path.relpath(file_path, repo_path),
                                    'line': content[:match.start()].count('\n') + 1,
                                    'message': description,
                                    'evidence': match.group(),
                                    'remediation': 'Enable secure authentication settings and use environment variables for secrets'
                                })
                    except Exception:
                        continue
        
        logger.info(f"🔐 Auth scanner found {len(findings)} auth issues")
        return findings
    
    async def _run_webapp_scanner(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scanner 3: Web App Security Anti-patterns"""
        findings = []
        
        # Dangerous patterns
        dangerous_patterns = [
            # JavaScript
            (r'eval\s*\(', 'JavaScript: Use of eval() function', 'high'),
            (r'innerHTML\s*=', 'JavaScript: Potential XSS with innerHTML', 'medium'),
            (r'document\.write\s*\(', 'JavaScript: Potential XSS with document.write', 'medium'),
            
            # Python
            (r'pickle\.loads\s*\(', 'Python: Dangerous pickle.loads()', 'high'),
            (r'exec\s*\(', 'Python: Dangerous exec() function', 'high'),
            (r'f["\']SELECT.*\{[^}]*\}', 'Python: Potential SQL injection with f-string', 'high'),
            
            # Go
            (r'template\.Parse\s*\(', 'Go: Template parsing without sanitization', 'medium'),
            (r'fmt\.Sprintf.*%s', 'Go: Potential format string injection', 'medium'),
            
            # PHP
            (r'eval\s*\(', 'PHP: Use of eval() function', 'high'),
            (r'file_get_contents\s*\(\$_GET', 'PHP: File inclusion from user input', 'high'),
            
            # Generic
            (r'Access-Control-Allow-Origin:\s*\*', 'CORS: Wildcard origin allowed', 'medium'),
            (r'credentials:\s*true.*origin:\s*\*', 'CORS: Credentials with wildcard origin', 'high')
        ]
        
        # Scan for dangerous patterns
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.php', '.rb', '.java', '.html', '.htm')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern, description, severity in dangerous_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                findings.append({
                                    'rule_id': f'WEBAPP.{description.split(":")[0].upper().replace(" ", "_")}',
                                    'severity': severity,
                                    'file': os.path.relpath(file_path, repo_path),
                                    'line': content[:match.start()].count('\n') + 1,
                                    'message': description,
                                    'evidence': match.group(),
                                    'remediation': 'Use safe alternatives and proper input validation'
                                })
                    except Exception:
                        continue
        
        logger.info(f"🌐 WebApp scanner found {len(findings)} security issues")
        return findings
    
    async def _run_deps_scanner(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scanner 4: Dependency & Configuration Security"""
        findings = []
        
        # Package manager files
        package_files = [
            ('package.json', 'JavaScript/Node.js'),
            ('requirements.txt', 'Python'),
            ('go.mod', 'Go'),
            ('Cargo.toml', 'Rust'),
            ('composer.json', 'PHP'),
            ('Gemfile', 'Ruby'),
            ('pom.xml', 'Java')
        ]
        
        for filename, language in package_files:
            file_path = os.path.join(repo_path, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Check for wildcard versions
                    import re
                    wildcard_patterns = [
                        (r'"version":\s*"\*"', 'Wildcard version (*) specified'),
                        (r'"version":\s*"latest"', '"latest" version specified'),
                        (r'"version":\s*"\^0\.0\.0"', 'Unstable version range'),
                        (r'==\s*\*', 'Wildcard version in requirements'),
                        (r'go\s+1\.0', 'Unstable Go version'),
                        (r'version\s*=\s*"0\.0\.0"', 'Unstable Rust version')
                    ]
                    
                    for pattern, description in wildcard_patterns:
                        if re.search(pattern, content):
                            findings.append({
                                'rule_id': f'DEPS.{language.upper().replace("/", "_").replace(".", "_")}_WILDCARD',
                                'severity': 'medium',
                                'file': filename,
                                'line': content.find(re.search(pattern, content).group()) // 50 + 1,
                                'message': f'{language}: {description}',
                                'evidence': re.search(pattern, content).group(),
                                'remediation': 'Pin to specific stable versions to avoid supply chain attacks'
                            })
                            
                except Exception:
                    continue
        
        logger.info(f"📦 Dependencies scanner found {len(findings)} dependency issues")
        return findings
    
    async def _run_deployment_scanner(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scanner 5: Deployment & Environment Security"""
        findings = []
        
        # Environment and deployment patterns
        deployment_patterns = [
            # Environment variables
            (r'DEBUG\s*=\s*true', 'Debug mode enabled in production', 'high'),
            (r'NODE_ENV\s*=\s*["\']development["\']', 'Node.js development environment', 'high'),
            (r'FLASK_ENV\s*=\s*["\']development["\']', 'Flask development environment', 'high'),
            
            # Logging
            (r'console\.log\s*\(', 'Console logging in production code', 'low'),
            (r'print\s*\(', 'Print statements in production code', 'low'),
            (r'fmt\.Println\s*\(', 'Go print statements in production code', 'low'),
            
            # URLs and endpoints
            (r'localhost:\d+', 'Localhost URL in production code', 'medium'),
            (r'127\.0\.0\.1:\d+', 'Local IP in production code', 'medium'),
            (r'http://[^s]', 'Non-HTTPS URL in production code', 'medium'),
            
            # Security headers
            (r'X-Frame-Options:\s*DENY', 'Missing X-Frame-Options header', 'medium'),
            (r'X-Content-Type-Options:\s*nosniff', 'Missing X-Content-Type-Options header', 'medium'),
            (r'Strict-Transport-Security', 'Missing HSTS header', 'medium')
        ]
        
        # Scan for deployment issues
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith(('.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.php', '.rb', '.java', '.env', '.config', '.yaml', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern, description, severity in deployment_patterns:
                            import re
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                findings.append({
                                    'rule_id': f'DEPLOY.{description.upper().replace(" ", "_").replace("-", "_")}',
                                    'severity': severity,
                                    'file': os.path.relpath(file_path, repo_path),
                                    'line': content[:match.start()].count('\n') + 1,
                                    'message': description,
                                    'evidence': match.group(),
                                    'remediation': 'Remove development code and enable production security settings'
                                })
                    except Exception:
                        continue
        
        logger.info(f"🚀 Deployment scanner found {len(findings)} deployment issues")
        return findings
    
    def _count_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'high': 0, 'medium': 0, 'low': 0, 'total': len(findings)}
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in counts:
                counts[severity] += 1
        return counts
    
    async def _update_scanner_progress(self, scanner_name: str, status: str):
        """Update scanner progress in Firestore"""
        try:
            scan_ref = db.collection('security_scans').document(self.scan_id)
            scan_ref.update({
                f'progress.{scanner_name}': status,
                f'updated_at': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            logger.warning(f"⚠️ Failed to update progress for {scanner_name}: {e}")
    
    async def _aggregate_findings(self, scanner_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregate findings from all scanners"""
        all_findings = []
        
        for result in scanner_results:
            if result['status'] == 'completed':
                all_findings.extend(result['findings'])
        
        # Remove duplicates based on file, line, and rule_id
        seen = set()
        unique_findings = []
        
        for finding in all_findings:
            key = (finding['file'], finding['line'], finding['rule_id'])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        logger.info(f"✅ Aggregated {len(unique_findings)} unique findings from {len(scanner_results)} scanners")
        return unique_findings
    
    async def _generate_ai_summary(self, findings: List[Dict[str, Any]], repo_path: str) -> Dict[str, Any]:
        """Generate AI summary of findings"""
        # For MVP, create a simple summary without external AI calls
        summary = {
            'total_findings': len(findings),
            'severity_breakdown': self._count_findings(findings),
            'top_issues': [],
            'recommendations': []
        }
        
        # Group findings by type
        findings_by_type = {}
        for finding in findings:
            rule_type = finding['rule_id'].split('.')[0]
            if rule_type not in findings_by_type:
                findings_by_type[rule_type] = []
            findings_by_type[rule_type].append(finding)
        
        # Generate recommendations
        for rule_type, type_findings in findings_by_type.items():
            if rule_type == 'SECRET':
                summary['recommendations'].append('Move all secrets to environment variables or secret management systems')
            elif rule_type == 'AUTH':
                summary['recommendations'].append('Enable secure authentication settings and use proper session management')
            elif rule_type == 'WEBAPP':
                summary['recommendations'].append('Implement proper input validation and avoid dangerous functions')
            elif rule_type == 'DEPS':
                summary['recommendations'].append('Pin dependency versions and regularly update packages')
            elif rule_type == 'DEPLOY':
                summary['recommendations'].append('Remove development code and enable production security settings')
        
        return summary
    
    async def _save_final_results(self, final_report: Dict[str, Any]):
        """Save final results to Firestore and Storage"""
        try:
            # Update scan record
            scan_ref = db.collection('security_scans').document(self.scan_id)
            scan_ref.update({
                'status': 'completed',
                'completed_at': firestore.SERVER_TIMESTAMP,
                'summary': final_report,
                'total_findings': final_report['total_findings']
            })
            
            logger.info(f"✅ Final results saved to Firestore")
            
        except Exception as e:
            logger.error(f"❌ Failed to save final results: {e}")
            raise e
    
    async def _mark_scan_failed(self, error_message: str):
        """Mark scan as failed"""
        try:
            scan_ref = db.collection('security_scans').document(self.scan_id)
            scan_ref.update({
                'status': 'failed',
                'error': error_message,
                'failed_at': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            logger.error(f"❌ Failed to mark scan as failed: {e}")

# Flask app for the orchestrator
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=['http://localhost:9002', 'http://localhost:3000', 'https://vibecatcher.dev'], supports_credentials=True)
orchestrator = SecurityScanOrchestrator()

@app.route('/', methods=['GET'])
def root_ok():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        data = request.get_json(force=True, silent=True) or {}
        repo_url = data.get('repo_url')
        github_token = data.get('github_token')
        user_id = data.get('user_id')

        if not repo_url:
            return jsonify({'error': 'repo_url is required'}), 400

        # Run async orchestrator synchronously in Flask
        result = asyncio.run(orchestrator.start_scan(repo_url, github_token, user_id))
        return jsonify(result)

    except Exception as e:
        logger.error(f"❌ API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
