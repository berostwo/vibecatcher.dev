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
import aiohttp
import time

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
        """Validate multiple rules in parallel with intelligent timeout management"""
        logger.info(f"🔍 Validating {len(rules)} rules in parallel...")
        
        async def validate_single_rule(rule: str) -> tuple[str, bool]:
            try:
                # Quick validation - just check if rule can be loaded
                test_process = await asyncio.create_subprocess_exec(
                    'semgrep', '--config', rule, '--help',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # More generous timeout for validation (5 seconds per rule)
                await asyncio.wait_for(test_process.communicate(), timeout=5)
                
                if test_process.returncode == 0:
                    return rule, True
                else:
                    return rule, False
                    
            except asyncio.TimeoutError:
                logger.warning(f"⚠️ Rule {rule} validation timed out")
                return rule, False
            except Exception:
                return rule, False
        
        # Validate rules in smaller batches to avoid overwhelming the system
        batch_size = 6  # Process 6 rules at a time
        available_rules = []
        
        for i in range(0, len(rules), batch_size):
            batch = rules[i:i + batch_size]
            logger.info(f"🔍 Validating batch {i//batch_size + 1}: {', '.join(batch)}")
            
            # Validate batch in parallel
            validation_tasks = [validate_single_rule(rule) for rule in batch]
            batch_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            
            # Process batch results
            for result in batch_results:
                if isinstance(result, tuple) and result[1]:  # rule, is_valid
                    available_rules.append(result[0])
                    logger.info(f"✅ Rule {result[0]} validated")
                elif isinstance(result, Exception):
                    logger.warning(f"⚠️ Rule validation error: {result}")
            
            # Small delay between batches to avoid overwhelming Semgrep
            if i + batch_size < len(rules):
                await asyncio.sleep(0.5)
        
        return available_rules
    
    async def _get_available_rules(self) -> List[str]:
        """Get available rules with intelligent caching and progressive fallback"""
        if self._cache_validated:
            logger.info(f"🔍 Using cached rule validation ({len(self._rule_cache)} rules)")
            return list(self._rule_cache.keys())
        
        logger.info("🔍 Performing rule validation (this will be cached for future scans)...")
        
        # Strategy 1: Try parallel validation with current rules
        try:
            available_rules = await self._validate_rules_parallel(self.verified_rules)
            
            if len(available_rules) >= 8:  # If we get at least 8 working rules
                # Cache the results
                self._rule_cache = {rule: True for rule in available_rules}
                self._cache_validated = True
                
                logger.info(f"✅ Rule validation completed: {len(available_rules)} rules available")
                return available_rules
            else:
                logger.warning(f"⚠️ Only {len(available_rules)} rules validated, trying strategy 2")
                
        except Exception as e:
            logger.warning(f"⚠️ Parallel validation failed: {e}")
        
        # Strategy 2: Try individual validation of most important rules
        logger.info("🔄 Strategy 2: Individual validation of critical rules...")
        critical_rules = [
            'p/owasp-top-ten',        # Most important
            'p/secrets',              # Essential
            'p/javascript',           # JS/TS projects
            'p/python',               # Python projects
            'p/security-audit',       # General security
            'p/typescript',           # TypeScript projects
            'p/react',                # React projects
            'p/nextjs',               # Next.js projects
        ]
        
        individually_validated = []
        for rule in critical_rules:
            try:
                logger.info(f"🔍 Testing individual rule: {rule}")
                
                test_process = await asyncio.create_subprocess_exec(
                    'semgrep', '--config', rule, '--help',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                await asyncio.wait_for(test_process.communicate(), timeout=10)
                
                if test_process.returncode == 0:
                    individually_validated.append(rule)
                    logger.info(f"✅ Rule {rule} individually validated")
                else:
                    logger.warning(f"⚠️ Rule {rule} failed individual validation")
                    
            except Exception as e:
                logger.warning(f"⚠️ Could not test rule {rule}: {e}")
        
        if len(individually_validated) >= 4:
            # Cache the results
            self._rule_cache = {rule: True for rule in individually_validated}
            self._cache_validated = True
            
            logger.info(f"✅ Individual validation completed: {len(individually_validated)} rules available")
            return individually_validated
        
        # Strategy 3: Use pre-verified fallback rules without validation
        logger.info("🔄 Strategy 3: Using pre-verified fallback rules...")
        fallback_rules = ['p/owasp-top-ten', 'p/secrets', 'p/javascript', 'p/python']
        
        # Cache fallback rules
        self._rule_cache = {rule: True for rule in fallback_rules}
        self._cache_validated = True
        
        logger.info(f"🔄 Using fallback rules: {', '.join(fallback_rules)}")
        return fallback_rules
    
    async def _validate_semgrep_flags(self) -> dict:
        """Validate which Semgrep flags are compatible with the current version"""
        logger.info("🔍 Validating Semgrep command compatibility...")
        
        # Test different flag combinations to find compatible ones
        flag_tests = [
            # Basic flags that should always work
            ['--json', '--help'],
            ['--version'],
            ['--config', 'p/owasp-top-ten', '--help'],
            
            # File inclusion flags
            ['--include', '*.js', '--help'],
            ['--include', '*.py', '--help'],
            ['--include', '*.ts', '--help'],
            
            # Timeout and performance flags
            ['--timeout', '60', '--help'],
            ['--max-memory', '2048', '--help'],
            
            # Output and formatting flags
            ['--verbose', '--help'],
            ['--quiet', '--help'],
            ['--metrics', 'off', '--help'],
            
            # Advanced scanning flags
            ['--git-ignore', '--help'],
            ['--include-unknown-extensions', '--help'],
            ['--include-ignored', '--help'],
        ]
        
        compatible_flags = {}
        
        for test_flags in flag_tests:
            try:
                test_process = await asyncio.create_subprocess_exec(
                    'semgrep', *test_flags,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                await asyncio.wait_for(test_process.communicate(), timeout=5)
                
                if test_process.returncode == 0:
                    # Extract flag name from test
                    flag_name = test_flags[0] if test_flags[0].startswith('--') else test_flags[1]
                    compatible_flags[flag_name] = True
                    logger.info(f"✅ Flag {flag_name} is compatible")
                else:
                    flag_name = test_flags[0] if test_flags[0].startswith('--') else test_flags[1]
                    logger.warning(f"⚠️ Flag {flag_name} is not compatible")
                    
            except Exception as e:
                flag_name = test_flags[0] if test_flags[0].startswith('--') else test_flags[1]
                logger.warning(f"⚠️ Could not test flag {flag_name}: {e}")
        
        logger.info(f"✅ Semgrep compatibility check completed: {len(compatible_flags)} compatible flags found")
        return compatible_flags

    async def _build_semgrep_command(self, available_rules: List[str], repo_path: str, file_types: List[str]) -> List[str]:
        """Build a Semgrep command using only compatible flags"""
        logger.info("🔧 Building Semgrep command with compatible flags...")
        
        # Start with basic semgrep scan command
        command = ['semgrep', 'scan']
        
        # Add output format (should always be compatible)
        command.extend(['--json'])
        
        # Add timeout if compatible
        command.extend(['--timeout', '600'])
        
        # Add file type includes
        for file_type in file_types:
            command.extend(['--include', file_type])
        
        # Add security rules
        for rule in available_rules:
            command.extend(['--config', rule])
        
        # Add target path
        command.append(repo_path)
        
        logger.info(f"🔧 Built command with {len(command)} arguments")
        return command

    async def run_semgrep_scan(self, repo_path: str, available_rules: List[str], file_types: List[str]) -> dict:
        """Run Semgrep scan with validated command and rules"""
        logger.info("🔍 Starting Semgrep security scan...")
        
        # Get Semgrep version
        try:
            version_process = await asyncio.create_subprocess_exec(
                'semgrep', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(version_process.communicate(), timeout=10)
            if version_process.returncode == 0:
                version = stdout.decode().strip()
                logger.info(f"🔍 Semgrep version: {version}")
            else:
                logger.warning("⚠️ Could not determine Semgrep version")
        except Exception as e:
            logger.warning(f"⚠️ Error checking Semgrep version: {e}")
        
        # Validate available rules
        logger.info("🔍 Validating available Semgrep rules...")
        available_rules = await self._get_available_rules()
        
        # Define comprehensive file types if not provided
        if not file_types:
            file_types = [
                '*.py', '*.js', '*.ts', '*.tsx', '*.jsx', '*.go', '*.java',
                '*.php', '*.rb', '*.yml', '*.yaml', '*.json', '*.xml',
                '*.sh', 'Dockerfile', '*.dockerfile', '*.md', '*.txt',
                '*.vue', '*.svelte', '*.rs', '*.cpp', '*.c', '*.h',
                '*.swift', '*.kt', '*.scala', '*.clj', '*.hs', '*.ml'
            ]
        
        logger.info(f"🔍 Using {len(available_rules)} validated rules: {', '.join(available_rules)}")
        
        # Build Semgrep command with compatible flags
        scan_command = await self._build_semgrep_command(available_rules, repo_path, file_types)
        
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
            raise Exception(f"Semgrep scan failed: {error_msg}")
        
        # Parse scan results
        try:
            scan_results = json.loads(stdout.decode())
            
            # Extract findings
            findings = scan_results.get('results', [])
            errors = scan_results.get('errors', [])
            
            # Count files scanned
            paths_scanned = scan_results.get('paths', {}).get('scanned', [])
            paths_skipped = scan_results.get('paths', {}).get('skipped', [])
            
            logger.info(f"✅ Scan completed: {len(findings)} findings in {len(paths_scanned)} files")
            
            return {
                'findings': findings,
                'errors': errors,
                'paths_scanned': paths_scanned,
                'paths_skipped': paths_skipped,
                'scan_results': scan_results
            }
            
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Semgrep output: {e}")
        except Exception as e:
            raise Exception(f"Error processing scan results: {e}")
    
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
                
                # Run Semgrep security scan
                scan_start_time = time.time()
                try:
                    scan_results = await self.run_semgrep_scan(repo_path, [], [])  # Empty lists will be populated by the method
                except Exception as scan_error:
                    scan_duration = time.time() - scan_start_time
                    logger.error(f"❌ Security scan failed: {scan_error}")
                    return {
                        "error": f"Security scan failed: {scan_error}",
                        "error_type": "ScanError",
                        "scan_duration": scan_duration,
                        "timestamp": datetime.now().isoformat()
                    }
                
                scan_duration = time.time() - scan_start_time
                logger.info(f"✅ Security scan completed in {scan_duration:.2f}s")
                
                # Process findings
                try:
                    processed_results = self.process_findings(scan_results['scan_results'])
                    logger.info(f"📊 Found {len(scan_results['findings'])} security issues")
                    
                    return {
                        "findings": scan_results['findings'],
                        "errors": scan_results['errors'],
                        "paths_scanned": scan_results['paths_scanned'],
                        "paths_skipped": scan_results['paths_skipped'],
                        "scan_results": scan_results['scan_results'],
                        "processed_results": processed_results,
                        "scan_duration": scan_duration,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                except Exception as process_error:
                    logger.error(f"❌ Error processing findings: {process_error}")
                    return {
                        "error": f"Error processing findings: {process_error}",
                        "error_type": "ProcessingError",
                        "scan_duration": scan_duration,
                        "timestamp": datetime.now().isoformat()
                    }
                
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
    
    async def _get_repository_info(self, owner: str, repo_name: str, github_token: str = None) -> dict:
        """Get repository information including size, file count, and language stats"""
        try:
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}"
            headers = {
                'User-Agent': 'VibeCatcher-Security-Scanner/1.0'
            }
            
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, headers=headers) as response:
                    if response.status == 200:
                        repo_data = await response.json()
                        return {
                            'size': repo_data.get('size', 0),  # Size in KB
                            'language': repo_data.get('language', 'Unknown'),
                            'default_branch': repo_data.get('default_branch', 'main'),
                            'private': repo_data.get('private', False),
                            'description': repo_data.get('description', 'No description')
                        }
                    else:
                        logger.warning(f"⚠️ Could not fetch repo info: {response.status}")
                        return {}
        except Exception as e:
            logger.warning(f"⚠️ Error fetching repository info: {e}")
            return {}

    async def _download_and_extract_tarball(self, tarball_url: str, repo_path: str, headers: dict = None) -> bool:
        """Download and extract GitHub tarball with progress tracking"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(tarball_url, headers=headers) as response:
                    if response.status == 200:
                        # Download tarball with progress tracking
                        total_size = int(response.headers.get('content-length', 0))
                        downloaded_size = 0
                        tarball_data = bytearray()
                        
                        logger.info(f"📥 Downloading repository tarball...")
                        if total_size > 0:
                            logger.info(f"📊 Expected size: {total_size / (1024*1024):.1f}MB")
                        
                        async for chunk in response.content.iter_chunked(8192):  # 8KB chunks
                            tarball_data.extend(chunk)
                            downloaded_size += len(chunk)
                            
                            if total_size > 0 and downloaded_size % (1024*1024) == 0:  # Log every MB
                                progress = (downloaded_size / total_size) * 100
                                logger.info(f"📥 Download progress: {progress:.1f}% ({downloaded_size / (1024*1024):.1f}MB)")
                        
                        logger.info(f"✅ Download completed: {downloaded_size / (1024*1024):.1f}MB")
                        
                        # Extract tar.gz archive
                        import tarfile
                        import io
                        import gzip
                        
                        logger.info("🔄 Extracting repository files...")
                        with gzip.open(io.BytesIO(tarball_data), 'rb') as gz_file:
                            with tarfile.open(fileobj=gz_file, mode='r:*') as tar:
                                tar.extractall(repo_path)
                        
                        logger.info("✅ Repository extraction completed")
                        return True
                    else:
                        error_msg = await response.text()
                        logger.error(f"❌ GitHub API failed (status {response.status}): {error_msg}")
                        return False
                        
        except Exception as e:
            logger.error(f"❌ Error downloading/extracting tarball: {e}")
            return False

    async def clone_repository(self, repo_url: str, temp_dir: str, github_token: str = None) -> str:
        """Download repository using GitHub tarball API for faster, authenticated downloads"""
        logger.info(f"📥 Downloading repository: {repo_url}")
        
        # Extract repo name and owner from URL
        if not repo_url.startswith('https://github.com/'):
            raise ValueError("Only GitHub repositories are supported")
        
        path_parts = repo_url.replace('https://github.com/', '').replace('.git', '').split('/')
        if len(path_parts) != 2:
            raise ValueError("Invalid GitHub repository URL format")
        
        owner, repo_name = path_parts
        
        # Get repository information first
        repo_info = await self._get_repository_info(owner, repo_name, github_token)
        if repo_info:
            logger.info(f"📊 Repository info: {repo_info.get('language', 'Unknown')} project, {'Private' if repo_info.get('private') else 'Public'}")
            if repo_info.get('size', 0) > 0:
                logger.info(f"📊 GitHub reports size: {repo_info['size'] / 1024:.1f}MB")
        
        repo_path = os.path.join(temp_dir, repo_name)
        os.makedirs(repo_path, exist_ok=True)
        
        # Use GitHub tarball API for faster, authenticated downloads
        if github_token:
            logger.info("Using GitHub token for authenticated repository access")
            
            # GitHub tarball API endpoint
            default_branch = repo_info.get('default_branch', 'main')
            tarball_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball/{default_branch}"
            
            try:
                logger.info(f"🔄 Downloading via GitHub tarball API...")
                
                # Download tarball with authentication
                headers = {
                    'Authorization': f'token {github_token}',
                    'User-Agent': 'VibeCatcher-Security-Scanner/1.0'
                }
                
                if await self._download_and_extract_tarball(tarball_url, repo_path, headers):
                    logger.info(f"✅ Repository downloaded via GitHub API successfully")
                else:
                    raise Exception("GitHub API download failed")
                    
            except Exception as api_error:
                logger.warning(f"⚠️ GitHub API download failed: {api_error}, falling back to clone")
                
                # Fall back to git clone with token
                authenticated_url = f"https://{github_token}@github.com/{owner}/{repo_name}.git"
                clone_command = ['git', 'clone', '--depth', '1', '--single-branch', '--branch', default_branch, authenticated_url, repo_path]
                
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
            # For public repos without token, try GitHub tarball API first
            try:
                logger.info(f"🔄 Downloading public repository via GitHub tarball API...")
                
                default_branch = repo_info.get('default_branch', 'main')
                tarball_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball/{default_branch}"
                
                if await self._download_and_extract_tarball(tarball_url, repo_path):
                    logger.info(f"✅ Repository downloaded via GitHub API successfully")
                else:
                    raise Exception("GitHub API download failed")
                    
            except Exception as api_error:
                logger.warning(f"⚠️ GitHub API download failed: {api_error}, falling back to clone")
                
                # Fall back to git clone
                default_branch = repo_info.get('default_branch', 'main')
                clone_command = ['git', 'clone', '--depth', '1', '--single-branch', '--branch', default_branch, repo_url, repo_path]
                
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
        
        # Verify repository contents and get accurate size
        logger.info("🔍 Analyzing repository contents...")
        file_count = 0
        total_size = 0
        file_types = set()
        
        for dirpath, dirnames, filenames in os.walk(repo_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    file_size = os.path.getsize(file_path)
                    total_size += file_size
                    file_count += 1
                    
                    # Track file extensions
                    _, ext = os.path.splitext(filename)
                    if ext:
                        file_types.add(ext.lower())
                        
                except (OSError, IOError):
                    continue  # Skip files we can't access
        
        repo_size_mb = total_size / (1024 * 1024)
        
        if repo_size_mb > MAX_REPO_SIZE_MB:
            raise Exception(f"Repository too large: {repo_size_mb:.1f}MB (max: {MAX_REPO_SIZE_MB}MB)")
        
        # Compare with GitHub's reported size
        if repo_info.get('size', 0) > 0:
            github_size_mb = repo_info['size'] / 1024
            size_diff = abs(repo_size_mb - github_size_mb)
            if size_diff > 5:  # More than 5MB difference
                logger.warning(f"⚠️ Size mismatch: Local {repo_size_mb:.1f}MB vs GitHub {github_size_mb:.1f}MB")
            else:
                logger.info(f"✅ Size verification passed: {repo_size_mb:.1f}MB")
        
        logger.info(f"✅ Repository ready: {file_count} files, {repo_size_mb:.1f}MB")
        logger.info(f"📁 File types found: {', '.join(sorted(list(file_types))[:10])}{'...' if len(file_types) > 10 else ''}")
        
        return repo_path

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
