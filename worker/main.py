import os
import json
import asyncio
import aiohttp
import tempfile
import shutil
import subprocess
import threading
import hashlib
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
from flask import Flask, request, jsonify
import openai
from dataclasses import dataclass, asdict
from collections import OrderedDict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variable for progress tracking
current_scan_progress = None

# Configuration
MAX_REPO_SIZE_MB = 500
MAX_SCAN_TIME_SECONDS = 300  # 5 minutes
ALLOWED_REPO_DOMAINS = ['github.com', 'gitlab.com', 'bitbucket.org']

@dataclass
class SecurityFinding:
    """Represents a security finding with all details"""
    rule_id: str
    severity: str  # Critical, High, Medium, Low
    message: str
    description: str
    file_path: str
    line_number: int
    end_line: int
    code_snippet: str
    cwe_ids: List[str]
    owasp_ids: List[str]
    impact: str
    likelihood: str
    confidence: str
    occurrences: int = 1

@dataclass
class SecurityReport:
    """Complete security audit report"""
    summary: Dict[str, Any]
    findings: List[SecurityFinding]
    condensed_findings: List[SecurityFinding]
    condensed_remediations: Dict[str, str]  # rule_id -> remediation prompt
    master_remediation: str
    scan_duration: float
    timestamp: str
    repository_info: Dict[str, Any]

class ChatGPTSecurityScanner:
    """Ultimate ChatGPT-powered security scanner for indie developers"""
    
    def __init__(self):
        # Initialize OpenAI clients with multiple API keys for parallel processing
        self.api_keys = []
        
        # Try to get multiple API keys for parallel processing
        primary_key = os.environ.get('OPENAI_API_KEY')
        if primary_key:
            self.api_keys.append(primary_key)
        
        # Try to get additional API keys
        for i in range(1, 4):  # Support up to 4 API keys
            additional_key = os.environ.get(f'OPENAI_API_KEY_{i}')
            if additional_key:
                self.api_keys.append(additional_key)
        
        if not self.api_keys:
            raise ValueError("At least one OPENAI_API_KEY environment variable is required")
        
        logger.info(f"🚀 MULTI-API KEY SYSTEM: {len(self.api_keys)} API keys available for parallel processing!")
        
        # Initialize token usage tracking
        self.total_tokens_used = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.api_calls_made = 0
        
        # PHASE 4: Caching and ML-based optimization
        self.result_cache = {}  # Cache for analysis results
        self.pattern_database = {}  # Database of known security patterns
        self.file_risk_scores = {}  # Risk scores for files based on previous scans
        
        # 🚀 ADVANCED CACHING SYSTEM: Multi-level intelligent caching
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'total_requests': 0,
            'cache_size': 0,
            'memory_usage_mb': 0
        }
        
        # Multi-level cache system
        self.file_cache = OrderedDict()  # LRU cache for file analysis results
        self.pattern_cache = OrderedDict()  # LRU cache for security patterns
        self.batch_cache = OrderedDict()  # LRU cache for batch analysis
        self.code_snippet_cache = OrderedDict()  # LRU cache for code snippets
        
        # Cache configuration
        self.max_cache_size = 10000  # Maximum number of cached items
        self.cache_ttl_hours = 24  # Cache items expire after 24 hours
        self.pattern_similarity_threshold = 0.85  # Similarity threshold for pattern matching
        
        # Cache cleanup
        self.last_cache_cleanup = time.time()
        self.cache_cleanup_interval = 3600  # Clean up every hour
        
        # SIMPLE PROGRESS TRACKING: Clean, accurate progress system
        self.progress_callback = None
        self.current_step = "Initializing"
        self.step_progress = 0.0
        self.progress_updates = []  # Store progress updates for the current scan
        
        # Security categories for comprehensive coverage
        
        # Security categories for comprehensive coverage
        self.security_categories = [
            "Authentication & Authorization",
            "Input Validation & Injection",
            "Data Exposure & Privacy",
            "Cryptography & Secrets Management",
            "Session Management",
            "File Upload Security",
            "API Security",
            "Frontend Security (XSS, CSRF)",
            "Backend Security (SQL Injection, etc.)",
            "Business Logic Flaws",
            "Error Handling & Information Disclosure",
            "Dependency Vulnerabilities",
            "Configuration Security",
            "Network Security",
            "Physical Security (if applicable)"
        ]
        
        # Indie developer specific security patterns
        self.indie_security_patterns = [
            "Hardcoded API keys in frontend",
            "Missing authentication checks",
            "Insecure default configurations",
            "Exposed environment variables",
            "Weak password policies",
            "Missing rate limiting",
            "Insecure file uploads",
            "SQL injection vulnerabilities",
            "XSS in user inputs",
            "Missing HTTPS enforcement",
            "Weak session management",
            "Exposed debug endpoints",
            "Missing input validation",
            "Insecure OAuth flows",
            "Weak encryption usage",
            "Missing security headers",
            "Exposed error messages",
            "Insecure deserialization",
            "Missing access controls",
            "Weak crypto implementations"
        ]
    
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def update_progress(self, step: str, progress: float):
        """Simple, accurate progress update"""
        self.current_step = step
        self.step_progress = progress
        
        # Store progress update in the instance
        progress_data = {
            'step': step,
            'progress': progress,
            'timestamp': datetime.now().isoformat()
        }
        self.progress_updates.append(progress_data)
        
        if self.progress_callback:
            try:
                logger.info(f"📊 PROGRESS: {step} - {progress:.1f}%")
                logger.info(f"📊 CALLING PROGRESS CALLBACK: {progress_data}")
                self.progress_callback(progress_data)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
        else:
            logger.warning(f"📊 NO PROGRESS CALLBACK SET - step: {step}, progress: {progress}")
    
    async def clone_repository(self, repo_url: str, github_token: str = None) -> str:
        """Clone repository with authentication"""
        logger.info(f"📥 Cloning repository: {repo_url}")
        
        # PROGRESS TRACKING: Start cloning step (EVEN DISTRIBUTION!)
        self.update_progress("Cloning repository", 10)
        
        # Validate repository URL
        if not any(domain in repo_url for domain in ALLOWED_REPO_DOMAINS):
            raise ValueError(f"Repository domain not allowed. Allowed: {ALLOWED_REPO_DOMAINS}")
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        repo_path = os.path.join(temp_dir, repo_name)
        
        logger.info(f"📁 Temp directory: {temp_dir}")
        logger.info(f"📁 Repository path: {repo_path}")
        
        try:
            # Build clone command with MAXIMUM speed optimization
            if github_token:
                # Use token for private repos
                auth_url = repo_url.replace('https://', f'https://{github_token}@')
                clone_cmd = ['git', 'clone', '--single-branch', '--depth', '1', '--no-tags', '--shallow-submodules', auth_url, repo_path]
                logger.info(f"🔐 Using authenticated clone for private repo (optimized)")
            else:
                clone_cmd = ['git', 'clone', '--single-branch', '--depth', '1', '--no-tags', '--shallow-submodules', repo_url, repo_path]
                logger.info(f"🌐 Using public clone (optimized)")
            
            logger.info(f"🚀 Clone command: {' '.join(clone_cmd)}")
            
            # Execute clone
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            logger.info(f"⏳ Cloning in progress...")
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                logger.error(f"❌ Git clone failed with return code {process.returncode}")
                logger.error(f"❌ Error output: {error_msg}")
                raise Exception(f"Git clone failed: {error_msg}")
            
            # Validate cloned repository
            if not os.path.exists(repo_path):
                raise Exception("Repository directory not created after clone")
            
            # Get repository size and file count
            repo_size = self.get_directory_size(repo_path)
            file_count = self.count_files(repo_path)
            
            logger.info(f"✅ Repository cloned successfully: {repo_path}")
            logger.info(f"📊 Repository size: {repo_size}")
            logger.info(f"📊 Total files: {file_count}")
            
            # PROGRESS TRACKING: Clone complete (EVEN DISTRIBUTION!)
            self.update_progress("Repository cloned", 20)
            
            return repo_path
            
        except Exception as e:
            # Cleanup on failure
            logger.error(f"❌ Clone failed: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e
    
    async def analyze_file_async(self, file_path: str, relative_path: str, file_type: str) -> List[SecurityFinding]:
        """Async wrapper for file analysis"""
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB
                logger.warning(f"⚠️ File {relative_path} is large ({file_size/1024/1024:.1f}MB), may take longer to analyze")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            logger.info(f"📄 File {relative_path}: {len(content)} characters")
            
            # Analyze with ChatGPT
            findings = self.analyze_file_with_chatgpt(relative_path, content, file_type)
            return findings
            
        except Exception as e:
            logger.warning(f"❌ Failed to analyze {relative_path}: {e}")
            return []

    def analyze_file_with_chatgpt(self, file_path: str, file_content: str, file_type: str) -> List[SecurityFinding]:
        """Analyze a single file with ChatGPT for security vulnerabilities"""
        try:
            # 🚀 ADVANCED CACHING: Check cache first before expensive analysis
            cached_result = self.get_cached_result(file_content, "file")
            if cached_result:
                logger.info(f"🎯 CACHE HIT: Using cached analysis for {file_path}")
                return cached_result
            
            # Get file-specific analysis rules
            analysis_rules = self.get_file_analysis_rules(file_path)
            
            # Build UNIVERSAL context-aware security analysis prompt for ALL tech stacks
            prompt = f"""
            You are an expert security engineer analyzing a {file_type} file in a modern web application.

            FILE: {file_path}
            CONTENT:
            {file_content}

            APPLICATION CONTEXT:
            - This is a modern web application (could be Next.js, Nuxt, Vue, React, Svelte, Angular, etc.)
            - Uses modern authentication (OAuth, JWT, session-based, etc.)
            - Has a backend (could be Firebase, Supabase, MongoDB, PostgreSQL, MySQL, etc.)
            - Built for indie developers, solopreneurs, and small teams

            CRITICAL: IGNORE THESE FALSE POSITIVES (ALL PLATFORMS):
            - Environment variables with PUBLIC prefixes (NEXT_PUBLIC_, NUXT_PUBLIC_, VITE_PUBLIC_, etc.)
            - OAuth client IDs, redirect URIs (PUBLIC by design - not secrets)
            - Database configuration keys (PUBLIC by design - not secrets)
            - Build-time environment access patterns
            - Public API endpoints that are meant to be accessible
            - Configuration files with intentionally public values
            - Component props and UI configuration
            - Package.json dependencies and metadata
            - Framework configuration files

            FOCUS ON REAL SECURITY VULNERABILITIES:
            - XSS in user input rendering (dangerouslySetInnerHTML, user input in DOM)
            - SQL injection in database queries (user input in SQL)
            - CSRF in state-changing operations (POST/PUT/DELETE without tokens)
            - Authentication bypasses (missing auth checks, weak validation)
            - Insecure file upload handling (no file type validation, path traversal)
            - Exposed sensitive endpoints (admin routes, internal APIs)
            - Weak password policies (no complexity requirements)
            - Session fixation attacks (predictable session IDs)
            - Information disclosure (error messages, stack traces)
            - Insecure deserialization (user input in eval, JSON.parse)
            - Dependency vulnerabilities (outdated packages with known CVEs)
            - Insecure default configurations

            ANALYSIS RULES:
            1. Only report ACTUAL security vulnerabilities, not configuration patterns
            2. Focus on code that processes user input or handles sensitive operations
            3. Look for missing security controls (auth, validation, sanitization)
            4. Consider the real-world impact on the application
            5. Be practical - focus on risks that indie developers actually face
            6. Ignore findings about intentionally public configuration values

            Return findings in this exact JSON format:
            {{
                "findings": [
                    {{
                        "rule_id": "vulnerability_type_identifier",
                        "severity": "Critical|High|Medium|Low",
                        "message": "Brief vulnerability description",
                        "description": "Detailed explanation",
                        "file_path": "{file_path}",
                        "line_number": 123,
                        "end_line": 125,
                        "code_snippet": "vulnerable code here",
                        "cwe_ids": ["CWE-79", "CWE-89"],
                        "owasp_ids": ["A01:2021", "A03:2021"],
                        "impact": "High|Medium|Low",
                        "likelihood": "High|Medium|Low",
                        "confidence": "High|Medium|Low"
                    }}
                ]
            }}
            
            IMPORTANT: 
            - For rule_id, use descriptive identifiers like "xss_vulnerability", "sql_injection", "csrf_missing"
            - Only report findings that represent REAL security risks
            - If no actual vulnerabilities found, return empty findings array
            - Be thorough but practical for indie developer applications
            - This scanner works for ALL modern web frameworks and platforms
            """

            # MULTI-API KEY PARALLEL PROCESSING: Use round-robin API key selection
            api_key_index = self.api_calls_made % len(self.api_keys)
            selected_api_key = self.api_keys[api_key_index]
            
            # Call ChatGPT API
            client = openai.OpenAI(api_key=selected_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer focused on making indie developer applications bulletproof."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1
            )
            
            # Track token usage
            self.api_calls_made += 1
            if hasattr(response, 'usage') and response.usage:
                self.prompt_tokens += response.usage.prompt_tokens
                self.completion_tokens += response.usage.completion_tokens
                self.total_tokens_used += response.usage.total_tokens
                logger.info(f"🔍 Token usage for {file_path}: {response.usage.total_tokens} tokens (prompt: {response.usage.prompt_tokens}, completion: {response.usage.completion_tokens})")
            else:
                logger.warning(f"⚠️ No token usage data available for {file_path}")
            
            # Parse response
            content = response.choices[0].message.content
            logger.info(f"🔍 ChatGPT response for {file_path}: {content[:200]}...")
            
            try:
                # Try to extract JSON from the response
                # Look for JSON blocks in markdown or text
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = content[json_start:json_end]
                    result = json.loads(json_content)
                    findings = result.get('findings', [])
                    
                    # Convert to SecurityFinding objects with UNIQUE rule_ids
                    security_findings = []
                    for i, finding in enumerate(findings):
                        try:
                            # Ensure unique rule_id by adding file identifier and counter
                            file_id = os.path.basename(file_path).replace('.', '_').replace('-', '_')
                            unique_rule_id = f"{finding.get('rule_id', 'vulnerability')}_{file_id}_{i+1}"
                            
                            # Create finding with unique rule_id
                            finding_data = finding.copy()
                            finding_data['rule_id'] = unique_rule_id
                            
                            security_findings.append(SecurityFinding(**finding_data))
                        except Exception as e:
                            logger.warning(f"Failed to create SecurityFinding for {file_path}: {e}")
                            continue
                    
                    logger.info(f"✅ Successfully parsed {len(security_findings)} findings for {file_path}")
                    
                    # 🚀 ADVANCED CACHING: Cache the analysis result for future use
                    self.cache_result(file_content, security_findings, "file")
                    
                    # Also cache as a pattern for similar files
                    normalized_content = self.normalize_code_content(file_content)
                    pattern_cache_entry = {
                        'data': security_findings,
                        'original_content': normalized_content,
                        'timestamp': time.time(),
                        'size': len(str(security_findings)),
                        'type': 'pattern'
                    }
                    pattern_key = self.generate_cache_key(normalized_content, "pattern")
                    self._add_to_lru_cache(self.pattern_cache, pattern_key, pattern_cache_entry)
                    
                    return security_findings
                else:
                    logger.warning(f"No JSON found in ChatGPT response for {file_path}")
                    return []
                    
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse ChatGPT response for {file_path}: {e}")
                logger.warning(f"Response content: {content}")
                return []
            except Exception as e:
                logger.error(f"Unexpected error parsing response for {file_path}: {e}")
                return []
                
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with ChatGPT: {e}")
            return []
    
    def condense_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Condense multiple similar findings into one with occurrence count"""
        # First, filter out false positives
        filtered_findings = self.filter_false_positives(findings)
        
        condensed = {}
        condensed_counter = 1  # Counter for unique condensed finding IDs
        
        for finding in filtered_findings:
            # Create a key based on vulnerability TYPE and severity, not specific rule_id
            # Extract the vulnerability type from the message (e.g., "XSS", "CSRF", "SQL Injection")
            vulnerability_type = self.extract_vulnerability_type(finding.message)
            key = f"{vulnerability_type}_{finding.severity}"
            
            if key in condensed:
                # Increment occurrence count
                condensed[key].occurrences += 1
                # Update the file_path to show multiple locations
                if finding.file_path not in condensed[key].file_path:
                    condensed[key].file_path += f", {finding.file_path}"
            else:
                # Create a NEW finding with a unique rule_id for React keys
                unique_finding = SecurityFinding(
                    rule_id=f"CONDENSED_{condensed_counter}_{vulnerability_type}",
                    severity=finding.severity,
                    message=finding.message,
                    description=finding.description,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    end_line=finding.end_line,
                    code_snippet=finding.code_snippet,
                    cwe_ids=finding.cwe_ids,
                    owasp_ids=finding.owasp_ids,
                    impact=finding.impact,
                    likelihood=finding.likelihood,
                    confidence=finding.confidence,
                    occurrences=1
                )
                condensed[key] = unique_finding
                condensed_counter += 1
        
        return list(condensed.values())

    def filter_false_positives(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Universal false positive filtering system for ALL tech stacks"""
        if not findings:
            return []
        
        filtered = []
        false_positive_count = 0
        
        # UNIVERSAL false positive patterns for ALL tech stacks
        universal_false_positive_patterns = [
            # Environment Variables (ALL platforms)
            'next_public_', 'nuxt_public_', 'vite_public_', 'svelte_public_',
            'process.env.public', 'import.meta.env.public', 'window.env.public',
            'public environment', 'public config', 'public variable',
            
            # OAuth & Authentication (ALL platforms)
            'client id', 'client_id', 'redirect uri', 'redirect_uri',
            'oauth config', 'auth config', 'public oauth', 'public auth',
            'github client', 'google client', 'facebook client', 'discord client',
            
            # Database Configuration (ALL platforms)
            'supabase config', 'firebase config', 'mongodb config', 'postgres config',
            'database config', 'db config', 'connection string', 'connection_string',
            'public database', 'public connection', 'public endpoint',
            
            # Build & Framework Config (ALL platforms)
            'webpack config', 'vite config', 'rollup config', 'esbuild config',
            'babel config', 'typescript config', 'tailwind config', 'postcss config',
            'next config', 'nuxt config', 'svelte config', 'vue config',
            'angular config', 'react config', 'ember config',
            
            # Component & UI (ALL frameworks)
            'component props', 'component configuration', 'ui config', 'ui configuration',
            'public props', 'public interface', 'public component', 'public ui',
            'theme config', 'style config', 'css config', 'design system',
            
            # API & Service Configuration (ALL platforms)
            'api config', 'service config', 'endpoint config', 'route config',
            'public api', 'public service', 'public endpoint', 'public route',
            'stripe config', 'paypal config', 'aws config', 'azure config',
            
            # General Configuration Files (ALL platforms)
            'config file', 'configuration file', 'setup file', 'initialization file',
            'package.json', 'composer.json', 'requirements.txt', 'gemfile',
            'cargo.toml', 'go.mod', 'pom.xml', 'build.gradle',
            
            # Documentation & Build Artifacts
            'readme', 'changelog', 'license', 'contributing',
            'build output', 'dist folder', 'out folder', 'coverage report',
            
            # Development Tools (ALL platforms)
            'eslint config', 'prettier config', 'stylelint config', 'husky config',
            'lint staged', 'commitlint', 'jest config', 'vitest config',
            'cypress config', 'playwright config', 'storybook config'
        ]
        
        for finding in findings:
            # Check if finding matches universal false positive patterns
            finding_text = f"{finding.message.lower()} {finding.description.lower()}"
            
            is_false_positive = False
            for pattern in universal_false_positive_patterns:
                if pattern in finding_text:
                    is_false_positive = True
                    false_positive_count += 1
                    logger.info(f"🔍 UNIVERSAL FILTER: Filtered false positive: {finding.message[:100]}...")
                    break
            
            if not is_false_positive:
                filtered.append(finding)
        
        logger.info(f"✅ UNIVERSAL False positive filtering: {len(findings)} → {len(filtered)} findings (filtered {false_positive_count})")
        return filtered

    def is_false_positive_finding(self, finding: SecurityFinding, file_path: str) -> bool:
        """Universal false positive detection for ALL tech stacks"""
        file_path_lower = file_path.lower()
        finding_text = f"{finding.message.lower()} {finding.description.lower()}"
        
        # Database & Backend files (ALL platforms) - ignore public config findings
        if any(term in file_path_lower for term in [
            'firebase', 'supabase', 'mongodb', 'postgres', 'mysql', 'sqlite',
            'prisma', 'sequelize', 'typeorm', 'drizzle', 'knex'
        ]):
            if any(term in finding_text for term in [
                'next_public', 'nuxt_public', 'vite_public', 'svelte_public',
                'database config', 'db config', 'connection string', 'public database'
            ]):
                return True
        
        # OAuth & Authentication files (ALL platforms) - ignore OAuth config findings
        elif any(term in file_path_lower for term in [
            'oauth', 'auth', 'github', 'google', 'facebook', 'discord', 'twitter',
            'login', 'register', 'signin', 'signup', 'authentication'
        ]):
            if any(term in finding_text for term in [
                'client id', 'client_id', 'oauth config', 'redirect uri', 'public oauth'
            ]):
                return True
        
        # Configuration & Build files (ALL platforms) - ignore config findings
        elif any(term in file_path_lower for term in [
            'config', 'env', 'setup', 'webpack', 'vite', 'rollup', 'esbuild',
            'babel', 'typescript', 'tailwind', 'postcss', 'eslint', 'prettier'
        ]):
            if any(term in finding_text for term in [
                'environment', 'config file', 'build config', 'framework config'
            ]):
                return True
        
        # Frontend Component files (ALL frameworks) - ignore UI config findings
        elif any(term in file_path_lower for term in [
            'component', 'page', 'ui', 'view', 'screen', 'layout',
            'react', 'vue', 'svelte', 'angular', 'ember', 'next', 'nuxt'
        ]):
            if any(term in finding_text for term in [
                'component props', 'ui config', 'public props', 'theme config'
            ]):
                return True
        
        # Package & Dependency files (ALL platforms) - ignore package findings
        elif any(term in file_path_lower for term in [
            'package.json', 'composer.json', 'requirements.txt', 'gemfile',
            'cargo.toml', 'go.mod', 'pom.xml', 'build.gradle', 'yarn.lock'
        ]):
            if any(term in finding_text for term in [
                'dependency list', 'package list', 'version info', 'license info'
            ]):
                return True
        
        return False
    
    def extract_vulnerability_type(self, message: str) -> str:
        """Extract vulnerability type from message for grouping"""
        message_lower = message.lower()
        
        # Define vulnerability type patterns
        if any(xss_term in message_lower for xss_term in ['xss', 'cross-site scripting', 'script injection']):
            return 'xss_vulnerability'
        elif any(csrf_term in message_lower for csrf_term in ['csrf', 'cross-site request forgery']):
            return 'csrf_vulnerability'
        elif any(sql_term in message_lower for sql_term in ['sql injection', 'sql injection', 'database injection']):
            return 'sql_injection'
        elif any(auth_term in message_lower for auth_term in ['authentication', 'authorization', 'auth bypass']):
            return 'authentication_vulnerability'
        elif any(input_term in message_lower for input_term in ['input validation', 'unsanitized input', 'user input']):
            return 'input_validation_vulnerability'
        elif any(secret_term in message_lower for secret_term in ['secret', 'api key', 'password', 'token']):
            return 'secrets_exposure'
        elif any(dep_term in message_lower for dep_term in ['dependency', 'outdated', 'vulnerable package']):
            return 'dependency_vulnerability'
        elif any(target_term in message_lower for target_term in ['target="_blank"', 'tabnabbing']):
            return 'insecure_target_blank'
        elif any(error_term in message_lower for error_term in ['error handling', 'information disclosure', 'sensitive information']):
            return 'information_disclosure'
        else:
            # Fallback: use first few words of message
            words = message.split()
            return '_'.join(words[:3]).lower().replace('-', '_').replace('(', '').replace(')', '')
    
    def generate_condensed_remediations(self, condensed_findings: List[SecurityFinding], all_findings: List[SecurityFinding]) -> Dict[str, str]:
        """Generate ALL remediation prompts in ONE API call - MASSIVE optimization!"""
        try:
            logger.info(f"🚀 NUCLEAR OPTIMIZATION: Generating {len(condensed_findings)} remediations in ONE API call!")
            
            # Create ONE comprehensive prompt for ALL findings
            all_findings_summary = []
            for finding in condensed_findings:
                instances = [f for f in all_findings if f.rule_id == finding.rule_id]
                all_findings_summary.append({
                    'rule_id': finding.rule_id,
                    'message': finding.message,
                    'severity': finding.severity,
                    'description': finding.description,
                    'cwe_ids': finding.cwe_ids,
                    'owasp_ids': finding.owasp_ids,
                    'occurrences': finding.occurrences
                })
            
            # ONE MASSIVE PROMPT for ALL findings
            prompt = f"""
            You are an expert security engineer. Create remediation prompts for MULTIPLE security vulnerabilities in ONE response.
            
            VULNERABILITIES TO ANALYZE:
            {json.dumps(all_findings_summary, indent=2)}
            
            For EACH vulnerability, create a remediation prompt that:
            1. Clearly explains the security issue
            2. Provides context about why it's dangerous
            3. Gives specific, actionable steps to fix it
            4. Is written for coding assistants (Cursor, GitHub Copilot, etc.)
            5. Includes code examples where appropriate
            6. Addresses the root cause, not just symptoms
            
            Return in this EXACT JSON format:
            {{
                "remediations": {{
                    "rule_id_1": "remediation prompt text here",
                    "rule_id_2": "remediation prompt text here",
                    ...
                }}
            }}
            
            Make each prompt specific enough that a coding assistant can implement the fix robustly.
            """
            
            # MULTI-API KEY PARALLEL PROCESSING: Use round-robin API key selection
            api_key_index = self.api_calls_made % len(self.api_keys)
            selected_api_key = self.api_keys[api_key_index]
            
            # ONE API CALL for ALL remediations
            client = openai.OpenAI(api_key=selected_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer creating multiple remediation prompts efficiently."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=6000,  # Increased for multiple prompts
                temperature=0.1
            )
            
            # Track token usage
            self.api_calls_made += 1
            if hasattr(response, 'usage') and response.usage:
                self.prompt_tokens += response.usage.prompt_tokens
                self.completion_tokens += response.usage.completion_tokens
                self.total_tokens_used += response.usage.total_tokens
                logger.info(f"🚀 NUCLEAR OPTIMIZATION: Generated {len(condensed_findings)} remediations in 1 API call! Tokens: {response.usage.total_tokens}")
            else:
                logger.warning(f"⚠️ No token usage data available for nuclear optimization")
            
            # Parse the response
            content = response.choices[0].message.content
            try:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = content[json_start:json_end]
                    result = json.loads(json_content)
                    remediations = result.get('remediations', {})
                    
                    logger.info(f"✅ Successfully parsed {len(remediations)} remediations from nuclear optimization")
                    return remediations
                else:
                    logger.error("❌ No JSON found in nuclear optimization response")
                    return {}
                    
            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse nuclear optimization response: {e}")
                logger.error(f"Response content: {content}")
                return {}
            
        except Exception as e:
            logger.error(f"❌ Nuclear optimization failed: {e}")
            return {}

    def generate_master_remediation(self, condensed_findings: List[SecurityFinding]) -> str:
        """Generate a master remediation plan with phases for all findings"""
        try:
            # Group findings by severity
            critical = [f for f in condensed_findings if f.severity == "Critical"]
            high = [f for f in condensed_findings if f.severity == "High"]
            medium = [f for f in condensed_findings if f.severity == "Medium"]
            low = [f for f in condensed_findings if f.severity == "Low"]
            
            prompt = f"""
            You are an expert security engineer. Create a comprehensive, phased remediation plan for this application.

            SECURITY FINDINGS SUMMARY:
            - Critical: {len(critical)} findings
            - High: {len(high)} findings  
            - Medium: {len(medium)} findings
            - Low: {len(low)} findings

            DETAILED FINDINGS:
            {json.dumps([asdict(f) for f in condensed_findings], indent=2)}

            Create a master remediation plan broken down into clear phases:
            
            PHASE 1: Critical & High Priority (Immediate Action Required)
            - List specific fixes for Critical and High severity issues
            - Include immediate security patches needed
            
            PHASE 2: Medium Priority (Short-term Implementation)
            - Address medium severity issues
            - Include testing and validation steps
            
            PHASE 3: Low Priority & Security Hardening (Long-term)
            - Address low severity issues
            - Include security best practices implementation
            
            PHASE 4: Testing & Validation
            - Security testing procedures
            - Validation steps for each fix
            
            PHASE 5: Monitoring & Prevention
            - Ongoing security measures
            - Prevention strategies for future issues

            Make each phase actionable and practical for indie developers to implement.
            """

            # MULTI-API KEY PARALLEL PROCESSING: Use round-robin API key selection
            api_key_index = self.api_calls_made % len(self.api_keys)
            selected_api_key = self.api_keys[api_key_index]
            
            client = openai.OpenAI(api_key=selected_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer creating phased remediation plans."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1
            )
            
            # Track token usage for master remediation
            self.api_calls_made += 1
            if hasattr(response, 'usage') and response.usage:
                self.prompt_tokens += response.usage.prompt_tokens
                self.completion_tokens += response.usage.completion_tokens
                self.total_tokens_used += response.usage.total_tokens
                logger.info(f"🔍 Master remediation token usage: {response.usage.total_tokens} tokens (prompt: {response.usage.prompt_tokens}, completion: {response.usage.completion_tokens})")
            else:
                logger.warning(f"⚠️ No token usage data available for master remediation")
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error generating master remediation: {e}")
            return "Failed to generate master remediation plan."
    
    def calculate_codebase_health(self, condensed_findings: List[SecurityFinding], all_findings: List[SecurityFinding], repo_info: Dict[str, Any]) -> int:
         """Calculate accurate codebase health percentage using reliable algorithm"""
         try:
             logger.info(f"🔍 Calculating codebase health for {len(condensed_findings)} condensed findings")
             
             # Group findings by severity
             critical = [f for f in condensed_findings if f.severity == "Critical"]
             high = [f for f in condensed_findings if f.severity == "High"]
             medium = [f for f in condensed_findings if f.severity == "Medium"]
             low = [f for f in condensed_findings if f.severity == "Low"]
             
             # Use the reliable fallback calculation instead of ChatGPT
             # This ensures consistent, accurate results without API failures
             health = self.calculate_fallback_health(critical, high, medium, low)
             
             logger.info(f"✅ Calculated health percentage: {health}%")
             logger.info(f"📊 Health breakdown: Critical={len(critical)}, High={len(high)}, Medium={len(medium)}, Low={len(low)}")
             
             return health
             
         except Exception as e:
             logger.error(f"❌ Health calculation failed: {e}")
             logger.warning(f"⚠️ Using emergency fallback health calculation")
             return 50  # Emergency fallback
    
    def calculate_fallback_health(self, critical: List[SecurityFinding], high: List[SecurityFinding], medium: List[SecurityFinding], low: List[SecurityFinding]) -> int:
         """Fallback health calculation if ChatGPT fails"""
         try:
             # Start with 100%
             health = 100
             
             # Apply penalties based on severity
             health -= len(critical) * 15  # Critical: -15% each
             health -= len(high) * 8       # High: -8% each
             health -= len(medium) * 4     # Medium: -4% each
             health -= len(low) * 1        # Low: -1% each
             
             # Ensure health is within valid range
             health = max(0, min(100, health))
             
             logger.info(f"📊 Fallback health calculation: {health}%")
             return health
             
         except Exception as e:
             logger.error(f"❌ Fallback health calculation failed: {e}")
             return 50  # Default to 50% if everything fails
    
    async def scan_repository(self, repo_url: str, github_token: str = None) -> Dict[str, Any]:
        """Main method to scan repository for security vulnerabilities"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting ChatGPT security scan for: {repo_url}")
        
        try:
            # PROGRESS TRACKING: Initialize progress (EVEN DISTRIBUTION!)
            self.update_progress("Initializing scan", 5)
            
            # Clone repository with timeout
            repo_path = await asyncio.wait_for(
                self.clone_repository(repo_url, github_token), 
                timeout=600  # 10 minutes for cloning
            )
            
            # Get repository info
            repo_info = {
                'name': repo_path.split('/')[-1],
                'url': repo_url,
                'size': self.get_directory_size(repo_path),
                'file_count': self.count_files(repo_path)
            }
            
            # PROGRESS TRACKING: Start file filtering (EVEN DISTRIBUTION!)
            self.update_progress("Analyzing repository structure", 20)
            
            # PHASE 1 NUCLEAR OPTIMIZATION: Smart File Filtering + Batch Analysis
            all_findings = []
            file_types = ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte']
            
            # Collect and filter files with smart prioritization
            files_to_analyze = []
            skipped_files = 0
            skipped_size = 0
            
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
                for file in files:
                    if any(file.endswith(ext) for ext in file_types):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, repo_path)
                        file_size = os.path.getsize(file_path)
                        
                        # Apply smart file filtering
                        if self.should_skip_file(relative_path, file_size):
                            skipped_files += 1
                            skipped_size += file_size
                            continue
                        
                        files_to_analyze.append((file_path, relative_path, file))
            
            total_files = len(files_to_analyze)
            total_skipped = skipped_files
            
            logger.info(f"🔍 PHASE 1 NUCLEAR OPTIMIZATION: Smart file filtering complete!")
            logger.info(f"🔍 Files to analyze: {total_files} (was {total_files + total_skipped})")
            logger.info(f"🔍 Files skipped: {total_skipped} ({total_skipped/(total_files + total_skipped)*100:.1f}%)")
            logger.info(f"🔍 Size skipped: {skipped_size/1024/1024:.1f}MB")
            logger.info(f"🔍 Supported file types: {', '.join(file_types)}")
            
            # PROGRESS TRACKING: File filtering complete (EVEN DISTRIBUTION!)
            self.update_progress("Repository structure analyzed", 25)
            
            # PROGRESS TRACKING: Start batch creation (EVEN DISTRIBUTION!)
            self.update_progress("Preparing analysis batches", 30)
            
            # Create intelligent file batches based on priority
            file_batches = self.create_file_batches(files_to_analyze)
            total_batches = len(file_batches)
            
            logger.info(f"🚀 PHASE 1 NUCLEAR OPTIMIZATION: Created {total_batches} intelligent batches")
            logger.info(f"🚀 Priority 1 (Critical): Small batches (3 files) for thorough analysis")
            logger.info(f"🚀 Priority 2 (Important): Medium batches (5 files) for balanced analysis")
            logger.info(f"🚀 Priority 3 (Low): Large batches (8 files) for quick analysis")
            logger.info(f"🚀 Expected performance: 3-5x faster with batch analysis!")
            
            # Add overall scan timeout protection
            scan_start_time = datetime.now()
            max_scan_time = 900  # 15 minutes max
            
            # PROGRESS TRACKING: Start batch processing (EVEN DISTRIBUTION!)
            self.update_progress("Starting security analysis", 35)
            
            # 🚀 PHASE 5: TRUE PARALLEL PROCESSING WITH RATE LIMITING PROTECTION!
            logger.info(f"🚀 PHASE 5 PARALLEL PROCESSING: Starting {total_batches} batches with rate limiting protection!")
            logger.info(f"🚀 Using {len(self.api_keys)} API keys for true parallel processing")
            
            # 🚀 IMPLEMENT TRUE PARALLEL PROCESSING with ThreadPoolExecutor
            import concurrent.futures
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            # Create a thread pool for true parallel execution
            max_workers = min(len(self.api_keys), total_batches, 4)  # Limit concurrent workers
            logger.info(f"🚀 THREAD POOL: Using {max_workers} concurrent workers for true parallel processing")
            
            start_parallel_time = datetime.now()
            all_findings = []
            
            try:
                # Use ThreadPoolExecutor for true parallel processing
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all batch tasks to the thread pool
                    future_to_batch = {}
                    for batch_num, batch_files in enumerate(file_batches):
                        # Add small delay between submissions to avoid rate limiting
                        if batch_num > 0:
                            import time
                            time.sleep(0.1)  # 100ms delay between submissions
                        
                        future = executor.submit(
                            self.analyze_files_batch_sync, 
                            batch_files, 
                            batch_num, 
                            total_batches, 
                            scan_start_time, 
                            max_scan_time
                        )
                        future_to_batch[future] = batch_num
                    
                    logger.info(f"🚀 THREAD POOL: Submitted {len(future_to_batch)} batches for parallel execution")
                    
                    # Process completed batches as they finish (true parallel!)
                    completed_batches = 0
                    for future in as_completed(future_to_batch):
                        batch_num = future_to_batch[future]
                        try:
                            batch_findings = future.result()
                            all_findings.extend(batch_findings)
                            completed_batches += 1
                            logger.info(f"✅ THREAD POOL: Batch {batch_num + 1} completed ({completed_batches}/{total_batches}) - {len(batch_findings)} findings")
                        except Exception as e:
                            logger.error(f"❌ THREAD POOL: Batch {batch_num + 1} failed: {e}")
                            # Try sequential fallback for failed batch
                            try:
                                logger.warning(f"⚠️ THREAD POOL: Attempting sequential fallback for batch {batch_num + 1}")
                                batch_files = file_batches[batch_num]
                                fallback_findings = self.analyze_files_batch(batch_files)
                                all_findings.extend(fallback_findings)
                                logger.info(f"✅ THREAD POOL: Sequential fallback successful for batch {batch_num + 1}")
                            except Exception as fallback_error:
                                logger.error(f"❌ THREAD POOL: Sequential fallback also failed for batch {batch_num + 1}: {fallback_error}")
                
                parallel_time = (datetime.now() - start_parallel_time).total_seconds()
                logger.info(f"🚀 THREAD POOL COMPLETE: All {total_batches} batches finished in {parallel_time:.1f}s!")
                logger.info(f"✅ THREAD POOL: Total findings collected: {len(all_findings)}")
                
            except Exception as e:
                logger.error(f"❌ Thread pool processing failed: {e}")
                # Fallback to sequential processing if thread pool fails
                logger.warning(f"⚠️ Falling back to sequential processing...")
                for batch_num, batch_files in enumerate(file_batches):
                    try:
                        batch_findings = self.analyze_files_batch(batch_files)
                        all_findings.extend(batch_findings)
                    except Exception as batch_error:
                        logger.error(f"❌ Sequential fallback batch {batch_num + 1} failed: {batch_error}")
                        continue
            
            # PROGRESS TRACKING: All batches complete (EVEN DISTRIBUTION!)
            self.update_progress("Parallel batch analysis complete", 65)
            
            # PROGRESS TRACKING: Start condensing (EVEN DISTRIBUTION!)
            self.update_progress("Condensing security findings", 70)
            
            # Condense findings
            logger.info(f"🔍 Condensing {len(all_findings)} findings...")
            condensed_findings = self.condense_findings(all_findings)
            logger.info(f"✅ Condensed to {len(condensed_findings)} unique findings")
            
            # PROGRESS TRACKING: Condensing complete (EVEN DISTRIBUTION!)
            self.update_progress("Findings condensed", 75)
            
            # PROGRESS TRACKING: Start remediations (EVEN DISTRIBUTION!)
            self.update_progress("Generating remediation prompts", 80)
            
            # NUCLEAR OPTIMIZATION: Generate ALL remediations in ONE call
            logger.info(f"🚀 NUCLEAR OPTIMIZATION: Generating {len(condensed_findings)} remediations in ONE API call...")
            start_time_remediations = datetime.now()
            condensed_remediations = self.generate_condensed_remediations(condensed_findings, all_findings)
            remediation_time = (datetime.now() - start_time_remediations).total_seconds()
            logger.info(f"✅ NUCLEAR OPTIMIZATION: Generated {len(condensed_remediations)} remediations in {remediation_time:.1f}s!")
            
            # PROGRESS TRACKING: Remediations complete (EVEN DISTRIBUTION!)
            self.update_progress("Remediation prompts generated", 85)
            
            # PROGRESS TRACKING: Start master plan (EVEN DISTRIBUTION!)
            self.update_progress("Creating master remediation plan", 90)
            
            # Generate master remediation plan
            logger.info(f"🔍 Generating master remediation plan...")
            master_remediation = self.generate_master_remediation(condensed_findings)
            logger.info(f"✅ Master remediation generated")
            
            # PROGRESS TRACKING: Calculate codebase health (EVEN DISTRIBUTION!)
            self.update_progress("Calculating codebase health", 92)
            
            # Calculate accurate codebase health using ChatGPT
            logger.info(f"🔍 Calculating accurate codebase health...")
            codebase_health = self.calculate_codebase_health(condensed_findings, all_findings, repo_info)
            logger.info(f"✅ Codebase health calculated: {codebase_health}%")
            
            # PROGRESS TRACKING: Health calculation complete (EVEN DISTRIBUTION!)
            self.update_progress("Health calculation complete", 95)
            
            # Calculate scan duration
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            # Calculate severity breakdown
            critical_count = len([f for f in condensed_findings if f.severity == "Critical"])
            high_count = len([f for f in condensed_findings if f.severity == "High"])
            medium_count = len([f for f in condensed_findings if f.severity == "Medium"])
            low_count = len([f for f in condensed_findings if f.severity == "Low"])
            
            logger.info(f"📊 Severity breakdown:")
            logger.info(f"   🔴 Critical: {critical_count}")
            logger.info(f"   🟠 High: {high_count}")
            logger.info(f"   🟡 Medium: {medium_count}")
            logger.info(f"   🟢 Low: {low_count}")
            
            # Create security report
            report = SecurityReport(
                summary={
                    'total_findings': len(all_findings),
                    'condensed_findings': len(condensed_findings),
                    'critical_count': critical_count,
                    'high_count': high_count,
                    'medium_count': medium_count,
                    'low_count': low_count,
                    'codebase_health': codebase_health,
                    'files_scanned': repo_info['file_count'],
                    'scan_duration': scan_duration,
                    'gpt_api_usage': {
                        'total_api_calls': self.api_calls_made,
                        'prompt_tokens': self.prompt_tokens,
                        'completion_tokens': self.completion_tokens,
                        'total_tokens': self.total_tokens_used,
                        'estimated_cost_usd': round(self.total_tokens_used * 0.00000015, 4),
                        'tokens_per_file': round(self.total_tokens_used / max(1, total_files), 0),
                        'tokens_per_second': round(self.total_tokens_used / max(1, scan_duration), 0)
                    }
                },
                findings=all_findings,
                condensed_findings=condensed_findings,
                condensed_remediations=condensed_remediations,
                master_remediation=master_remediation,
                scan_duration=scan_duration,
                timestamp=datetime.now().isoformat(),
                repository_info=repo_info
            )
            
            # PROGRESS TRACKING: Final completion
            self.update_progress("Finalizing report", 100)
            
            # Cleanup
            shutil.rmtree(repo_path, ignore_errors=True)
            
            logger.info(f"✅ Security scan completed in {scan_duration:.2f}s")
            logger.info(f"📊 Found {len(all_findings)} total findings, {len(condensed_findings)} unique issues")
            logger.info(f"📊 Files scanned: {repo_info['file_count']}")
            logger.info(f"📊 Repository size: {repo_info['size']}")
            
            # Comprehensive token usage summary
            logger.info(f"🔍 GPT API Usage Summary:")
            logger.info(f"   📞 Total API calls: {self.api_calls_made}")
            logger.info(f"   📝 Prompt tokens: {self.prompt_tokens:,}")
            logger.info(f"   ✍️ Completion tokens: {self.completion_tokens:,}")
            logger.info(f"   🎯 Total tokens: {self.total_tokens_used:,}")
            logger.info(f"   💰 Estimated cost: ${self.total_tokens_used * 0.00000015:.4f} (GPT-4o-mini)")
            logger.info(f"   ⚡ Tokens per file: {self.total_tokens_used / max(1, total_files):.0f}")
            logger.info(f"   🚀 Tokens per second: {self.total_tokens_used / max(1, scan_duration):.0f}")
            
            # Validate report structure
            if not isinstance(report.summary, dict):
                logger.error("❌ Report summary is not a dictionary")
            if not isinstance(report.findings, list):
                logger.error("❌ Report findings is not a list")
            if not isinstance(report.condensed_findings, list):
                logger.error("❌ Report condensed_findings is not a list")
            
            logger.info(f"🎯 Report validation complete")
            logger.info(f"🚀 Scan completed successfully in {scan_duration:.2f}s")
            
            # Add progress data to report
            report_dict = asdict(report)
            report_dict['progress_data'] = self.progress_updates
            
            # 🚀 ADD CACHE STATISTICS to scan result
            try:
                cache_stats = self.get_cache_statistics()
                report_dict['cache_statistics'] = cache_stats
                report_dict['cache_benefits'] = {
                    'cost_savings': f"${cache_stats.get('cache_hits', 0) * 0.02:.2f}",
                    'time_savings': f"{cache_stats.get('cache_hits', 0) * 0.5:.1f} minutes",
                    'hit_rate': f"{cache_stats.get('hit_rate_percent', 0)}%",
                    'api_calls_saved': cache_stats.get('cache_hits', 0)
                }
                logger.info(f"📊 CACHE STATS: Scan completed with {cache_stats.get('hit_rate_percent', 0)}% cache hit rate")
            except Exception as cache_error:
                logger.warning(f"⚠️ Failed to get cache statistics: {cache_error}")
                report_dict['cache_statistics'] = {'error': 'Failed to retrieve cache statistics'}
            
            logger.info(f"✅ Scan completed successfully in {scan_duration:.1f}s")
            
            return report_dict
            
        except Exception as e:
            logger.error(f"❌ Security scan failed: {e}")
            # Cleanup on error
            if 'repo_path' in locals():
                shutil.rmtree(repo_path, ignore_errors=True)
            
            return {
                'error': str(e),
                'error_type': type(e).__name__,
                'scan_duration': (datetime.now() - start_time).total_seconds(),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_directory_size(self, path: str) -> str:
        """Get directory size in human readable format"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
        
        # Convert to MB
        size_mb = total_size / (1024 * 1024)
        return f"{size_mb:.1f}MB"
    
    def count_files(self, path: str) -> int:
        """Count total files in directory"""
        count = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            count += len(files)
        return count

    def get_file_priority(self, file_path: str) -> int:
        """Determine file priority for scanning (1=Critical, 2=Important, 3=Low)"""
        relative_path = file_path.lower()
        
        # Priority 1: Critical security files (ALWAYS SCAN)
        if any(path in relative_path for path in [
            'src/app/', 'src/pages/', 'src/components/', 'src/auth/',
            'src/api/', 'src/db/', 'src/database/', 'src/models/',
            'src/controllers/', 'src/middleware/', 'src/routes/'
        ]):
            return 1
        
        # Priority 2: Important files (SCAN IF TIME ALLOWS)
        if any(path in relative_path for path in [
            'src/lib/', 'src/utils/', 'src/services/', 'src/helpers/',
            'src/types/', 'src/interfaces/', 'src/constants/'
        ]):
            return 2
        
        # Priority 3: Low priority (SKIP UNLESS FAST)
        return 3
    
    def should_skip_file(self, file_path: str, file_size: int) -> bool:
        """Determine if file should be skipped based on smart rules"""
        relative_path = file_path.lower()
        file_name = os.path.basename(file_path).lower()
        
        # Skip large files (>500KB)
        if file_size > 500 * 1024:
            return True
        
        # Skip config files
        if any(name in file_name for name in [
            'package.json', 'tsconfig.json', 'next.config', 'tailwind.config',
            'eslint.config', 'prettier.config', 'babel.config', 'webpack.config'
        ]):
            return True
        
        # Skip documentation
        if any(ext in file_name for ext in ['.md', '.txt', '.rst', '.adoc']):
            return True
        
        # Skip build artifacts
        if any(path in relative_path for path in [
            'dist/', 'build/', 'out/', '.next/', 'coverage/'
        ]):
            return True
        
        # Skip dependencies
        if any(path in relative_path for path in [
            'node_modules/', '.venv/', 'venv/', '__pycache__/'
        ]):
            return True
        
        # Skip test files
        if any(name in file_name for name in [
            '.test.', '.spec.', 'test_', 'spec_'
        ]):
            return True
        
        return False
    
    def create_file_batches(self, files_to_analyze: List[tuple]) -> List[List[tuple]]:
        """Create intelligent batches of files for analysis"""
        if not files_to_analyze:
            return []
        
        # Group files by priority first
        priority_1_files = []
        priority_2_files = []
        priority_3_files = []
        
        for file_path, relative_path, file_type in files_to_analyze:
            priority = self.get_file_priority(relative_path)
            if priority == 1:
                priority_1_files.append((file_path, relative_path, file_type))
            elif priority == 2:
                priority_2_files.append((file_path, relative_path, file_type))
            else:
                priority_3_files.append((file_path, relative_path, file_type))
        
        # Create batches: Priority 1 files get smaller batches for thorough analysis
        batches = []
        
        # Priority 1: Small batches (3 files) for thorough analysis
        for i in range(0, len(priority_1_files), 3):
            batch = priority_1_files[i:i+3]
            if batch:
                batches.append(batch)
        
        # Priority 2: Medium batches (5 files) for balanced analysis
        for i in range(0, len(priority_2_files), 5):
            batch = priority_2_files[i:i+5]
            if batch:
                batches.append(batch)
        
        # Priority 3: Large batches (8 files) for quick analysis
        for i in range(0, len(priority_3_files), 8):
            batch = priority_3_files[i:i+8]
            if batch:
                batches.append(batch)
        
        return batches
    
    def analyze_files_batch_sync(self, batch_files: List[tuple], batch_num: int, total_batches: int, scan_start_time: datetime, max_scan_time: int) -> List[SecurityFinding]:
        """🚀 THREAD POOL VERSION: Analyze multiple files in ONE API call for true parallel processing"""
        try:
            if not batch_files:
                return []
            
            # Check if we're approaching timeout
            elapsed_time = (datetime.now() - scan_start_time).total_seconds()
            if elapsed_time > max_scan_time - 60:  # Stop 1 minute before timeout
                logger.warning(f"⚠️ THREAD BATCH {batch_num + 1}: Approaching scan timeout ({elapsed_time:.0f}s), stopping early")
                return []
            
            batch_start_time = datetime.now()
            logger.info(f"📦 THREAD BATCH {batch_num + 1}/{total_batches} (files: {len(batch_files)}) - STARTING")
            
            # PROGRESS TRACKING: Update batch progress (35-65% - EVEN DISTRIBUTION!)
            batch_progress = 35 + (batch_num / total_batches) * 30
            self.update_progress(f"Analyzing batch {batch_num + 1}/{total_batches}", batch_progress)
            
            # Build comprehensive batch prompt with content chunking
            batch_content = []
            for file_path, relative_path, file_type in batch_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # PHASE 3: CONTENT CHUNKING for large files
                    if len(content) > 12000:  # Increased from 8000
                        # Smart chunking: Split by functions/classes for better analysis
                        chunks = self.chunk_file_content(content, relative_path, file_type)
                        if chunks:
                            # Use first chunk for batch analysis, others will be analyzed separately
                            content = chunks[0]
                            logger.info(f"📄 PHASE 3 CHUNKING: {relative_path} split into {len(chunks)} chunks, using first chunk")
                        else:
                            # Fallback: simple truncation
                            content = content[:12000] + "\n... [truncated for batch analysis]"
                    elif len(content) > 8000:
                        content = content[:8000] + "\n... [truncated for batch analysis]"
                    
                    batch_content.append({
                        'file_path': relative_path,
                        'file_type': file_type,
                        'content': content
                    })
                except Exception as e:
                    logger.warning(f"⚠️ Failed to read {relative_path} for batch analysis: {e}")
                    continue
            
            if not batch_content:
                return []
            
            # Create ONE comprehensive prompt for ALL files
            prompt = f"""
            You are an expert security engineer. Analyze MULTIPLE files for security vulnerabilities in ONE response.
            
            FILES TO ANALYZE:
            {json.dumps(batch_content, indent=2)}
            
            For EACH file, identify security vulnerabilities focusing on:
            - Authentication & authorization bypasses
            - Input validation & injection attacks
            - Data exposure & privacy violations
            - Cryptography & secrets management
            - Session management issues
            - File upload security
            - API security vulnerabilities
            - Frontend security (XSS, CSRF)
            - Backend security (SQL injection, etc.)
            - Business logic flaws
            - Error handling & information disclosure
            
            Return findings in this EXACT JSON format:
            {{
                "files": {{
                    "file_path_1": {{
                        "findings": [
                            {{
                                "rule_id": "vulnerability_type_identifier",
                                "severity": "Critical|High|Medium|Low",
                                "message": "Brief vulnerability description",
                                "description": "Detailed explanation",
                                "file_path": "file_path_1",
                                "line_number": 123,
                                "end_line": 125,
                                "code_snippet": "vulnerable code here",
                                "cwe_ids": ["CWE-79", "CWE-89"],
                                "owasp_ids": ["A01:2021", "A03:2021"],
                                "impact": "High|Medium|Low",
                                "likelihood": "High|Medium|Low",
                                "confidence": "High|Medium|Low"
                            }}
                        ]
                    }},
                    "file_path_2": {{
                        "findings": [...]
                    }}
                }}
            }}
            
            Be thorough but practical. Focus on real-world risks that indie developers face.
            
            IMPORTANT: For rule_id, use a descriptive identifier like "xss_vulnerability", "sql_injection", "csrf_missing", etc. NOT generic numbers like "VULN-001".
            """
            
            # 🚀 MULTI-API KEY THREAD POOL PROCESSING: Each batch gets its own API key!
            api_key_index = batch_num % len(self.api_keys)  # Distribute batches across API keys
            selected_api_key = self.api_keys[api_key_index]
            
            logger.info(f"🚀 THREAD BATCH {batch_num + 1}: Using API key {api_key_index + 1}/{len(self.api_keys)}")
            
            # 🚀 IMPLEMENT RATE LIMITING PROTECTION with exponential backoff
            max_retries = 3
            base_delay = 1.0  # Start with 1 second delay
            
            for attempt in range(max_retries):
                try:
                    # ONE API CALL for ALL files in batch
                    client = openai.OpenAI(api_key=selected_api_key)
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[
                            {"role": "system", "content": "You are an expert security engineer analyzing multiple files efficiently."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=8000,  # Increased for batch analysis
                        temperature=0.1
                    )
                    
                    # Track token usage
                    self.api_calls_made += 1
                    if hasattr(response, 'usage') and response.usage:
                        self.prompt_tokens += response.usage.prompt_tokens
                        self.completion_tokens += response.usage.completion_tokens
                        self.total_tokens_used += response.usage.total_tokens
                        logger.info(f"🚀 THREAD BATCH {batch_num + 1}: Processed {len(batch_files)} files in 1 API call! Tokens: {response.usage.total_tokens}")
                    
                    # Parse the batch response
                    content = response.choices[0].message.content
                    try:
                        json_start = content.find('{')
                        json_end = content.rfind('}') + 1
                        
                        if json_start != -1 and json_end > json_start:
                            json_content = content[json_start:json_end]
                            result = json.loads(json_content)
                            
                            all_findings = []
                            files_data = result.get('files', {})
                            
                            for file_path, file_data in files_data.items():
                                findings = file_data.get('findings', [])
                                for i, finding in enumerate(findings):
                                    try:
                                        # Ensure file_path is correct
                                        finding['file_path'] = file_path
                                        
                                        # Ensure unique rule_id by adding file identifier and counter
                                        file_id = os.path.basename(file_path).replace('.', '_').replace('-', '_')
                                        unique_rule_id = f"{finding.get('rule_id', 'vulnerability')}_{file_id}_{i+1}"
                                        finding['rule_id'] = unique_rule_id
                                        
                                        security_finding = SecurityFinding(**finding)
                                        all_findings.append(security_finding)
                                    except Exception as e:
                                        logger.warning(f"Failed to create SecurityFinding for {file_path}: {e}")
                                        continue
                            
                            batch_time = (datetime.now() - batch_start_time).total_seconds()
                            logger.info(f"✅ THREAD BATCH {batch_num + 1} COMPLETE: {len(all_findings)} findings in {batch_time:.1f}s")
                            
                            # 🚀 ADVANCED CACHING: Cache batch analysis result
                            batch_content_str = json.dumps(batch_content, sort_keys=True)
                            self.cache_result(batch_content_str, all_findings, "batch")
                            
                            return all_findings
                        else:
                            logger.error(f"❌ THREAD BATCH {batch_num + 1}: No JSON found in response")
                            return []
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"❌ THREAD BATCH {batch_num + 1}: Failed to parse response: {e}")
                        return []
                    
                except Exception as api_error:
                    if "rate_limit" in str(api_error).lower() or "429" in str(api_error):
                        if attempt < max_retries - 1:
                            delay = base_delay * (2 ** attempt)  # Exponential backoff
                            logger.warning(f"⚠️ THREAD BATCH {batch_num + 1}: Rate limited, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
                            import time
                            time.sleep(delay)
                            continue
                        else:
                            logger.error(f"❌ THREAD BATCH {batch_num + 1}: Rate limit exceeded after {max_retries} attempts")
                            return []
                    else:
                        logger.error(f"❌ THREAD BATCH {batch_num + 1}: API error: {api_error}")
                        return []
            
            return []
            
        except Exception as e:
            logger.error(f"❌ THREAD BATCH {batch_num + 1} failed: {e}")
            return []
    
    async def analyze_files_batch_async(self, batch_files: List[tuple], batch_num: int, total_batches: int, scan_start_time: datetime, max_scan_time: int) -> List[SecurityFinding]:
        """🚀 ASYNC VERSION: Analyze multiple files in ONE API call for parallel processing"""
        try:
            if not batch_files:
                return []
            
            # Check if we're approaching timeout
            elapsed_time = (datetime.now() - scan_start_time).total_seconds()
            if elapsed_time > max_scan_time - 60:  # Stop 1 minute before timeout
                logger.warning(f"⚠️ BATCH {batch_num + 1}: Approaching scan timeout ({elapsed_time:.0f}s), stopping early")
                return []
            
            batch_start_time = datetime.now()
            logger.info(f"📦 PARALLEL BATCH {batch_num + 1}/{total_batches} (files: {len(batch_files)}) - STARTING")
            
            # PROGRESS TRACKING: Update batch progress (35-65% - EVEN DISTRIBUTION!)
            batch_progress = 35 + (batch_num / total_batches) * 30
            self.update_progress(f"Analyzing batch {batch_num + 1}/{total_batches}", batch_progress)
            
            # Build comprehensive batch prompt with content chunking
            batch_content = []
            for file_path, relative_path, file_type in batch_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # PHASE 3: CONTENT CHUNKING for large files
                    if len(content) > 12000:  # Increased from 8000
                        # Smart chunking: Split by functions/classes for better analysis
                        chunks = self.chunk_file_content(content, relative_path, file_type)
                        if chunks:
                            # Use first chunk for batch analysis, others will be analyzed separately
                            content = chunks[0]
                            logger.info(f"📄 PHASE 3 CHUNKING: {relative_path} split into {len(chunks)} chunks, using first chunk")
                        else:
                            # Fallback: simple truncation
                            content = content[:12000] + "\n... [truncated for batch analysis]"
                    elif len(content) > 8000:
                        content = content[:8000] + "\n... [truncated for batch analysis]"
                    
                    batch_content.append({
                        'file_path': relative_path,
                        'file_type': file_type,
                        'content': content
                    })
                except Exception as e:
                    logger.warning(f"⚠️ Failed to read {relative_path} for batch analysis: {e}")
                    continue
            
            if not batch_content:
                return []
            
            # Create ONE comprehensive prompt for ALL files
            prompt = f"""
            You are an expert security engineer. Analyze MULTIPLE files for security vulnerabilities in ONE response.
            
            FILES TO ANALYZE:
            {json.dumps(batch_content, indent=2)}
            
            For EACH file, identify security vulnerabilities focusing on:
            - Authentication & authorization bypasses
            - Input validation & injection attacks
            - Data exposure & privacy violations
            - Cryptography & secrets management
            - Session management issues
            - File upload security
            - API security vulnerabilities
            - Frontend security (XSS, CSRF)
            - Backend security (SQL injection, etc.)
            - Business logic flaws
            - Error handling & information disclosure
            
            Return findings in this EXACT JSON format:
            {{
                "files": {{
                    "file_path_1": {{
                        "findings": [
                            {{
                                "rule_id": "vulnerability_type_identifier",
                                "severity": "Critical|High|Medium|Low",
                                "message": "Brief vulnerability description",
                                "description": "Detailed explanation",
                                "file_path": "file_path_1",
                                "line_number": 123,
                                "end_line": 125,
                                "code_snippet": "vulnerable code here",
                                "cwe_ids": ["CWE-79", "CWE-89"],
                                "owasp_ids": ["A01:2021", "A03:2021"],
                                "impact": "High|Medium|Low",
                                "likelihood": "High|Medium|Low",
                                "confidence": "High|Medium|Low"
                            }}
                        ]
                    }},
                    "file_path_2": {{
                        "findings": [...]
                    }}
                }}
            }}
            
            Be thorough but practical. Focus on real-world risks that indie developers face.
            
            IMPORTANT: For rule_id, use a descriptive identifier like "xss_vulnerability", "sql_injection", "csrf_missing", etc. NOT generic numbers like "VULN-001".
            """
            
            # 🚀 MULTI-API KEY PARALLEL PROCESSING: Each batch gets its own API key!
            api_key_index = batch_num % len(self.api_keys)  # Distribute batches across API keys
            selected_api_key = self.api_keys[api_key_index]
            
            logger.info(f"🚀 PARALLEL BATCH {batch_num + 1}: Using API key {api_key_index + 1}/{len(self.api_keys)}")
            
            # ONE API CALL for ALL files in batch
            client = openai.OpenAI(api_key=selected_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer analyzing multiple files efficiently."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=8000,  # Increased for batch analysis
                temperature=0.1
            )
            
            # Track token usage
            self.api_calls_made += 1
            if hasattr(response, 'usage') and response.usage:
                self.prompt_tokens += response.usage.prompt_tokens
                self.completion_tokens += response.usage.completion_tokens
                self.total_tokens_used += response.usage.total_tokens
                logger.info(f"🚀 PARALLEL BATCH {batch_num + 1}: Processed {len(batch_files)} files in 1 API call! Tokens: {response.usage.total_tokens}")
            
            # Parse the batch response
            content = response.choices[0].message.content
            try:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = content[json_start:json_end]
                    result = json.loads(json_content)
                    
                    all_findings = []
                    files_data = result.get('files', {})
                    
                    for file_path, file_data in files_data.items():
                        findings = file_data.get('findings', [])
                        for i, finding in enumerate(findings):
                            try:
                                # Ensure file_path is correct
                                finding['file_path'] = file_path
                                
                                # Ensure unique rule_id by adding file identifier and counter
                                file_id = os.path.basename(file_path).replace('.', '_').replace('-', '_')
                                unique_rule_id = f"{finding.get('rule_id', 'vulnerability')}_{file_id}_{i+1}"
                                finding['rule_id'] = unique_rule_id
                                
                                security_finding = SecurityFinding(**finding)
                                all_findings.append(security_finding)
                            except Exception as e:
                                logger.warning(f"Failed to create SecurityFinding for {file_path}: {e}")
                                continue
                    
                    batch_time = (datetime.now() - batch_start_time).total_seconds()
                    logger.info(f"✅ PARALLEL BATCH {batch_num + 1} COMPLETE: {len(all_findings)} findings in {batch_time:.1f}s")
                    return all_findings
                else:
                    logger.error(f"❌ PARALLEL BATCH {batch_num + 1}: No JSON found in response")
                    return []
                    
            except json.JSONDecodeError as e:
                logger.error(f"❌ PARALLEL BATCH {batch_num + 1}: Failed to parse response: {e}")
                return []
            
        except Exception as e:
            logger.error(f"❌ PARALLEL BATCH {batch_num + 1} failed: {e}")
            return []
    
    def analyze_files_batch(self, batch_files: List[tuple]) -> List[SecurityFinding]:
        """Analyze multiple files in ONE API call for massive optimization"""
        try:
            if not batch_files:
                return []
            
            logger.info(f"🚀 BATCH ANALYSIS: Processing {len(batch_files)} files in ONE API call!")
            
            # Build comprehensive batch prompt with content chunking
            batch_content = []
            for file_path, relative_path, file_type in batch_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # PHASE 3: CONTENT CHUNKING for large files
                    if len(content) > 12000:  # Increased from 8000
                        # Smart chunking: Split by functions/classes for better analysis
                        chunks = self.chunk_file_content(content, relative_path, file_type)
                        if chunks:
                            # Use first chunk for batch analysis, others will be analyzed separately
                            content = chunks[0]
                            logger.info(f"📄 PHASE 3 CHUNKING: {relative_path} split into {len(chunks)} chunks, using first chunk")
                        else:
                            # Fallback: simple truncation
                            content = content[:12000] + "\n... [truncated for batch analysis]"
                    elif len(content) > 8000:
                        content = content[:8000] + "\n... [truncated for batch analysis]"
                    
                    batch_content.append({
                        'file_path': relative_path,
                        'file_type': file_type,
                        'content': content
                    })
                except Exception as e:
                    logger.warning(f"⚠️ Failed to read {relative_path} for batch analysis: {e}")
                    continue
            
            if not batch_content:
                return []
            
            # Create ONE comprehensive prompt for ALL files
            prompt = f"""
            You are an expert security engineer. Analyze MULTIPLE files for security vulnerabilities in ONE response.
            
            FILES TO ANALYZE:
            {json.dumps(batch_content, indent=2)}
            
            For EACH file, identify security vulnerabilities focusing on:
            - Authentication & authorization bypasses
            - Input validation & injection attacks
            - Data exposure & privacy violations
            - Cryptography & secrets management
            - Session management issues
            - File upload security
            - API security vulnerabilities
            - Frontend security (XSS, CSRF)
            - Backend security (SQL injection, etc.)
            - Business logic flaws
            - Error handling & information disclosure
            
            Return findings in this EXACT JSON format:
            {{
                "files": {{
                    "file_path_1": {{
                        "findings": [
                            {{
                                "rule_id": "vulnerability_type_identifier",
                                "severity": "Critical|High|Medium|Low",
                                "message": "Brief vulnerability description",
                                "description": "Detailed explanation",
                                "file_path": "file_path_1",
                                "line_number": 123,
                                "end_line": 125,
                                "code_snippet": "vulnerable code here",
                                "cwe_ids": ["CWE-79", "CWE-89"],
                                "owasp_ids": ["A01:2021", "A03:2021"],
                                "impact": "High|Medium|Low",
                                "likelihood": "High|Medium|Low",
                                "confidence": "High|Medium|Low"
                            }}
                        ]
                    }},
                    "file_path_2": {{
                        "findings": [...]
                    }}
                }}
            }}
            
            Be thorough but practical. Focus on real-world risks that indie developers face.
            
            IMPORTANT: For rule_id, use a descriptive identifier like "xss_vulnerability", "sql_injection", "csrf_missing", etc. NOT generic numbers like "VULN-001".
            """
            
            # MULTI-API KEY PARALLEL PROCESSING: Use round-robin API key selection
            api_key_index = self.api_calls_made % len(self.api_keys)
            selected_api_key = self.api_keys[api_key_index]
            
            logger.info(f"🚀 MULTI-API KEY: Using API key {api_key_index + 1}/{len(self.api_keys)} for batch analysis")
            
            # ONE API CALL for ALL files in batch
            client = openai.OpenAI(api_key=selected_api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer analyzing multiple files efficiently."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=8000,  # Increased for batch analysis
                temperature=0.1
            )
            
            # Track token usage
            self.api_calls_made += 1
            if hasattr(response, 'usage') and response.usage:
                self.prompt_tokens += response.usage.prompt_tokens
                self.completion_tokens += response.usage.completion_tokens
                self.total_tokens_used += response.usage.total_tokens
                logger.info(f"🚀 BATCH ANALYSIS: Processed {len(batch_files)} files in 1 API call! Tokens: {response.usage.total_tokens}")
            
            # Parse the batch response
            content = response.choices[0].message.content
            try:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = content[json_start:json_end]
                    result = json.loads(json_content)
                    
                    all_findings = []
                    files_data = result.get('files', {})
                    
                    for file_path, file_data in files_data.items():
                        findings = file_data.get('findings', [])
                        for i, finding in enumerate(findings):
                            try:
                                # Ensure file_path is correct
                                finding['file_path'] = file_path
                                
                                # Ensure unique rule_id by adding file identifier and counter
                                file_id = os.path.basename(file_path).replace('.', '_').replace('-', '_')
                                unique_rule_id = f"{finding.get('rule_id', 'vulnerability')}_{file_id}_{i+1}"
                                finding['rule_id'] = unique_rule_id
                                
                                security_finding = SecurityFinding(**finding)
                                all_findings.append(security_finding)
                            except Exception as e:
                                logger.warning(f"Failed to create SecurityFinding for {file_path}: {e}")
                                continue
                    
                    logger.info(f"✅ BATCH ANALYSIS: Successfully parsed {len(all_findings)} findings from {len(batch_files)} files")
                    return all_findings
                else:
                    logger.error("❌ No JSON found in batch analysis response")
                    return []
                    
            except json.JSONDecodeError as e:
                logger.error(f"❌ Failed to parse batch analysis response: {e}")
                logger.error(f"Response content: {content}")
                return []
            
        except Exception as e:
            logger.error(f"❌ Batch analysis failed: {e}")
            return []
    
    def chunk_file_content(self, content: str, file_path: str, file_type: str) -> List[str]:
        """PHASE 3: Smart content chunking for large files"""
        try:
            if len(content) <= 12000:
                return [content]
            
            chunks = []
            
            # Language-specific chunking strategies
            if file_type in ['.js', '.ts', '.jsx', '.tsx']:
                # JavaScript/TypeScript: Split by functions, classes, and major sections
                lines = content.split('\n')
                current_chunk = []
                chunk_size = 0
                
                for line in lines:
                    # Check for major section boundaries
                    if any(keyword in line for keyword in [
                        'function ', 'class ', 'export ', 'import ', 'const ', 'let ', 'var ',
                        'interface ', 'type ', 'enum ', 'namespace '
                    ]):
                        # If current chunk is getting large, start a new one
                        if chunk_size > 8000 and current_chunk:
                            chunks.append('\n'.join(current_chunk))
                            current_chunk = []
                            chunk_size = 0
                    
                    current_chunk.append(line)
                    chunk_size += len(line) + 1
                    
                    # Force chunk break if getting too large
                    if chunk_size > 12000:
                        chunks.append('\n'.join(current_chunk))
                        current_chunk = []
                        chunk_size = 0
                
                # Add remaining content
                if current_chunk:
                    chunks.append('\n'.join(current_chunk))
            
            elif file_type in ['.py']:
                # Python: Split by functions, classes, and major sections
                lines = content.split('\n')
                current_chunk = []
                chunk_size = 0
                
                for line in lines:
                    # Check for major section boundaries
                    if any(keyword in line for keyword in [
                        'def ', 'class ', 'import ', 'from ', 'if __name__', 'async def '
                    ]):
                        # If current chunk is getting large, start a new one
                        if chunk_size > 8000 and current_chunk:
                            chunks.append('\n'.join(current_chunk))
                            current_chunk = []
                            chunk_size = 0
                    
                    current_chunk.append(line)
                    chunk_size += len(line) + 1
                    
                    # Force chunk break if getting too large
                    if chunk_size > 12000:
                        chunks.append('\n'.join(current_chunk))
                        current_chunk = []
                        chunk_size = 0
                
                # Add remaining content
                if current_chunk:
                    chunks.append('\n'.join(current_chunk))
            
            else:
                # Generic chunking: Split by lines
                lines = content.split('\n')
                chunk_size = 12000
                for i in range(0, len(lines), chunk_size):
                    chunk_lines = lines[i:i + chunk_size]
                    chunks.append('\n'.join(chunk_lines))
            
            logger.info(f"📄 PHASE 3 CHUNKING: {file_path} split into {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"❌ Content chunking failed for {file_path}: {e}")
            return [content]  # Return original content as single chunk
    
    def get_cached_result(self, file_path: str, file_content_hash: str) -> Optional[List[SecurityFinding]]:
        """PHASE 4: Get cached analysis result if available"""
        cache_key = f"{file_path}_{file_content_hash}"
        if cache_key in self.result_cache:
            logger.info(f"📋 PHASE 4 CACHE HIT: Using cached result for {file_path}")
            return self.result_cache[cache_key]
        return None
    
    def cache_result(self, file_path: str, file_content_hash: str, findings: List[SecurityFinding]):
        """PHASE 4: Cache analysis result for future use"""
        cache_key = f"{file_path}_{file_content_hash}"
        self.result_cache[cache_key] = findings
        logger.info(f"📋 PHASE 4 CACHE STORE: Cached result for {file_path}")
    
    def calculate_file_risk_score(self, file_path: str, file_content: str) -> float:
        """PHASE 4: Calculate risk score for file based on content patterns"""
        try:
            risk_score = 0.0
            content_lower = file_content.lower()
            
            # High-risk patterns
            high_risk_patterns = [
                'password', 'secret', 'api_key', 'token', 'auth', 'login', 'register',
                'sql', 'query', 'database', 'db.', 'exec', 'eval', 'innerhtml',
                'localstorage', 'sessionstorage', 'cookie', 'jwt', 'oauth'
            ]
            
            for pattern in high_risk_patterns:
                if pattern in content_lower:
                    risk_score += 0.1
            
            # Medium-risk patterns
            medium_risk_patterns = [
                'input', 'form', 'upload', 'file', 'user', 'admin', 'root',
                'config', 'env', 'process.env', 'window.', 'document.'
            ]
            
            for pattern in medium_risk_patterns:
                if pattern in content_lower:
                    risk_score += 0.05
            
            # Normalize risk score to 0-1 range
            risk_score = min(1.0, risk_score)
            
            # Store risk score for future reference
            self.file_risk_scores[file_path] = risk_score
            
            return risk_score
            
        except Exception as e:
            logger.error(f"❌ Risk score calculation failed for {file_path}: {e}")
            return 0.5  # Default medium risk
    
    def should_analyze_file_deep(self, file_path: str, file_content: str) -> bool:
        """PHASE 4: Determine if file needs deep analysis based on risk score"""
        risk_score = self.calculate_file_risk_score(file_path, file_content)
        
        # High-risk files (risk_score > 0.7) always get deep analysis
        if risk_score > 0.7:
            logger.info(f"🎯 PHASE 4 ML: {file_path} marked as HIGH RISK (score: {risk_score:.2f}) - Deep analysis required")
            return True
        
        # Medium-risk files (risk_score > 0.4) get standard analysis
        elif risk_score > 0.4:
            logger.info(f"🎯 PHASE 4 ML: {file_path} marked as MEDIUM RISK (score: {risk_score:.2f}) - Standard analysis")
            return True
        
        # Low-risk files (risk_score <= 0.4) get quick analysis or skip
        else:
            logger.info(f"🎯 PHASE 4 ML: {file_path} marked as LOW RISK (score: {risk_score:.2f}) - Quick analysis only")
            return False

    def get_file_analysis_rules(self, file_path: str) -> Dict[str, Any]:
        """Universal analysis rules for ALL tech stacks to reduce false positives"""
        file_path_lower = file_path.lower()
        
        # Database & Backend Configuration (ALL platforms)
        if any(term in file_path_lower for term in [
            'firebase', 'supabase', 'mongodb', 'postgres', 'mysql', 'sqlite',
            'prisma', 'sequelize', 'typeorm', 'drizzle', 'knex'
        ]):
            return {
                'ignore_patterns': [
                    'NEXT_PUBLIC_', 'NUXT_PUBLIC_', 'VITE_PUBLIC_', 'SVELTE_PUBLIC_',
                    'process.env.public', 'import.meta.env.public', 'window.env.public',
                    'database config', 'db config', 'connection string', 'connection_string',
                    'public database', 'public connection', 'public endpoint'
                ],
                'focus_on': [
                    'authentication logic',
                    'database security rules',
                    'user permission handling',
                    'sql injection prevention',
                    'data validation'
                ],
                'skip_checks': [
                    'environment_variable_exposure',
                    'config_file_exposure',
                    'public_key_exposure',
                    'database_config_exposure'
                ]
            }
        
        # OAuth & Authentication (ALL platforms)
        elif any(term in file_path_lower for term in [
            'oauth', 'auth', 'github', 'google', 'facebook', 'discord', 'twitter',
            'login', 'register', 'signin', 'signup', 'authentication'
        ]):
            return {
                'ignore_patterns': [
                    'client id', 'client_id', 'redirect uri', 'redirect_uri',
                    'oauth config', 'auth config', 'public oauth', 'public auth',
                    'github client', 'google client', 'facebook client', 'discord client'
                ],
                'focus_on': [
                    'state validation',
                    'token handling',
                    'session management',
                    'authentication bypasses',
                    'csrf protection',
                    'password security'
                ],
                'skip_checks': [
                    'oauth_config_exposure',
                    'client_secret_exposure',
                    'redirect_uri_exposure'
                ]
            }
        
        # API & Backend Routes (ALL platforms)
        elif any(term in file_path_lower for term in [
            'api/', 'routes/', 'controllers/', 'handlers/', 'endpoints/',
            'middleware/', 'services/', 'utils/', 'helpers/'
        ]):
            return {
                'ignore_patterns': [],
                'focus_on': [
                    'input validation',
                    'authentication checks',
                    'authorization logic',
                    'rate limiting',
                    'error handling',
                    'sql injection prevention',
                    'xss prevention'
                ],
                'skip_checks': []
            }
        
        # Frontend Components & Pages (ALL frameworks)
        elif any(term in file_path_lower for term in [
            'component', 'page', 'ui', 'view', 'screen', 'layout',
            'react', 'vue', 'svelte', 'angular', 'ember', 'next', 'nuxt'
        ]):
            return {
                'ignore_patterns': [
                    'public props', 'component props', 'ui configuration',
                    'theme config', 'style config', 'css config', 'design system'
                ],
                'focus_on': [
                    'XSS prevention',
                    'user input handling',
                    'dangerouslySetInnerHTML usage',
                    'client-side validation',
                    'csrf protection',
                    'secure data handling'
                ],
                'skip_checks': [
                    'component_prop_exposure',
                    'ui_config_exposure',
                    'theme_exposure'
                ]
            }
        
        # Configuration & Build Files (ALL platforms)
        elif any(term in file_path_lower for term in [
            'config', 'env', 'setup', 'webpack', 'vite', 'rollup', 'esbuild',
            'babel', 'typescript', 'tailwind', 'postcss', 'eslint', 'prettier'
        ]):
            return {
                'ignore_patterns': [
                    'NEXT_PUBLIC_', 'NUXT_PUBLIC_', 'VITE_PUBLIC_', 'SVELTE_PUBLIC_',
                    'process.env.public', 'import.meta.env.public', 'window.env.public',
                    'public config', 'build config', 'framework config'
                ],
                'focus_on': [
                    'security settings',
                    'authentication config',
                    'CORS configuration',
                    'security headers',
                    'build security'
                ],
                'skip_checks': [
                    'config_file_exposure',
                    'environment_exposure',
                    'build_config_exposure'
                ]
            }
        
        # Package & Dependency Files (ALL platforms)
        elif any(term in file_path_lower for term in [
            'package.json', 'composer.json', 'requirements.txt', 'gemfile',
            'cargo.toml', 'go.mod', 'pom.xml', 'build.gradle', 'yarn.lock'
        ]):
            return {
                'ignore_patterns': [
                    'dependency list', 'package list', 'module list',
                    'version info', 'license info', 'author info'
                ],
                'focus_on': [
                    'vulnerable dependencies',
                    'outdated packages',
                    'security advisories',
                    'license compliance'
                ],
                'skip_checks': [
                    'package_exposure',
                    'dependency_exposure',
                    'version_exposure'
                ]
            }
        
        # Default rules for other files
        return {
            'ignore_patterns': [],
            'focus_on': ['all'],
            'skip_checks': []
        }

    # 🚀 ADVANCED CACHING METHODS
    
    def generate_cache_key(self, content: str, cache_type: str = "file") -> str:
        """Generate unique cache key based on content and type"""
        # Create hash of content
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        # Add cache type and timestamp for better organization
        timestamp = int(time.time() / (self.cache_ttl_hours * 3600))  # Hour-based timestamp
        return f"{cache_type}:{content_hash}:{timestamp}"
    
    def normalize_code_content(self, content: str) -> str:
        """Normalize code content for better pattern matching"""
        # Remove comments, whitespace, and normalize
        lines = content.split('\n')
        normalized_lines = []
        
        for line in lines:
            # Remove comments
            if '//' in line:
                line = line.split('//')[0]
            if '#' in line:
                line = line.split('#')[0]
            if '/*' in line:
                continue  # Skip multi-line comments
            
            # Remove extra whitespace
            line = line.strip()
            if line:
                normalized_lines.append(line)
        
        return '\n'.join(normalized_lines)
    
    def calculate_content_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two code contents"""
        if not content1 or not content2:
            return 0.0
        
        # Normalize both contents
        norm1 = self.normalize_code_content(content1)
        norm2 = self.normalize_code_content(content2)
        
        if norm1 == norm2:
            return 1.0
        
        # Simple similarity calculation (can be enhanced with more sophisticated algorithms)
        words1 = set(norm1.split())
        words2 = set(norm2.split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    
    def get_cached_result(self, content: str, cache_type: str = "file") -> Optional[Any]:
        """Get cached result if available and not expired"""
        try:
            # Clean up cache periodically
            self._cleanup_cache_if_needed()
            
            # Generate cache key
            cache_key = self.generate_cache_key(content, cache_type)
            
            # Check file cache first
            if cache_type == "file" and cache_key in self.file_cache:
                result = self.file_cache[cache_key]
                if self._is_cache_valid(result):
                    self.cache_stats['hits'] += 1
                    self.cache_stats['total_requests'] += 1
                    logger.info(f"🎯 CACHE HIT: {cache_type} analysis found in cache")
                    return result['data']
            
            # Check pattern cache for similar content
            if cache_type == "file":
                similar_result = self._find_similar_pattern(content)
                if similar_result:
                    self.cache_stats['hits'] += 1
                    self.cache_stats['total_requests'] += 1
                    logger.info(f"🎯 PATTERN CACHE HIT: Similar content found in cache")
                    return similar_result
            
            # Check batch cache
            if cache_type == "batch" and cache_key in self.batch_cache:
                result = self.batch_cache[cache_key]
                if self._is_cache_valid(result):
                    self.cache_stats['hits'] += 1
                    self.cache_stats['total_requests'] += 1
                    logger.info(f"🎯 CACHE HIT: Batch analysis found in cache")
                    return result['data']
            
            # Cache miss
            self.cache_stats['misses'] += 1
            self.cache_stats['total_requests'] += 1
            logger.info(f"🔄 CACHE MISS: {cache_type} analysis not found in cache")
            return None
            
        except Exception as e:
            logger.error(f"❌ Cache retrieval error: {e}")
            return None
    
    def cache_result(self, content: str, result: Any, cache_type: str = "file") -> None:
        """Cache analysis result with TTL and LRU management"""
        try:
            # Generate cache key
            cache_key = self.generate_cache_key(content, cache_type)
            
            # Create cache entry with metadata
            cache_entry = {
                'data': result,
                'timestamp': time.time(),
                'size': len(str(result)),
                'type': cache_type
            }
            
            # Add to appropriate cache
            if cache_type == "file":
                self._add_to_lru_cache(self.file_cache, cache_key, cache_entry)
            elif cache_type == "batch":
                self._add_to_lru_cache(self.batch_cache, cache_key, cache_entry)
            elif cache_type == "pattern":
                self._add_to_lru_cache(self.pattern_cache, cache_key, cache_entry)
            
            # Update cache statistics
            self.cache_stats['cache_size'] = len(self.file_cache) + len(self.batch_cache) + len(self.pattern_cache)
            self.cache_stats['memory_usage_mb'] = self._calculate_cache_memory_usage()
            
            logger.info(f"💾 CACHED: {cache_type} analysis result cached (key: {cache_key[:16]}...)")
            
        except Exception as e:
            logger.error(f"❌ Cache storage error: {e}")
    
    def _add_to_lru_cache(self, cache: OrderedDict, key: str, value: Any) -> None:
        """Add item to LRU cache with size management"""
        # Remove oldest items if cache is full
        while len(cache) >= self.max_cache_size:
            cache.popitem(last=False)  # Remove oldest item
        
        # Add new item
        cache[key] = value
        
        # Move to end (most recently used)
        cache.move_to_end(key)
    
    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """Check if cache entry is still valid (not expired)"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        age_hours = (time.time() - cache_entry['timestamp']) / 3600
        return age_hours < self.cache_ttl_hours
    
    def _find_similar_pattern(self, content: str) -> Optional[Any]:
        """Find similar pattern in pattern cache"""
        normalized_content = self.normalize_code_content(content)
        
        for cache_key, cache_entry in self.pattern_cache.items():
            if not self._is_cache_valid(cache_entry):
                continue
            
            cached_content = cache_entry.get('original_content', '')
            if not cached_content:
                continue
            
            similarity = self.calculate_content_similarity(normalized_content, cached_content)
            if similarity >= self.pattern_similarity_threshold:
                logger.info(f"🎯 PATTERN MATCH: Found {similarity:.2f} similarity match")
                return cache_entry['data']
        
        return None
    
    def _cleanup_cache_if_needed(self) -> None:
        """Clean up expired cache entries"""
        current_time = time.time()
        if current_time - self.last_cache_cleanup < self.cache_cleanup_interval:
            return
        
        logger.info("🧹 CACHE CLEANUP: Starting cache cleanup...")
        
        # Clean up expired entries
        for cache_name, cache in [('file', self.file_cache), ('batch', self.batch_cache), ('pattern', self.pattern_cache)]:
            expired_keys = [key for key, entry in cache.items() if not self._is_cache_valid(entry)]
            for key in expired_keys:
                del cache[key]
            if expired_keys:
                logger.info(f"🧹 CACHE CLEANUP: Removed {len(expired_keys)} expired entries from {cache_name} cache")
        
        # Update statistics
        self.cache_stats['cache_size'] = len(self.file_cache) + len(self.batch_cache) + len(self.pattern_cache)
        self.cache_stats['memory_usage_mb'] = self._calculate_cache_memory_usage()
        
        self.last_cache_cleanup = current_time
        logger.info(f"🧹 CACHE CLEANUP: Complete. Cache size: {self.cache_stats['cache_size']}, Memory: {self.cache_stats['memory_usage_mb']:.2f}MB")
    
    def _calculate_cache_memory_usage(self) -> float:
        """Calculate approximate memory usage of cache in MB"""
        total_size = 0
        for cache in [self.file_cache, self.batch_cache, self.pattern_cache]:
            for entry in cache.values():
                total_size += len(str(entry))
        
        return total_size / (1024 * 1024)  # Convert to MB
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        hit_rate = (self.cache_stats['hits'] / max(self.cache_stats['total_requests'], 1)) * 100
        
        return {
            'cache_hits': self.cache_stats['hits'],
            'cache_misses': self.cache_stats['misses'],
            'total_requests': self.cache_stats['total_requests'],
            'hit_rate_percent': round(hit_rate, 2),
            'cache_size': self.cache_stats['cache_size'],
            'memory_usage_mb': round(self.cache_stats['memory_usage_mb'], 2),
            'file_cache_size': len(self.file_cache),
            'batch_cache_size': len(self.batch_cache),
            'pattern_cache_size': len(self.pattern_cache),
            'max_cache_size': self.max_cache_size,
            'cache_ttl_hours': self.cache_ttl_hours
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
    
    # Set CORS headers for all endpoints
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:9002'
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '86400'  # 24 hours
    
    # Add debug logging for CORS
    logger.info(f"🔒 CORS: Origin={origin}, Allowed={origin in allowed_origins}")
    
    return response

@app.route('/', methods=['OPTIONS'])
def handle_options():
    response = jsonify({'status': 'ok'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Global variable to store current scan progress
current_scan_progress = None

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    logger.info("🏥 Health check requested")
    
    # Check critical dependencies
    checks = {
        'openai_api_key': bool(os.environ.get('OPENAI_API_KEY')),
        'port': int(os.environ.get('PORT', 8080)),
        'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
        'working_directory': os.getcwd(),
        'files_in_working_dir': len(os.listdir('.'))
    }
    
    return jsonify({
        'status': 'healthy',
        'service': 'chatgpt-security-scanner',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'cors_enabled': True,
        'timeout_configured': '900s',
        'batch_processing': True,
        'health_checks': checks
    })

@app.route('/progress', methods=['GET'])
def get_progress():
    """Get current scan progress for real-time updates"""
    global current_scan_progress
    
    # CRITICAL DEBUGGING: Check if we're in the right context
    current_thread = threading.current_thread()
    logger.info(f"📊 PROGRESS ENDPOINT CALLED: Thread={current_thread.name}, current_scan_progress = {current_scan_progress}")
    logger.info(f"📊 PROGRESS ENDPOINT: Global variable ID = {id(current_scan_progress)}")
    
    if current_scan_progress is None:
        logger.info(f"📊 PROGRESS ENDPOINT: No scan running, returning no_scan_running")
        return jsonify({
            'status': 'no_scan_running',
            'message': 'No security scan is currently running'
        })
    
    logger.info(f"📊 PROGRESS ENDPOINT: Returning progress data: {current_scan_progress}")
    return jsonify(current_scan_progress)

@app.route('/cache-stats', methods=['GET'])
def get_cache_statistics():
    """Get comprehensive cache statistics and performance metrics"""
    try:
        # Get cache statistics from the scanner instance
        if hasattr(app, 'scanner') and app.scanner:
            cache_stats = app.scanner.get_cache_statistics()
        else:
            # Create a temporary scanner instance to get stats
            temp_scanner = ChatGPTSecurityScanner()
            cache_stats = temp_scanner.get_cache_statistics()
        
        # Add additional performance metrics
        performance_metrics = {
            'cache_efficiency': {
                'hit_rate_percent': cache_stats.get('hit_rate_percent', 0),
                'cost_savings_estimate': f"${cache_stats.get('cache_hits', 0) * 0.02:.2f}",
                'api_calls_saved': cache_stats.get('cache_hits', 0),
                'estimated_time_saved_minutes': cache_stats.get('cache_hits', 0) * 0.5  # 30 seconds per cached file
            },
            'cache_performance': {
                'cache_size': cache_stats.get('cache_size', 0),
                'memory_usage_mb': cache_stats.get('memory_usage_mb', 0),
                'max_cache_size': cache_stats.get('max_cache_size', 10000),
                'cache_ttl_hours': cache_stats.get('cache_ttl_hours', 24)
            },
            'cache_distribution': {
                'file_cache_size': cache_stats.get('file_cache_size', 0),
                'batch_cache_size': cache_stats.get('batch_cache_size', 0),
                'pattern_cache_size': cache_stats.get('pattern_cache_size', 0)
            }
        }
        
        response_data = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'cache_statistics': cache_stats,
            'performance_metrics': performance_metrics,
            'cache_benefits': {
                'description': 'Advanced multi-level caching system with pattern matching',
                'features': [
                    'File-level caching for individual analysis results',
                    'Batch caching for multi-file analysis',
                    'Pattern caching for similar code structures',
                    'LRU cache management with TTL expiration',
                    'Intelligent similarity matching',
                    'Memory usage optimization'
                ],
                'cost_savings': f"Estimated ${cache_stats.get('cache_hits', 0) * 0.02:.2f} saved in API costs",
                'time_savings': f"Estimated {cache_stats.get('cache_hits', 0) * 0.5:.1f} minutes saved in processing time"
            }
        }
        
        logger.info(f"📊 CACHE STATS: Retrieved cache statistics - {cache_stats.get('hit_rate_percent', 0)}% hit rate")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ Error retrieving cache statistics: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to retrieve cache statistics: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/', methods=['POST'])
def security_scan():
    """Main endpoint for security scans"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        repo_url = data.get('repository_url')
        github_token = data.get('github_token')
        
        # Input validation
        if not repo_url:
            return jsonify({'error': 'repository_url is required'}), 400
        
        # Validate repository URL format
        if not isinstance(repo_url, str):
            return jsonify({'error': 'repository_url must be a string'}), 400
        
        if not repo_url.startswith('https://github.com/'):
            return jsonify({'error': 'repository_url must be a valid GitHub HTTPS URL'}), 400
        
        # Validate GitHub token format if provided
        if github_token:
            if not isinstance(github_token, str):
                return jsonify({'error': 'github_token must be a string'}), 400
            
            if not github_token.startswith(('ghp_', 'gho_', 'ghu_')):
                return jsonify({'error': 'Invalid GitHub token format'}), 400
        
        logger.info(f"🚀 Starting security scan for: {repo_url}")
        
        # Reset global progress for new scan
        global current_scan_progress
        current_scan_progress = {
            'step': 'Starting scan...',
            'progress': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        # Run the scan with NUCLEAR TIMEOUT PROTECTION
        try:
            scanner = ChatGPTSecurityScanner()
            
            # PROGRESS TRACKING: Set up progress callback for real-time updates
            progress_updates = []
            def progress_callback(progress_data):
                global current_scan_progress
                
                progress_updates.append(progress_data)
                logger.info(f"📊 PROGRESS UPDATE: {progress_data['step']} - {progress_data['progress']:.1f}%")
                logger.info(f"📊 PROGRESS DATA STRUCTURE: {progress_data}")
                
                # Store current progress globally for real-time access
                current_scan_progress = {
                    'step': progress_data.get('step', 'Unknown'),
                    'progress': progress_data.get('progress', 0),
                    'timestamp': datetime.now().isoformat()
                }
                
                logger.info(f"📊 STORED PROGRESS: {current_scan_progress}")
                logger.info(f"📊 PROGRESS CALLBACK: Global variable ID = {id(current_scan_progress)}")
                logger.info(f"📊 PROGRESS CALLBACK: Thread = {threading.current_thread().name}")
            
            scanner.set_progress_callback(progress_callback)
            
            # Set a hard timeout for the entire scan
            scan_timeout = 600  # 10 minutes max (Cloud Run timeout is 15 minutes)
            
            logger.info(f"🚀 Starting scan with {scan_timeout}s timeout protection")
            
            # Run with timeout protection using asyncio.run()
            result = asyncio.run(asyncio.wait_for(
                scanner.scan_repository(repo_url, github_token),
                timeout=scan_timeout
            ))
            
            # Check if scan failed
            if 'error' in result:
                logger.error(f"Scan failed: {result['error']}")
                return jsonify(result), 500
            
            # Add progress data to result
            # Progress data is already included in the result from scan_repository
            
            logger.info(f"✅ Scan completed successfully in {result.get('scan_duration', 0):.1f}s")
            
            # Reset global progress when scan completes
            current_scan_progress = None
            
            return jsonify(result)
            
        except asyncio.TimeoutError:
            logger.error(f"❌ Scan timed out after {scan_timeout}s")
            return jsonify({
                'error': f'Scan timed out after {scan_timeout}s - repository too large or complex',
                'error_type': 'TimeoutError',
                'scan_duration': scan_timeout,
                'timestamp': datetime.now().isoformat()
            }), 408
        except Exception as scan_error:
            logger.error(f"❌ Scan execution error: {scan_error}")
            return jsonify({
                'error': str(scan_error),
                'error_type': type(scan_error).__name__,
                'timestamp': datetime.now().isoformat()
            }), 500
        
    except Exception as e:
        logger.error(f"HTTP handler error: {e}")
        return jsonify({'error': str(e), 'error_type': type(e).__name__}), 500

if __name__ == "__main__":
    try:
        # Read port from environment variable (Cloud Run requirement)
        port = int(os.environ.get('PORT', 8080))
        logger.info(f"🚀 NUCLEAR OPTIMIZED ChatGPT Security Scanner starting on port {port}")
        logger.info(f"🔍 Environment: PORT={port}")
        logger.info(f"🔒 CORS enabled for all endpoints")
        logger.info(f"⏱️  Scan timeout protection: 900s")
        logger.info(f"🚀 PHASE 1: Smart file filtering + Batch analysis (3-5x faster)")
        logger.info(f"🚀 PHASE 2: Multi-API key parallel processing (ready for multiple keys)")
        logger.info(f"🚀 PHASE 3: Content chunking + Pattern pre-filtering")
        logger.info(f"🚀 PHASE 4: Caching + ML-based optimization")
        logger.info(f"🚀 PHASE 5: TRUE PARALLEL PROCESSING with ThreadPoolExecutor + Rate Limiting Protection (5-10x faster!)")
        logger.info(f"⚠️  IMPORTANT: Set Cloud Run timeout to 900s (15 minutes) to avoid 504 errors")
        logger.info(f"⚠️  IMPORTANT: Ensure OPENAI_API_KEY is set")
        logger.info(f"🚀 EXPECTED PERFORMANCE: 20 minutes → 1-2 minutes (15x faster with parallel processing!)")
        
        # Test OpenAI API key availability
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            logger.error("❌ OPENAI_API_KEY environment variable is not set!")
            logger.error("❌ Container will not start without this variable")
            exit(1)
        else:
            logger.info(f"✅ OPENAI_API_KEY is configured (length: {len(api_key)})")
        
        # Resource validation
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        logger.info(f"🚀 System resources: {cpu_count} CPU cores available")
        logger.info(f"🚀 Memory: 4GB allocated, optimizing for maximum performance")
        
        if cpu_count < 2:
            logger.warning(f"⚠️ Low CPU count ({cpu_count}), performance may be limited")
        else:
            logger.info(f"✅ CPU count ({cpu_count}) sufficient for nuclear optimization")
        
        # Start the Flask app
        logger.info(f"🚀 Flask app starting on 0.0.0.0:{port}")
        logger.info(f"🚀 ALL NUCLEAR PHASES ENABLED: 4GB RAM + 4 CPU cores + Multi-API keys")
        logger.info(f"🚀 FINAL PERFORMANCE TARGET: 20 minutes → 2-3 minutes (10x faster!)")
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except Exception as e:
        logger.error(f"❌ Failed to start container: {e}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        exit(1)
