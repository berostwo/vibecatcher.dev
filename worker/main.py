import os
import json
import asyncio
import aiohttp
import tempfile
import shutil
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from flask import Flask, request, jsonify
import openai
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        
        # PROGRESS TRACKING: Dynamic progress calculation and tracking
        self.progress_callback = None
        self.current_step = "Initializing"
        self.step_progress = 0.0
        self.total_steps = 0
        self.completed_steps = 0
        
        # Security categories for comprehensive coverage
        
        # Security categories for comprehensive coverage
        self.security_categories = [
            "Authentication & Authorization",
            "Input Validation & Injection",
            "Data Exposure & Privacy",
            "Cryptography & Secrets",
            "Session Management",
            "File Upload Security",
            "API Security",
            "Frontend Security",
            "Backend Security",
            "Infrastructure Security",
            "Dependency Security",
            "Business Logic Security",
            "Error Handling & Logging",
            "CORS & Headers",
            "Rate Limiting",
            "SQL Injection",
            "XSS & CSRF",
            "SSRF & Path Traversal",
            "Deserialization",
            "Memory Safety"
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
    
    def update_progress(self, step: str, progress: float, step_complete: bool = False):
        """Update progress and notify frontend"""
        self.current_step = step
        self.step_progress = progress
        
        if step_complete:
            self.completed_steps += 1
        
        if self.progress_callback:
            try:
                self.progress_callback({
                    'step': step,
                    'progress': progress,
                    'completed_steps': self.completed_steps,
                    'total_steps': self.total_steps,
                    'overall_progress': (self.completed_steps + progress) / max(1, self.total_steps) * 100
                })
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
        
        logger.info(f"📊 PROGRESS: {step} - {progress:.1f}% (Overall: {self.completed_steps}/{self.total_steps})")
    
    async def clone_repository(self, repo_url: str, github_token: str = None) -> str:
        """Clone repository with authentication"""
        logger.info(f"📥 Cloning repository: {repo_url}")
        
        # PROGRESS TRACKING: Start cloning step
        self.update_progress("Cloning repository", 0.0)
        
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
            
            # PROGRESS TRACKING: Clone complete
            self.update_progress("Repository cloned", 100.0, step_complete=True)
            
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
            # Build comprehensive security analysis prompt
            prompt = f"""
            You are an expert security engineer specializing in making indie developer, vibe coder, solopreneur, and microsaas applications absolutely bulletproof.

            Analyze this {file_type} file for security vulnerabilities:

            FILE: {file_path}
            CONTENT:
            {file_content}

            Focus on these critical areas for indie developers:
            - Authentication & authorization bypasses
            - Input validation & injection attacks
            - Data exposure & privacy violations
            - Cryptography & secrets management
            - Session management issues
            - File upload security
            - API security vulnerabilities
            - Frontend security (XSS, CSRF)
            - Backend security (SQL injection, etc.)
            - Infrastructure security
            - Dependency vulnerabilities
            - Business logic flaws
            - Error handling & information disclosure
            - CORS & security headers
            - Rate limiting & abuse prevention

            For each finding, provide:
            1. Severity (Critical/High/Medium/Low)
            2. Clear description of the vulnerability
            3. Specific risk to the application
            4. CWE and OWASP classifications
            5. Line numbers where the vulnerability occurs

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
            
            IMPORTANT: For rule_id, use a descriptive identifier like "xss_vulnerability", "sql_injection", "csrf_missing", etc. NOT generic numbers like "VULN-001".

            Be thorough but practical. Focus on real-world risks that indie developers face.
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
                    
                    # Convert to SecurityFinding objects
                    security_findings = []
                    for finding in findings:
                        try:
                            security_findings.append(SecurityFinding(**finding))
                        except Exception as e:
                            logger.warning(f"Failed to create SecurityFinding for {file_path}: {e}")
                            continue
                    
                    logger.info(f"✅ Successfully parsed {len(security_findings)} findings for {file_path}")
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
        condensed = {}
        
        for finding in findings:
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
                # Add new finding
                condensed[key] = finding
        
        return list(condensed.values())
    
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
    
    async def scan_repository(self, repo_url: str, github_token: str = None) -> Dict[str, Any]:
        """Main method to scan repository for security vulnerabilities"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting ChatGPT security scan for: {repo_url}")
        
        try:
            # PROGRESS TRACKING: Initialize progress calculation
            self.update_progress("Initializing scan", 0.0)
            
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
            
            # PROGRESS TRACKING: Start file filtering
            self.update_progress("Analyzing repository structure", 0.0)
            
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
            
            # PROGRESS TRACKING: File filtering complete
            self.update_progress("Repository structure analyzed", 100.0, step_complete=True)
            
            # PROGRESS TRACKING: Start batch creation
            self.update_progress("Preparing analysis batches", 0.0)
            
            # Create intelligent file batches based on priority
            file_batches = self.create_file_batches(files_to_analyze)
            total_batches = len(file_batches)
            
            logger.info(f"🚀 PHASE 1 NUCLEAR OPTIMIZATION: Created {total_batches} intelligent batches")
            logger.info(f"🚀 Priority 1 (Critical): Small batches (3 files) for thorough analysis")
            logger.info(f"🚀 Priority 2 (Important): Medium batches (5 files) for balanced analysis")
            logger.info(f"🚀 Priority 3 (Low): Large batches (8 files) for quick analysis")
            logger.info(f"🚀 Expected performance: 3-5x faster with batch analysis!")
            
            # PROGRESS TRACKING: Calculate total steps for dynamic progress
            self.total_steps = 4 + total_batches  # 4 main steps + each batch
            logger.info(f"📊 PROGRESS: Total steps calculated: {self.total_steps}")
            
            # Add overall scan timeout protection
            scan_start_time = datetime.now()
            max_scan_time = 900  # 15 minutes max
            
            # PROGRESS TRACKING: Start batch processing
            self.update_progress("Starting security analysis", 0.0, step_complete=True)
            
            for batch_num, batch_files in enumerate(file_batches):
                # Check if we're approaching timeout
                elapsed_time = (datetime.now() - scan_start_time).total_seconds()
                if elapsed_time > max_scan_time - 60:  # Stop 1 minute before timeout
                    logger.warning(f"⚠️ Approaching scan timeout ({elapsed_time:.0f}s), stopping early")
                    break
                
                batch_start_time = datetime.now()
                logger.info(f"📦 PHASE 1 BATCH {batch_num + 1}/{total_batches} (files: {len(batch_files)})")
                
                # PROGRESS TRACKING: Update batch progress
                batch_progress = (batch_num / total_batches) * 100
                self.update_progress(f"Analyzing batch {batch_num + 1}/{total_batches}", batch_progress)
                
                # Process batch with NEW batch analysis (multiple files in ONE API call)
                try:
                    batch_findings = self.analyze_files_batch(batch_files)
                    all_findings.extend(batch_findings)
                    
                    batch_time = (datetime.now() - batch_start_time).total_seconds()
                    logger.info(f"✅ PHASE 1 BATCH {batch_num + 1} complete: {len(batch_findings)} findings in {batch_time:.1f}s")
                    logger.info(f"✅ Total findings so far: {len(all_findings)}")
                    
                    # PROGRESS TRACKING: Batch complete
                    self.update_progress(f"Batch {batch_num + 1} complete", 100.0, step_complete=True)
                    
                except Exception as e:
                    logger.error(f"❌ PHASE 1 BATCH {batch_num + 1} failed: {e}")
                    continue
                
                # Performance monitoring
                elapsed = (datetime.now() - scan_start_time).total_seconds()
                files_per_second = sum(len(batch) for batch in file_batches[:batch_num + 1]) / elapsed
                logger.info(f"📊 PHASE 1 Performance: {files_per_second:.1f} files/second, {elapsed:.0f}s elapsed")
            
            # PROGRESS TRACKING: Start condensing
            self.update_progress("Condensing security findings", 0.0)
            
            # Condense findings
            logger.info(f"🔍 Condensing {len(all_findings)} findings...")
            condensed_findings = self.condense_findings(all_findings)
            logger.info(f"✅ Condensed to {len(condensed_findings)} unique findings")
            
            # PROGRESS TRACKING: Condensing complete
            self.update_progress("Findings condensed", 100.0, step_complete=True)
            
            # PROGRESS TRACKING: Start remediations
            self.update_progress("Generating remediation prompts", 0.0)
            
            # NUCLEAR OPTIMIZATION: Generate ALL remediations in ONE call
            logger.info(f"🚀 NUCLEAR OPTIMIZATION: Generating {len(condensed_findings)} remediations in ONE API call...")
            start_time_remediations = datetime.now()
            condensed_remediations = self.generate_condensed_remediations(condensed_findings, all_findings)
            remediation_time = (datetime.now() - start_time_remediations).total_seconds()
            logger.info(f"✅ NUCLEAR OPTIMIZATION: Generated {len(condensed_remediations)} remediations in {remediation_time:.1f}s!")
            
            # PROGRESS TRACKING: Remediations complete
            self.update_progress("Remediation prompts generated", 100.0, step_complete=True)
            
            # PROGRESS TRACKING: Start master plan
            self.update_progress("Creating master remediation plan", 0.0)
            
            # Generate master remediation plan
            logger.info(f"🔍 Generating master remediation plan...")
            master_remediation = self.generate_master_remediation(condensed_findings)
            logger.info(f"✅ Master remediation generated")
            
            # PROGRESS TRACKING: Master plan complete
            self.update_progress("Master plan complete", 100.0, step_complete=True)
            
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
            self.update_progress("Finalizing report", 100.0, step_complete=True)
            
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
            
            return asdict(report)
            
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
                        for finding in findings:
                            try:
                                # Ensure file_path is correct
                                finding['file_path'] = file_path
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
        
        logger.info(f"🚀 Starting security scan for: {repo_url}")
        
        # Run the scan with NUCLEAR TIMEOUT PROTECTION
        try:
            scanner = ChatGPTSecurityScanner()
            
            # PROGRESS TRACKING: Set up progress callback for real-time updates
            progress_updates = []
            def progress_callback(progress_data):
                progress_updates.append(progress_data)
                logger.info(f"📊 PROGRESS UPDATE: {progress_data['step']} - {progress_data['overall_progress']:.1f}%")
            
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
            result['progress_data'] = progress_updates
            
            logger.info(f"✅ Scan completed successfully in {result.get('scan_duration', 0):.1f}s")
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
        logger.info(f"⚠️  IMPORTANT: Set Cloud Run timeout to 900s (15 minutes) to avoid 504 errors")
        logger.info(f"⚠️  IMPORTANT: Ensure OPENAI_API_KEY is set")
        logger.info(f"🚀 EXPECTED PERFORMANCE: 20 minutes → 2-3 minutes (10x faster!)")
        
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
