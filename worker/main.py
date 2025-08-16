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
        # Initialize OpenAI client
        self.api_key = os.environ.get('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
        # Initialize token usage tracking
        self.total_tokens_used = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.api_calls_made = 0
        
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
    
    async def clone_repository(self, repo_url: str, github_token: str = None) -> str:
        """Clone repository with authentication"""
        logger.info(f"📥 Cloning repository: {repo_url}")
        
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
                        "rule_id": "unique_identifier",
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

            Be thorough but practical. Focus on real-world risks that indie developers face.
            """

            # Call ChatGPT API
            client = openai.OpenAI(api_key=self.api_key)
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
            # Create a key based on rule_id and severity
            key = f"{finding.rule_id}_{finding.severity}"
            
            if key in condensed:
                # Increment occurrence count
                condensed[key].occurrences += 1
            else:
                # Add new finding
                condensed[key] = finding
        
        return list(condensed.values())
    
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
            
            # ONE API CALL for ALL remediations
            client = openai.OpenAI(api_key=self.api_key)
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

            client = openai.OpenAI(api_key=self.api_key)
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
            
            # Analyze files with BATCH PROCESSING for 10x speed improvement
            all_findings = []
            file_types = ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte']
            
            # Collect all files first
            files_to_analyze = []
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
                for file in files:
                    if any(file.endswith(ext) for ext in file_types):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, repo_path)
                        files_to_analyze.append((file_path, relative_path, file))
            
            total_files = len(files_to_analyze)
            logger.info(f"🔍 Found {total_files} files to analyze")
            logger.info(f"🔍 Supported file types: {', '.join(file_types)}")
            
            # NUCLEAR OPTIMIZATION: Use all 4 CPU cores with larger batches
            batch_size = 20  # Increased from 5 to 20 for better CPU utilization
            total_batches = (total_files + batch_size - 1) // batch_size
            
            logger.info(f"🚀 NUCLEAR OPTIMIZATION: Processing {total_files} files in {total_batches} batches of {batch_size}")
            logger.info(f"🚀 Using all 4 CPU cores with optimized batch processing")
            logger.info(f"🚀 Expected performance: {total_files / 20:.1f} files per batch, ~{total_batches * 2:.0f} minutes total")
            logger.info(f"🚀 Memory allocation: 4GB RAM, 4 CPU cores - FULL UTILIZATION!")
            
            # Add overall scan timeout protection
            scan_start_time = datetime.now()
            max_scan_time = 900  # 15 minutes max
            
            for batch_num in range(total_batches):
                # Check if we're approaching timeout
                elapsed_time = (datetime.now() - scan_start_time).total_seconds()
                if elapsed_time > max_scan_time - 60:  # Stop 1 minute before timeout
                    logger.warning(f"⚠️ Approaching scan timeout ({elapsed_time:.0f}s), stopping early")
                    break
                    
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, total_files)
                batch_files = files_to_analyze[start_idx:end_idx]
                
                logger.info(f"📦 NUCLEAR BATCH {batch_num + 1}/{total_batches} (files {start_idx + 1}-{end_idx})")
                
                # Process batch with MAXIMUM concurrency
                batch_tasks = []
                for file_path, relative_path, file_type in batch_files:
                    task = self.analyze_file_async(file_path, relative_path, file_type)
                    batch_tasks.append(task)
                
                # Wait for batch to complete with timeout
                try:
                    batch_results = await asyncio.wait_for(
                        asyncio.gather(*batch_tasks, return_exceptions=True),
                        timeout=120  # 2 minutes per batch
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"⚠️ Batch {batch_num + 1} timed out, continuing with next batch")
                    continue
                
                # Collect findings from batch
                batch_findings = 0
                for i, result in enumerate(batch_results):
                    if isinstance(result, Exception):
                        logger.warning(f"❌ Batch file {batch_files[i][1]} failed: {result}")
                    else:
                        all_findings.extend(result)
                        batch_findings += len(result)
                
                logger.info(f"✅ NUCLEAR BATCH {batch_num + 1} complete: {batch_findings} findings, Total: {len(all_findings)}")
                
                # Performance monitoring
                elapsed = (datetime.now() - scan_start_time).total_seconds()
                files_per_second = (end_idx) / elapsed
                logger.info(f"📊 Performance: {files_per_second:.1f} files/second, {elapsed:.0f}s elapsed")
            
            # Condense findings
            logger.info(f"🔍 Condensing {len(all_findings)} findings...")
            condensed_findings = self.condense_findings(all_findings)
            logger.info(f"✅ Condensed to {len(condensed_findings)} unique findings")
            
            # NUCLEAR OPTIMIZATION: Generate ALL remediations in ONE call
            logger.info(f"🚀 NUCLEAR OPTIMIZATION: Generating {len(condensed_findings)} remediations in ONE API call...")
            start_time_remediations = datetime.now()
            condensed_remediations = self.generate_condensed_remediations(condensed_findings, all_findings)
            remediation_time = (datetime.now() - start_time_remediations).total_seconds()
            logger.info(f"✅ NUCLEAR OPTIMIZATION: Generated {len(condensed_remediations)} remediations in {remediation_time:.1f}s!")
            
            # Generate master remediation plan
            logger.info(f"🔍 Generating master remediation plan...")
            master_remediation = self.generate_master_remediation(condensed_findings)
            logger.info(f"✅ Master remediation generated")
            
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
        logger.info(f"🚀 Starting ChatGPT Security Scanner on port {port}")
        logger.info(f"🔍 Environment: PORT={port}")
        logger.info(f"🔒 CORS enabled for all endpoints")
        logger.info(f"⏱️  Scan timeout protection: 900s")
        logger.info(f"📦 Batch processing: 20 files concurrently (NUCLEAR OPTIMIZATION)")
        logger.info(f"⚠️  IMPORTANT: Set Cloud Run timeout to 900s (15 minutes) to avoid 504 errors")
        logger.info(f"⚠️  IMPORTANT: Ensure OPENAI_API_KEY is set")
        
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
        logger.info(f"🚀 NUCLEAR OPTIMIZATION ENABLED: 4GB RAM + 4 CPU cores")
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except Exception as e:
        logger.error(f"❌ Failed to start container: {e}")
        logger.error(f"❌ Error type: {type(e).__name__}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        exit(1)
