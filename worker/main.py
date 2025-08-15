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
    remediation: str
    occurrences: int = 1

@dataclass
class SecurityReport:
    """Complete security audit report"""
    summary: Dict[str, Any]
    findings: List[SecurityFinding]
    condensed_findings: List[SecurityFinding]
    master_remediation: str
    scan_duration: float
    timestamp: str
    repository_info: Dict[str, Any]

class ChatGPTSecurityScanner:
    """Ultimate ChatGPT-powered security scanner for indie developers"""
    
    def __init__(self):
        # Initialize OpenAI client
        openai.api_key = os.environ.get('OPENAI_API_KEY')
        if not openai.api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        
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
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        repo_path = os.path.join(temp_dir, repo_name)
        
        try:
            # Build clone command
            if github_token:
                # Use token for private repos
                auth_url = repo_url.replace('https://', f'https://{github_token}@')
                clone_cmd = ['git', 'clone', '--single-branch', '--depth', '1', auth_url, repo_path]
            else:
                clone_cmd = ['git', 'clone', '--single-branch', '--depth', '1', repo_url, repo_path]
            
            # Execute clone
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode != 0:
                raise Exception(f"Git clone failed: {stderr.decode()}")
            
            logger.info(f"✅ Repository cloned successfully: {repo_path}")
            return repo_path
            
        except Exception as e:
            # Cleanup on failure
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e
    
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
            4. Exact remediation steps
            5. CWE and OWASP classifications

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
                        "confidence": "High|Medium|Low",
                        "remediation": "Step-by-step fix instructions"
                    }}
                ]
            }}

            Be thorough but practical. Focus on real-world risks that indie developers face.
            """

            # Call ChatGPT API
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer focused on making indie developer applications bulletproof."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1
            )
            
            # Parse response
            content = response.choices[0].message.content
            try:
                result = json.loads(content)
                findings = result.get('findings', [])
                
                # Convert to SecurityFinding objects
                security_findings = []
                for finding in findings:
                    security_findings.append(SecurityFinding(**finding))
                
                return security_findings
                
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse ChatGPT response for {file_path}")
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
    
    def generate_master_remediation(self, condensed_findings: List[SecurityFinding]) -> str:
        """Generate a master remediation prompt for all findings"""
        try:
            # Group findings by severity
            critical = [f for f in condensed_findings if f.severity == "Critical"]
            high = [f for f in condensed_findings if f.severity == "High"]
            medium = [f for f in condensed_findings if f.severity == "Medium"]
            low = [f for f in condensed_findings if f.severity == "Low"]
            
            prompt = f"""
            You are an expert security engineer. Create a comprehensive remediation plan for this application.

            SECURITY FINDINGS SUMMARY:
            - Critical: {len(critical)} findings
            - High: {len(high)} findings  
            - Medium: {len(medium)} findings
            - Low: {len(low)} findings

            DETAILED FINDINGS:
            {json.dumps([asdict(f) for f in condensed_findings], indent=2)}

            Create a master remediation plan that:
            1. Prioritizes fixes by severity and impact
            2. Groups related fixes together
            3. Provides step-by-step implementation order
            4. Includes testing and validation steps
            5. Addresses root causes, not just symptoms
            6. Is practical for indie developers to implement

            Format the response as a clear, actionable remediation plan.
            """

            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert security engineer creating remediation plans."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=3000,
                temperature=0.1
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error generating master remediation: {e}")
            return "Failed to generate master remediation plan."
    
    async def scan_repository(self, repo_url: str, github_token: str = None) -> Dict[str, Any]:
        """Main method to scan repository for security vulnerabilities"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting ChatGPT security scan for: {repo_url}")
        
        try:
            # Clone repository
            repo_path = await self.clone_repository(repo_url, github_token)
            
            # Get repository info
            repo_info = {
                'name': repo_path.split('/')[-1],
                'url': repo_url,
                'size': self.get_directory_size(repo_path),
                'file_count': self.count_files(repo_path)
            }
            
            # Analyze files
            all_findings = []
            file_types = ['.js', '.ts', '.tsx', '.jsx', '.py', '.php', '.rb', '.go', '.java', '.cs', '.rs', '.html', '.vue', '.svelte']
            
            for root, dirs, files in os.walk(repo_path):
                # Skip common directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
                
                for file in files:
                    if any(file.endswith(ext) for ext in file_types):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, repo_path)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Analyze with ChatGPT
                            findings = self.analyze_file_with_chatgpt(relative_path, content, file)
                            all_findings.extend(findings)
                            
                        except Exception as e:
                            logger.warning(f"Failed to analyze {file_path}: {e}")
                            continue
            
            # Condense findings
            condensed_findings = self.condense_findings(all_findings)
            
            # Generate master remediation
            master_remediation = self.generate_master_remediation(condensed_findings)
            
            # Calculate scan duration
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            # Create security report
            report = SecurityReport(
                summary={
                    'total_findings': len(all_findings),
                    'condensed_findings': len(condensed_findings),
                    'critical_count': len([f for f in condensed_findings if f.severity == "Critical"]),
                    'high_count': len([f for f in condensed_findings if f.severity == "Critical"]),
                    'medium_count': len([f for f in condensed_findings if f.severity == "Medium"]),
                    'low_count': len([f for f in condensed_findings if f.severity == "Low"]),
                    'files_scanned': repo_info['file_count'],
                    'scan_duration': scan_duration
                },
                findings=all_findings,
                condensed_findings=condensed_findings,
                master_remediation=master_remediation,
                scan_duration=scan_duration,
                timestamp=datetime.now().isoformat(),
                repository_info=repo_info
            )
            
            # Cleanup
            shutil.rmtree(repo_path, ignore_errors=True)
            
            logger.info(f"✅ Security scan completed in {scan_duration:.2f}s")
            logger.info(f"📊 Found {len(all_findings)} total findings, {len(condensed_findings)} unique issues")
            
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
    logger.info("🏥 Health check requested")
    return jsonify({
        'status': 'healthy',
        'service': 'chatgpt-security-scanner',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
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
        scanner = ChatGPTSecurityScanner()
        result = asyncio.run(scanner.scan_repository(repo_url, github_token))
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"HTTP handler error: {e}")
        return jsonify({'error': str(e), 'error_type': type(e).__name__}), 500

if __name__ == "__main__":
    # Read port from environment variable (Cloud Run requirement)
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"🚀 Starting ChatGPT Security Scanner on port {port}")
    logger.info(f"🔍 Environment: PORT={port}")
    app.run(host='0.0.0.0', port=port, debug=False)
