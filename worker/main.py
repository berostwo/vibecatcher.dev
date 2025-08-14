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

@dataclass
class AuditSummary:
    total_vulnerabilities: int
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
        """Run Semgrep security scan on repository with timeout"""
        try:
            # Run semgrep scan with security-focused rules
            process = await asyncio.create_subprocess_exec(
                'semgrep', 'scan', '--json', '--config', 'auto', '--timeout', '300', repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=MAX_SCAN_TIME_SECONDS)
            except asyncio.TimeoutError:
                process.kill()
                raise Exception("Semgrep scan timed out")
            
            if process.returncode != 0 and process.returncode != 1:  # Semgrep returns 1 for findings
                raise Exception(f"Semgrep scan failed: {stderr.decode()}")
            
            # Parse JSON output
            scan_results = json.loads(stdout.decode())
            logger.info(f"Semgrep scan completed with {len(scan_results.get('results', []))} findings")
            
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
        """Create prompt for GPT-4 analysis"""
        findings = semgrep_results.get('results', [])
        
        if not findings:
            return "No security vulnerabilities found in the codebase. Please confirm this is accurate."
        
        prompt = f"""Analyze these {len(findings)} security findings from Semgrep:

"""
        
        for i, finding in enumerate(findings[:10], 1):  # Limit to first 10 findings
            prompt += f"""Finding {i}:
- Rule: {finding.get('check_id', 'Unknown')}
- Severity: {finding.get('extra', {}).get('severity', 'Unknown')}
- File: {finding.get('path', 'Unknown')}:{finding.get('start', {}).get('line', 'Unknown')}
- Message: {finding.get('extra', {}).get('message', 'Unknown')}

"""
        
        prompt += """For each finding, provide:
1. A clear description of the security risk
2. Specific remediation steps with code examples
3. Why this vulnerability is dangerous
4. Best practices to prevent similar issues

Also provide a master summary of all critical issues and their priority order."""
        
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
                
                # Process findings
                findings = semgrep_results.get('results', [])
                vulnerabilities = []
                
                for finding in findings:
                    vuln = Vulnerability(
                        rule_id=finding.get('check_id', 'Unknown'),
                        message=finding.get('extra', {}).get('message', 'Unknown'),
                        severity=finding.get('extra', {}).get('severity', 'Unknown'),
                        file_path=finding.get('path', 'Unknown'),
                        line_number=finding.get('start', {}).get('line', 0),
                        description=finding.get('extra', {}).get('description', 'No description available'),
                        remediation='See GPT analysis for detailed remediation steps'
                    )
                    vulnerabilities.append(vuln)
                
                # Calculate summary
                high_sev = len([v for v in vulnerabilities if v.severity.lower() == 'error'])
                medium_sev = len([v for v in vulnerabilities if v.severity.lower() == 'warning'])
                low_sev = len([v for v in vulnerabilities if v.severity.lower() not in ['error', 'warning']])
                
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()
                
                summary = AuditSummary(
                    total_vulnerabilities=len(vulnerabilities),
                    high_severity=high_sev,
                    medium_severity=medium_sev,
                    low_severity=low_sev,
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
        
        if openai_api_key == 'your-openai-api-key-here':
            logger.error("❌ OPENAI_API_KEY is still set to placeholder value!")
            raise ValueError("OPENAI_API_KEY is set to placeholder value - please set your actual API key")
        
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
