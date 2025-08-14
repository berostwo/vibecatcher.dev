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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    rule_id: str
    message: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    end_line_number: int
    code_snippet: str
    metadata: Dict[str, Any]

@dataclass
class SemgrepResult:
    findings: List[SecurityFinding]
    scan_time: float
    total_files_scanned: int

@dataclass
class GPTAnalysis:
    security_assessment: str
    risk_level: str
    remediation_prompts: List[str]
    master_prompt: str
    analysis_time: float

@dataclass
class AuditReport:
    repository_name: str
    scan_timestamp: datetime
    semgrep_results: SemgrepResult
    gpt_analysis: GPTAnalysis
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int

class SecurityAuditor:
    def __init__(self):
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.openai_base_url = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1')
        self.model = os.getenv('GPT_MODEL', 'gpt-4-turbo-preview')
        
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> str:
        """Clone repository to temporary directory"""
        temp_dir = tempfile.mkdtemp()
        try:
            logger.info(f"Cloning repository: {repo_url}")
            result = subprocess.run([
                'git', 'clone', '--depth', '1', '--branch', branch, repo_url, temp_dir
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                raise Exception(f"Failed to clone repository: {result.stderr}")
            
            logger.info(f"Repository cloned successfully to {temp_dir}")
            return temp_dir
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e
    
    async def run_semgrep_scan(self, repo_path: str) -> SemgrepResult:
        """Run Semgrep security scan on repository"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting Semgrep security scan...")
            
            # Run Semgrep with optimized rules and output format
            cmd = [
                'semgrep', 'scan',
                '--config', 'auto',  # Use Semgrep's auto-config for security rules
                '--json',  # JSON output for parsing
                '--no-git-ignore',  # Scan all files
                '--max-target-bytes', '1000000',  # Limit file size to 1MB
                '--timeout', '300',  # 5 minute timeout per file
                '--max-memory', '4096',  # 4GB memory limit
                repo_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode not in [0, 1]:  # Semgrep returns 1 when findings are found
                raise Exception(f"Semgrep scan failed: {result.stderr}")
            
            # Parse Semgrep JSON output
            try:
                semgrep_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Failed to parse Semgrep JSON output, using stderr")
                semgrep_data = {"results": []}
            
            findings = []
            for result_item in semgrep_data.get('results', []):
                finding = SecurityFinding(
                    rule_id=result_item.get('check_id', 'unknown'),
                    message=result_item.get('message', ''),
                    severity=result_item.get('extra', {}).get('severity', 'medium'),
                    confidence=result_item.get('extra', {}).get('confidence', 'medium'),
                    file_path=result_item.get('path', ''),
                    line_number=result_item.get('start', {}).get('line', 0),
                    end_line_number=result_item.get('end', {}).get('line', 0),
                    code_snippet=result_item.get('extra', {}).get('lines', ''),
                    metadata=result_item.get('extra', {})
                )
                findings.append(finding)
            
            scan_time = asyncio.get_event_loop().time() - start_time
            total_files = len(semgrep_data.get('paths', {}).get('scanned', []))
            
            logger.info(f"Semgrep scan completed: {len(findings)} findings in {scan_time:.2f}s")
            
            return SemgrepResult(
                findings=findings,
                scan_time=scan_time,
                total_files_scanned=total_files
            )
            
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            raise
    
    async def analyze_with_gpt4(self, findings: List[SecurityFinding], repo_name: str) -> GPTAnalysis:
        """Analyze security findings with GPT-4 for quick assessment and remediation"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            logger.info("Starting GPT-4 security analysis...")
            
            # Prepare findings summary for GPT-4
            findings_summary = []
            for finding in findings:
                findings_summary.append({
                    'rule': finding.rule_id,
                    'severity': finding.severity,
                    'message': finding.message,
                    'file': finding.file_path,
                    'line': finding.line_number,
                    'code': finding.code_snippet[:200]  # Limit code snippet length
                })
            
            # Create optimized prompt for GPT-4
            prompt = self._create_gpt_prompt(findings_summary, repo_name)
            
            # Make GPT-4 API call
            async with aiohttp.ClientSession() as session:
                headers = {
                    'Authorization': f'Bearer {self.openai_api_key}',
                    'Content-Type': 'application/json'
                }
                
                payload = {
                    'model': self.model,
                    'messages': [
                        {
                            'role': 'system',
                            'content': 'You are an expert security engineer specializing in static code analysis and security remediation. Provide concise, actionable security assessments and remediation guidance.'
                        },
                        {
                            'role': 'user',
                            'content': prompt
                        }
                    ],
                    'max_tokens': 2000,
                    'temperature': 0.1,  # Low temperature for consistent security advice
                    'timeout': 60
                }
                
                async with session.post(
                    f'{self.openai_base_url}/chat/completions',
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=120)
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"OpenAI API error: {response.status} - {error_text}")
                    
                    result = await response.json()
                    gpt_response = result['choices'][0]['message']['content']
            
            # Parse GPT-4 response
            analysis = self._parse_gpt_response(gpt_response)
            analysis_time = asyncio.get_event_loop().time() - start_time
            
            logger.info(f"GPT-4 analysis completed in {analysis_time:.2f}s")
            
            return GPTAnalysis(
                security_assessment=analysis['assessment'],
                risk_level=analysis['risk_level'],
                remediation_prompts=analysis['remediation_prompts'],
                master_prompt=analysis['master_prompt'],
                analysis_time=analysis_time
            )
            
        except Exception as e:
            logger.error(f"GPT-4 analysis failed: {e}")
            raise
    
    def _create_gpt_prompt(self, findings: List[Dict], repo_name: str) -> str:
        """Create optimized prompt for GPT-4 analysis"""
        findings_text = json.dumps(findings, indent=2)
        
        return f"""Analyze these security findings from repository '{repo_name}' and provide:

1. **Quick Security Assessment** (2-3 sentences)
2. **Overall Risk Level** (Critical/High/Medium/Low)
3. **Individual Remediation Prompts** (one per finding, concise)
4. **Master Remediation Prompt** (comprehensive fix for all issues)

Findings: {findings_text}

Format your response as JSON:
{{
  "assessment": "brief security assessment",
  "risk_level": "Critical/High/Medium/Low",
  "remediation_prompts": ["prompt1", "prompt2"],
  "master_prompt": "comprehensive remediation prompt"
}}

Be concise and actionable. Focus on common security mistakes and quick fixes."""
    
    def _parse_gpt_response(self, response: str) -> Dict[str, Any]:
        """Parse GPT-4 response and extract structured data"""
        try:
            # Try to extract JSON from response
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
            else:
                # Fallback parsing if JSON extraction fails
                return self._fallback_parse(response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse GPT response as JSON, using fallback")
            return self._fallback_parse(response)
    
    def _fallback_parse(self, response: str) -> Dict[str, Any]:
        """Fallback parsing for GPT response"""
        lines = response.split('\n')
        assessment = ""
        risk_level = "Medium"
        remediation_prompts = []
        master_prompt = ""
        
        for line in lines:
            line = line.strip()
            if line.startswith('Assessment:') or line.startswith('Security Assessment:'):
                assessment = line.split(':', 1)[1].strip()
            elif line.startswith('Risk Level:') or line.startswith('Risk:'):
                risk_level = line.split(':', 1)[1].strip()
            elif line.startswith('Remediation:') or line.startswith('Fix:'):
                remediation_prompts.append(line.split(':', 1)[1].strip())
            elif line.startswith('Master Prompt:') or line.startswith('Comprehensive Fix:'):
                master_prompt = line.split(':', 1)[1].strip()
        
        return {
            'assessment': assessment or "Security analysis completed",
            'risk_level': risk_level,
            'remediation_prompts': remediation_prompts or ["Review and fix identified security issues"],
            'master_prompt': master_prompt or "Address all security findings systematically"
        }
    
    async def generate_audit_report(self, repo_name: str, semgrep_results: SemgrepResult, gpt_analysis: GPTAnalysis) -> AuditReport:
        """Generate comprehensive audit report"""
        # Count issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in semgrep_results.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return AuditReport(
            repository_name=repo_name,
            scan_timestamp=datetime.utcnow(),
            semgrep_results=semgrep_results,
            gpt_analysis=gpt_analysis,
            total_issues=len(semgrep_results.findings),
            critical_issues=severity_counts['critical'],
            high_issues=severity_counts['high'],
            medium_issues=severity_counts['medium'],
            low_issues=severity_counts['low']
        )

async def security_audit_worker(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Main worker function for Google Cloud Run"""
    try:
        logger.info("Starting security audit worker...")
        
        # Extract request data
        repo_url = request_data.get('repository_url')
        repo_name = request_data.get('repository_name', 'unknown')
        branch = request_data.get('branch', 'main')
        
        if not repo_url:
            return {'error': 'repository_url is required'}
        
        # Initialize security auditor
        auditor = SecurityAuditor()
        
        # Clone repository
        repo_path = await auditor.clone_repository(repo_url, branch)
        
        try:
            # Run Semgrep scan
            semgrep_results = await auditor.run_semgrep_scan(repo_path)
            
            # Analyze with GPT-4
            gpt_analysis = await auditor.analyze_with_gpt4(semgrep_results.findings, repo_name)
            
            # Generate audit report
            audit_report = await auditor.generate_audit_report(repo_name, semgrep_results, gpt_analysis)
            
            # Convert to JSON-serializable format
            report_dict = asdict(audit_report)
            report_dict['scan_timestamp'] = report_dict['scan_timestamp'].isoformat()
            
            logger.info(f"Security audit completed successfully for {repo_name}")
            
            return {
                'success': True,
                'audit_report': report_dict,
                'execution_time': semgrep_results.scan_time + gpt_analysis.analysis_time
            }
            
        finally:
            # Clean up cloned repository
            shutil.rmtree(repo_path, ignore_errors=True)
            
    except Exception as e:
        logger.error(f"Security audit worker failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__
        }

# Google Cloud Run entry point
def security_audit(request):
    """HTTP Cloud Function entry point"""
    from flask import Request, jsonify
    
    if request.method != 'POST':
        return jsonify({'error': 'Only POST method is supported'}), 405
    
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Run async worker
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(security_audit_worker(request_data))
            return jsonify(result)
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"HTTP handler error: {e}")
        return jsonify({'error': str(e)}), 500

def health_check(request):
    """Health check endpoint for Cloud Run"""
    from flask import jsonify
    
    return jsonify({
        'status': 'healthy',
        'service': 'security-audit-worker',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

if __name__ == "__main__":
    # For local testing
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            test_data = json.load(f)
        
        async def test():
            result = await security_audit_worker(test_data)
            print(json.dumps(result, indent=2))
        
        asyncio.run(test())
    else:
        print("Usage: python main.py <test_data.json>")

from flask import Flask, request, jsonify

app = Flask(__name__)

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
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Run the audit
        result = asyncio.run(security_audit_worker(data))
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=False)
