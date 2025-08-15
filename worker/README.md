# Enterprise Semgrep Security Scanner

A clean, focused, enterprise-grade security scanner built specifically for indie developers and micro-SaaS entrepreneurs.

## 🚀 Features

- **30+ Enterprise Security Rules**: Comprehensive coverage of OWASP Top 10, modern web vulnerabilities, and business logic issues
- **Multi-Language Support**: TypeScript, JavaScript, Python, Go, Java, PHP, Ruby, and more
- **Framework-Specific Rules**: React, Next.js, Express.js, Django, Flask, Firebase security patterns
- **Clean Output**: Raw Semgrep results with organized severity breakdown
- **No Bloat**: Focused on what works - just Semgrep analysis

## 🛡️ Security Coverage

### Core Vulnerabilities
- SQL Injection, XSS, CSRF, SSRF
- Authentication & Authorization flaws
- Input validation bypasses
- Path traversal, command injection
- Insecure deserialization, XXE attacks

### Modern Web Security
- React/Next.js specific patterns
- API security vulnerabilities
- Cloud security misconfigurations
- Container security issues
- Dependency vulnerabilities

### Business Logic
- Rate limiting bypasses
- Access control weaknesses
- Data exposure patterns
- Logging sensitive information
- Weak cryptography usage

## 🏗️ Architecture

- **Flask Web Server**: Lightweight HTTP API
- **Async Processing**: Non-blocking repository operations
- **Git Integration**: Secure repository cloning with token support
- **Semgrep Engine**: Industry-standard static analysis
- **Clean Output**: Structured results with raw data

## 📦 Deployment

### Google Cloud Run
```bash
# Build and deploy
gcloud builds submit --config cloudbuild.yaml

# Or manual deployment
docker build -t enterprise-semgrep-scanner .
docker push gcr.io/PROJECT_ID/enterprise-semgrep-scanner
gcloud run deploy enterprise-semgrep-scanner --image gcr.io/PROJECT_ID/enterprise-semgrep-scanner
```

### Environment Variables
- `PORT`: Server port (default: 8080)
- No external API keys required

## 🔌 API Usage

### Security Scan
```bash
POST /
Content-Type: application/json

{
  "repository_url": "https://github.com/user/repo",
  "github_token": "ghp_..." // Optional for private repos
}
```

### Response Format
```json
{
  "summary": {
    "total_findings": 15,
    "files_scanned": 98,
    "scan_duration": 45.2,
    "rules_executed": 30
  },
  "findings": [...],
  "severity_breakdown": {
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  },
  "raw_semgrep_output": {...}
}
```

## 🎯 Use Cases

- **Indie Developers**: Security audit before launching SaaS
- **Micro-SaaS**: Regular security checks for production code
- **Startups**: Pre-funding security assessment
- **Agencies**: Client security audits
- **Open Source**: Security analysis of contributions

## 🔧 Customization

### Adding Rules
Edit `security_rules` in `SecurityScanner` class:
```python
self.security_rules = [
    'p/owasp-top-ten',
    'p/secrets',
    # Add custom rules here
    'custom-rules.yaml'
]
```

### Custom Rule Files
Create YAML files with custom Semgrep patterns:
```yaml
rules:
  - id: custom-sql-injection
    pattern: $QUERY = "SELECT * FROM users WHERE id = " + $USER_INPUT
    message: "Potential SQL injection detected"
    severity: ERROR
```

## 📊 Performance

- **Repository Size**: Up to 500MB
- **Scan Time**: Up to 10 minutes
- **Memory**: 4GB allocated
- **CPU**: 2 cores allocated
- **Concurrency**: 10 concurrent requests

## 🚨 Limitations

- **No GPT Integration**: Pure Semgrep analysis only
- **No Remediation**: Findings only, no fix suggestions
- **No Historical Data**: Each scan is independent
- **No Custom Templates**: Standard Semgrep output format

## 🔮 Future Enhancements

- Separate GPT analysis worker
- Custom report templates
- Historical trend analysis
- Remediation suggestions
- Integration with CI/CD pipelines

## 📝 License

MIT License - Use freely for personal and commercial projects.
