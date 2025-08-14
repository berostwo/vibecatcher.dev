# 🔒 Security Audit Worker

A high-performance Google Cloud Run worker that performs deep static code analysis using **Semgrep** and **GPT-4** for comprehensive security auditing and remediation guidance.

## 🚀 Features

- **⚡ Time-Optimized**: Parallel processing with async/await for maximum efficiency
- **🔍 Deep Static Analysis**: Semgrep-powered security rule scanning
- **🤖 AI-Powered Insights**: GPT-4 analysis for security assessment and remediation
- **📊 Comprehensive Reports**: Detailed findings with severity classification
- **🔄 Scalable**: Cloud Run auto-scaling for high-demand scenarios
- **🔐 Secure**: Non-root container execution and secure token handling

## 🏗️ Architecture

```
Repository Clone → Semgrep Scan → GPT-4 Analysis → Report Generation
      ↓              ↓              ↓              ↓
   Git Clone    Security Rules   AI Assessment   JSON Report
   (5-30s)      (30-300s)       (10-60s)        (Instant)
```

## 📋 Prerequisites

- Google Cloud Platform account with billing enabled
- OpenAI API key with GPT-4 access
- Git repository access (public or private with proper authentication)
- Docker installed (for local testing)

## 🛠️ Local Development Setup

### 1. Clone and Setup

```bash
git clone <your-repo>
cd worker
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Environment Variables

Create `.env` file:

```bash
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_BASE_URL=https://api.openai.com/v1
GPT_MODEL=gpt-4-turbo-preview
```

### 3. Install Semgrep

```bash
# macOS
brew install semgrep

# Ubuntu/Debian
curl -L https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-v1.60.0-ubuntu-20.04.tgz | tar -xz
sudo mv semgrep-v1.60.0-ubuntu-20.04/semgrep /usr/local/bin/

# Windows
# Download from https://github.com/returntocorp/semgrep/releases
```

### 4. Test Locally

```bash
# Create test data
echo '{"repository_url": "https://github.com/username/repo", "repository_name": "test-repo"}' > test_data.json

# Run worker
python main.py test_data.json
```

## 🚀 Google Cloud Run Deployment

### 1. Enable Required APIs

```bash
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  containerregistry.googleapis.com
```

### 2. Set Project ID

```bash
export PROJECT_ID=$(gcloud config get-value project)
echo $PROJECT_ID
```

### 3. Build and Deploy

```bash
# Build and deploy using Cloud Build
gcloud builds submit --config cloudbuild.yaml \
  --substitutions=_OPENAI_API_KEY="your-actual-api-key" \
  --substitutions=_GPT_MODEL="gpt-4-turbo-preview"
```

### 4. Manual Deployment (Alternative)

```bash
# Build image
docker build -t gcr.io/$PROJECT_ID/security-audit-worker .

# Push to Container Registry
docker push gcr.io/$PROJECT_ID/security-audit-worker

# Deploy to Cloud Run
gcloud run deploy security-audit-worker \
  --image gcr.io/$PROJECT_ID/security-audit-worker \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 4Gi \
  --cpu 2 \
  --timeout 900 \
  --set-env-vars OPENAI_API_KEY="your-api-key"
```

## 📡 API Usage

### Endpoint

```
POST https://security-audit-worker-xxxxx-uc.a.run.app/security_audit
```

### Request Format

```json
{
  "repository_url": "https://github.com/username/repository",
  "repository_name": "my-app",
  "branch": "main"
}
```

### Response Format

```json
{
  "success": true,
  "audit_report": {
    "repository_name": "my-app",
    "scan_timestamp": "2024-01-15T10:30:00Z",
    "semgrep_results": {
      "findings": [...],
      "scan_time": 45.2,
      "total_files_scanned": 150
    },
    "gpt_analysis": {
      "security_assessment": "Multiple critical vulnerabilities detected...",
      "risk_level": "High",
      "remediation_prompts": [...],
      "master_prompt": "Comprehensive security fix...",
      "analysis_time": 12.8
    },
    "total_issues": 8,
    "critical_issues": 2,
    "high_issues": 3,
    "medium_issues": 2,
    "low_issues": 1
  },
  "execution_time": 58.0
}
```

## ⚡ Performance Optimization

### Time Targets

- **Repository Clone**: 5-30 seconds (depending on size)
- **Semgrep Scan**: 30-300 seconds (depending on codebase size)
- **GPT-4 Analysis**: 10-60 seconds (depending on findings)
- **Total Execution**: 45 seconds - 6.5 minutes

### Optimization Features

- **Async Processing**: Parallel execution of independent operations
- **Smart Timeouts**: Per-file and overall scan timeouts
- **Memory Limits**: 4GB memory allocation for large codebases
- **Concurrency Control**: Up to 10 concurrent requests per instance
- **Auto-scaling**: 0-5 instances based on demand

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | Required | Your OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI API endpoint |
| `GPT_MODEL` | `gpt-4-turbo-preview` | GPT model to use |

### Semgrep Configuration

The worker uses Semgrep's `auto` configuration which includes:
- Security rules for common vulnerabilities
- Best practices for multiple languages
- Customizable rule sets

### Resource Limits

- **Memory**: 4GB per instance
- **CPU**: 2 vCPUs per instance
- **Timeout**: 15 minutes maximum
- **Concurrency**: 10 requests per instance
- **Max Instances**: 5 auto-scaling

## 📊 Monitoring and Logging

### Cloud Logging

All operations are logged with structured logging:
- Repository cloning status
- Semgrep scan progress
- GPT-4 analysis results
- Error handling and debugging

### Health Checks

```bash
# Check worker health
curl https://security-audit-worker-xxxxx-uc.a.run.app/health
```

### Metrics

- Execution time per audit
- Success/failure rates
- Resource utilization
- API response times

## 🧪 Testing

### Unit Tests

```bash
pytest tests/ -v
```

### Integration Tests

```bash
# Test with real repository
python -m pytest tests/test_integration.py -v
```

### Load Testing

```bash
# Test concurrent requests
python tests/load_test.py --concurrent 10 --duration 60
```

## 🔒 Security Considerations

- **Non-root Execution**: Container runs as non-privileged user
- **Token Security**: API keys stored as environment variables
- **Network Isolation**: Minimal network access required
- **Resource Limits**: Prevents resource exhaustion attacks
- **Input Validation**: All inputs are validated and sanitized

## 🚨 Troubleshooting

### Common Issues

1. **Semgrep Installation Failed**
   ```bash
   # Check Semgrep installation
   semgrep --version
   ```

2. **OpenAI API Errors**
   ```bash
   # Verify API key
   curl -H "Authorization: Bearer $OPENAI_API_KEY" \
        https://api.openai.com/v1/models
   ```

3. **Repository Clone Failures**
   - Check repository URL format
   - Verify access permissions
   - Check network connectivity

4. **Memory Issues**
   - Increase Cloud Run memory allocation
   - Optimize Semgrep scan parameters
   - Reduce concurrent requests

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
```

## 📈 Scaling and Performance

### Auto-scaling

- **Min Instances**: 0 (cold start)
- **Max Instances**: 5
- **Concurrency**: 10 requests per instance
- **Scaling**: Based on request queue length

### Performance Tuning

```bash
# Increase memory for large repositories
gcloud run services update security-audit-worker \
  --memory 8Gi

# Increase CPU for faster processing
gcloud run services update security-audit-worker \
  --cpu 4
```

## 🔄 Updates and Maintenance

### Updating Dependencies

```bash
# Update Python packages
pip install -r requirements.txt --upgrade

# Update Semgrep
curl -L https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-v1.60.0-ubuntu-20.04.tgz | tar -xz
```

### Rolling Updates

```bash
# Deploy new version
gcloud builds submit --config cloudbuild.yaml

# Monitor deployment
gcloud run services describe security-audit-worker
```

## 📞 Support

For issues and questions:
- Check Cloud Run logs
- Review Semgrep documentation
- Verify OpenAI API status
- Check network connectivity

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Built with ❤️ for secure code analysis**
