# 🚀 Quick Start Guide

Get your Security Audit Worker running in 5 minutes!

## ⚡ Super Quick Setup

### 1. Prerequisites (2 min)
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Install Docker
# macOS: brew install docker
# Ubuntu: sudo apt-get install docker.io
# Windows: Download from docker.com
```

### 2. Deploy (3 min)
```bash
# Clone this repo and navigate to worker folder
cd worker

# Make deployment script executable
chmod +x deploy.sh

# Run deployment (it will prompt for your OpenAI API key)
./deploy.sh
```

### 3. Test
```bash
# Get your service URL
gcloud run services describe security-audit-worker --region=us-central1 --format="value(status.url)"

# Test with a sample repository
curl -X POST "YOUR_SERVICE_URL/security_audit" \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/octocat/Hello-World", "repository_name": "test"}'
```

## 🔧 Manual Setup (Alternative)

### 1. Enable APIs
```bash
gcloud services enable cloudbuild.googleapis.com run.googleapis.com containerregistry.googleapis.com
```

### 2. Build & Deploy
```bash
export PROJECT_ID=$(gcloud config get-value project)
docker build -t gcr.io/$PROJECT_ID/security-audit-worker .
docker push gcr.io/$PROJECT_ID/security-audit-worker

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

## 🧪 Local Testing

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Install Semgrep
```bash
# macOS
brew install semgrep

# Ubuntu
curl -L https://github.com/returntocorp/semgrep/releases/latest/download/semgrep-v1.60.0-ubuntu-20.04.tgz | tar -xz
sudo mv semgrep-v1.60.0-ubuntu-20.04/semgrep /usr/local/bin/
```

### 3. Test Locally
```bash
# Set environment variable
export OPENAI_API_KEY="your-api-key"

# Run test
python test_local.py
```

## 📡 API Usage

### Endpoint
```
POST https://your-service-url/security_audit
```

### Request
```json
{
  "repository_url": "https://github.com/username/repo",
  "repository_name": "my-app",
  "branch": "main"
}
```

### Response
```json
{
  "success": true,
  "audit_report": {
    "repository_name": "my-app",
    "total_issues": 5,
    "critical_issues": 1,
    "high_issues": 2,
    "medium_issues": 1,
    "low_issues": 1,
    "gpt_analysis": {
      "security_assessment": "Multiple vulnerabilities detected...",
      "risk_level": "High",
      "remediation_prompts": [...],
      "master_prompt": "Comprehensive fix..."
    }
  },
  "execution_time": 45.2
}
```

## 🚨 Common Issues

### OpenAI API Key
- Make sure you have GPT-4 access
- Check your API key is correct
- Verify billing is enabled

### Repository Access
- Use HTTPS URLs for public repos
- For private repos, ensure proper authentication

### Semgrep Issues
- Check Semgrep is installed: `semgrep --version`
- Verify you have internet access for rule updates

## 📊 Performance

- **Small repos (<100 files)**: 1-2 minutes
- **Medium repos (100-1000 files)**: 2-5 minutes  
- **Large repos (>1000 files)**: 5-10 minutes

## 🔗 Next Steps

1. **Integrate with Frontend**: Update your dashboard to call the worker
2. **Monitor Performance**: Check Cloud Run metrics and logs
3. **Customize Rules**: Modify Semgrep configuration for your needs
4. **Scale Up**: Adjust memory/CPU based on repository sizes

## 📞 Need Help?

- Check Cloud Run logs: `gcloud logs tail --service=security-audit-worker`
- Review deployment: `gcloud run services describe security-audit-worker`
- Test health: `curl YOUR_SERVICE_URL/health`

---

**🎯 Goal: Get from zero to working security audits in under 5 minutes!**
