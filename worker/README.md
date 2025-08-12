# VibeCatcher Security Audit Worker

A Python Cloud Run function that performs comprehensive security audits on GitHub repositories using OpenAI GPT-4.

## 🏗️ Architecture

- **Google Cloud Run**: Scalable, serverless function platform
- **OpenAI GPT-4**: AI-powered security vulnerability detection
- **Firebase Admin SDK**: User management and audit storage
- **GitHub Integration**: Repository cloning and code extraction
- **Python**: Fast, efficient code analysis

## 🚀 Features

- **Automated Security Audits**: Clone repositories and analyze code
- **AI-Powered Analysis**: GPT-4 identifies OWASP Top 10 vulnerabilities
- **Real-time Processing**: Async audit processing with status updates
- **Multi-language Support**: JavaScript, TypeScript, Python, Java, C++, Go, Rust and more
- **Audit Management**: Track audit history and results
- **User Quota System**: Integrates with main app's audit system

## 📋 Prerequisites

- Google Cloud Platform account
- Firebase project with service account
- OpenAI API key
- GitHub personal access token (for private repos)

## 🛠️ Setup

### 1. Install Dependencies

```bash
cd worker
pip install -r requirements.txt
```

### 2. Environment Configuration

Set these environment variables in your Cloud Run service:

```
OPENAI_API_KEY=your_openai_api_key
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour private key here\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your_service_account_email@project.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=your_client_id
FIREBASE_CLIENT_X509_CERT_URL=https://www.googleapis.com/robot/v1/metadata/x509/your_service_account_email%40project.iam.gserviceaccount.com
```

### 3. Firebase Service Account Setup

1. Go to Firebase Console → Project Settings → Service Accounts
2. Click "Generate New Private Key"
3. Download JSON file and extract values to environment variables

### 4. Local Development

```bash
python main.py
```

The worker will run on `http://localhost:8080`

## 🚀 Deployment to Google Cloud Run

### Option 1: Cloud Console (Recommended)

1. Go to Cloud Run in Google Cloud Console
2. Click "Create Service"
3. Choose "Continuously deploy from a source repository"
4. Select your worker directory
5. Set environment variables
6. Configure:
   - Memory: 2GB+
   - CPU: 2
   - Timeout: 900s (15 minutes)
   - Concurrency: 1
7. Deploy

### Option 2: Command Line

```bash
gcloud run deploy vibecatcher-worker \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 2 \
  --timeout 900 \
  --concurrency 1
```

## 📡 API Endpoints

- `POST /` - Start security audit
- `GET /health` - Health check

### Request Format

```json
{
  "userId": "user123",
  "repositoryUrl": "https://github.com/username/repo",
  "repositoryName": "my-repo",
  "branch": "main",
  "accessToken": "github_token_optional"
}
```

### Response Format

```json
{
  "success": true,
  "reportId": "uuid-here",
  "message": "Audit started successfully"
}
```

## 🔧 Configuration

- **Memory**: Set to 2GB+ for large repositories
- **Timeout**: Set to 900s (15 minutes) for long-running audits
- **Concurrency**: Use 1 to avoid resource conflicts
- **CPU**: 2 cores recommended for optimal performance

## 📊 What Gets Analyzed

The worker automatically detects:
- SQL injection vulnerabilities
- XSS (Cross-Site Scripting) issues
- Authentication bypass vulnerabilities
- Authorization flaws
- Insecure dependencies
- Hardcoded secrets
- Input validation issues
- Output encoding problems

## 🚨 Security Features

- Non-root user execution
- Temporary file cleanup
- Input validation and sanitization
- Secure environment variable handling
- CORS protection

## 📝 Logs and Monitoring

- Cloud Run logs automatically capture all output
- Health check endpoint for monitoring
- Structured error handling and reporting
- Performance metrics tracking

