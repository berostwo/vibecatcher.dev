# VibeCatcher Security Audit Worker

A Google Cloud Run worker service that performs comprehensive security audits on GitHub repositories using OpenAI GPT-4.

## 🏗️ Architecture

- **Google Cloud Run**: Scalable, serverless container platform
- **OpenAI GPT-4**: AI-powered security vulnerability detection
- **Firebase Admin SDK**: User management and audit storage
- **GitHub Integration**: Repository cloning and code extraction
- **Express.js**: RESTful API endpoints

## 🚀 Features

- **Automated Security Audits**: Clone repositories and analyze code
- **AI-Powered Analysis**: GPT-4 identifies OWASP Top 10 vulnerabilities
- **Real-time Processing**: Async audit processing with status updates
- **Multi-language Support**: JavaScript, TypeScript, Python, Java, C++, and more
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
npm install
```

### 2. Environment Configuration

Copy `env.example` to `.env` and configure:

```bash
cp env.example .env
```

**Required Environment Variables:**
- `OPENAI_API_KEY`: Your OpenAI API key
- `FIREBASE_PROJECT_ID`: Firebase project ID
- `FIREBASE_PRIVATE_KEY`: Service account private key
- `FIREBASE_CLIENT_EMAIL`: Service account email
- `FIREBASE_CLIENT_ID`: Service account client ID
- `FIREBASE_AUTH_URI`: Firebase auth URI
- `FIREBASE_TOKEN_URI`: Firebase token URI
- `FIREBASE_AUTH_PROVIDER_X509_CERT_URL`: Firebase cert URL
- `FIREBASE_CLIENT_X509_CERT_URL`: Firebase client cert URL

### 3. Firebase Service Account Setup

1. Go to Firebase Console → Project Settings → Service Accounts
2. Click "Generate New Private Key"
3. Download JSON file and extract values to environment variables

### 4. Local Development

```bash
npm run dev
```

The worker will run on `http://localhost:8080`

## 🚀 Deployment to Google Cloud Run

### Option 1: Manual Deployment

```bash
# Build and deploy
npm run build
npm run deploy
```

### Option 2: Cloud Build (Recommended)

```bash
# Deploy using Cloud Build
gcloud builds submit --config cloudbuild.yaml
```

### Option 3: Docker

```bash
# Build Docker image
docker build -t vibecatcher-worker .

# Run locally
docker run -p 8080:8080 --env-file .env vibecatcher-worker

# Push to Google Container Registry
docker tag vibecatcher-worker gcr.io/PROJECT_ID/vibecatcher-worker
docker push gcr.io/PROJECT_ID/vibecatcher-worker
```

## 📡 API Endpoints

### Health Check
```
GET /health
```

### Start Security Audit
```
POST /api/audit/start
{
  "userId": "user123",
  "repositoryUrl": "https://github.com/user/repo",
  "repositoryName": "my-repo",
  "branch": "main",
  "accessToken": "ghp_..." // Optional for private repos
}
```

### Get Audit Report
```
GET /api/audit/{reportId}
```

### Get User's Audit Reports
```
GET /api/audit/user/{userId}
```

## 🔄 Audit Process Flow

1. **Request Received**: User submits repository for audit
2. **Validation**: Check user has available audits
3. **Repository Clone**: Clone GitHub repo to temp directory
4. **Code Extraction**: Parse relevant code files
5. **AI Analysis**: Send code to OpenAI GPT-4 for security review
6. **Result Processing**: Parse and validate AI response
7. **Database Update**: Store results in Firebase
8. **Cleanup**: Remove temporary files
9. **Audit Deduction**: Deduct one audit from user's account

## 🧪 Testing

### Test with Sample Repository

```bash
curl -X POST http://localhost:8080/api/audit/start \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test-user",
    "repositoryUrl": "https://github.com/username/repo",
    "repositoryName": "test-repo"
  }'
```

### Monitor Audit Progress

```bash
# Get report status
curl http://localhost:8080/api/audit/{reportId}

# Get user's reports
curl http://localhost:8080/api/audit/user/{userId}
```

## 📊 Monitoring & Logging

- **Health Checks**: `/health` endpoint for monitoring
- **Structured Logging**: Console output with timestamps
- **Error Handling**: Comprehensive error catching and reporting
- **Performance Metrics**: Analysis time tracking

## 🔧 Configuration

### Resource Limits (Cloud Run)
- **Memory**: 2GB (configurable in cloudbuild.yaml)
- **CPU**: 2 vCPU (configurable in cloudbuild.yaml)
- **Timeout**: 15 minutes (900 seconds)
- **Concurrency**: 10 concurrent requests
- **Max Instances**: 5

### Supported Languages
- JavaScript/TypeScript (Node.js, React, Vue, etc.)
- Python (Django, Flask, etc.)
- Java (Spring, etc.)
- C/C++ (CMake, Make, etc.)
- PHP (Laravel, Symfony, etc.)
- Ruby (Rails, Sinatra, etc.)
- Go, Rust, and more

## 🚨 Security Considerations

- **Environment Variables**: Never commit secrets to code
- **Service Account**: Use least-privilege Firebase service account
- **GitHub Tokens**: Store tokens securely, rotate regularly
- **API Keys**: Secure OpenAI API key access
- **CORS**: Configure CORS for production domains

## 🔄 Integration with Main App

The worker integrates with your main VibeCatcher app through:

1. **Firebase**: Shared user data and audit reports
2. **API Calls**: Main app calls worker endpoints
3. **Real-time Updates**: Firestore listeners for status updates
4. **Audit Quota**: Synchronized audit counting system

## 📈 Scaling

- **Auto-scaling**: Cloud Run automatically scales based on demand
- **Concurrency**: Handle multiple audit requests simultaneously
- **Resource Optimization**: Efficient memory and CPU usage
- **Cost Management**: Pay-per-use pricing model

## 🆘 Troubleshooting

### Common Issues

1. **Firebase Connection**: Check service account credentials
2. **OpenAI API**: Verify API key and quota limits
3. **GitHub Access**: Ensure repository is accessible
4. **Memory Issues**: Increase memory allocation if needed
5. **Timeout Errors**: Extend timeout for large repositories

### Debug Mode

Set `WORKER_ENV=development` for verbose logging.

## 📝 License

This worker is part of the VibeCatcher project and follows the same license terms.
