# Cloud Run Deployment Guide

## Prerequisites
- Google Cloud CLI installed and configured
- Project with Cloud Run API enabled
- Firebase Admin SDK service account key

## Environment Variables
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

## Deploy to Cloud Run

1. **Build and deploy:**
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

2. **Or use the Cloud Console:**
   - Go to Cloud Run in Google Cloud Console
   - Click "Create Service"
   - Choose "Continuously deploy from a source repository" or "Deploy one revision from an existing container image"
   - Select your source code
   - Set environment variables
   - Deploy

## API Endpoints

- `POST /` - Start security audit
- `GET /health` - Health check

## Request Format
```json
{
  "userId": "user123",
  "repositoryUrl": "https://github.com/username/repo",
  "repositoryName": "my-repo",
  "branch": "main",
  "accessToken": "github_token_optional"
}
```

## Response Format
```json
{
  "success": true,
  "reportId": "uuid-here",
  "message": "Audit started successfully"
}
```

## Notes
- The function will clone repositories, analyze code with OpenAI GPT-4, and store results in Firebase
- Set memory to 2GB+ for large repositories
- Set timeout to 900s (15 minutes) for long-running audits
- Use concurrency=1 to avoid resource conflicts
