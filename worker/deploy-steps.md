# 🚀 Cloud Run Web Interface Deployment Guide

## **Step 1: Build and Test Locally**
```bash
# Build the worker
npm run build

# Test locally (optional)
npm run dev
```

## **Step 2: Access Google Cloud Console**
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Select your project (or create one if needed)
3. Navigate to **Cloud Run** in the left sidebar

## **Step 3: Create New Service**
1. Click **"CREATE SERVICE"**
2. Choose **"Deploy one revision from an existing container image"**
3. Click **"SELECT"**

## **Step 4: Build Container Image**
1. Click **"BROWSE"** to select your Dockerfile
2. Or use **Cloud Build** to build automatically:
   - Click **"CLOUD BUILD"**
   - Upload your `worker` folder as a ZIP file
   - Or connect your GitHub repository

## **Step 5: Configure Service**
- **Service name**: `vibecatcher-worker`
- **Region**: Choose closest to you (e.g., `us-central1`)
- **CPU allocation**: `CPU is only allocated during request processing`
- **CPU**: `2`
- **Memory**: `2 GiB`
- **Request timeout**: `900` seconds (15 minutes)
- **Maximum number of instances**: `5`
- **Concurrency**: `10`

## **Step 6: Set Environment Variables**
Click **"VARIABLES & SECRETS"** and add:

```
OPENAI_API_KEY=sk-your-actual-openai-key
FIREBASE_PROJECT_ID=your-firebase-project-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour actual private key\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
WORKER_ENV=production
```

## **Step 7: Deploy**
1. Click **"CREATE"**
2. Wait for deployment (usually 2-5 minutes)
3. Copy your service URL

## **Step 8: Test Your Worker**
```bash
# Health check
curl https://your-service-url/health

# Test audit endpoint
curl -X POST https://your-service-url/api/audit/start \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test-user",
    "repositoryUrl": "https://github.com/username/repo",
    "repositoryName": "test-repo"
  }'
```

## **Step 9: Update Main App**
Update your main app to use the new worker URL:
```typescript
const WORKER_URL = 'https://your-service-url';
```

## **🔧 Troubleshooting**
- **Build errors**: Check Dockerfile and dependencies
- **Environment variables**: Ensure all required vars are set
- **Permission errors**: Check Firebase service account permissions
- **Timeout issues**: Increase timeout or optimize code
