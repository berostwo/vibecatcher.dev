# 🚀 Simple Cloud Run Deployment (No Docker!)

## **Method 1: Source Upload (Easiest)**

### Step 1: Prepare Your Code
- Make sure your `worker` folder has all the source code
- You can zip the entire `worker` folder

### Step 2: Deploy on Cloud Run
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to **Cloud Run**
3. Click **"CREATE SERVICE"**
4. Choose **"Deploy from source"**
5. Upload your `worker` folder (or ZIP file)
6. Set service name: `vibecatcher-worker`
7. Click **"DEPLOY"**

## **Method 2: GitHub Integration**

### Step 1: Push to GitHub
- Push your worker code to a GitHub repository
- Make sure it's public or you have proper access

### Step 2: Connect GitHub
1. In Cloud Run, choose **"Continuously deploy from a Git repository"**
2. Connect your GitHub account
3. Select your repository
4. Set the branch (usually `main` or `master`)
5. Click **"SET UP"**

## **Configuration (Both Methods)**

### Service Settings
- **Region**: Choose closest to you (e.g., `us-central1`)
- **CPU**: `2`
- **Memory**: `2 GiB`
- **Request timeout**: `900` seconds
- **Max instances**: `5`

### Environment Variables
Add these in the **"VARIABLES & SECRETS"** section:

```
OPENAI_API_KEY=sk-your-actual-openai-key
FIREBASE_PROJECT_ID=your-firebase-project-id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYour actual private key\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
WORKER_ENV=production
```

## **What Happens Next**

1. **Cloud Run automatically:**
   - Detects it's a Node.js app
   - Installs dependencies from `package.json`
   - Builds your TypeScript code
   - Creates a container image
   - Deploys your service

2. **You get:**
   - A public URL for your worker
   - Automatic scaling
   - Built-in monitoring

## **Test Your Worker**

Once deployed, test with:
```bash
# Health check
curl https://your-service-url/health
```

## **Benefits of This Approach**

✅ **No Docker knowledge needed**  
✅ **Automatic dependency management**  
✅ **Built-in TypeScript support**  
✅ **Easy updates** (just push new code)  
✅ **Automatic scaling**  
✅ **Pay-per-use pricing**
