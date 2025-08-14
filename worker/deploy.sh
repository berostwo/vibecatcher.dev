#!/bin/bash

# 🔒 Security Audit Worker Deployment Script
# This script automates the deployment to Google Cloud Run

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID=""
REGION="us-central1"
SERVICE_NAME="security-audit-worker"
OPENAI_API_KEY=""
GPT_MODEL="gpt-4-turbo-preview"

echo -e "${BLUE}🔒 Security Audit Worker Deployment${NC}"
echo "=================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ Google Cloud SDK (gcloud) is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker to build the container image"
    exit 1
fi

# Get project ID
if [ -z "$PROJECT_ID" ]; then
    PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
    if [ -z "$PROJECT_ID" ]; then
        echo -e "${YELLOW}⚠️  No project ID set${NC}"
        read -p "Enter your Google Cloud Project ID: " PROJECT_ID
    fi
fi

echo -e "${GREEN}✅ Project ID: ${PROJECT_ID}${NC}"

# Get OpenAI API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${YELLOW}⚠️  No OpenAI API key provided${NC}"
    read -s -p "Enter your OpenAI API key: " OPENAI_API_KEY
    echo
fi

if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}❌ OpenAI API key is required${NC}"
    exit 1
fi

echo -e "${GREEN}✅ OpenAI API key configured${NC}"

# Enable required APIs
echo -e "${BLUE}🔧 Enabling required APIs...${NC}"
gcloud services enable cloudbuild.googleapis.com run.googleapis.com containerregistry.googleapis.com --project="$PROJECT_ID"

# Set project
gcloud config set project "$PROJECT_ID"

# Build and push Docker image
echo -e "${BLUE}🐳 Building Docker image...${NC}"
docker build -t "gcr.io/$PROJECT_ID/$SERVICE_NAME" .

echo -e "${BLUE}📤 Pushing image to Container Registry...${NC}"
docker push "gcr.io/$PROJECT_ID/$SERVICE_NAME"

# Deploy to Cloud Run
echo -e "${BLUE}🚀 Deploying to Cloud Run...${NC}"
gcloud run deploy "$SERVICE_NAME" \
    --image "gcr.io/$PROJECT_ID/$SERVICE_NAME" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --memory 4Gi \
    --cpu 2 \
    --timeout 900 \
    --concurrency 10 \
    --max-instances 5 \
    --set-env-vars "OPENAI_API_KEY=$OPENAI_API_KEY,GPT_MODEL=$GPT_MODEL" \
    --project "$PROJECT_ID"

# Get service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID")

echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
echo -e "${GREEN}🌐 Service URL: ${SERVICE_URL}${NC}"
echo -e "${GREEN}📡 Endpoint: ${SERVICE_URL}/security_audit${NC}"

# Test the deployment
echo -e "${BLUE}🧪 Testing deployment...${NC}"
sleep 10  # Wait for service to be ready

# Create test payload
TEST_PAYLOAD='{"repository_url": "https://github.com/octocat/Hello-World", "repository_name": "test", "branch": "main"}'

# Test the endpoint
echo -e "${BLUE}📡 Testing endpoint...${NC}"
curl -X POST "${SERVICE_URL}/security_audit" \
    -H "Content-Type: application/json" \
    -d "$TEST_PAYLOAD" \
    --max-time 30 \
    --silent \
    --show-error \
    --fail-with-body > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Service is responding correctly${NC}"
else
    echo -e "${YELLOW}⚠️  Service test failed (this might be normal for the first request)${NC}"
fi

echo -e "${GREEN}🎉 Deployment script completed!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Update your frontend to use the new endpoint"
echo "2. Monitor the service in Google Cloud Console"
echo "3. Check logs: gcloud logs tail --service=$SERVICE_NAME"
echo "4. Test with a real repository"
echo ""
echo -e "${BLUE}🔗 Useful commands:${NC}"
echo "View service: gcloud run services describe $SERVICE_NAME --region=$REGION"
echo "View logs: gcloud logs tail --service=$SERVICE_NAME"
echo "Update service: gcloud run services update $SERVICE_NAME --region=$REGION"
echo "Delete service: gcloud run services delete $SERVICE_NAME --region=$REGION"
