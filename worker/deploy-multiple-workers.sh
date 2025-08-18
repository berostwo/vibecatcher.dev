#!/bin/bash

# Multi-Worker Deployment Script for ChatGPT Security Scanner
# This script deploys 4 additional worker instances alongside the main service

# Configuration
PROJECT_ID="your-project-id"  # Change this to your actual project ID
REGION="us-central1"
IMAGE_NAME="chatgpt-security-scanner"
SERVICE_BASE_NAME="chatgpt-security-scanner"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Multiple Worker Instances${NC}"
echo -e "${YELLOW}Make sure to update PROJECT_ID in this script first!${NC}"
echo ""

# Check if PROJECT_ID is set
if [ "$PROJECT_ID" = "your-project-id" ]; then
    echo -e "${RED}❌ Please update PROJECT_ID in this script before running${NC}"
    exit 1
fi

# Deploy Worker 1
echo -e "${GREEN}📦 Deploying ${SERVICE_BASE_NAME}-1...${NC}"
gcloud run deploy "${SERVICE_BASE_NAME}-1" \
    --image "gcr.io/${PROJECT_ID}/${IMAGE_NAME}" \
    --region "${REGION}" \
    --platform managed \
    --allow-unauthenticated \
    --memory "2Gi" \
    --cpu 2 \
    --timeout 900 \
    --min-instances 4 \
    --max-instances 20 \
    --concurrency 1 \
    --cpu-throttling \
    --cpu-boost \
    --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY},OPENAI_API_KEY_1=${OPENAI_API_KEY_1},OPENAI_API_KEY_2=${OPENAI_API_KEY_2},OPENAI_API_KEY_3=${OPENAI_API_KEY_3}"

# Deploy Worker 2
echo -e "${GREEN}📦 Deploying ${SERVICE_BASE_NAME}-2...${NC}"
gcloud run deploy "${SERVICE_BASE_NAME}-2" \
    --image "gcr.io/${PROJECT_ID}/${IMAGE_NAME}" \
    --region "${REGION}" \
    --platform managed \
    --allow-unauthenticated \
    --memory "2Gi" \
    --cpu 2 \
    --timeout 900 \
    --min-instances 4 \
    --max-instances 20 \
    --concurrency 1 \
    --cpu-throttling \
    --cpu-boost \
    --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY},OPENAI_API_KEY_1=${OPENAI_API_KEY_1},OPENAI_API_KEY_2=${OPENAI_API_KEY_2},OPENAI_API_KEY_3=${OPENAI_API_KEY_3}"

# Deploy Worker 3
echo -e "${GREEN}📦 Deploying ${SERVICE_BASE_NAME}-3...${NC}"
gcloud run deploy "${SERVICE_BASE_NAME}-3" \
    --image "gcr.io/${PROJECT_ID}/${IMAGE_NAME}" \
    --region "${REGION}" \
    --platform managed \
    --allow-unauthenticated \
    --memory "2Gi" \
    --cpu 2 \
    --timeout 900 \
    --min-instances 4 \
    --max-instances 20 \
    --concurrency 1 \
    --cpu-throttling \
    --cpu-boost \
    --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY},OPENAI_API_KEY_1=${OPENAI_API_KEY_1},OPENAI_API_KEY_2=${OPENAI_API_KEY_2},OPENAI_API_KEY_3=${OPENAI_API_KEY_3}"

# Deploy Worker 4
echo -e "${GREEN}📦 Deploying ${SERVICE_BASE_NAME}-4...${NC}"
gcloud run deploy "${SERVICE_BASE_NAME}-4" \
    --image "gcr.io/${PROJECT_ID}/${IMAGE_NAME}" \
    --region "${REGION}" \
    --platform managed \
    --allow-unauthenticated \
    --memory "2Gi" \
    --cpu 2 \
    --timeout 900 \
    --min-instances 4 \
    --max-instances 20 \
    --concurrency 1 \
    --cpu-throttling \
    --cpu-boost \
    --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY},OPENAI_API_KEY_1=${OPENAI_API_KEY_1},OPENAI_API_KEY_2=${OPENAI_API_KEY_2},OPENAI_API_KEY_3=${OPENAI_API_KEY_3}"

echo ""
echo -e "${GREEN}✅ All worker instances deployed successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 Next Steps:${NC}"
echo "1. Set WORKER_PEERS environment variable in main service:"
echo "   ${SERVICE_BASE_NAME}-1,${SERVICE_BASE_NAME}-2,${SERVICE_BASE_NAME}-3,${SERVICE_BASE_NAME}-4"
echo "2. Set SHARDING_ENABLED=true in main service"
echo "3. Test sharding with a repository ≥300 files"
echo ""
echo -e "${GREEN}🎯 Your workers are now ready for horizontal scaling!${NC}"
