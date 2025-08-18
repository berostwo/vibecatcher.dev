#!/bin/bash

# Deploy Multiple Workers Script
# This script deploys multiple worker instances with different API key configurations

set -e

PROJECT_ID="your-project-id"  # Replace with your actual project ID
REGION="us-central1"
BASE_SERVICE_NAME="chatgpt-security-scanner"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Multiple Worker Instances for Horizontal Scaling${NC}"

# Function to deploy a worker instance
deploy_worker() {
    local instance_num=$1
    local service_name="${BASE_SERVICE_NAME}-${instance_num}"
    
    echo -e "${YELLOW}Deploying ${service_name}...${NC}"
    
    # Deploy to Cloud Run with specific configuration
    gcloud run deploy "${service_name}" \
        --image "gcr.io/${PROJECT_ID}/${BASE_SERVICE_NAME}" \
        --region "${REGION}" \
        --platform managed \
        --allow-unauthenticated \
        --memory 2Gi \
        --cpu 2 \
        --timeout 900 \
        --min-instances 1 \
        --max-instances 5 \
        --concurrency 1 \
        --cpu-throttling \
        --cpu-boost \
        --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY_${instance_num}_1},OPENAI_API_KEY_1=${OPENAI_API_KEY_${instance_num}_2}" \
        --quiet
    
    echo -e "${GREEN}✅ ${service_name} deployed successfully${NC}"
}

# Check if required environment variables are set
if [ -z "$OPENAI_API_KEY_1_1" ] || [ -z "$OPENAI_API_KEY_1_2" ]; then
    echo -e "${RED}❌ Error: Please set OPENAI_API_KEY_1_1 and OPENAI_API_KEY_1_2 environment variables${NC}"
    echo -e "${YELLOW}Example:${NC}"
    echo -e "export OPENAI_API_KEY_1_1='your-first-api-key'"
    echo -e "export OPENAI_API_KEY_1_2='your-second-api-key'"
    echo -e "export OPENAI_API_KEY_2_1='your-third-api-key'"
    echo -e "export OPENAI_API_KEY_2_2='your-fourth-api-key'"
    exit 1
fi

# Deploy 4 worker instances
echo -e "${GREEN}Deploying 4 worker instances...${NC}"

for i in {1..4}; do
    deploy_worker $i
done

echo -e "${GREEN}🎉 All worker instances deployed successfully!${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Update your frontend to use multiple worker URLs"
echo -e "2. Test with multiple concurrent scans"
echo -e "3. Monitor Cloud Run metrics for auto-scaling"

# Display service URLs
echo -e "${GREEN}Service URLs:${NC}"
for i in {1..4}; do
    local service_name="${BASE_SERVICE_NAME}-${i}"
    local url=$(gcloud run services describe "${service_name}" --region="${REGION}" --format="value(status.url)" --quiet)
    echo -e "${service_name}: ${url}"
done
