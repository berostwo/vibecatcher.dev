# Multi-Worker Horizontal Scaling Setup

This guide explains how to deploy multiple worker instances for horizontal scaling of the ChatGPT Security Scanner.

## 🚀 Overview

The system supports deploying 4 worker instances, each with 2 OpenAI API keys, providing:
- **Minimum capacity**: 4 workers always running
- **Maximum capacity**: Up to 20 workers during peak load
- **Redundancy**: Each worker has backup API keys
- **Load balancing**: Automatic distribution of scans across workers

## 📋 Prerequisites

1. **Google Cloud Project** with Cloud Run enabled
2. **8 OpenAI API Keys** (4 workers × 2 keys each)
3. **gcloud CLI** installed and configured
4. **Docker** installed locally

## 🔑 API Key Setup

Set up your environment variables with 8 API keys:

```bash
# Worker 1 API Keys
export OPENAI_API_KEY_1_1="sk-your-first-api-key"
export OPENAI_API_KEY_1_2="sk-your-second-api-key"

# Worker 2 API Keys  
export OPENAI_API_KEY_2_1="sk-your-third-api-key"
export OPENAI_API_KEY_2_2="sk-your-fourth-api-key"

# Worker 3 API Keys
export OPENAI_API_KEY_3_1="sk-your-fifth-api-key"
export OPENAI_API_KEY_3_2="sk-your-sixth-api-key"

# Worker 4 API Keys
export OPENAI_API_KEY_4_1="sk-your-seventh-api-key"
export OPENAI_API_KEY_4_2="sk-your-eighth-api-key"
```

## 🚀 Deployment Options

### Option 1: Automated Deployment Script

1. **Update the script** with your project ID:
   ```bash
   cd worker
   nano deploy-multiple-workers.sh
   # Change PROJECT_ID="your-project-id" to your actual project ID
   ```

2. **Make the script executable**:
   ```bash
   chmod +x deploy-multiple-workers.sh
   ```

3. **Run the deployment**:
   ```bash
   ./deploy-multiple-workers.sh
   ```

### Option 2: Manual Deployment

Deploy each worker individually:

```bash
# Deploy Worker 1
gcloud run deploy chatgpt-security-scanner-1 \
  --image gcr.io/YOUR_PROJECT_ID/chatgpt-security-scanner \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 2 \
  --timeout 900 \
  --min-instances 1 \
  --max-instances 5 \
  --concurrency 1 \
  --set-env-vars "OPENAI_API_KEY=${OPENAI_API_KEY_1_1},OPENAI_API_KEY_1=${OPENAI_API_KEY_1_2}"

# Repeat for workers 2, 3, and 4...
```

## 🔧 Configuration

### Scaling Parameters

- **Min Instances**: 1 per worker (4 total minimum)
- **Max Instances**: 5 per worker (20 total maximum)
- **Memory**: 2Gi per worker
- **CPU**: 2 cores per worker
- **Concurrency**: 1 scan per worker instance
- **Timeout**: 900 seconds (15 minutes)

### Auto-scaling Triggers

- **CPU Threshold**: 70% triggers scale-up
- **Concurrency**: Based on incoming requests
- **Memory**: Automatic based on usage

## 📊 Monitoring

### Health Checks

Each worker includes health checks:
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Retries**: 3 before marking unhealthy

### Cloud Run Metrics

Monitor in Google Cloud Console:
- Request count per worker
- Response times
- Error rates
- Instance count scaling

## 🔄 Load Balancing

### Scan Distribution

- **Round-robin**: New scans distributed across available workers
- **Fallback**: If one worker is busy, others handle the load
- **Auto-scaling**: Each worker scales independently based on demand

### API Key Distribution

- **Primary Key**: Main scanning operations
- **Backup Key**: Fallback if primary hits rate limits
- **Load Distribution**: Spreads API usage across multiple keys

## 💰 Cost Optimization

### Always-On Workers

- **4 workers × 1 instance**: Minimum cost for guaranteed capacity
- **Cost**: ~$0.40-0.80/hour for base capacity

### Auto-scaling

- **Additional instances**: Only pay when running
- **Peak handling**: Scale to 20 instances during busy periods
- **Idle instances**: Cost nothing when not in use

## 🧪 Testing

### Single Worker Test

```bash
curl -X POST https://chatgpt-security-scanner-1-abc123.run.app/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/test/repo"}'
```

### Load Testing

Test with multiple concurrent scans to verify auto-scaling:

```bash
# Test with 10 concurrent scans
for i in {1..10}; do
  curl -X POST https://chatgpt-security-scanner-1-abc123.run.app/scan \
    -H "Content-Type: application/json" \
    -d '{"repository_url": "https://github.com/test/repo"}' &
done
wait
```

## 🚨 Troubleshooting

### Common Issues

1. **API Key Limits**: Check OpenAI rate limits per key
2. **Memory Issues**: Increase memory if scans fail
3. **Timeout Errors**: Increase timeout for large repositories
4. **Scaling Issues**: Check Cloud Run quotas and limits

### Debug Commands

```bash
# Check worker status
gcloud run services list --region us-central1

# View logs
gcloud run services logs read chatgpt-security-scanner-1 --region us-central1

# Check metrics
gcloud run services describe chatgpt-security-scanner-1 --region us-central1
```

## 🔄 Updates

### Code Updates

1. **Push to GitHub**: Updates trigger automatic builds
2. **All Workers**: Get updated simultaneously
3. **Zero Downtime**: Rolling updates with health checks

### Configuration Updates

1. **Environment Variables**: Update via Cloud Run console
2. **Scaling Parameters**: Modify via gcloud commands
3. **API Keys**: Rotate keys without redeployment

## 📈 Performance Benefits

- **4x Base Capacity**: Handle 4 scans simultaneously
- **20x Peak Capacity**: Scale to 20 scans during busy periods
- **Reduced Wait Times**: Faster scan completion
- **Better Reliability**: Redundant workers and API keys
- **Cost Efficiency**: Pay only for what you use

## 🎯 Next Steps

1. **Deploy the workers** using the provided scripts
2. **Update your frontend** to use multiple worker URLs
3. **Test the scaling** with concurrent scans
4. **Monitor performance** and adjust as needed
5. **Consider advanced features** like worker health monitoring
