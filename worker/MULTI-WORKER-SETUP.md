# Multi-Worker Horizontal Scaling Setup

## Overview
This setup deploys 5 worker instances with horizontal scaling to handle multiple concurrent security scans efficiently.

## Architecture
- **5 Worker Services**: `chatgpt-security-scanner` (main) + 4 clones
- **API Keys**: 4 OpenAI API keys per worker (20 total)
- **Sharding**: Only for repos ≥300 files, max 2 workers collaborate
- **Scaling**: 4-20 instances per worker based on demand

## Configuration

### API Key Distribution
Each worker gets 4 API keys for maximum parallel processing:
```bash
# Worker 1 (main)
OPENAI_API_KEY=sk-...
OPENAI_API_KEY_1=sk-...
OPENAI_API_KEY_2=sk-...
OPENAI_API_KEY_3=sk-...

# Worker 2
OPENAI_API_KEY=sk-...
OPENAI_API_KEY_1=sk-...
OPENAI_API_KEY_2=sk-...
OPENAI_API_KEY_3=sk-...

# ... repeat for workers 3-5
```

### Sharding Logic
- **Small repos (<300 files)**: Process locally with all 4 API keys
- **Large repos (≥300 files)**: Use sharding with max 2 workers
- **Benefits**: No overhead for small repos, turbo boost for large ones

## Deployment Options

### Option 1: Automated Script
```bash
./deploy-multiple-workers.sh
```

### Option 2: Manual Deployment
Deploy each worker service individually with the same image but different environment variables.

## Performance Expectations

### Small Repos (<300 files)
- **Processing**: Local with 4 parallel API keys
- **Speed**: 2-4x faster than single key
- **Overhead**: Minimal

### Large Repos (≥300 files)
- **Processing**: 2 workers collaborate via sharding
- **Speed**: 3-6x faster than single worker
- **Overhead**: Network latency + payload packaging

### Concurrent Users
- **Capacity**: 5 workers × 4 API keys = 20 parallel scans
- **Distribution**: Each user gets dedicated worker(s)
- **Efficiency**: No idle time, predictable performance

## Cost Optimization
- **API Usage**: Same total cost, faster completion
- **Compute**: Workers scale down when not needed
- **Sharding**: Only enabled when beneficial

## Monitoring
- Track worker utilization and API key usage
- Monitor sharding effectiveness (files processed vs. time saved)
- Adjust thresholds based on performance data

## Troubleshooting
- Ensure all API keys are valid and have sufficient quota
- Check worker peer connectivity for sharding
- Monitor Cloud Run logs for scaling behavior
