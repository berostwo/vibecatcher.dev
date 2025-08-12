import json
from datetime import datetime

# Cloud Run function entry point
def audit_worker(request):
    """Cloud Run function entry point"""
    # Set CORS headers
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json'
    }
    
    # Handle preflight request
    if request.method == 'OPTIONS':
        return ('', 204, headers)
    
    try:
        # Parse request
        if request.method == 'POST':
            request_data = request.get_json()
            
            if not request_data:
                return (json.dumps({'error': 'No data provided'}), 400, headers)
            
            # Validate required fields
            required_fields = ['userId', 'repositoryUrl', 'repositoryName']
            for field in required_fields:
                if field not in request_data:
                    return (json.dumps({'error': f'Missing required field: {field}'}), 400, headers)
            
            # Validate GitHub URL
            if 'github.com' not in request_data['repositoryUrl']:
                return (json.dumps({'error': 'Only GitHub repositories are supported'}), 400, headers)
            
            # For now, return a simple response to test deployment
            # TODO: Implement async processing later
            return (json.dumps({
                'success': True,
                'reportId': 'test-123',
                'message': 'Audit endpoint ready - async processing to be implemented'
            }), 200, headers)
        
        elif request.method == 'GET':
            # Handle health check
            if request.path == '/health':
                return (json.dumps({
                    'status': 'healthy',
                    'timestamp': datetime.now().isoformat()
                }), 200, headers)
            
            return (json.dumps({'error': 'Method not allowed'}), 405, headers)
        
        else:
            return (json.dumps({'error': 'Method not allowed'}), 405, headers)
    
    except Exception as error:
        print(f"Function error: {error}")
        return (json.dumps({
            'error': str(error)
        }), 500, headers)

# For local testing (only needed for development)
if __name__ == "__main__":
    print("This is a Cloud Run function. Use 'gcloud run deploy' to deploy.")
