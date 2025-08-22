#!/usr/bin/env python3
"""Test script for database-driven progress endpoints"""

import requests
import json

def test_progress_endpoints():
    """Test the progress endpoints"""
    base_url = "http://localhost:8080"
    
    # Test audit-specific progress endpoint
    test_audit_id = "test_audit_123"
    
    print(f"🧪 Testing progress endpoint: /progress/{test_audit_id}")
    
    try:
        response = requests.get(f"{base_url}/progress/{test_audit_id}")
        print(f"📡 Status Code: {response.status_code}")
        print(f"📡 Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Progress endpoint working: {data.get('status', 'unknown')}")
        else:
            print(f"❌ Progress endpoint failed with status {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("⚠️ Worker not running - start the worker first with: python main.py")
    except Exception as e:
        print(f"❌ Error testing progress endpoint: {e}")

if __name__ == "__main__":
    test_progress_endpoints()
