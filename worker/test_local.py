#!/usr/bin/env python3
"""
Local test script for the Security Audit Worker
Run this to test the worker functionality locally
"""

import asyncio
import json
import sys
from main import security_audit_worker

async def test_worker():
    """Test the security audit worker with sample data"""
    
    # Test data - replace with your actual repository
    test_data = {
        "repository_url": "https://github.com/username/test-repo",
        "repository_name": "test-repo",
        "branch": "main"
    }
    
    print("🔒 Testing Security Audit Worker...")
    print(f"📁 Repository: {test_data['repository_name']}")
    print(f"🔗 URL: {test_data['repository_url']}")
    print("=" * 50)
    
    try:
        # Run the worker
        result = await security_audit_worker(test_data)
        
        if result.get('success'):
            print("✅ Security audit completed successfully!")
            print(f"⏱️  Total execution time: {result.get('execution_time', 0):.2f}s")
            
            audit_report = result.get('audit_report', {})
            print(f"📊 Total issues found: {audit_report.get('total_issues', 0)}")
            print(f"🚨 Critical: {audit_report.get('critical_issues', 0)}")
            print(f"⚠️  High: {audit_report.get('high_issues', 0)}")
            print(f"🔶 Medium: {audit_report.get('medium_issues', 0)}")
            print(f"🔷 Low: {audit_report.get('low_issues', 0)}")
            
            # Show GPT analysis summary
            gpt_analysis = audit_report.get('gpt_analysis', {})
            print(f"\n🤖 GPT-4 Analysis:")
            print(f"   Risk Level: {gpt_analysis.get('risk_level', 'Unknown')}")
            print(f"   Assessment: {gpt_analysis.get('security_assessment', 'No assessment')}")
            
            # Save detailed report
            with open('test_audit_report.json', 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\n📄 Detailed report saved to: test_audit_report.json")
            
        else:
            print("❌ Security audit failed!")
            print(f"Error: {result.get('error', 'Unknown error')}")
            print(f"Error Type: {result.get('error_type', 'Unknown')}")
            
    except Exception as e:
        print(f"💥 Test failed with exception: {e}")
        import traceback
        traceback.print_exc()

def test_with_file(filename):
    """Test with data from a JSON file"""
    try:
        with open(filename, 'r') as f:
            test_data = json.load(f)
        
        print(f"📖 Loading test data from: {filename}")
        return asyncio.run(test_worker())
        
    except FileNotFoundError:
        print(f"❌ Test file not found: {filename}")
        return False
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON in test file: {filename}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Test with file
        test_with_file(sys.argv[1])
    else:
        # Test with default data
        asyncio.run(test_worker())
