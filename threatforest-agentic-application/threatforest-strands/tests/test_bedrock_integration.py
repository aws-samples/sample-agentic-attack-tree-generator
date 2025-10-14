#!/usr/bin/env python3
"""Test Bedrock API integration"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool

async def test_bedrock_integration():
    """Test information extraction with real Bedrock API"""
    
    print("🧪 Testing Bedrock API Integration")
    
    # First get context
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print(f"📁 Context analysis complete - {context_result['summary']['total_files']} files found")
    
    # Test extraction with real Bedrock
    extraction_tool = InformationExtractionTool()
    
    print("🤖 Calling Bedrock API for project information extraction...")
    
    result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        interactive=False  # No user validation for this test
    )
    
    print(f"\n📊 Extraction Results:")
    print(f"Total threats: {result['extraction_summary']['total_threats']}")
    print(f"High severity threats: {result['extraction_summary']['high_severity_count']}")
    
    # Show project info from Bedrock
    project_info = result['project_info']
    
    if project_info.get('error'):
        print(f"❌ Error: {project_info['error']}")
    else:
        print(f"\n🤖 Bedrock Extracted Information:")
        print(f"📱 Application: {project_info.get('application_name')}")
        print(f"🔧 Technologies: {', '.join(project_info.get('technologies', []))}")
        print(f"🏢 Sector: {project_info.get('sector')}")
        print(f"🏗️ Architecture: {project_info.get('architecture_type')}")
        print(f"☁️ Deployment: {project_info.get('deployment_environment')}")
        
        if project_info.get('security_objectives'):
            objectives = project_info['security_objectives']
            print(f"🔒 Security Objectives:")
            print(f"   • Confidentiality: {objectives.get('confidentiality')}")
            print(f"   • Integrity: {objectives.get('integrity')}")
            print(f"   • Availability: {objectives.get('availability')}")
    
    # Show high severity threats that will generate attack trees
    high_threats = result['high_severity_threats']
    if high_threats:
        print(f"\n🔥 High Severity Threats (will generate attack trees):")
        for threat in high_threats[:3]:  # Show first 3
            print(f"• {threat['id']}: {threat['category']}")
        if len(high_threats) > 3:
            print(f"... and {len(high_threats) - 3} more")

if __name__ == "__main__":
    asyncio.run(test_bedrock_integration())
