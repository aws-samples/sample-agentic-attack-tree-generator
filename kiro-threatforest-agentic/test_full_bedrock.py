#!/usr/bin/env python3
"""Full Bedrock integration test"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool

async def test_full_bedrock():
    """Test complete information extraction with Bedrock"""
    
    print("🧪 Full Bedrock Integration Test")
    
    # Get context
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print(f"📁 Context: {context_result['summary']['total_files']} files, {context_result['summary']['threat_files_found']} threat files")
    
    # Extract with Bedrock
    extraction_tool = InformationExtractionTool()
    
    print("🤖 Extracting project information with Bedrock...")
    
    result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model="anthropic.claude-3-haiku-20240307-v1:0",
        interactive=False
    )
    
    # Results
    project_info = result['project_info']
    
    if project_info.get('error'):
        print(f"❌ Bedrock Error: {project_info['error']}")
        return
    
    print(f"\n🤖 Bedrock Analysis Results:")
    print(f"📱 Application: [cyan]{project_info.get('application_name', 'Unknown')}[/cyan]")
    print(f"🏢 Sector: [cyan]{project_info.get('sector', 'Unknown')}[/cyan]")
    print(f"🏗️ Architecture: [cyan]{project_info.get('architecture_type', 'Unknown')}[/cyan]")
    print(f"☁️ Deployment: [cyan]{project_info.get('deployment_environment', 'Unknown')}[/cyan]")
    
    technologies = project_info.get('technologies', [])
    if technologies:
        print(f"🔧 Technologies ({len(technologies)}):")
        for tech in technologies:
            print(f"   • {tech}")
    
    objectives = project_info.get('security_objectives', {})
    if objectives:
        print(f"🔒 Security Objectives:")
        print(f"   • Confidentiality: {objectives.get('confidentiality', 'Unknown')}")
        print(f"   • Integrity: {objectives.get('integrity', 'Unknown')}")
        print(f"   • Availability: {objectives.get('availability', 'Unknown')}")
    
    # Threat analysis
    print(f"\n🎯 Threat Analysis:")
    print(f"Total threats: {result['extraction_summary']['total_threats']}")
    print(f"High severity: {result['extraction_summary']['high_severity_count']}")
    
    # Show high severity threats for attack tree generation
    high_threats = result['high_severity_threats']
    if high_threats:
        print(f"\n🔥 High Severity Threats (Attack Trees will be generated):")
        for i, threat in enumerate(high_threats, 1):
            print(f"{i}. {threat['id']}: {threat['category']}")
            print(f"   {threat['description'][:80]}...")
    
    print(f"\n✅ Bedrock integration successful!")
    print(f"Ready to generate {len(high_threats)} attack trees")

if __name__ == "__main__":
    asyncio.run(test_full_bedrock())
