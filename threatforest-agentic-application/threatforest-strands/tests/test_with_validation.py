#!/usr/bin/env python3
"""Test with user validation"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool

async def test_with_validation():
    """Test information extraction with user validation"""
    
    print("🧪 Testing Information Extraction with User Validation")
    
    # First get context
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print(f"📁 Context analysis complete")
    
    # Test extraction with validation
    extraction_tool = InformationExtractionTool()
    
    result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        interactive=True  # Enable user validation
    )
    
    print(f"\n📊 Extraction Results:")
    print(f"Total threats: {result['extraction_summary']['total_threats']}")
    print(f"High severity threats: {result['extraction_summary']['high_severity_count']}")
    print(f"Technologies identified: {result['extraction_summary']['technologies_identified']}")
    print(f"User validated: {result['extraction_summary']['user_validated']}")
    
    # Show project info
    project_info = result['project_info']
    print(f"\n📱 Project Information:")
    print(f"Application: {project_info.get('application_name')}")
    print(f"Technologies: {', '.join(project_info.get('technologies', []))}")
    print(f"Sector: {project_info.get('sector')}")
    print(f"Architecture: {project_info.get('architecture_type')}")
    
    # Check if files were saved
    tf_dir = Path.cwd() / ".tf"
    if tf_dir.exists():
        print(f"\n📄 Generated files in {tf_dir}:")
        for file_path in tf_dir.iterdir():
            print(f"  • {file_path.name}")

if __name__ == "__main__":
    asyncio.run(test_with_validation())
