#!/usr/bin/env python3
"""Simple test for context analysis"""

import sys
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
import asyncio

async def test_context_analysis():
    """Test context analysis tool"""
    
    print("🧪 Testing Context Analysis Tool")
    
    # Test with genai-chatbot-example directory
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    if not test_project.exists():
        print(f"❌ Test project not found: {test_project}")
        return
    
    print(f"📁 Testing with project: {test_project}")
    
    tool = ContextAnalysisTool()
    result = await tool.execute(str(test_project))
    
    print(f"\n📊 Results:")
    print(f"Total files discovered: {result['summary']['total_files']}")
    print(f"READMEs found: {result['summary']['readmes_found']}")
    print(f"Threat files found: {result['summary']['threat_files_found']}")
    print(f"Has sufficient context: {result['summary']['has_sufficient_context']}")
    
    # Show discovered files
    for category, files in result['discovered_files'].items():
        if files:
            print(f"\n{category.upper()}:")
            for file_path in files:
                print(f"  • {file_path}")

if __name__ == "__main__":
    asyncio.run(test_context_analysis())
