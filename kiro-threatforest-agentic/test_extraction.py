#!/usr/bin/env python3
"""Test information extraction"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool

async def test_extraction():
    """Test information extraction"""
    
    print("🧪 Testing Information Extraction")
    
    # First get context
    test_project = Path(__file__).parent / "genai-chatbot-example"
    
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print(f"📁 Context analysis complete")
    print(f"Files found: {context_result['summary']['total_files']}")
    
    # Test threat parsing (without LLM call)
    extraction_tool = InformationExtractionTool()
    
    # Parse threats only
    threats = extraction_tool._parse_threat_statements(context_result)
    
    print(f"\n🎯 Threat Analysis:")
    print(f"Total threats found: {len(threats)}")
    
    high_threats = [t for t in threats if t.get("severity") == "High"]
    print(f"High severity threats: {len(high_threats)}")
    
    # Show first few threats
    for i, threat in enumerate(threats[:5]):
        print(f"\n{i+1}. {threat['id']} - {threat['category']}")
        print(f"   Severity: {threat['severity']}")
        print(f"   Description: {threat['description'][:100]}...")
    
    # Show high severity threats
    if high_threats:
        print(f"\n🔥 High Severity Threats:")
        for threat in high_threats:
            print(f"• {threat['id']}: {threat['category']}")

if __name__ == "__main__":
    asyncio.run(test_extraction())
