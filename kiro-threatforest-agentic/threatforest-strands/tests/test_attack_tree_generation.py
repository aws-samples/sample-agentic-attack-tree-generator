#!/usr/bin/env python3
"""Test attack tree generation with Bedrock"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest-strands package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool
from threatforest.tools.attack_tree_generator_tool import AttackTreeGeneratorTool

async def test_attack_tree_generation():
    """Test attack tree generation for high severity threats"""
    
    print("🧪 Testing Attack Tree Generation with Bedrock")
    
    # Get context and extract information
    test_project = Path(__file__).parent.parent.parent / "genai-chatbot-example"
    
    print("📁 Analyzing context...")
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print("🤖 Extracting project information...")
    extraction_tool = InformationExtractionTool()
    extraction_result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model="us.anthropic.claude-opus-4-1-20250805-v1:0",
        interactive=False
    )
    
    high_threats = extraction_result['high_severity_threats']
    project_info = extraction_result['project_info']
    
    print(f"🎯 Found {len(high_threats)} high severity threats")
    print(f"📱 Project: {project_info.get('application_name')}")
    
    # Generate attack trees
    print("\n🌳 Generating attack trees...")
    tree_generator = AttackTreeGeneratorTool()
    
    # Test with first high severity threat
    if high_threats:
        test_threat = high_threats[0]
        print(f"Testing with: {test_threat['id']} - {test_threat['category']}")
        
        result = await tree_generator.execute(
            threat_statements=[test_threat],  # Just test one
            extracted_info=extraction_result,
            bedrock_model="us.anthropic.claude-opus-4-1-20250805-v1:0"
        )
        
        if result['attack_trees']:
            tree = result['attack_trees'][0]
            
            if 'error' in tree:
                print(f"❌ Error: {tree['error']}")
            else:
                print(f"✅ Attack tree generated successfully!")
                print(f"Threat: {tree['threat_id']} - {tree['threat_category']}")
                print(f"Attack steps: {len(tree.get('attack_steps', []))}")
                
                # Show Mermaid code preview
                mermaid_code = tree.get('mermaid_code', '')
                if mermaid_code:
                    lines = mermaid_code.split('\n')
                    print(f"\n📊 Mermaid Code Preview (first 10 lines):")
                    for i, line in enumerate(lines[:10]):
                        print(f"  {i+1:2d}: {line}")
                    if len(lines) > 10:
                        print(f"  ... and {len(lines) - 10} more lines")
                
                # Show attack steps
                attack_steps = tree.get('attack_steps', [])
                if attack_steps:
                    print(f"\n🎯 Attack Steps ({len(attack_steps)}):")
                    for step in attack_steps[:5]:  # Show first 5
                        print(f"  • {step.get('node_id')}: {step.get('description')}")
                    if len(attack_steps) > 5:
                        print(f"  ... and {len(attack_steps) - 5} more steps")
        else:
            print("❌ No attack trees generated")
    else:
        print("❌ No high severity threats found")

if __name__ == "__main__":
    asyncio.run(test_attack_tree_generation())
