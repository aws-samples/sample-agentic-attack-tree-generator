#!/usr/bin/env python3
"""Test TTC mapping with sample attack tree"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest-strands package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatforest.tools.ttc_mapping_tool import TTCMappingTool

async def test_ttc_mapping():
    """Test TTC mapping with sample data"""
    
    print("🧪 Testing TTC Mapping Tool")
    
    # Create sample attack tree data
    sample_attack_trees = {
        "attack_trees": [{
            "threat_id": "T3",
            "threat_category": "LLM01 Prompt Injection",
            "mermaid_code": "graph TD\n    goal[\"Compromise System\"]\n    attack1[\"Inject malicious prompts\"]\n    attack2[\"Bypass input validation\"]\n    attack3[\"Execute unauthorized commands\"]\n    attack4[\"Escalate privileges\"]\n    attack5[\"Access sensitive data\"]\n    \n    attack1 --> attack2\n    attack2 --> attack3\n    attack3 --> attack4\n    attack4 --> attack5\n    attack5 --> goal",
            "attack_steps": [
                {"node_id": "attack1", "description": "Inject malicious prompts"},
                {"node_id": "attack2", "description": "Bypass input validation"},
                {"node_id": "attack3", "description": "Execute unauthorized commands"},
                {"node_id": "attack4", "description": "Escalate privileges"},
                {"node_id": "attack5", "description": "Access sensitive data"}
            ]
        }]
    }
    
    # Test TTC mapping
    ttc_mapper = TTCMappingTool(threshold=0.3)  # Lower threshold for testing
    result = await ttc_mapper.execute(sample_attack_trees)
    
    summary = result['mapping_summary']
    print(f"📊 Mapping Summary:")
    print(f"   Techniques loaded: {summary.get('techniques_loaded', 0)}")
    print(f"   Total mappings: {summary.get('total_mappings', 0)}")
    print(f"   Successful mappings: {summary.get('successful_mappings', 0)}")
    
    if summary.get('error'):
        print(f"❌ Error: {summary['error']}")
        return
    
    # Show mappings
    if result['ttc_mapped_trees']:
        tree = result['ttc_mapped_trees'][0]
        mappings = tree.get('ttc_mappings', [])
        
        print(f"\n🎯 Found {len(mappings)} mappings:")
        for i, mapping in enumerate(mappings[:3]):  # Show first 3
            print(f"{i+1}. Attack: {mapping['attack_step']}")
            if mapping['mapped_techniques']:
                technique = mapping['mapped_techniques'][0]
                print(f"   → {technique['technique_id']}: {technique['technique_name']}")
                print(f"   → Confidence: {technique['confidence']:.2f}")
                print(f"   → Tactics: {', '.join(technique['tactics'])}")
            print()

if __name__ == "__main__":
    asyncio.run(test_ttc_mapping())
