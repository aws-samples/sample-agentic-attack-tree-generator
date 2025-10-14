#!/usr/bin/env python3
"""Test complete workflow: context -> extraction -> attack trees"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest-strands package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool
from threatforest.tools.attack_tree_generator_tool import AttackTreeGeneratorTool

async def test_full_workflow():
    """Test complete ThreatForest workflow"""
    
    print("🧪 Testing Complete ThreatForest Workflow")
    
    # Setup
    test_project = Path(__file__).parent.parent.parent / "genai-chatbot-example"
    model = "us.anthropic.claude-opus-4-1-20250805-v1:0"
    
    # Step 1: Context Analysis
    print("\n📁 Step 1: Context Analysis")
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    print(f"   Files found: {context_result['summary']['total_files']}")
    
    # Step 2: Information Extraction
    print("\n🤖 Step 2: Information Extraction")
    extraction_tool = InformationExtractionTool()
    extraction_result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model=model,
        interactive=False
    )
    
    project_info = extraction_result['project_info']
    high_threats = extraction_result['high_severity_threats']
    
    print(f"   Application: {project_info.get('application_name')}")
    print(f"   Technologies: {len(project_info.get('technologies', []))}")
    print(f"   High severity threats: {len(high_threats)}")
    
    # Step 3: Attack Tree Generation
    print(f"\n🌳 Step 3: Generating {len(high_threats)} Attack Trees")
    tree_generator = AttackTreeGeneratorTool()
    
    trees_result = await tree_generator.execute(
        threat_statements=high_threats,
        extracted_info=extraction_result,
        bedrock_model=model
    )
    
    attack_trees = trees_result['attack_trees']
    successful = len([t for t in attack_trees if 'mermaid_code' in t])
    failed = len([t for t in attack_trees if 'error' in t])
    
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ Failed: {failed}")
    
    # Step 4: Save Results
    print(f"\n💾 Step 4: Saving Results")
    
    # Create output directory
    app_name = project_info.get('application_name', 'unknown_app').replace(' ', '_').lower()
    output_dir = Path.cwd() / "outputs" / app_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save attack trees
    saved_files = []
    for tree in attack_trees:
        if 'mermaid_code' in tree:
            threat_id = tree['threat_id']
            filename = f"attack_tree_{threat_id}.mmd"
            file_path = output_dir / filename
            
            # Create content with metadata
            content = f"""# Attack Tree: {tree['threat_category']}
## Threat ID: {threat_id}
## Description: {tree['threat_description'][:100]}...

```mermaid
{tree['mermaid_code']}
```

## Attack Steps
{len(tree.get('attack_steps', []))} attack steps identified.
"""
            
            file_path.write_text(content)
            saved_files.append(str(file_path))
    
    # Save summary
    summary_content = f"""# ThreatForest Analysis Summary

## Project Information
- **Application**: {project_info.get('application_name')}
- **Architecture**: {project_info.get('architecture_type')}
- **Technologies**: {', '.join(project_info.get('technologies', [])[:5])}{'...' if len(project_info.get('technologies', [])) > 5 else ''}

## Threat Analysis
- **Total Threats**: {extraction_result['extraction_summary']['total_threats']}
- **High Severity**: {len(high_threats)}
- **Attack Trees Generated**: {successful}

## Generated Files
{chr(10).join(f'- {Path(f).name}' for f in saved_files)}

## High Severity Threats
{chr(10).join(f'{i+1}. {t["id"]}: {t["category"]}' for i, t in enumerate(high_threats))}
"""
    
    summary_file = output_dir / "analysis_summary.md"
    summary_file.write_text(summary_content)
    saved_files.append(str(summary_file))
    
    print(f"   📁 Output directory: {output_dir}")
    print(f"   📄 Files saved: {len(saved_files)}")
    
    # Final Results
    print(f"\n🎉 Workflow Complete!")
    print(f"   📊 {len(high_threats)} high severity threats analyzed")
    print(f"   🌳 {successful} attack trees generated")
    print(f"   💾 {len(saved_files)} files saved to {output_dir}")
    
    return {
        "status": "success",
        "threats_analyzed": len(high_threats),
        "trees_generated": successful,
        "output_directory": str(output_dir),
        "files_saved": saved_files
    }

if __name__ == "__main__":
    result = asyncio.run(test_full_workflow())
    print(f"\n📋 Final Result: {result}")
