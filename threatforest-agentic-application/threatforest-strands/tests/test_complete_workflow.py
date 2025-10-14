#!/usr/bin/env python3
"""Test complete ThreatForest workflow end-to-end"""

import sys
import asyncio
from pathlib import Path

# Add the threatforest-strands package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from threatforest.tools.context_analysis_tool import ContextAnalysisTool
from threatforest.tools.information_extraction_tool import InformationExtractionTool
from threatforest.tools.attack_tree_generator_tool import AttackTreeGeneratorTool
from threatforest.tools.ttc_mapping_tool import TTCMappingTool
from threatforest.tools.summary_generator_tool import SummaryGeneratorTool

async def test_complete_workflow():
    """Test complete ThreatForest workflow"""
    
    print("🚀 ThreatForest Complete Workflow Test")
    print("=" * 50)
    
    # Configuration
    test_project = Path(__file__).parent.parent.parent / "genai-chatbot-example"
    model = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    output_dir = Path.cwd() / "outputs" / "complete_workflow_test"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Context Analysis
    print("\n📁 Step 1: Context Analysis")
    context_tool = ContextAnalysisTool()
    context_result = await context_tool.execute(str(test_project))
    
    print(f"   ✅ Files discovered: {context_result['summary']['total_files']}")
    print(f"   ✅ READMEs found: {context_result['summary']['readmes_found']}")
    print(f"   ✅ Threat files: {context_result['summary']['threat_files_found']}")
    
    # Step 2: Information Extraction
    print("\n🤖 Step 2: Information Extraction with Bedrock")
    extraction_tool = InformationExtractionTool()
    extraction_result = await extraction_tool.execute(
        context_files=context_result,
        bedrock_model=model,
        interactive=False
    )
    
    project_info = extraction_result['project_info']
    high_threats = extraction_result['high_severity_threats']
    
    print(f"   ✅ Application: {project_info.get('application_name')}")
    print(f"   ✅ Technologies: {len(project_info.get('technologies', []))} identified")
    print(f"   ✅ Total threats: {extraction_result['extraction_summary']['total_threats']}")
    print(f"   ✅ High severity: {len(high_threats)}")
    
    # Step 3: Attack Tree Generation
    print(f"\n🌳 Step 3: Attack Tree Generation ({len(high_threats)} trees)")
    tree_generator = AttackTreeGeneratorTool()
    
    # Generate trees for first 3 high severity threats (to avoid throttling)
    test_threats = high_threats[:3]
    trees_result = await tree_generator.execute(
        threat_statements=test_threats,
        extracted_info=extraction_result,
        bedrock_model=model
    )
    
    attack_trees = trees_result['attack_trees']
    successful_trees = [t for t in attack_trees if 'mermaid_code' in t]
    failed_trees = [t for t in attack_trees if 'error' in t]
    
    print(f"   ✅ Successful: {len(successful_trees)}")
    print(f"   ❌ Failed: {len(failed_trees)}")
    
    # Step 4: TTC Mapping
    print(f"\n🎯 Step 4: Enhanced TTC Mapping with Bedrock")
    ttc_mapper = TTCMappingTool(threshold=0.5)
    mapped_result = await ttc_mapper.execute(
        trees_result,
        bedrock_model=model  # Use Bedrock for enhanced mapping
    )
    
    mapping_summary = mapped_result['mapping_summary']
    print(f"   ✅ Bedrock enhanced: {mapping_summary.get('bedrock_enhanced', False)}")
    print(f"   ✅ Techniques loaded: {mapping_summary.get('techniques_loaded', 0)}")
    print(f"   ✅ Total mappings: {mapping_summary.get('total_mappings', 0)}")
    print(f"   ✅ High confidence mappings: {mapping_summary.get('successful_mappings', 0)}")
    
    # Step 5: Summary Generation
    print(f"\n📄 Step 5: Summary Generation")
    summary_generator = SummaryGeneratorTool()
    summary_result = await summary_generator.execute(
        attack_trees=mapped_result,
        extracted_info=extraction_result,
        output_dir=str(output_dir)
    )
    
    print(f"   ✅ Files generated: {len(summary_result.get('output_files', []))}")
    print(f"   ✅ Output directory: {output_dir}")
    
    # Final Results Summary
    print(f"\n🎉 Workflow Complete!")
    print("=" * 50)
    print(f"📊 Final Results:")
    print(f"   • Project: {project_info.get('application_name')}")
    print(f"   • Technologies: {len(project_info.get('technologies', []))}")
    print(f"   • Threats analyzed: {len(test_threats)}")
    print(f"   • Attack trees: {len(successful_trees)} successful")
    print(f"   • TTC mappings: {mapping_summary.get('total_mappings', 0)}")
    print(f"   • Output files: {len(summary_result.get('output_files', []))}")
    
    # Show generated files
    if summary_result.get('output_files'):
        print(f"\n📁 Generated Files:")
        for file_path in summary_result['output_files']:
            file_name = Path(file_path).name
            print(f"   • {file_name}")
    
    return {
        "status": "success",
        "project_name": project_info.get('application_name'),
        "threats_processed": len(test_threats),
        "trees_generated": len(successful_trees),
        "ttc_mappings": mapping_summary.get('total_mappings', 0),
        "output_directory": str(output_dir),
        "files_generated": len(summary_result.get('output_files', []))
    }

if __name__ == "__main__":
    result = asyncio.run(test_complete_workflow())
    print(f"\n✅ Workflow Result: {result}")
