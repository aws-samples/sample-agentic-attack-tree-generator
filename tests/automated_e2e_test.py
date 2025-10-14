#!/usr/bin/env python3
"""
Automated E2E test for ThreatForest Priority 1 validation
Directly calls orchestrator to bypass CLI wizard
"""
import sys
import asyncio
import time
import json
from pathlib import Path

# Add threatforest-strands to path
base_dir = Path(__file__).parent.parent / 'kiro-threatforest-agentic' / 'threatforest-strands'
sys.path.insert(0, str(base_dir / 'src'))

from strands_agent import ThreatForestOrchestrator, ThreatForestConfig

def validate_output(output_dir):
    """Validate generated output files"""
    issues = []
    
    # Check for required files
    required_files = [
        'threat_model.json',
        'attack_trees.json',
        'mitre_mappings.json'
    ]
    
    for file in required_files:
        filepath = output_dir / file
        if not filepath.exists():
            issues.append(f"Missing: {file}")
        else:
            try:
                with open(filepath) as f:
                    data = json.load(f)
                    if not data:
                        issues.append(f"Empty: {file}")
            except json.JSONDecodeError as e:
                issues.append(f"Invalid JSON in {file}: {e}")
    
    return issues

async def run_e2e_test():
    """Run E2E test"""
    print("=" * 60)
    print("AUTOMATED E2E TEST - Priority 1 Validation")
    print("=" * 60)
    
    # Test configuration
    base_dir = Path(__file__).parent.parent / 'kiro-threatforest-agentic'
    project_path = base_dir / 'examples' / 'hcls-example'
    output_dir = Path(__file__).parent.parent / 'test_output'
    profile = 'dicorteg+zetaworkload-test-Admin'
    model_id = 'us.anthropic.claude-sonnet-4-20250514-v1:0'
    
    print(f"\n[CONFIG]")
    print(f"  Project: {project_path}")
    print(f"  Output: {output_dir}")
    print(f"  Profile: {profile}")
    print(f"  Model: {model_id}")
    
    # Validate project exists
    if not project_path.exists():
        print(f"\n[ERROR] Project path not found: {project_path}")
        return False
    
    # Clean output directory
    if output_dir.exists():
        import shutil
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    
    print(f"\n[START] Initializing ThreatForestOrchestrator...")
    start_time = time.time()
    
    try:
        # Create config
        config = ThreatForestConfig(
            project_path=project_path,
            output_dir=output_dir,
            aws_profile=profile,
            bedrock_model=model_id
        )
        
        # Initialize orchestrator
        orchestrator = ThreatForestOrchestrator(config)
        
        print(f"[RUNNING] Executing workflow...")
        
        # Execute workflow
        result = await orchestrator.run()
        
        elapsed = time.time() - start_time
        print(f"\n[COMPLETE] Workflow finished in {elapsed:.1f}s")
        
        # Validate output
        print(f"\n[VALIDATION] Checking output files...")
        issues = validate_output(output_dir)
        
        if issues:
            print(f"[FAILED] Validation issues found:")
            for issue in issues:
                print(f"  - {issue}")
            return False
        else:
            print(f"[PASSED] All output files validated successfully")
            
            # Show file sizes
            for file in output_dir.glob('*.json'):
                size = file.stat().st_size
                print(f"  ✓ {file.name}: {size} bytes")
            
            return True
            
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"\n[ERROR] Test failed after {elapsed:.1f}s")
        print(f"  Exception: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = asyncio.run(run_e2e_test())
    sys.exit(0 if success else 1)
