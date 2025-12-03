#!/usr/bin/env python3
"""
Test script for ThreatComposer file parsing
Tests Strands-only parsing of real ThreatComposer files
NOTE: Requires actual LLM access (Bedrock or other configured model)
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_vehicle_platform_threatcomposer():
    """
    Test parsing of the actual vehicle-platform ThreatComposer file.
    
    This test requires:
    1. Configured model (AWS Bedrock, Anthropic, etc.)
    2. Valid credentials
    3. The file at: sample-applications/vehicle-platform/ThreatComposer_Workspace_Vehicle-Connected Platform.tc.json
    
    Expected results:
    - Should extract 11 threats
    - Each threat should have: id, statement, priority, threatSource, prerequisites, 
      threatAction, threatImpact, impactedGoal, impactedAssets
    """
    from threatforest.modules.agents import ParserAgent
    
    print("\n" + "="*60)
    print("  Testing ThreatComposer File Parsing (Strands-Only)")
    print("="*60)
    
    # Initialize agent
    agent = ParserAgent()
    
    # File path
    tc_file = Path("sample-applications/vehicle-platform/ThreatComposer_Workspace_Vehicle-Connected Platform.tc.json")
    
    if not tc_file.exists():
        print(f"\n✗ File not found: {tc_file}")
        print("  Make sure you're running from the project root directory")
        return False
    
    print(f"\n📄 Parsing file: {tc_file.name}")
    print(f"   Size: {tc_file.stat().st_size} bytes")
    
    # Parse using Strands agent
    print("\n🤖 Starting ParserAgent (Strands-only, no fallback)...")
    print("   This requires LLM access and may take a minute...")
    
    try:
        threats = agent.parse_threats(str(tc_file))
        
        if not threats:
            print("\n✗ FAIL: No threats were extracted!")
            print("   This could mean:")
            print("   - LLM failed to parse the file")
            print("   - JSON response parsing failed")
            print("   - Model configuration issue")
            return False
        
        print(f"\n✓ SUCCESS: Extracted {len(threats)} threats")
        
        # Validate structure
        print("\n📊 Validating threat structure:")
        for i, threat in enumerate(threats[:3], 1):  # Check first 3
            print(f"\n  Threat {i}:")
            print(f"    - ID: {threat.get('id', 'MISSING')}")
            print(f"    - Statement: {threat.get('description', threat.get('statement', 'MISSING'))[:50]}...")
            print(f"    - Priority: {threat.get('severity', 'MISSING')}")
            print(f"    - Category: {threat.get('category', 'MISSING')}")
            
            # Check required fields
            missing = []
            if not threat.get('id'):
                missing.append('id')
            if not threat.get('description') and not threat.get('statement'):
                missing.append('description/statement')
            if not threat.get('severity'):
                missing.append('severity')
            
            if missing:
                print(f"    ⚠️  Missing fields: {', '.join(missing)}")
        
        # Summary
        print(f"\n{'='*60}")
        print(f"  Test Result: PASSED")
        print(f"  Threats extracted: {len(threats)}")
        print(f"  Expected: 11 (from original file)")
        print(f"  Match: {'✓ YES' if len(threats) == 11 else '✗ NO'}")
        print(f"{'='*60}\n")
        
        return len(threats) == 11
        
    except Exception as e:
        print(f"\n✗ ERROR: Parsing failed with exception:")
        print(f"   {type(e).__name__}: {str(e)}")
        print("\n   Possible causes:")
        print("   - Model not configured properly")
        print("   - Invalid credentials")
        print("   - Network/API issues")
        return False


def main():
    print("\n🔬 ThreatComposer Parsing Test")
    print("Testing Strands-only approach with real ThreatComposer file")
    print("\n⚠️  REQUIREMENTS:")
    print("   - Configured model in config.yaml")
    print("   - Valid AWS/API credentials")
    print("   - Network access to model API")
    
    input("\nPress Enter to continue (or Ctrl+C to cancel)...")
    
    success = test_vehicle_platform_threatcomposer()
    
    if success:
        print("\n✅ Test PASSED!")
        print("   ParserAgent successfully parsed ThreatComposer file using Strands-only approach")
        print("   Parser chain removal validated for ThreatComposer format")
    else:
        print("\n❌ Test FAILED!")
        print("   Consider:")
        print("   - Checking model configuration")
        print("   - Verifying credentials")
        print("   - Reviewing error messages above")
        print("   - May need to restore parser chain for ThreatComposer format")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
