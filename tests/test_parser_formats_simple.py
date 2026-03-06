#!/usr/bin/env python3
"""
Simple unit tests for ParserAgent format parsing
Tests parser chain baseline (no LLM needed)
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_section(title):
    """Print test section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def main():
    print("\n🧪 Parser Agent Format Tests")
    print("Testing parser chain baseline (deterministic, no LLM)")
    print("=" * 60)
    
    from threatforest.modules.agents import ParserAgent
    
    agent = ParserAgent()
    fixtures_dir = Path(__file__).parent / "fixtures"
    
    all_passed = True
    results = []
    
    # Test 1: JSON Format
    test_section("JSON Format Parsing")
    try:
        json_file = fixtures_dir / "threats.json"
        if not json_file.exists():
            print(f"  ✗ JSON fixture not found: {json_file}")
            all_passed = False
        else:
            threats = agent._parse_with_chain(json_file)
            if len(threats) == 3 and threats[0]['id'] == 'T001':
                print(f"  ✓ JSON: Parsed {len(threats)} threats")
                print(f"    - T001: {threats[0]['category']} (High)")
                print(f"    - T002: {threats[1]['category']} (High)")
                print(f"    - T003: {threats[2]['category']} (Medium)")
                results.append(("JSON", True, len(threats)))
            else:
                print(f"  ✗ JSON: Got {len(threats)} threats, expected 3")
                all_passed = False
                results.append(("JSON", False, len(threats)))
    except Exception as e:
        print(f"  ✗ JSON parsing failed: {e}")
        all_passed = False
        results.append(("JSON", False, 0))
    
    # Test 2: YAML Format
    test_section("YAML Format Parsing")
    try:
        yaml_file = fixtures_dir / "threats.yaml"
        if not yaml_file.exists():
            print(f"  ✗ YAML fixture not found: {yaml_file}")
            all_passed = False
        else:
            threats = agent._parse_with_chain(yaml_file)
            if len(threats) == 3 and threats[0]['id'] == 'T001':
                print(f"  ✓ YAML: Parsed {len(threats)} threats")
                print(f"    - T001: {threats[0]['category']} (High)")
                print(f"    - T002: {threats[1]['category']} (High)")
                print(f"    - T003: {threats[2]['category']} (Medium)")
                results.append(("YAML", True, len(threats)))
            else:
                print(f"  ✗ YAML: Got {len(threats)} threats, expected 3")
                all_passed = False
                results.append(("YAML", False, len(threats)))
    except Exception as e:
        print(f"  ✗ YAML parsing failed: {e}")
        all_passed = False
        results.append(("YAML", False, 0))
    
    # Test 3: Markdown Format
    test_section("Markdown Format Parsing")
    try:
        md_file = fixtures_dir / "threats.md"
        if not md_file.exists():
            print(f"  ✗ Markdown fixture not found: {md_file}")
            all_passed = False
        else:
            threats = agent._parse_with_chain(md_file)
            if len(threats) >= 1:
                print(f"  ✓ Markdown: Parsed {len(threats)} threats")
                for t in threats:
                    print(f"    - {t['id']}: {t.get('category', 'N/A')} ({t.get('severity', 'Unknown')})")
                results.append(("Markdown", True, len(threats)))
            else:
                print(f"  ✗ Markdown: Got {len(threats)} threats, expected at least 1")
                all_passed = False
                results.append(("Markdown", False, len(threats)))
    except Exception as e:
        print(f"  ✗ Markdown parsing failed: {e}")
        all_passed = False
        results.append(("Markdown", False, 0))
    
    # Test 4: ThreatComposer Format
    test_section("ThreatComposer Format Parsing")
    try:
        tc_file = fixtures_dir / "threats.tc.json"
        if not tc_file.exists():
            print(f"  ⊘ ThreatComposer fixture not found (skipped)")
            results.append(("ThreatComposer", None, 0))
        else:
            threats = agent._parse_with_chain(tc_file)
            if len(threats) >= 1:
                print(f"  ✓ ThreatComposer: Parsed {len(threats)} threats")
                for t in threats:
                    print(f"    - {t.get('id', 'Unknown')}: {t.get('category', 'N/A')}")
                results.append(("ThreatComposer", True, len(threats)))
            else:
                print(f"  ✗ ThreatComposer: Got {len(threats)} threats")
                all_passed = False
                results.append(("ThreatComposer", False, len(threats)))
    except Exception as e:
        print(f"  ✗ ThreatComposer parsing failed: {e}")
        all_passed = False
        results.append(("ThreatComposer", False, 0))
    
    # Summary
    test_section("Test Summary")
    
    print("\n  Format          | Status | Threats")
    print("  " + "-" * 45)
    for format_name, passed, count in results:
        if passed is None:
            status = "SKIPPED"
            color_start = ""
            color_end = ""
        elif passed:
            status = "✓ PASS"
            color_start = ""
            color_end = ""
        else:
            status = "✗ FAIL"
            color_start = ""
            color_end = ""
        
        print(f"  {format_name:15} | {status:7} | {count}")
    
    print("\n  " + "=" * 45)
    
    if all_passed:
        print("\n  ✅ All format tests passed!")
        print("\n  📝 Conclusion:")
        print("     Parser chain works reliably for all formats.")
        print("     It serves as a good fallback when LLM is unavailable.")
        print("\n  💡 Recommendation:")
        print("     KEEP parser chain as reliable fallback.")
        print("     It provides:")
        print("     - Fast parsing without LLM calls")
        print("     - Deterministic results")
        print("     - Works offline")
        print("     - Cost savings")
        return 0
    else:
        print("\n  ⚠️  Some tests failed")
        print("     Check fixtures and parser implementations")
        return 1


if __name__ == "__main__":
    sys.exit(main())
