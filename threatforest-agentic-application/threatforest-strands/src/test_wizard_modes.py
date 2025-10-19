#!/usr/bin/env python3
"""Test wizard mode selection"""
from pathlib import Path

def test_mode_selection():
    """Test that mode selection logic works"""
    
    print("🧪 Testing Wizard Mode Selection")
    print("=" * 70)
    
    # Test imports
    print("\n1. Testing imports...")
    try:
        from wizard import ThreatForestWizard
        print("✅ Wizard imported successfully")
    except Exception as e:
        print(f"❌ Failed to import wizard: {e}")
        return
    
    # Test mode selection method exists
    print("\n2. Testing mode selection method...")
    wizard = ThreatForestWizard()
    
    if hasattr(wizard, '_select_mode'):
        print("✅ _select_mode method exists")
    else:
        print("❌ _select_mode method not found")
        return
    
    if hasattr(wizard, '_run_enrichment_only'):
        print("✅ _run_enrichment_only method exists")
    else:
        print("❌ _run_enrichment_only method not found")
        return
    
    # Test TTC module import
    print("\n3. Testing TTC module import...")
    try:
        from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher
        print("✅ TTC modules imported successfully")
    except Exception as e:
        print(f"❌ Failed to import TTC modules: {e}")
        return
    
    # Test embeddings file exists
    print("\n4. Testing embeddings file...")
    embeddings_path = Path("modules/ttc_mappings/data/ttc_embeddings.json")
    if embeddings_path.exists():
        print(f"✅ Embeddings file found: {embeddings_path}")
        print(f"   Size: {embeddings_path.stat().st_size / 1024 / 1024:.1f} MB")
    else:
        print(f"❌ Embeddings file not found: {embeddings_path}")
    
    # Test output directory structure
    print("\n5. Testing output directory structure...")
    output_dir = Path("../output/attack_trees")
    if output_dir.exists():
        project_dirs = [d for d in output_dir.iterdir() if d.is_dir() and not d.name.endswith("_enriched")]
        print(f"✅ Output directory exists: {output_dir}")
        print(f"   Found {len(project_dirs)} project directories")
        for proj_dir in project_dirs:
            tree_count = len(list(proj_dir.glob("attack_tree_*.md")))
            print(f"   - {proj_dir.name}: {tree_count} attack trees")
    else:
        print(f"⚠️  Output directory not found: {output_dir}")
        print("   (This is OK if no attack trees have been generated yet)")
    
    print("\n" + "=" * 70)
    print("✅ Mode selection test complete!")
    print("\nTo test the wizard:")
    print("  python threatforest_wizard.py")
    print("\nExpected flow:")
    print("  1. Welcome message")
    print("  2. Mode selection (Full Analysis or TTC Enrichment)")
    print("  3. If Full Analysis: normal workflow")
    print("  4. If TTC Enrichment: select project and enrich")

if __name__ == "__main__":
    test_mode_selection()
