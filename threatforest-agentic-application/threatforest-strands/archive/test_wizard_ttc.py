#!/usr/bin/env python3
"""Test TTC enrichment in wizard"""
import asyncio
from pathlib import Path
from modules.ttc_mappings import TTCMatcher, AttackTreeEnricher

async def test_enrichment():
    """Test TTC enrichment functionality"""
    
    print("🧪 Testing TTC Enrichment Integration")
    print("=" * 70)
    
    # Setup paths
    embeddings_path = Path("modules/ttc_mappings/data/ttc_embeddings.json")
    
    if not embeddings_path.exists():
        print(f"❌ Embeddings not found: {embeddings_path}")
        return
    
    print(f"✅ Found embeddings: {embeddings_path}")
    
    # Initialize matcher
    print("\n📦 Initializing TTC matcher...")
    matcher = TTCMatcher(
        embeddings_path=str(embeddings_path),
        min_similarity=0.35
    )
    print("✅ Matcher initialized")
    
    # Initialize enricher
    print("\n🔧 Initializing enricher...")
    enricher = AttackTreeEnricher(matcher)
    print("✅ Enricher initialized")
    
    # Create sample attack tree
    sample_tree = """# Attack Tree: T001 - Data Breach

**Threat ID**: T001  
**Description**: Unauthorized access to sensitive data

---

## Attack Tree Diagram

```mermaid
graph TD
    A["Malicious insider"] --> B["Query AWS S3 bucket"]
    A --> C["Access DynamoDB table"]
    B --> D["Exfiltrate sensitive data"]
    C --> D
```

## Attack Path Analysis

This attack tree represents potential attack paths.
"""
    
    print("\n📝 Sample attack tree:")
    print(sample_tree[:200] + "...")
    
    # Test enrichment
    print("\n🎯 Enriching attack tree...")
    enriched = enricher.enrich_attack_tree(sample_tree)
    
    print("\n✅ Enriched attack tree (first 500 chars):")
    print(enriched[:500] + "...")
    
    # Check if technique IDs were added
    if "T1190.A012" in enriched or "AT1029" in enriched:
        print("\n✅ Technique IDs successfully added to mermaid diagram")
    else:
        print("\n⚠️  No technique IDs found in enriched output")
    
    # Check if technique table was added
    if "## TTC Technique Mappings" in enriched:
        print("✅ Technique mapping table added")
    else:
        print("⚠️  No technique mapping table found")
    
    print("\n" + "=" * 70)
    print("✅ TTC enrichment test complete!")

if __name__ == "__main__":
    asyncio.run(test_enrichment())
