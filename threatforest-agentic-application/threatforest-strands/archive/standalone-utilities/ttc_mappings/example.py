#!/usr/bin/env python3
"""Example usage of TTC mappings module"""
from pathlib import Path
from .matcher import TTCMatcher
from .enricher import AttackTreeEnricher

def example_matching():
    """Example: Match attack steps to techniques"""
    print("=" * 70)
    print("Example 1: Matching Attack Steps")
    print("=" * 70)
    
    # Initialize matcher with pre-generated embeddings
    embeddings_path = Path(__file__).parent / 'data' / 'ttc_embeddings.json'
    matcher = TTCMatcher(
        embeddings_path=str(embeddings_path),
        min_similarity=0.35
    )
    
    # Sample attack steps
    steps = [
        "Query AWS S3 bucket for sensitive data",
        "Exploit Lambda function vulnerability",
        "Access DynamoDB table without authorization",
        "Steal credentials from memory"
    ]
    
    print(f"\n🔍 Matching {len(steps)} attack steps...\n")
    matches = matcher.match_steps(steps, top_k=3)
    
    for match in matches:
        print(f"📝 {match['attack_step']}")
        for m in match['matches']:
            conf_emoji = '🟢' if m['confidence'] == 'high' else '🟡' if m['confidence'] == 'medium' else '🔴'
            print(f"   {conf_emoji} {m['technique_id']:12s} {m['name']:45s} ({m['similarity']:.3f})")
        print()

def example_enrichment():
    """Example: Enrich attack tree"""
    print("=" * 70)
    print("Example 2: Enriching Attack Tree")
    print("=" * 70)
    
    # Initialize matcher and enricher
    embeddings_path = Path(__file__).parent / 'data' / 'ttc_embeddings.json'
    matcher = TTCMatcher(
        embeddings_path=str(embeddings_path),
        min_similarity=0.35
    )
    enricher = AttackTreeEnricher(matcher)
    
    # Sample attack tree markdown
    sample_tree = """# Attack Tree: Data Breach

## Mermaid Diagram

```mermaid
graph TD
    A["Malicious insider"] --> B["Query AWS S3 bucket"]
    A --> C["Access DynamoDB table"]
    B --> D["Exfiltrate sensitive data"]
    C --> D
```

## Description
Sample attack tree for demonstration.
"""
    
    print("\n📄 Original attack tree:")
    print(sample_tree)
    
    print("\n🔧 Enriching with TTC mappings...\n")
    enriched = enricher.enrich_attack_tree(sample_tree)
    
    print("✅ Enriched attack tree:")
    print(enriched)

def example_create_embeddings():
    """Example: Create embeddings from STIX bundle"""
    print("=" * 70)
    print("Example 3: Creating Embeddings")
    print("=" * 70)
    
    # Load config
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from config import config
    
    stix_bundle = config.stix_bundle_path
    
    if not stix_bundle.exists():
        print(f"⚠️  STIX bundle not found at {stix_bundle}")
        print("   Skipping embedding creation example")
        return
    
    matcher = TTCMatcher(model_name='Qwen/Qwen3-Embedding-0.6B')
    
    print(f"\n📦 Creating embeddings from {stix_bundle.name}")
    print("🤖 Using model: Qwen/Qwen3-Embedding-0.6B")
    print("⏳ This may take a few seconds...\n")
    
    embeddings_data = matcher.create_embeddings(
        str(stix_bundle),
        output_path=None  # Don't save, just demonstrate
    )
    
    print(f"✅ Created {len(embeddings_data['patterns'])} embeddings")
    print(f"📊 Embedding dimensions: {embeddings_data['embedding_dim']}")

if __name__ == '__main__':
    example_matching()
    print("\n")
    example_enrichment()
    print("\n")
    # Uncomment to test embedding creation (requires model download)
    # example_create_embeddings()
