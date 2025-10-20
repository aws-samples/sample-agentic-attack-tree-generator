#!/usr/bin/env python3
"""CLI for enriching attack trees with mitigations"""
import json
import argparse
from pathlib import Path
from mitigation_enricher import MitigationEnricher


def main():
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from config import config
    
    parser = argparse.ArgumentParser(
        description='Enrich attack trees with mitigations from STIX bundle'
    )
    parser.add_argument(
        'attack_tree',
        help='Path to attack tree JSON file'
    )
    parser.add_argument(
        '--stix-bundle',
        default=None,
        help=f'Path to STIX bundle (default: {config.stix_bundle_path})'
    )
    parser.add_argument(
        '--output',
        help='Output path (default: <input>_mitigated.json)'
    )
    parser.add_argument(
        '--mermaid',
        help='Also generate Mermaid diagram output'
    )
    
    args = parser.parse_args()
    
    # Load attack tree
    with open(args.attack_tree, 'r') as f:
        attack_tree = json.load(f)
    
    # Enrich with mitigations
    bundle_path = args.stix_bundle if args.stix_bundle else str(config.stix_bundle_path)
    enricher = MitigationEnricher(bundle_path)
    enriched_tree = enricher.enrich_attack_tree(attack_tree)
    
    # Determine output path
    output_path = args.output
    if not output_path:
        input_path = Path(args.attack_tree)
        output_path = input_path.parent / f"{input_path.stem}_mitigated{input_path.suffix}"
    
    # Save enriched tree
    with open(output_path, 'w') as f:
        json.dump(enriched_tree, f, indent=2)
    
    print(f"✅ Enriched attack tree saved to: {output_path}")
    
    # Generate Mermaid if requested
    if args.mermaid:
        # Load original mermaid if exists
        mermaid_input = Path(args.attack_tree).parent / f"{Path(args.attack_tree).stem}.mmd"
        if mermaid_input.exists():
            with open(mermaid_input, 'r') as f:
                mermaid_content = f.read()
            
            enriched_mermaid = enricher.enrich_mermaid(mermaid_content, enriched_tree)
            
            with open(args.mermaid, 'w') as f:
                f.write(enriched_mermaid)
            
            print(f"✅ Enriched Mermaid diagram saved to: {args.mermaid}")
    
    # Print summary
    original_count = len(attack_tree.get('nodes', []))
    enriched_count = len(enriched_tree.get('nodes', []))
    mitigation_count = enriched_count - original_count
    
    print(f"\n📊 Summary:")
    print(f"   Original nodes: {original_count}")
    print(f"   Mitigations added: {mitigation_count}")
    print(f"   Total nodes: {enriched_count}")


if __name__ == '__main__':
    main()
