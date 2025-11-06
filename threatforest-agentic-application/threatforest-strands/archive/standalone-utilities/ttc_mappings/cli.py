#!/usr/bin/env python3
"""CLI for TTC mappings module"""
import argparse
import json
from pathlib import Path
from .matcher import TTCMatcher
from .enricher import AttackTreeEnricher

def create_embeddings(args):
    """Create embeddings from STIX bundle"""
    matcher = TTCMatcher(model_name=args.model)
    
    print(f"📦 Creating embeddings from {args.stix_bundle}")
    print(f"🤖 Using model: {args.model}")
    
    embeddings_data = matcher.create_embeddings(
        args.stix_bundle,
        output_path=args.output
    )
    
    print(f"✅ Created {len(embeddings_data['patterns'])} embeddings")
    print(f"💾 Saved to {args.output}")

def match_steps(args):
    """Match attack steps to techniques"""
    matcher = TTCMatcher(
        embeddings_path=args.embeddings,
        model_name=args.model,
        min_similarity=args.min_similarity
    )
    
    # Read attack steps from file or stdin
    if args.input:
        with open(args.input, 'r') as f:
            steps = [line.strip() for line in f if line.strip()]
    else:
        steps = args.steps
    
    print(f"🔍 Matching {len(steps)} attack steps...")
    matches = matcher.match_steps(steps, top_k=args.top_k)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(matches, f, indent=2)
        print(f"💾 Saved matches to {args.output}")
    else:
        for match in matches:
            print(f"\n📝 {match['attack_step']}")
            for m in match['matches']:
                conf_emoji = '🟢' if m['confidence'] == 'high' else '🟡' if m['confidence'] == 'medium' else '🔴'
                print(f"   {conf_emoji} {m['technique_id']:12s} {m['name']:45s} ({m['similarity']:.3f})")

def enrich_trees(args):
    """Enrich attack trees with TTC mappings"""
    matcher = TTCMatcher(
        embeddings_path=args.embeddings,
        model_name=args.model,
        min_similarity=args.min_similarity
    )
    enricher = AttackTreeEnricher(matcher)
    
    input_path = Path(args.input)
    output_path = Path(args.output)
    
    if input_path.is_file():
        print(f"📄 Enriching {input_path}")
        output_file = output_path / f"enriched_{input_path.name}"
        enricher.enrich_file(str(input_path), str(output_file))
        print(f"✅ Saved to {output_file}")
    else:
        print(f"📁 Enriching attack trees in {input_path}")
        enricher.enrich_directory(str(input_path), str(output_path), args.pattern)
        print(f"✅ Enriched files saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='TTC Mappings CLI')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create embeddings
    create_parser = subparsers.add_parser('create', help='Create embeddings from STIX bundle')
    create_parser.add_argument('stix_bundle', help='Path to STIX bundle JSON')
    create_parser.add_argument('-o', '--output', required=True, help='Output embeddings file')
    create_parser.add_argument('-m', '--model', default='Qwen/Qwen3-Embedding-0.6B', help='Model name')
    
    # Match steps
    match_parser = subparsers.add_parser('match', help='Match attack steps to techniques')
    match_parser.add_argument('-e', '--embeddings', required=True, help='Path to embeddings file')
    match_parser.add_argument('-i', '--input', help='Input file with attack steps (one per line)')
    match_parser.add_argument('-s', '--steps', nargs='+', help='Attack steps to match')
    match_parser.add_argument('-o', '--output', help='Output JSON file')
    match_parser.add_argument('-m', '--model', default='Qwen/Qwen3-Embedding-0.6B', help='Model name')
    match_parser.add_argument('--min-similarity', type=float, default=0.35, help='Minimum similarity threshold')
    match_parser.add_argument('--top-k', type=int, default=3, help='Number of matches per step')
    
    # Enrich trees
    enrich_parser = subparsers.add_parser('enrich', help='Enrich attack trees with TTC mappings')
    enrich_parser.add_argument('-e', '--embeddings', required=True, help='Path to embeddings file')
    enrich_parser.add_argument('-i', '--input', required=True, help='Input file or directory')
    enrich_parser.add_argument('-o', '--output', required=True, help='Output directory')
    enrich_parser.add_argument('-m', '--model', default='Qwen/Qwen3-Embedding-0.6B', help='Model name')
    enrich_parser.add_argument('--min-similarity', type=float, default=0.35, help='Minimum similarity threshold')
    enrich_parser.add_argument('--pattern', default='attack_tree_*.md', help='File pattern for directory mode')
    
    args = parser.parse_args()
    
    if args.command == 'create':
        create_embeddings(args)
    elif args.command == 'match':
        match_steps(args)
    elif args.command == 'enrich':
        enrich_trees(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
